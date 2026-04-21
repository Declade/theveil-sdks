# Custom PyPI OIDC + twine publish — design note

**Status:** Phase 1 design locked. Awaits external Codex review before Phase 2 (implementation).
**Scope:** Python SDK (`theveil` on PyPI) publish workflow only. Does not touch `publish-ts.yml` or `publish-go.yml`.
**Supersedes:** `.github/workflows/publish-python.yml`'s `- uses: pypa/gh-action-pypi-publish@<sha>` step only. Everything else in that workflow (trigger pattern, environment, permissions, build step) is retained.
**Branch:** `arc/custom-pypi-oidc-publish` off `main` at `971066e`.

---

## Decisions locked

All 7 decisions from Section 8 are locked. Summary for quick reference; detailed reasoning retained in Section 8.

| # | Topic | Locked choice |
|---|---|---|
| 8.1 | Attestations | **A** — accept attestation loss; sigstore attestations as separate fast-follow arc (backlog-tracked, narrative-mismatch note retained so it doesn't get forgotten) |
| 8.2 | `--skip-existing` | **A** — omit the flag; duplicate-version upload fails hard |
| 8.3 | twine hash-pinning | **A** — version pin only (`twine==6.2.0`); `--require-hashes` filed as hardening backlog item alongside Dependabot |
| 8.4 | Smoke-test change pairing | **(a)** — add `python/SECURITY.md`, referencing Clario security posture |
| 8.5 | Single vs split step | **B (overridden from design recommendation A)** — two steps: mint step outputs masked token → upload step consumes via step-scoped `env:`. Rationale: split failure modes yield clearer `::error::` annotations in the Actions UI |
| 8.6 | Upload URL | **Hardcode** `https://upload.pypi.org/legacy/` (self-documenting, immune to twine default changes) |
| 8.7 | Retain `environment: pypi` | **Yes** — load-bearing for OIDC claim verification on PyPI side; do not touch |

---

## 1. Why (not what)

### What issue #19 says

`pypa/gh-action-pypi-publish` is a GitHub Actions *composite* action. The outer composite (`action.yml`) is SHA-pinned by us at `cef221092ed1bacb1cc03d23a2d87d1d172e277b` (v1.14.0, the current head of the `release/v1` branch) in PR #18. That pin protects the outer orchestration code. Inside the composite, the `Create Docker container action` step runs `create-docker-action.py`, which writes a trampoline sub-action at `.github/.tmp/.generated-actions/run-pypi-publish-in-docker-container/action.yml`. The body of that generated sub-action — verbatim from `create-docker-action.py:15-17` — is:

```python
def set_image(ref: str, repo: str, repo_id: str) -> str:
    if repo_id == REPO_ID_GH_ACTION:
        return str(ACTION_SHELL_CHECKOUT_PATH / 'Dockerfile')
    docker_ref = ref.replace('/', '-')
    return f'docker://ghcr.io/{repo}:{docker_ref}'
```

For external consumers (us), `repo_id != REPO_ID_GH_ACTION` (178055147), so the fallback branch runs and the generated sub-action references `docker://ghcr.io/pypa/gh-action-pypi-publish:<ref>` — a **Docker registry tag**, not a digest. Even when we pin the outer action at a 40-character commit SHA, the Docker reference resolves through the `ghcr.io` registry, which serves whatever image is currently tagged with that string. An attacker with push access to `ghcr.io/pypa/gh-action-pypi-publish` (or an exploited GHCR registry vulnerability) can repoint that tag to a malicious image. Our SHA pin protects us against a repo-level compromise of `pypa/gh-action-pypi-publish` but does nothing for a GHCR tag-repoint.

**Blast radius if exploited:** the malicious image runs inside our Python publish job with `id-token: write` + `environment: pypi`. It can mint a short-lived PyPI trusted-publishing token for `theveil` and upload any arbitrary package content to the name `theveil` on PyPI. Every user who subsequently runs `pip install theveil` ingests that payload.

### What the custom flow replaces (and does NOT replace)

**Replaces:**
- The single `- uses: pypa/gh-action-pypi-publish@<sha>` step in `publish-python.yml`.
- Its transitive Docker pull of `docker://ghcr.io/pypa/gh-action-pypi-publish:<mutable-tag>`.

**Does NOT replace:**
- `twine` (the actual upload library — still a dependency, now installed directly via `pip` into the job runtime).
- `curl` (used for the OIDC exchange — pre-installed on `ubuntu-latest`).
- `jq` (used to parse JSON responses — pre-installed on `ubuntu-latest`).
- The PyPI registry endpoints (`/_/oidc/audience`, `/_/oidc/mint-token`, `upload.pypi.org/legacy/`) — these are first-party PyPI infrastructure; we depend on them regardless of which client does the upload.
- GitHub's OIDC endpoint (`$ACTIONS_ID_TOKEN_REQUEST_URL`) — first-party GitHub infrastructure.
- `actions/setup-python` — still needed to bring a pinned CPython + pip into the job. Already SHA-pinned by PR #18.

### Is the supply-chain surface unambiguously smaller?

**Before** (current `publish-python.yml`, after PR #18):

| Artifact | Pin form | Trust anchor |
|---|---|---|
| `pypa/gh-action-pypi-publish` | SHA pin | GitHub (outer action code) |
| `docker://ghcr.io/pypa/gh-action-pypi-publish:<tag>` | Mutable tag | **GHCR registry — mutable** |
| `twine` (inside Docker image) | Pinned in `requirements/runtime.txt` inside the image | Docker image content |
| `pypi_attestations`, `sigstore`, `requests`, `id` (inside image) | Pinned in image's requirements | Docker image content |
| Python 3.13-slim base image (per `Dockerfile:1`) | Tag `python:3.13-slim` — mutable | Docker Hub |

**After** (Option A, no attestations — recommended):

| Artifact | Pin form | Trust anchor |
|---|---|---|
| `twine==6.2.0` | Version pin (optionally `--require-hashes`) | PyPI with TUF metadata (PEP 458 once enabled) |
| `curl` | Pre-installed on runner, GitHub-maintained | GitHub Actions runner image |
| `jq` | Pre-installed on runner, GitHub-maintained | GitHub Actions runner image |
| PyPI endpoints | First-party | PyPI |
| GitHub OIDC endpoint | First-party | GitHub |

**Net verdict:** strictly smaller surface. Eliminates one mutable Docker tag on GHCR and one transitive Docker Hub base-image tag. The remaining dependencies are either explicitly pinned to PyPI-resolved artifacts (twine) or pre-baked into the GitHub runner (curl, jq). No new external trust anchors are introduced.

**After** (Option B, with sigstore attestations): adds `sigstore==<pinned>` and `pypi-attestations==<pinned>` as new PyPI-installed dependencies. Still smaller than today — one mutable Docker tag + one mutable base-image tag are swapped for two PyPI-pinned packages — but nonzero additive surface versus Option A.

---

## 2. The OIDC exchange flow

Reference: `pypa/gh-action-pypi-publish@cef22109.../oidc-exchange.py`. The flow below is a faithful replication of that script's behavior in bash, with explicit field names and HTTP mechanics.

### Step 2.1 — Discover audience

PyPI publishes its expected OIDC audience string at a well-known endpoint. We fetch it rather than hardcoding so we automatically track any future PyPI audience rotation.

```
GET https://pypi.org/_/oidc/audience
Accept: application/json
```

**Expected response** (HTTP 200, JSON):

```json
{"audience": "pypi"}
```

**Failure modes:**
- **404** — index does not support OIDC trusted publishing. Should never happen on `pypi.org`; if it does, PyPI infrastructure is broken. Fail hard with `::error::`.
- **403** — trusted publishing is disabled for this repo. Fail hard with guidance to re-verify the trusted-publisher configuration on PyPI.
- **5xx** — PyPI maintenance or outage. Fail hard, log `status.python.org`.
- **Missing `audience` field** — malformed response. Fail hard.
- **Timeout (>10s)** — fail hard; do not retry (PyPI outages are typically on-the-order-of minutes, retry-in-workflow adds no value).

### Step 2.2 — Request GitHub OIDC JWT

GitHub injects two env vars on jobs with `permissions: id-token: write`:

- `ACTIONS_ID_TOKEN_REQUEST_URL` — the JWT request URL, **already containing query parameters** (the string ends with `?api-version=2.0&...` or similar opaque Microsoft-internal query params). The `audience` parameter is appended with `&audience=<value>`, **never `?audience=`**.
- `ACTIONS_ID_TOKEN_REQUEST_TOKEN` — a bearer token used to authenticate the JWT request.

Request:

```
GET ${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=pypi
Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}
```

**Expected response** (HTTP 200, JSON):

```json
{"value": "<signed-jwt>"}
```

The JWT's claims (extractable by base64-decoding the middle segment) include: `sub`, `aud`, `iss`, `repository`, `repository_owner`, `repository_owner_id`, `workflow_ref`, `job_workflow_ref`, `ref`, `environment`. PyPI verifies these against the trusted-publisher configuration to decide whether to mint a token.

**Failure modes:**
- **HTTP non-2xx** (401, 403, 5xx, or anything else) — fail hard. Most likely causes: missing `id-token: write`, workflow triggered by a fork PR (GitHub denies OIDC on fork PRs even when permissions look right), or transient GitHub issue.
- **Missing `value` field** — malformed. Fail hard.
- **Null `value` field** — same. Fail hard.
- **Rate limit** — should not be hit in practice; each tag push is one JWT request. If ever hit, fail hard.

### Step 2.3 — Exchange OIDC JWT for PyPI token

Request:

```
POST https://pypi.org/_/oidc/mint-token
Content-Type: application/json

{"token": "<signed-jwt-from-step-2.2>"}
```

**Expected response** (HTTP 200, JSON):

```json
{
  "success": true,
  "token": "pypi-AgEI...",
  "expires": 1234567890,
  "message": "...",
  "errors": []
}
```

The minted token is a standard PyPI API token (prefix `pypi-`). Lifetime per PyPI: ~15 minutes (PyPI docs-stated; the exact value is controlled by the `expires` field but is tight enough that we cannot reuse across jobs).

**Failure modes:**
- **HTTP 403** — trusted-publisher misconfigured: typically audience mismatch, wrong workflow filename, wrong environment, or claim mismatch. PyPI returns a JSON body with `errors: [{"code": "...", "description": "..."}]` — fail hard and print the errors verbatim + the JWT claims (extracted from the JWT payload) so the operator can diagnose which claim mismatched.
- **HTTP 422** — malformed request body. Should never happen in a well-formed script; fail hard.
- **HTTP 5xx** — PyPI outage. Fail hard.
- **Malformed JSON response** — catch the JSON parse error and fail hard with `status_code` + the first 500 bytes of the raw response body (truncated to avoid log bloat).
- **Response 200 but `token` field missing/null** — fail hard; this should be impossible but would be a silent PyPI regression.
- **Clock skew** — the JWT includes `iat`/`exp` claims. GitHub Actions runner clocks are synced against NTP; skew is never a realistic cause of `exp` rejection. If it ever becomes one, PyPI's 403 response will make the cause clear.

### Step 2.4 — Token masking and scoping (two-step flow — locked per 8.5)

The workflow is split across two distinct steps (per 8.5 = B):

- **Step A (mint):** performs 2.1 → 2.3; at the end, masks the minted token and writes it to the step's output. Upload artefacts are NOT touched in this step.
- **Step B (upload):** consumes the token from Step A's output into its step-scoped `env:` block, runs `twine check` + `twine upload`, exits.

**Token masking — ordering invariant:**

The masking command MUST execute BEFORE the token is written anywhere the runner can log. Concretely, Step A's bash body is structured so that `::add-mask::<token>` is emitted to stderr before either `echo "token=<val>" >> "$GITHUB_OUTPUT"` or any other write. Failing to order this correctly would leak the token to the raw log before the scrubber learns about it.

```bash
# (inside Step A, after parsing the mint response)
printf '::add-mask::%s\n' "$PYPI_TOKEN" 1>&2
printf 'token=%s\n' "$PYPI_TOKEN" >> "$GITHUB_OUTPUT"
```

**Step-output handling (the overridden concern):**

`$GITHUB_OUTPUT` writes are durable within the job's step-output map and are consumable by later steps via `${{ steps.mint.outputs.token }}`. The runner applies masking to the stored value across the job lifetime — any subsequent log statement that emits the masked string is scrubbed. Known footguns handled:

- **Step summaries:** the runner's step-summary feature renders `GITHUB_STEP_SUMMARY` markdown, NOT step outputs. The minted token is never written to `$GITHUB_STEP_SUMMARY`. Codex should verify this invariant in the implemented YAML.
- **Log echo on output write:** the runner does not echo `GITHUB_OUTPUT` lines to the log. The `printf 'token=...' >> "$GITHUB_OUTPUT"` line produces no log output. Verified against the pypa action's own token-handling (it prints the token to stdout where `twine-upload.sh` captures it via `$(python /app/oidc-exchange.py)`; our split-step variant is materially more explicit about masking).
- **Job-level `env:`:** never used for the token. Only the upload step's own `env:` block gets `TWINE_PASSWORD: ${{ steps.mint.outputs.token }}`. This scopes the token to Step B's process tree; no other step (present or future) sees it.

**Scoping rules (locked):**

- Token is written ONLY to `$GITHUB_OUTPUT` of the mint step, and masked before that write.
- Token is NEVER written to disk (`~/.pypirc`, `/tmp/token`, environment files on disk).
- Token is NEVER written to `$GITHUB_STEP_SUMMARY` or `$GITHUB_ENV`.
- Token is NEVER passed to any step other than Step B (upload).
- Step B's `env:` block for `TWINE_PASSWORD` is scoped to that step's `run:` only, never to the job.

**Trade-off accepted (per 8.5 override):** two-step split means the token persists in the job's step-output map for the lifetime of the job (several seconds between Step A and Step B). The single-step alternative would have held the token in a bash shell variable for a shorter lifetime. Marc's override prioritizes operator debuggability (Step A failure surfaces distinct from Step B failure in the Actions UI) over the marginally-shorter token lifetime. Codex should flag if the job-level step-output exposure is larger than expected — but under current GitHub Actions runner semantics, a masked step output is scrubbed consistently and cannot be exfiltrated by a later step unless that step explicitly writes the token to a new surface, which this design forbids.

---

## 3. twine invocation

### Version pin

**twine 6.2.0** (latest stable at design time, 2026-04-21; verified via `curl https://pypi.org/pypi/twine/json | jq -r .info.version`).

Requires Python >= 3.9; our workflow already pins `python-version: '3.12'` via `actions/setup-python`, so the Python requirement is trivially satisfied.

### Install mechanics

```bash
python -m pip install --upgrade pip
python -m pip install 'twine==6.2.0'
```

**Hash-pinning — LOCKED per 8.3 = A:** version pin only (`twine==6.2.0`), no constraints file, no `--require-hashes`. Hash-pinning is tracked as a hardening backlog item alongside Dependabot enablement — both land uniformly across all three SDKs' CI workflows in a later arc, not just this one.

Reasoning retained for audit:
- **A — version pin only** (locked): simple; any transitive-dependency hijack on PyPI could slip malicious code into the runtime. Low probability given twine's small transitive graph and PyPI's Sigstore attestations on modern releases.
- **B — `--require-hashes` with a vendored `python/constraints/publish-requirements.txt`** (deferred): each direct + transitive dep pinned to a SHA-256 hash; refuses to install anything not in the file. Requires periodic regeneration via `pip-compile --generate-hashes`; drift is failure-closed but has an operational cost.

### Pre-upload check

Always run `twine check` before upload. It validates distribution metadata (`long_description` renders correctly on PyPI, required metadata fields present, wheel tag sanity). Does not verify signatures or hit the network. Fast, no side effects.

```bash
twine check python/dist/*
```

Exits 0 on success; non-zero on any metadata issue. Failure halts the job.

### Upload invocation

```bash
TWINE_USERNAME=__token__ \
TWINE_PASSWORD="$PYPI_TOKEN" \
TWINE_REPOSITORY_URL=https://upload.pypi.org/legacy/ \
  twine upload --non-interactive --disable-progress-bar python/dist/*
```

- `TWINE_USERNAME=__token__` + `TWINE_PASSWORD=<token>` is the canonical way to pass an API token. `twine-upload.sh:165-167` at the pinned SHA uses exactly this pattern.
- `TWINE_REPOSITORY_URL=https://upload.pypi.org/legacy/` — explicit PyPI upload endpoint. Matches the default in `pypa/gh-action-pypi-publish/action.yml:14`.
- `--non-interactive` — never prompt; any auth failure exits non-zero instead of hanging.
- `--disable-progress-bar` — avoids TTY-shaped output in the CI log.
- Working directory: `python` (already set at the workflow job level via `defaults.run.working-directory: python`). Dist glob is therefore `dist/*`, resolving to `python/dist/*` from the repo root — matches where `python -m build` writes its outputs.

### `--skip-existing` — LOCKED per 8.2 = A

**Locked: omit `--skip-existing`.** Duplicate-version upload fails hard with twine exit code 1 and PyPI HTTP 400. Recovery is an explicit version bump. Silent-skip would hide real version-bump bugs.

Reasoning retained for audit:
- **A — omit** (locked): fail-hard on duplicate; forces operator to bump version rather than silently no-op.
- **B — include** (rejected): idempotent retries; hides state confusion.

---

## 4. Attestation / sigstore — LOCKED per 8.1 = A

**Locked: ship without PEP 740 attestations initially.** Sigstore attestations are tracked as a separate fast-follow arc (backlog item). Reasoning from both options retained below for audit — the original option comparison drove the locked decision and is preserved as design evidence.

**Narrative-mismatch note (do not forget):** The Veil's product pitch is cryptographically-verifiable provenance for AI inference. Shipping Python SDK without PEP 740 attestations is a thematic off-key. The TS SDK has npm auto-provenance; the Python SDK must reach PEP 740 parity before the post-Clario customer engagement cycle widens. File a GitHub issue for the sigstore follow-up arc when this arc merges, and reference this note so it doesn't get forgotten.

### Background

PEP 740 (Final, accepted 2024-07-17) defines a wire format for per-file digital attestations on Python package indices. The current `pypa/gh-action-pypi-publish@v1.14.0` generates PEP 740 attestations automatically when all of the following are true (per `action.yml:72-75` + `twine-upload.sh` logic):

1. Trusted Publishing flow is active (no `INPUT_PASSWORD` supplied by the caller).
2. The index URL matches `pypi.org` or `test.pypi.org`.
3. `attestations: true` (the default).

When active, the action invokes `attestations.py` inside the Docker container, which:

- Uses `sigstore.sign.Signer` with `ClientTrustConfig.production()` to sign each dist file.
- Obtains a *separate* OIDC credential with audience `sigstore` (not `pypi`) to identify the signer.
- Writes a `<dist>.publish.attestation` JSON file alongside each dist.
- Relies on twine's `--attestations` flag (supported in twine 6.x) to include those attestations in the upload multipart form.

PyPI then exposes the attestations on a `<dist>.provenance` URL and a `data-provenance` Simple Index attribute. Consumers verify via the PEP 740 in-toto DSSE chain rooted at the Sigstore public instance.

### Option A — Accept attestation loss for initial landing

**What is lost:** PEP 740 attestations on `theveil` dists published via this workflow.

**What remains:**
- Trusted Publishing (OIDC-minted tokens) still used — unchanged from today.
- Users can still verify package origin via PyPI's existing metadata (PEP 458 once PyPI enables it, PyPI's own account-level signing, etc.).
- The package is still legitimately ours — there is no authenticity loss, only loss of the cryptographic *attestation* artifact that a third-party verifier can check offline.

**Impact on The Veil's pitch:** The Veil's product narrative is cryptographically-verifiable provenance for AI inference. Shipping our Python SDK *without* a cryptographic provenance attestation is thematically off-key. Any customer who inspects our package on PyPI and notices the absence of a provenance badge (which PyPI shows when attestations are present) would have a legitimate question. However:
- The TS SDK on npm already publishes with provenance attestations (automatic via npm trusted publishing, PR #16).
- The Go SDK has no equivalent attestation mechanism on the Go proxy — there's nothing to lose.
- So the gap is Python-only, and only until Option B is landed.

**Effort to revisit:** Low. Adding sigstore signing to the custom flow is a separable arc (install sigstore + pypi-attestations, run `python -m sigstore sign` or call the pypi-attestations API, pass `--attestations` to twine). No design refactor needed.

### Option B — Add explicit sigstore signing now

**What is added** to the custom flow:

1. Install `sigstore==<pinned>` + `pypi-attestations==<pinned>` alongside twine.
2. After the build step, before the upload step:
   - Obtain a *second* GitHub OIDC JWT with audience `sigstore` (separate from the `pypi` JWT already obtained for the mint-token call).
   - Invoke sigstore's signer to produce `<dist>.publish.attestation` sidecars.
3. Invoke twine with `--attestations`, which includes the sidecars in the upload multipart form.

**Added supply-chain surface:**
- `sigstore` Python package — recent versions are small and have few transitive deps, but still a nonzero addition.
- `pypi-attestations` Python package — small, PyPA-maintained.
- Sigstore root-of-trust bundle (shipped inside `sigstore` package via `ClientTrustConfig.production()`).
- Sigstore OIDC issuance + Rekor log — same infrastructure we already rely on for the Go SDK's DSA backend certificate attestations (memory `project_dsa_48_49_rekor_hashedrekord_shipped.md`). Not a *new* trust anchor at the org level; familiar infrastructure.

**Hash-pinning recommendation:** If Option B is chosen, the `--require-hashes` constraints file (Section 3 decision) becomes more important — sigstore has a larger transitive graph than twine alone, and the whole point of attestations is to tighten the trust chain.

**Timing-failure consideration:** Sigstore signing can fail independently of twine upload. Specifically: signing happens *before* upload (in the twine invocation sequence). If signing fails, we fail hard *before* any network request to PyPI; no mixed state is possible. If twine upload fails *after* signing succeeded, we have a `.publish.attestation` file on the runner that never gets uploaded — no harm, runner state is ephemeral.

**Unlikely but specific failure mode:** sigstore is rate-limited; a tag push storm (shouldn't happen for us) would hit it. Mitigation: none needed at our volume.

### Locked rationale (A)

The locked decision (A) was chosen for the following reasons, preserved here as the audit trail:

- Option A ships the security fix (issue #19) immediately with minimum change. Smaller diff, simpler review, fewer moving parts on the first smoke test.
- The attestation-narrative mismatch is real but mitigable via the Option A → Option B fast-follow arc (trivial add, not a rewrite); attestations land within the following arc cycle.
- Shipping sigstore on the first smoke test would add a second failure axis. If the smoke test breaks (Section 6), the operator would have to diagnose "was it the OIDC flow or the sigstore integration?" Option A localizes the smoke-test failure space to the OIDC flow alone.
- The TS and Go SDKs are already proving the OIDC pattern; the Python smoke-testing of OIDC alone is analogous.

---

## 5. Failure modes and recovery

The custom flow has fewer failure surfaces than the current action (no Docker pull, no attestation generation — per decision 8.1 = A), so the enumeration is short.

**Two-step structure consequence (per 8.5 = B locked):** 5.1, 5.2, 5.3, 5.4 are Step A failures — they surface as step-level `::error::` annotations on the "Mint PyPI token via OIDC" step in the Actions UI. 5.6, 5.7 are Step B failures — they surface on the "twine check + upload" step. 5.5 may affect either step. This clean split is the operational reason 8.5 was overridden to B: a red marker on Step A tells the operator "OIDC / trusted-publisher problem", a red marker on Step B tells them "build artefact or PyPI upload problem" — without the operator having to parse step logs to distinguish.

### 5.1 — OIDC audience discovery fails

- **Observable:** `curl` exits non-zero, or response body is not JSON, or `.audience` field is missing/null.
- **Log:** `::error::PyPI OIDC audience discovery failed: <http-status> <body-excerpt>`.
- **Recovery:** job halts. Recovery requires PyPI-side fix (if their endpoint is down) or workflow re-run (if transient).
- **Does NOT** fall back to a hardcoded audience — PyPI's stated contract is that the audience is discoverable at `/_/oidc/audience`, and silently accepting an assumed value would mask a real configuration drift.

### 5.2 — GitHub OIDC JWT request fails

- **Observable:** `curl` exits non-zero, or response body has no `.value` field, or `.value` is null.
- **Log:** `::error::GitHub OIDC token request failed: <http-status> <body-excerpt>` plus a reminder that `id-token: write` must be granted at the job level and that fork-PR triggers are disallowed.
- **Recovery:** job halts. Most common cause: accidental removal of `id-token: write`. Fork-PR case is already handled by our trigger pattern (`tags: ['python/v*']`, `workflow_dispatch`) — forks cannot push tags to our repo, so this path is unreachable for external PRs.

### 5.3 — PyPI token mint returns 403

- **Observable:** HTTP 403 from `/_/oidc/mint-token`. Response body is JSON of shape `{"errors": [{"code": "...", "description": "..."}]}`.
- **Log:** `::error::PyPI token mint refused:` followed by each error's code + description + the claims extracted from the JWT payload (decoded from base64), so the operator can compare against the trusted-publisher configuration on PyPI.
- **Recovery:** job halts. Recovery requires updating the trusted-publisher configuration on `https://pypi.org/manage/project/theveil/settings/publishing/` to match the current workflow's claims (owner, repository, workflow filename, environment).

### 5.4 — PyPI token mint returns 2xx but malformed JSON

- **Observable:** HTTP 2xx but `jq` exits non-zero, or the `.token` field is missing/null.
- **Log:** `::error::PyPI mint-token malformed response: status=<N> body-head=<first-500-chars>`.
- **Recovery:** job halts. Signals PyPI configuration drift or transient PyPI bug. Retry after a few minutes.

### 5.5 — `curl`, `jq`, or `python` missing on runner

- **Assumption:** `ubuntu-latest` runner images include `curl`, `jq`, and `python3` pre-installed. GitHub's documented runner image manifest confirms this.
- **If violated:** `::error::missing prerequisite: <tool>`. Job halts. Recovery: add explicit apt install step. Not expected to happen in practice — but the assumption is stated here so Codex can push back if wrong.

### 5.6 — `twine check` fails

- **Observable:** twine exits non-zero on metadata validation.
- **Log:** twine's own error output surfaces to the runner log.
- **Recovery:** job halts before any PyPI network request — safe, no partial state. Fix: correct the package metadata in `pyproject.toml` (most commonly malformed `long_description` or missing `license` field) and re-tag.

### 5.7 — `twine upload` partial success

- **PyPI's behavior on duplicate upload:** PyPI rejects subsequent uploads of the *same version* (including sdists and wheels with identical filenames), returning HTTP 400 with a `File already exists` error message. This is independent of `--skip-existing`.
- **If the job fails mid-upload** (network blip after first wheel uploads but before second): PyPI has the first wheel, we cannot re-upload it, but the sdist or second wheel is missing. The version is effectively broken on PyPI (`pip install` may or may not succeed depending on platform tag match). **Recovery:** bump the version, re-tag, re-run the full upload. Deleting the partial artifact on PyPI requires manual intervention via the PyPI UI and is generally not an operator-allowed path.
- **Mitigation:** accept this failure mode. Version bump is the canonical PyPI remediation across the ecosystem.

### 5.8 — Sigstore signing fails (Option B only)

- **Observable:** sigstore Python lib raises `IdentityError` or signing fails.
- **Log:** `::error::sigstore attestation generation failed: <exception>`.
- **Recovery:** job halts *before* any PyPI upload. No partial state. Fix: diagnose sigstore-side issue (OIDC audience, Rekor log availability) and re-run.

---

## 6. Testing strategy

### Can this be tested without a real PyPI publish?

**No.** The only authoritative smoke test for the OIDC exchange is a real tag cut against a real PyPI trusted-publisher configuration. Identical to the TS situation (the TS SDK's OIDC flow is not proven until `ts/v0.2.1` is tagged per the separate SDK arc).

Partial testing possibilities considered and rejected as insufficient:
- **Mock the PyPI endpoints** — proves the bash escaping and `jq` parsing but does not exercise the trusted-publisher configuration or PyPI's actual mint logic. Value: near-zero for security hardening.
- **Publish to TestPyPI first** — plausible, but requires a separate trusted-publisher configuration on TestPyPI, and the failure modes on TestPyPI are not always identical to PyPI. Value: marginal; not worth the setup overhead on a one-shot arc.
- **Dry-run via `twine upload --repository test.pypi.org`** — same problem as above, and doesn't exercise our actual PyPI configuration.

### What version gets burned on the smoke test?

**Proposal: `python/v0.1.1`** with a real, non-cosmetic change paired with the version bump. Candidates (Marc picks in Section 8 question 4):

- **(a) Add a `python/SECURITY.md`** documenting the PEP 740 attestation status (if Option A, note that attestations are pending; if Option B, note the sigstore signer identity and verification command).
- **(b) Bump `pytest>=8.0` to the current stable minor** in `python/pyproject.toml`'s dev extras — verifies the dev-deps install path still works under the new CI. Minor dev-only change.
- **(c) Add a type stub or JSDoc-equivalent docstring** to one public Python SDK entry point that currently lacks one. Zero behavioural change, doc-only.

All three are real changes that justify a version bump (Marc's "real change pairing" rule from memory `project_ts_sdk_v020_npm_bootstrap.md`). None touch load-bearing runtime logic.

### Rollback path

If the custom flow breaks OIDC publish on the smoke test:
1. The failure is observable within ~30s of the tag push (the OIDC exchange step runs early).
2. **Do not** attempt in-workflow fixes during the failing run. Cancel if still running.
3. **Hotfix branch** restores the single-line `- uses: pypa/gh-action-pypi-publish@<sha>` step, reverting the custom flow. A new tag `python/v0.1.2` cut from the hotfix commit recovers publishing.
4. `v0.1.1` remains broken on PyPI in whatever state it reached (probably "version reserved but no dists published", which is recoverable: the name stays reserved to us and `v0.1.2` supersedes without conflict).
5. Post-mortem diagnoses which step failed. The OIDC mint step is the highest-risk spot — if PyPI returns 403 with a specific `errors[].code`, the trusted-publisher config likely needs re-verification against the new workflow filename.

---

## 7. Explicit non-goals

This arc does NOT:

- Touch `publish-ts.yml` or `publish-go.yml` (Python-only change).
- Modify any SDK source code (`python/src/theveil/**/*` untouched).
- Add features to the Python SDK (no new public API, no new CLI, no new HTTP endpoints).
- Change the trigger pattern (`tags: ['python/v*']` + `workflow_dispatch` retained).
- Change the `permissions:` block (`id-token: write` + `contents: read` retained).
- Change the `environment: pypi` declaration (retained).
- Change the working directory (`python` retained via `defaults.run.working-directory`).
- Address Dependabot enablement (separate arc; tracked as part of the post-Clario backlog).
- Address broader CI hardening beyond issue #19 (e.g., CodeQL, SAST, secret-scanning, merge protection) — out of scope.
- Make the custom flow available as a reusable action or composite — inlined-only, per-SDK-workflow, no abstraction.
- Bootstrap `theveil` on PyPI if it's not already registered — trusted-publisher configuration must already exist on PyPI (per the current workflow's precondition).

---

## 8. Decisions (locked)

All 7 decisions are locked. Detailed reasoning preserved below for audit purposes. Summary table lives at the top of the document.

### 8.1 — Attestation decision — **LOCKED: A**

**Option A** (no attestations initially, fast-follow separate arc) **vs. Option B** (sigstore attestations in this arc).

**Locked: A — accept attestation loss for the initial landing.** Sigstore attestations are a **tracked backlog item** under a separate fast-follow arc. The Python SDK will land on PyPI without PEP 740 attestations until that arc ships.

**Narrative-mismatch note (explicit so it doesn't get forgotten):** The Veil's product pitch is cryptographically-verifiable provenance for AI inference. Shipping the Python SDK without PEP 740 attestations is a thematic off-key. The TS SDK on npm already has provenance attestations via npm's trusted-publisher auto-provenance; the Python SDK should reach parity before the post-Clario customer engagement cycle widens. **Backlog item: open a GitHub issue for the sigstore follow-up arc after this arc merges, referencing this locked-decision note.**

*Original design recommendation: A. No override.*

### 8.2 — `--skip-existing` behavior — **LOCKED: A**

**A** (omit `--skip-existing`, duplicate-version upload fails hard) **vs. B** (include `--skip-existing`, idempotent retries).

**Locked: A — omit the flag.** Duplicate-version upload fails hard with twine exit code 1 and PyPI HTTP 400. Silent-skip hides state confusion on retries and masks real version-bump bugs.

*Original design recommendation: A. No override.*

### 8.3 — twine hash-pinning — **LOCKED: A**

**A** (version pin only: `twine==6.2.0`) **vs. B** (`--require-hashes` with a constraints file).

**Locked: A — version pin only, `twine==6.2.0`, no constraints file, no `--require-hashes`.** Hash-pinning is filed as a **hardening backlog item alongside Dependabot enablement** — both are cross-cutting supply-chain improvements that should land uniformly across all three SDKs' CI workflows, not just this one.

*Original design recommendation: A. No override.*

### 8.4 — Smoke-test version and real change pairing — **LOCKED: (a)**

**Locked: (a) — add `python/SECURITY.md`.** Real content (not a cosmetic version bump), long-term useful documentation, and references Clario security posture. Gives CISOs a document to point at during the post-Clario customer engagement cycle. Aligns with the arc's theme.

Options considered:
- **(a)** `python/SECURITY.md` documenting attestation status. ✓ LOCKED.
- (b) Bump `pytest>=8.0` to the current stable minor in dev extras.
- (c) Add a docstring to one public Python SDK entry point that lacks one.
- (d) Something else.

*Original design recommendation: (a). No override.*

### 8.5 — Single vs split mint-and-upload steps — **LOCKED: B (OVERRIDDEN from design recommendation A)**

**Locked: B — two steps.** Mint step outputs masked token via `$GITHUB_OUTPUT`; upload step consumes via step-scoped `env:` block.

**Marc's rationale (overriding the design's A recommendation):** split failure modes yield clearer `::error::` annotations in the Actions UI. When a smoke test fails, the operator sees immediately whether the failure was in the OIDC/trusted-publisher path (Step A) or the build-artefact/PyPI-upload path (Step B), without having to parse step logs. Acceptable trade-off: token persists in the job's step-output map for a few seconds between Step A and Step B, rather than in a bash shell variable. Masking via `::add-mask::` before the `$GITHUB_OUTPUT` write is the load-bearing safety measure; the full masking discipline is specified in Section 2.4.

**Design implications of the override (propagated through the note):**
- Section 2.4 rewritten to specify the two-step token-handoff pattern, masking ordering invariant, and the explicit forbidden surfaces (`$GITHUB_STEP_SUMMARY`, `$GITHUB_ENV`, job-level `env:`, disk).
- Section 5 annotated: 5.1–5.4 are Step A failures; 5.6–5.7 are Step B failures; 5.5 may affect either.
- Phase 2 (implementation) must produce a workflow YAML with exactly two publish-related steps (beyond the existing checkout/setup/build/install) and exercise the step-scoped `env:` pattern — not a `run: |` block that performs both mint and upload inline.

*Original design recommendation: A. Overridden to B per Marc.*

### 8.6 — Explicit PyPI upload URL or default — **LOCKED: hardcode**

**Locked: hardcode `TWINE_REPOSITORY_URL=https://upload.pypi.org/legacy/`.** Twine's default URL has shifted historically; hardcoding is self-documenting and immune to twine default changes. Matches the pypa action's explicit value in `action.yml:14`.

*Original design recommendation: hardcode. No override.*

### 8.7 — Retain the `environment: pypi` GitHub environment — **LOCKED: retain**

**Locked: retain.** `publish-python.yml:17`'s `environment: pypi` is load-bearing for the trusted-publisher configuration on PyPI (the environment name is one of the verified claims in the JWT `sub`/`environment` fields). Phase 2 must not touch this declaration. Flagged here so Codex review doesn't misread a "cleanup" opportunity that would break OIDC.

*No decision — retained as originally scoped.*

---

## Phase 2 preconditions (do not start Phase 2 until all true)

- [x] Marc has answered 8.1–8.7 — all 7 decisions locked (summary at top of document; detailed reasoning in Section 8).
- [ ] External Codex adversarial review of this design note complete with PASS verdict.
- [ ] Issue #19 still open (has not been closed by another arc in the interim).
- [ ] PR #18 still open, not merged (closing PR #18 ahead of this arc is explicitly not allowed per the working agreements).

Only after all remaining conditions are met does Phase 2 (YAML implementation on this branch) begin.
