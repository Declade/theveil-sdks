# Security Policy

## Supported versions

| Version      | Supported          |
| ------------ | ------------------ |
| 0.1.x        | :white_check_mark: |
| < 0.1.0      | :x:                |

`theveil` is in pre-1.0 alpha. Security fixes ship against the current 0.1.x
line. Pre-0.1.0 builds are not supported and should not be relied on.

## Reporting a vulnerability

Please report suspected security issues to:

**security@dsaveil.io**

Do **not** open a public GitHub issue for security reports. Use email so
we can triage under embargo before details are public.

Include, when possible:

- affected version (output of `python -c "import theveil; print(theveil.__version__)"`)
- reproduction steps or a minimal PoC
- observed vs. expected behaviour
- impact assessment, if you have one

## Response commitment

- **Acknowledgement**: within 72 hours of receipt.
- **Coordinated disclosure**: we work with you on a disclosure timeline.
- **Default embargo**: 90 days from acknowledgement, unless mutually
  shortened (e.g. low-risk) or extended (e.g. dependency coordination).
- **Credit**: researchers are credited in the release notes unless they
  request anonymity.

## Scope

**In scope**

- The `theveil` PyPI package and its source in this repository.
- The publish pipeline (`.github/workflows/publish-python.yml`) and its
  trusted-publisher configuration.
- Cryptographic verification paths inside the SDK (certificate signature
  verification, witness validation).

**Out of scope**

- User code that *uses* the SDK — please report to the user code's
  maintainer, not here.
- Upstream dependencies (`httpx`, `pydantic`, `cryptography`) — please
  report directly to those projects. If a vulnerability in an upstream
  dependency affects `theveil` specifically, you may CC us.
- The hosted gateway service (`gateway.dsaveil.io`) — report infrastructure
  issues to `security@dsaveil.io` with "gateway:" in the subject line.

## Release integrity

From `theveil` 0.1.1 onward, releases are published to PyPI via
[PyPI trusted publishers](https://docs.pypi.org/trusted-publishers/) using
OIDC tokens minted by GitHub Actions. The uploader identity is bound to
this repository, the `publish-python.yml` workflow, and the `pypi`
deployment environment — no long-lived PyPI API token exists.

Each release is traceable to a specific workflow run. The workflow run
link is recorded on the corresponding GitHub release page; the run's
OIDC claims are cryptographically tied to the uploaded artifact by PyPI's
mint-token flow.

If you believe a release was published from an identity *other* than this
repository, please report it via `security@dsaveil.io` immediately.
