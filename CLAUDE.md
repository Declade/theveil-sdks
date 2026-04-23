## Merge Workflow

- Do NOT use `gh pr merge --squash --delete-branch` — it fails on the local checkout step in this environment.
- Use separate commands: `gh pr merge --squash` then `git branch -d <branch>`. Or merge via the GitHub UI.
- Always run subagent pre-commit review checks before committing. Do not skip on "simple" commits. If no relevant subagent exists for the diff, say so explicitly before committing.

## Server & Deploy Conventions

- For server 116 and other production hosts, look up the SSH user and key from Obsidian/memory before attempting connection. Do not try default credentials.
- When restarting docker compose services, always include the required override files (e.g. the overlay that sets VEIL_TSA_URL, VEIL_REKOR_URL, and TRACEVAULT_* vars). Omitting overrides silently wipes environment variables and has caused deploy outages.
- Use pnpm, not npm, for any repo with pnpm-lock.yaml. Using npm in a pnpm repo has caused a production outage.

## Review & Verification Gates

- After implementing changes, run the appropriate subagent review (bug-hunter, security-review, or equivalent) BEFORE opening a PR. Past sessions have caught log-injection, null-JSON 500s, and route-ordering bugs at this gate.
- Honor literal string requirements exactly. Do not substitute (e.g. use the literal `'22'` pin rather than `node-version-file`; do not introduce forbidden tokens like `Pro+` that trip the CI banlist).
- Before executing any multi-phase plan, restate: (1) the exact scope, (2) any ambiguous terms you would interpret, (3) which repo, branch, or server you will touch. HALT and wait for confirmation if the prompt looks truncated or any premise is unclear. Do not proceed on best-guess.
