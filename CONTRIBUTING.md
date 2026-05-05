# Contributing to lucairn-sdks

Thanks for your interest. This monorepo hosts the official Lucairn client SDKs at parity: TypeScript, Python, Go, plus an MCP server.

It is **MIT-licensed** (see [LICENSE](LICENSE)). Contributions are welcome under those terms.

## Getting started

Per-language setup is in each package's README:

- TypeScript — [`ts/README.md`](ts/README.md) (`pnpm install && pnpm test` from `ts/`)
- Python — [`python/README.md`](python/README.md) (`uv sync && uv run pytest` or pip equivalent)
- Go — [`go/README.md`](go/README.md) (`go test ./...` from `go/`)
- MCP server — [`mcp-server/README.md`](mcp-server/README.md)

The three SDKs are kept at observable parity. Cross-language byte-equivalence is locked via shared Go-assembler-generated fixtures.

## Filing issues

Use the templates in [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/):

- **Bug** — include the SDK language, SDK version, runtime version (Node / Python / Go), minimal reproduction.
- **Feature** — problem statement, proposed solution, alternatives.
- **Security** — DO NOT use the issue tracker for vulnerabilities. See [SECURITY.md](SECURITY.md).

## Pull requests

1. Branch from `main`: `git checkout -b <type>/<lang-or-scope>/<short-slug>` (e.g. `fix/python/streaming-cancel`).
2. **Parity rule:** behaviour-changing fixes that apply to multiple SDKs should land in all three (or have a follow-up issue tracking the gap). The repo CI checks fixture compatibility.
3. Tests must pass for the language(s) you touched.
4. Conventional-commit style, matching what the repo already uses:
   - `feat(scope): ...` — `feat(ts): ...`, `feat(python): ...`, `feat(go): ...`, `feat(mcp): ...`
   - `fix(scope): ...`
   - `chore(scope): ...`
   - `docs(scope): ...`
5. Reference any linked issue in the PR body.

## Releases

Releases are tagged per-package (`ts/vX.Y.Z`, `python/vX.Y.Z`, `go/vX.Y.Z`, `mcp/vX.Y.Z`) and trigger workflow-based publishing to npm / PyPI / pkg.go.dev. See `.github/workflows/`.

## Scope

This repo is the SDKs only. Gateway lives in [`dual-sandbox-architecture`](https://github.com/Declade/dual-sandbox-architecture); website lives in [`theveil-website`](https://github.com/Declade/theveil-website); evidence service lives in [`VeilVault`](https://github.com/Declade/VeilVault).

## Questions

Open a GitHub Discussion or a `[FEATURE]` issue.
