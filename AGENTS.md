# Repository Guidelines

## Project Structure & Module Organization

- `cmd/j-ui/`: server entry point and `j-ui` lifecycle commands.
- `internal/`: backend packages. Keep HTTP concerns in `api`, persistence in `database`, protocol generation in `engine/singbox`, and node orchestration in `node`.
- `web/src/`: Vue 3 and TypeScript source.
- `web/dist/`: frontend build; never edit or commit its contents.
- `deploy/`: systemd units and default production configuration.
- `scripts/`: idempotent install, update, and uninstall workflows.

`J-UI-PRD-v0.1.md` is retained as historical design context. Current behavior and release boundaries are defined by the code, README files, and legal notices.

## Build, Test, and Development Commands

```bash
npm --prefix web install   # install the pinned frontend dependencies
npm --prefix web run dev   # run Vite and proxy API calls to port 8080
npm --prefix web test      # run core Vue form tests with Vitest
npm --prefix web run test:e2e # smoke-test desktop and mobile flows
npm --prefix web run build # type-check and generate embedded assets
go test ./...              # run backend unit and integration tests
go vet ./...               # check common Go defects
go build ./cmd/j-ui        # build the combined server and UI binary
```

Build the frontend before release binaries. Without sing-box or root, set temporary `JUI_DATA_DIR`, `JUI_CONFIG_DIR`, and `JUI_ENGINE_MODE=mock`.

## Coding Style & Naming Conventions

Run `gofmt` on Go changes. Use lowercase package names and small exported APIs. Version routes under `/api/v1`; mutations use POST, PUT, or DELETE. TypeScript uses two-space indentation, `PascalCase` for components and types, and `camelCase` for functions and variables. Reuse the API wrapper and CSS tokens before adding dependencies.

## UI Design Guidelines

Action buttons are borderless by default, including close, cancel, edit, copy, and tab controls. Communicate interaction through spacing, color, background, hover state, and a visible keyboard focus ring. Reserve borders for form fields, cards, and structural separators; do not add decorative button outlines.

## Testing Guidelines

Place Go tests beside implementation as `*_test.go` and name cases `TestBehavior`. Add regression coverage for every bug fix. Configuration and subscription changes require fixtures or golden-style assertions for every affected protocol. Isolate tests requiring systemd, nftables, certificates, TUN, or external networks from default unit runs.

Before handing off, run the frontend build, `go test ./...`, `go vet ./...`, and `bash -n scripts/*.sh`.

## Commit & Pull Request Guidelines

Use imperative, scoped subjects such as `api: reject invalid public hosts`. Keep commits focused. Pull requests must explain behavior, tests, security or migration impact, and related issues. Include screenshots for UI changes and sanitized sample output for subscription changes.

## Security & Configuration

Never log or return passwords, session tokens, private keys, or decrypted credentials. Preserve atomic sing-box validation and rollback. Execute privileged programs with fixed argument arrays, never interpolated shell commands. Keep databases, keys, backups, and environment files out of Git.
