# Repository Guidelines

- Run `gofmt` on all Go source files that you touch.
- Keep Go packages covered by unit tests; add table-driven tests when sensible.
- Update or add documentation in `docs/` when behaviour or design changes.
- Prefer descriptive commit messages and PR summaries.
- When editing Markdown, wrap lines at roughly 100 characters unless a table or URL would break.
- Changes to the CLI should include coverage in `internal/runner` so plan construction and probe
  execution stay wired together.
