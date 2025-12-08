# Repository Guidelines

- Run `gofmt` on all Go source files that you touch.
- Keep Go packages covered by unit tests; add table-driven tests when sensible.
- Update or add documentation in `docs/` when behaviour or design changes.
- Prefer descriptive commit messages and PR summaries.
- When editing Markdown, wrap lines at roughly 100 characters unless a table or URL would break.
- Changes to the CLI should include coverage in `internal/runner` so plan construction and probe
  execution stay wired together.
- **When modifying output structures** (structs with `json` tags in `internal/runner`, `internal/plan`,
  `internal/probe`, `internal/config`, or `internal/discovery`), regenerate the JSON schema by running
  `make schema` and commit the updated schema. The schema must stay synchronized with the code.
- The JSON schema validation is enforced in CI via `make schema-check`. If this check fails, run
  `make schema` locally and commit the updated schema.
