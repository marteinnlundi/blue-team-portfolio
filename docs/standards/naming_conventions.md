# Naming Conventions

## Tools and directories

- lower-case, hyphen-separated: `sigma-lite`, `ir-triage`
- one directory per tool under `tools/`, each with a `README.md` and its own tests

## JSON fields

- `snake_case` in events and alerts (`src_ip`, `command_line`)
- dotted paths in prose and in rules refer to nesting: `network.src_ip`

## Rule ids

- sigma-lite: `<category>-<3 digits>`, for example `auth-001`, `exec-002`. Categories in use: `auth`, `privesc`, `exec`, `persist`, `net`.
- Rule files: `<category>_<number>_<short_name>.yaml`
- Other detectors: `<tool>-<detection>`, for example `auth-anom-brute-force`, `ioc-feed-match`
- An id never changes meaning. Retire an id instead of reusing it.

## Branches and commits

- `main` is always releasable
- `feat/<topic>`, `fix/<topic>`, `docs/<topic>`
- Commit subjects in the imperative, prefixed with the tool where it helps: `sigma-lite: add regex operator`
