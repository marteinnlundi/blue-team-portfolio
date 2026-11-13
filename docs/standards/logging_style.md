# Output and Logging Conventions

## Streams

- **stdout** carries data only: events or alerts as JSON Lines. Nothing else is ever printed there, so tools can be piped together.
- **stderr** carries human-readable diagnostics, prefixed with the tool name (`logpipe: skipping line: ...`).
- Never log secrets, and never copy more of the input into a diagnostic than is needed to find the problem.

## Bad input

- A line that cannot be parsed is skipped, and the tool keeps running. One corrupt line must not stop a pipeline.
- A rule or feed file that cannot be loaded is reported on stderr.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Runtime failure (I/O error, database error) |
| 2 | Invalid usage or invalid input file (bad flag, unreadable rules directory, malformed feed) |
