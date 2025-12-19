# Event Schema v0.1

## Required
- event.time
- event.source
- event.kind
- host.name
- severity

## Optional
- user.*
- process.*
- network.*
- file.*
- tags[]

## Format
- JSON Lines
- ISO 8601 UTC timestamps
