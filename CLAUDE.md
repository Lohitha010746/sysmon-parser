# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository. It is the stable "north star": it describes what the
project is and how to work in it. Keep it concise. Put transient
progress, current tasks, and debugging notes in **STATE.md**, not here.

## Session Workflow (read this first)

- **At the start of every session**, read **STATE.md** to learn the current
  status, active task, and next steps before doing anything else.
- **After meaningful work** (a feature, fix, or decision), update **STATE.md**
  so it always reflects reality — status, what works, known issues, decisions,
  current task, next steps, and the "Last updated" date.
- **Before ending a major work session**, update **HANDOFF.md** with a concise
  handoff: what was completed, key implementation details, files changed, tests
  run and their results, remaining work, and the recommended next action.

## Project Purpose

Sysmon Parser is a dependency-free Python tool for parsing Windows
[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) event-log
XML into structured JSON, for detection and incident-investigation workflows.

It extracts the fields that matter per event type and is namespace-agnostic
(works whether or not the XML declares the Windows event schema namespace),
accepting either a single `<Event>` root or an `<Events>` wrapper.

## Architecture & File Structure

Single-module tool; the standard library only (`argparse`, `json`,
`xml.etree.ElementTree`, `sys`). Data flows: **XML → parse → (filter) → JSON**.

```
parser.py            CLI entry point + all parsing/filtering logic
├─ parse_file(path)      -> list[dict]   (reads XML, finds <Event> elements)
├─ parse_event(event)    -> dict         (extracts fields for one event)
├─ filter_events(...)    -> list[dict]   (pure post-parse filter)
├─ format_events(...)    -> str          (serialize to json / jsonl / csv)
├─ main(argv)            -> int          (argparse, orchestration, output)
└─ helpers: _local, _clean, _find, _iter_local  (namespace-agnostic XML access)

EVENT_FIELDS         curated <Data> field list per Event ID (1, 3, 11, 13, 22)
EVENT_TYPE_NAMES     human-readable label per curated Event ID

tests/test_parser.py unittest suite (stdlib only)
samples/             example Sysmon XML fixtures + one parsed .json
README.md            user-facing documentation
STATE.md             current project bookmark (living doc)
HANDOFF.md           handoff summary for the next session
```

Key design decisions live in STATE.md ("Decisions made"). The most load-bearing:
parsing and filtering are separate pure functions; unmapped Event IDs fall back
to emitting every `<Data>` field so no event type is silently dropped.

## Coding Standards

- **Python 3.7+, standard library only.** Do not add third-party dependencies
  without discussion (`requirements.txt` is intentionally empty).
- **PEP 8**, 4-space indent, ~79-char lines (matches existing code).
- Prefer **small pure functions**; keep parsing, filtering, and I/O separate.
- Use **docstrings** on public functions and brief comments for non-obvious
  intent (see existing code for tone/density — match it).
- Preserve **namespace-agnostic** access: match XML by local tag name via the
  `_local`/`_find`/`_iter_local` helpers, never hard-code a namespace.
- Fields absent from an event should surface as `null`/absent, never crash.

## Testing Expectations

- All changes must keep `tests/test_parser.py` green.
- Add tests for new behavior (new event type, new filter, new edge case).
- Tests use only `unittest` and run against the fixtures in `samples/`.
- Run the suite before committing.

## Important Commands

```
python parser.py samples/mixed_events.xml                  # parse, print JSON
python parser.py samples/mixed_events.xml -o out.json      # print + save
python parser.py samples/mixed_events.xml --integrity High # filter (AND, ci)
python parser.py samples/multi_events.xml --format jsonl   # jsonl / csv output
python tests/test_parser.py                                # run tests (verbose)
python -m unittest discover -s tests                       # run tests (discover)
```

## Usage Reference

```
python parser.py <path-to-sysmon-xml> [-o/--output FILE]
                 [--image SUBSTR] [--user USER] [--integrity LEVEL]
                 [--format json|jsonl|csv]
```

Filters combine with **AND** and are **case-insensitive**. Events missing the
relevant field never match (e.g. `--integrity` excludes Network events). Zero
matches prints `[]` (json) and exits 0; a file with no `<Event>` elements is an
error (exit 1).

Output `--format` (default `json`) is handled by `format_events()`: `json`
(object for one event, array for many), `jsonl` (one compact object per line),
`csv` (header + row per event; columns are the union of all event keys).

### Supported event types

`EventID` and `Computer` come from `<System>`; the rest from `<EventData>`.
Curated events get a readable `EventType` label (except Registry, which has its
own `EventType`, e.g. `SetValue`).

| Event ID | Type | Key extracted fields |
|----------|------|----------------------|
| 1 | Process Create | `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Hashes` |
| 3 | Network Connection | `UtcTime`, `Image`, `User`, `Protocol`, `Initiated`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationHostname`, `DestinationPort`, `DestinationPortName` |
| 11 | File Create | `UtcTime`, `Image`, `TargetFilename`, `CreationUtcTime`, `User` |
| 13 | Registry Value Set | `UtcTime`, `EventType`, `Image`, `TargetObject`, `Details`, `User` |
| 22 | DNS Query | `UtcTime`, `Image`, `QueryName`, `QueryStatus`, `QueryResults`, `User` |

**Fallback:** any other Event ID emits every `<Data>` field present. Add a new
curated type by extending `EVENT_FIELDS` (and optionally `EVENT_TYPE_NAMES`).

### Output & errors

- Output: selectable via `--format` (json/jsonl/csv). Default json is
  pretty-printed (2-space indent) — one object per event, array for many.
- Exit codes: `0` success, `1` bad path / malformed XML / no `<Event>` found,
  `2` invalid arguments.

### Samples

- `event1.xml`, `event2.xml`, `event3.xml` — single Event ID 1 events.
- `multi_events.xml` — three Event ID 1 events under an `<Events>` root.
- `multi_events1.xml` — varied event IDs (3, 11, 13, 22).
- `mixed_events.xml` — mixed IDs (1, 3, 10, 22) incl. an unmapped ID exercising
  the fallback; `mixed_events.json` is its parsed output.
