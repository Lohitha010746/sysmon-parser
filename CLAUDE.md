# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Sysmon Parser - a Python tool for parsing Windows Sysmon event logs from XML.

It extracts key fields from Sysmon events and emits them as structured JSON.
The parser is namespace-agnostic (works whether or not the XML declares the
Windows event schema namespace) and accepts either a single `<Event>` root or
an `<Events>` wrapper containing many events.

## Usage

```
python parser.py <path-to-sysmon-xml> [-o/--output FILE]
                 [--image SUBSTR] [--user USER] [--integrity LEVEL]
```

The parsed JSON is always printed to stdout. With `-o/--output`, it is also
written to the given file (the "Saved JSON to ..." confirmation goes to stderr,
so piping stdout stays clean).

```
python parser.py samples/mixed_events.xml                       # print only
python parser.py samples/mixed_events.xml -o out.json           # print + save
python parser.py samples/mixed_events.xml --integrity High      # filter
```

### Filters

Optional flags narrow the output; they combine with AND and are
case-insensitive. Implemented by `filter_events()` in `parser.py` as a
post-parse step (parsing logic is untouched).

- `--image SUBSTR` — `Image` contains the substring.
- `--user USER` — `User` matches exactly.
- `--integrity LEVEL` — `IntegrityLevel` is one of `High`, `Medium`, `Low`,
  `System`.

Events missing the relevant field never match that filter (e.g. `--integrity`
excludes Network events). Zero matches prints `[]` and exits 0; a file with no
`<Event>` elements at all is still an error (exit 1).

## Supported Event Types

Each Event ID has a curated set of fields. `EventID` and `Computer` are always
pulled from `<System>`; the remaining fields come from `<EventData>`. Curated
events also get a human-readable `EventType` label (except Registry events,
which carry their own `EventType` field, e.g. `SetValue`).

| Event ID | Type | Key extracted fields |
|----------|------|----------------------|
| 1 | Process Create | `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Hashes` |
| 3 | Network Connection | `UtcTime`, `Image`, `User`, `Protocol`, `Initiated`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationHostname`, `DestinationPort`, `DestinationPortName` |
| 11 | File Create | `UtcTime`, `Image`, `TargetFilename`, `CreationUtcTime`, `User` |
| 13 | Registry Value Set | `UtcTime`, `EventType`, `Image`, `TargetObject`, `Details`, `User` |
| 22 | DNS Query | `UtcTime`, `Image`, `QueryName`, `QueryStatus`, `QueryResults`, `User` |

**Fallback:** any Event ID not listed above emits *every* `<Data>` field
present (in document order) rather than dropping it or forcing it into another
event's schema. So no event type is silently lost.

Curated field lists live in `EVENT_FIELDS` in `parser.py`; add a new Event ID
there (and optionally in `EVENT_TYPE_NAMES`) to give it a curated schema.

## Output Format

JSON — one object per event, or an array of objects when parsing multiple
events. Output is pretty-printed (2-space indent).

## Errors

- Missing argument → usage message to stderr, exit code 2.
- Bad path / malformed XML → error to stderr, exit code 1.
- No `<Event>` elements found → warning to stderr, exit code 1 (guards against
  silently succeeding on empty or non-Sysmon XML).

## Samples

`samples/` holds test fixtures:

- `event1.xml`, `event2.xml`, `event3.xml` — single Event ID 1 (Process Create) events.
- `multi_events.xml` — three Event ID 1 events under an `<Events>` root.
- `multi_events1.xml` — varied event IDs (3, 11, 13, 22).
- `mixed_events.xml` — mixed IDs (1, 3, 10, 22) including an unmapped ID that
  exercises the fallback path; `mixed_events.json` is its parsed output.
