# Sysmon Parser

A lightweight, dependency-free Python tool for parsing Windows
[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) event logs
from XML into structured JSON.

Sysmon (System Monitor) writes rich process, network, file, registry, and DNS
telemetry to the Windows event log. This tool extracts the fields that matter
for detection and investigation from that XML and emits clean JSON you can feed
into a SIEM, a notebook, or a `jq` pipeline.

## Features

- **Multiple event types** — curated field sets for the most common Sysmon
  events (Process Create, Network Connection, File Create, Registry Value Set,
  DNS Query), plus a fallback that captures *every* field for any other event
  ID so nothing is silently dropped.
- **Namespace-agnostic** — works whether or not the XML declares the Windows
  event schema namespace.
- **Flexible input** — accepts a single `<Event>` document or an `<Events>`
  wrapper containing many events.
- **Readable output** — pretty-printed JSON, one object per event (or an array
  for multiple), with a human-readable `EventType` label on known events.
- **Print and/or save** — always prints to stdout; optionally writes to a file.
- **No third-party dependencies** — pure Python standard library.

## Requirements

- Python 3.7+

No installation or `pip install` needed.

## Usage

```
python parser.py <path-to-sysmon-xml> [-o/--output FILE]
                 [--image SUBSTR] [--user USER] [--integrity LEVEL]
                 [--format json|jsonl|csv]
```

| Argument | Description |
|----------|-------------|
| `xml` | Path to the Sysmon XML file (required). |
| `-o`, `--output FILE` | Also write the output to `FILE`. It is still printed to stdout. |
| `--image SUBSTR` | Keep only events whose `Image` **contains** `SUBSTR` (case-insensitive). |
| `--user USER` | Keep only events whose `User` matches `USER` **exactly** (case-insensitive). |
| `--integrity LEVEL` | Keep only events with this `IntegrityLevel`. One of `High`, `Medium`, `Low`, `System` (case-insensitive). |
| `--format FORMAT` | Output format: `json` (default), `jsonl`, or `csv`. |

### Output formats

- **`json`** (default) — pretty-printed. A single event is a bare object;
  multiple events are an array.
- **`jsonl`** — one compact JSON object per line. Ideal for streaming, piping,
  and SIEM/log ingestion.
- **`csv`** — a header row plus one row per event. Columns are the union of all
  event keys (in first-seen order), so mixed event types line up; fields an
  event lacks are left blank. Values are quoted/escaped per RFC 4180.

### Filtering

The three filter flags narrow the output to matching events. They combine with
**AND** — an event must satisfy every supplied filter. An event whose relevant
field is missing (e.g. a Network Connection event has no `IntegrityLevel`) does
not match that filter and is excluded. If no event matches, the tool prints
`[]` and exits `0`.

### Examples

Print the parsed JSON to the terminal:

```
python parser.py samples/event1.xml
```

Print **and** save to a file:

```
python parser.py samples/mixed_events.xml -o samples/mixed_events.json
```

Pipe into `jq` (the "Saved JSON to ..." message goes to stderr, so it won't
interfere):

```
python parser.py samples/mixed_events.xml | jq '.[] | select(.EventID == "3")'
```

Filter to high-integrity PowerShell process events:

```
python parser.py samples/mixed_events.xml --image powershell --integrity High
```

Emit newline-delimited JSON (JSONL) for streaming, or CSV for a spreadsheet:

```
python parser.py samples/multi_events.xml --format jsonl
python parser.py samples/multi_events.xml --format csv -o events.csv
```

## Supported Event Types

`EventID` and `Computer` are always taken from `<System>`; the remaining fields
come from `<EventData>`. Known event types also get a human-readable
`EventType` label (except Registry events, which carry their own `EventType`
value such as `SetValue`).

| Event ID | Type | Key extracted fields |
|----------|------|----------------------|
| 1 | Process Create | `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Hashes` |
| 3 | Network Connection | `UtcTime`, `Image`, `User`, `Protocol`, `Initiated`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationHostname`, `DestinationPort`, `DestinationPortName` |
| 11 | File Create | `UtcTime`, `Image`, `TargetFilename`, `CreationUtcTime`, `User` |
| 13 | Registry Value Set | `UtcTime`, `EventType`, `Image`, `TargetObject`, `Details`, `User` |
| 22 | DNS Query | `UtcTime`, `Image`, `QueryName`, `QueryStatus`, `QueryResults`, `User` |

### Fallback for other event IDs

Any Event ID not in the table above is still parsed — the tool emits **every**
`<Data>` field present (in document order) rather than dropping it or forcing
it into another event's schema. For example, an Event ID 10 (ProcessAccess)
event returns its `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`,
and so on.

## Output Format

The output format is selected with `--format` (see [Output
formats](#output-formats) above); the default is `json`.

Default JSON is pretty-printed (2-space indent):

- A **single** event produces one JSON **object**.
- **Multiple** events produce a JSON **array** of objects.

Example (Event ID 1):

```json
{
  "EventID": "1",
  "EventType": "Process Create",
  "UtcTime": "2026-07-21 14:03:11.480",
  "Image": "C:\\Windows\\System32\\whoami.exe",
  "CommandLine": "whoami /all",
  "User": "CORP\\jsmith",
  "IntegrityLevel": "Medium",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentCommandLine": "\"C:\\Windows\\System32\\cmd.exe\"",
  "Hashes": "SHA256=B9F5...,MD5=A1B2...",
  "Computer": "WORKSTATION-07.corp.example.com"
}
```

Fields not present in an event are returned as `null` (for curated event
types) rather than omitted.

## Exit Codes & Errors

| Exit code | Meaning |
|-----------|---------|
| `0` | Success. |
| `1` | Bad path, malformed XML, no `<Event>` elements found, or a file-write error. |
| `2` | Invalid command-line arguments (e.g. missing the XML path). |

The "no `<Event>` elements" case guards against silently succeeding on empty or
non-Sysmon XML — it reports the problem to stderr instead of printing `[]`.

## Samples

The `samples/` directory contains ready-to-run test fixtures:

| File | Contents |
|------|----------|
| `event1.xml` | Single Process Create — `whoami /all`. |
| `event2.xml` | Single Process Create — `cmd.exe` spawning `powershell.exe`. |
| `event3.xml` | Single Process Create — suspicious encoded PowerShell from an Office macro. |
| `multi_events.xml` | Three Process Create events under an `<Events>` root. |
| `multi_events1.xml` | Varied event IDs (3, 11, 13, 22). |
| `mixed_events.xml` | Mixed IDs (1, 3, 10, 22), including an unmapped ID that exercises the fallback. |
| `mixed_events.json` | Parsed output of `mixed_events.xml`. |

Try one:

```
python parser.py samples/mixed_events.xml
```

## Extending

To give a new Event ID a curated schema, edit `parser.py`:

1. Add an entry to `EVENT_FIELDS` mapping the Event ID (as a string) to the
   list of `<Data>` field names to extract.
2. Optionally add a label to `EVENT_TYPE_NAMES` for a readable `EventType`.

Event IDs without an entry automatically use the "emit all fields" fallback.

## Testing

The test suite uses only the standard library (`unittest`). From the project
root:

```
python tests/test_parser.py
# or
python -m unittest discover -s tests
```

## Project Layout

```
sysmon-parser/
├── parser.py              # the parser (CLI entry point)
├── CLAUDE.md              # guidance for Claude Code
├── README.md              # this file
├── LICENSE                # MIT license
├── requirements.txt       # dependency manifest (stdlib only — no packages)
├── samples/               # example Sysmon XML files and parsed output
└── tests/
    └── test_parser.py     # unit tests
```
