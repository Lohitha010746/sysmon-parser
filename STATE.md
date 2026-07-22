# STATE.md

Living project bookmark. Read this at the start of each session; update it
after meaningful work. For stable project facts see **CLAUDE.md**.

**Last updated:** 2026-07-21

## Current Status

Feature-complete for the current scope and published to GitHub
(https://github.com/Lohitha010746/sysmon-parser). Parser handles multiple
Sysmon event types with filtering and selectable output formats (json / jsonl /
csv); docs and tests are in place. No open bugs.

## What Is Working

- Parsing single `<Event>` documents and `<Events>` wrappers → JSON
  (object for one event, array for many).
- Namespace-agnostic XML access (works with or without the schema namespace).
- Curated field extraction for Event IDs 1, 3, 11, 13, 22, each with a readable
  `EventType` label.
- Fallback for unmapped Event IDs: emits every `<Data>` field (verified on ID 10).
- Filtering by `--image` (substring), `--user` (exact), `--integrity`
  (High/Medium/Low/System) — AND-combined, case-insensitive.
- Output `--format`: `json` (default), `jsonl` (one object/line), `csv`
  (header + rows, union-of-keys columns). Handled by `format_events()`.
- `-o/--output` writes the output to a file while still printing to stdout.
- Error handling: exit 1 (no events / bad file), exit 2 (bad args), exit 0
  (valid parse, including zero filter matches → `[]` for json).
- Test suite: 25 tests, all passing.

## Known Issues

- None currently.
- Minor by-design note: a single surviving event (after filtering or in a
  one-event file) prints as a bare object, not a one-element array. Intentional
  and consistent, but downstream consumers should handle both shapes.

## Decisions Made

- **Stdlib only**, Python 3.7+ — zero-install; `requirements.txt` stays empty.
- **Parsing vs filtering separated** — `filter_events()` is a pure post-parse
  step operating on dicts, so both are independently testable.
- **Per-event-ID schemas + fallback** — curated fields for common events;
  unknown IDs emit all `<Data>` fields so nothing is silently dropped.
- **Namespace-agnostic** — match by local tag name (`_local`/`_find`/
  `_iter_local`), never hard-code a namespace.
- **Filters:** AND semantics, case-insensitive; missing field never matches.
- **Error vs empty:** no `<Event>` in file = error (exit 1); zero filter matches
  = valid empty result (`[]`, exit 0).
- **Output formats:** one `format_events()` function; `json` keeps the
  object-or-array shape, `jsonl`/`csv` always one row per event. CSV columns are
  the union of all event keys (first-seen order) so mixed event types align.
- **Docs split:** CLAUDE.md stable/north-star; STATE.md + HANDOFF.md living.

## Current Task

None active — `--format` (json/jsonl/csv) feature is complete, tested, and
documented. Ready to commit and push.

## Next Steps

- Optional: add a GitHub Actions CI workflow to run `python tests/test_parser.py`
  on push.
- Optional: extend curated schemas to more Event IDs (e.g. 5 Process Terminate,
  7 Image Loaded, 8 CreateRemoteThread, 12 Registry key create/delete).

## Last Updated

2026-07-21
