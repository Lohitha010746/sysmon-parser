#!/usr/bin/env python3
"""Parse Windows Sysmon event XML into JSON, JSONL, or CSV.

Usage:
    python parser.py <path-to-sysmon-xml> [--format json|jsonl|csv]

Extracts the key fields defined in CLAUDE.md and writes them to stdout. The
default JSON format produces one object for a single event or an array for
multiple; JSONL produces one JSON object per line; CSV produces a header row
plus one row per event.
"""
import argparse
import csv
import io
import json
import sys
import xml.etree.ElementTree as ET

# Curated <EventData> fields to extract per Sysmon Event ID. EventID and
# Computer are always pulled from <System>; the fields below come from the
# <Data Name="..."> entries under <EventData>. Event IDs not listed here fall
# back to emitting every <Data> field present, in document order.
EVENT_FIELDS = {
    "1": [  # Process Create (per CLAUDE.md)
        "UtcTime",
        "Image",
        "CommandLine",
        "User",
        "IntegrityLevel",
        "ParentImage",
        "ParentCommandLine",
        "Hashes",
    ],
    "3": [  # Network Connection
        "UtcTime",
        "Image",
        "User",
        "Protocol",
        "Initiated",
        "SourceIp",
        "SourcePort",
        "DestinationIp",
        "DestinationHostname",
        "DestinationPort",
        "DestinationPortName",
    ],
    "11": [  # File Create
        "UtcTime",
        "Image",
        "TargetFilename",
        "CreationUtcTime",
        "User",
    ],
    "13": [  # Registry Value Set
        "UtcTime",
        "EventType",
        "Image",
        "TargetObject",
        "Details",
        "User",
    ],
    "22": [  # DNS Query
        "UtcTime",
        "Image",
        "QueryName",
        "QueryStatus",
        "QueryResults",
        "User",
    ],
}

# Human-readable labels for the event types we curate, added to the output for
# readability. Keyed by Event ID string.
EVENT_TYPE_NAMES = {
    "1": "Process Create",
    "3": "Network Connection",
    "11": "File Create",
    "13": "Registry Value Set",
    "22": "DNS Query",
}


def _local(tag):
    """Return an element tag with any XML namespace stripped."""
    return tag.split("}")[-1] if isinstance(tag, str) else tag


def _clean(text):
    """Strip element text, returning None if absent or empty."""
    if text is None:
        return None
    text = text.strip()
    return text or None


def _find(elem, *names):
    """Follow a chain of local child names, ignoring namespaces.

    Returns the first matching element for each step, or None if any step
    has no match.
    """
    current = elem
    for name in names:
        current = next(
            (child for child in current if _local(child.tag) == name), None
        )
        if current is None:
            return None
    return current


def _iter_local(elem, name):
    """Yield every descendant (and self) whose local tag matches ``name``."""
    for node in elem.iter():
        if _local(node.tag) == name:
            yield node


def parse_event(event):
    """Extract the key fields from a single <Event> element.

    The set of EventData fields extracted depends on the Event ID (see
    EVENT_FIELDS). Event IDs without a curated field list fall back to
    emitting every <Data> field present, so no event type is silently dropped.
    """
    eventid_el = _find(event, "System", "EventID")
    eventid = _clean(eventid_el.text) if eventid_el is not None else None

    result = {"EventID": eventid}

    # Build a lookup of the EventData Data elements by their Name attribute,
    # preserving document order for the fallback path.
    data = {}
    eventdata = _find(event, "EventData")
    if eventdata is not None:
        for node in eventdata:
            if _local(node.tag) == "Data":
                name = node.get("Name")
                if name is not None:
                    data[name] = _clean(node.text)

    # Add a human-readable label, unless the event has its own EventType field
    # (e.g. registry events use it for SetValue/DeleteValue).
    if eventid in EVENT_TYPE_NAMES and "EventType" not in data:
        result["EventType"] = EVENT_TYPE_NAMES[eventid]

    fields = EVENT_FIELDS.get(eventid)
    if fields is None:
        # Unknown/unmapped Event ID: emit every field present rather than
        # forcing it into another event's schema or dropping its data.
        result.update(data)
    else:
        for field in fields:
            result[field] = data.get(field)

    computer = _find(event, "System", "Computer")
    result["Computer"] = _clean(computer.text) if computer is not None else None
    return result


def parse_file(path):
    """Parse a Sysmon XML file, returning a list of extracted event dicts.

    Namespace-agnostic: works whether or not the XML declares the Windows
    event schema namespace. The root may itself be an <Event>, or a wrapper
    containing many <Event> elements.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    if _local(root.tag) == "Event":
        events = [root]
    else:
        events = list(_iter_local(root, "Event"))

    return [parse_event(event) for event in events]


def filter_events(events, image=None, user=None, integrity=None):
    """Return only events matching all supplied filters (case-insensitive).

    - image: substring match against the event's Image field
    - user: exact match against the event's User field
    - integrity: exact match against the event's IntegrityLevel field

    Filters are combined with AND. An event whose relevant field is missing or
    None never matches that filter, so it is excluded when that filter is
    active.
    """
    def matches(event):
        if image is not None:
            value = event.get("Image")
            if value is None or image.lower() not in value.lower():
                return False
        if user is not None:
            value = event.get("User")
            if value is None or value.lower() != user.lower():
                return False
        if integrity is not None:
            value = event.get("IntegrityLevel")
            if value is None or value.lower() != integrity.lower():
                return False
        return True

    return [event for event in events if matches(event)]


def format_events(events, fmt):
    """Serialize a list of event dicts to the requested output format.

    - "json"  : pretty-printed; a single event is a bare object, multiple
                events are an array (backwards-compatible default).
    - "jsonl" : one compact JSON object per line (streaming/piping friendly).
    - "csv"   : a header row plus one row per event. Columns are the union of
                all event keys, in first-seen order; missing values are blank.
    """
    if fmt == "json":
        output = events[0] if len(events) == 1 else events
        return json.dumps(output, indent=2)

    if fmt == "jsonl":
        return "\n".join(json.dumps(event) for event in events)

    if fmt == "csv":
        fieldnames = []
        seen = set()
        for event in events:
            for key in event:
                if key not in seen:
                    seen.add(key)
                    fieldnames.append(key)
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer, fieldnames=fieldnames, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(events)
        return buffer.getvalue().rstrip("\n")

    raise ValueError(f"unknown format: {fmt}")


def main(argv):
    parser = argparse.ArgumentParser(
        description="Parse Windows Sysmon event XML into JSON."
    )
    parser.add_argument("xml", help="path to the Sysmon XML file")
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="also write the JSON to this file (still printed to stdout)",
    )
    parser.add_argument(
        "--image",
        metavar="SUBSTR",
        help="only events whose Image contains this substring "
        "(case-insensitive)",
    )
    parser.add_argument(
        "--user",
        metavar="USER",
        help="only events whose User matches exactly (case-insensitive)",
    )
    parser.add_argument(
        "--integrity",
        choices=["High", "Medium", "Low", "System"],
        type=str.title,
        help="only events with this IntegrityLevel",
    )
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help="output format (default: json)",
    )
    args = parser.parse_args(argv[1:])

    try:
        events = parse_file(args.xml)
    except (ET.ParseError, OSError) as exc:
        print(f"Error parsing {args.xml}: {exc}", file=sys.stderr)
        return 1

    if not events:
        print(
            f"No <Event> elements found in {args.xml}; "
            "is this a Sysmon event XML file?",
            file=sys.stderr,
        )
        return 1

    # Apply optional filters. Unlike an empty file (an error above), zero
    # matches here is a valid result: print an empty array and exit cleanly.
    if args.image or args.user or args.integrity:
        events = filter_events(
            events, image=args.image, user=args.user, integrity=args.integrity
        )
        if not events:
            print("No events matched the given filters.", file=sys.stderr)
            # json renders empty as "[]"; jsonl/csv have no rows to emit.
            if args.format == "json":
                print("[]")
            return 0

    text = format_events(events, args.format)

    # Always display the result; optionally save it to a file as well.
    print(text)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except OSError as exc:
            print(f"Error writing {args.output}: {exc}", file=sys.stderr)
            return 1
        print(f"Saved output to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
