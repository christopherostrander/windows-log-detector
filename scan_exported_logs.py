import csv
import re
from collections import Counter
from pathlib import Path

TARGET_EVENT_IDS = {"4624", "4625"}

EVENT_NAMES = {
    "4624": "Successful logon",
    "4625": "Failed logon",
}


def normalize_column_name(column_name):
    return re.sub(r"[^a-z0-9]", "", column_name.lower())


def find_column(headers, candidates):
    normalized_headers = {
        normalize_column_name(header): header
        for header in headers
        if header
    }

    for candidate in candidates:
        if candidate in normalized_headers:
            return normalized_headers[candidate]

    return None


def extract_event_id(row, event_id_column):
    raw_value = str(row.get(event_id_column, "")).strip()
    match = re.search(r"\b(4624|4625)\b", raw_value)
    return match.group(1) if match else None


def read_security_csv(file_path):
    events = []

    with file_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
        errors="replace"
    ) as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError(f"No CSV headers found in: {file_path.name}")

        event_id_column = find_column(
            reader.fieldnames,
            ["eventid", "eventcode", "id"]
        )

        if not event_id_column:
            raise ValueError(
                f"Could not find an Event ID column in {file_path.name}. "
                f"Headers found: {reader.fieldnames}"
            )

        time_column = find_column(
            reader.fieldnames,
            ["datetime", "dateandtime", "timecreated", "time"]
        )

        source_column = find_column(
            reader.fieldnames,
            ["source", "providername", "provider"]
        )

        level_column = find_column(
            reader.fieldnames,
            ["level", "leveldisplayname"]
        )

        task_column = find_column(
            reader.fieldnames,
            ["taskcategory", "task"]
        )

        message_column = find_column(
            reader.fieldnames,
            ["description", "message", "eventdata"]
        )

        for row in reader:
            event_id = extract_event_id(row, event_id_column)

            if event_id not in TARGET_EVENT_IDS:
                continue

            events.append(
                {
                    "file": file_path.name,
                    "timestamp": row.get(time_column, "-") if time_column else "-",
                    "event_id": event_id,
                    "event_name": EVENT_NAMES[event_id],
                    "source": row.get(source_column, "-") if source_column else "-",
                    "level": row.get(level_column, "-") if level_column else "-",
                    "task_category": row.get(task_column, "-") if task_column else "-",
                    "message": row.get(message_column, "-") if message_column else "-",
                }
            )

    return events


def write_events_csv(events, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    columns = [
        "file",
        "timestamp",
        "event_id",
        "event_name",
        "source",
        "level",
        "task_category",
        "message",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(events)


def print_summary(label, events):
    counts = Counter(event["event_id"] for event in events)

    print(f"\n=== {label} ===")
    print(f"Matching logon events: {len(events)}")
    print(f"Event ID 4624 - successful logons: {counts['4624']}")
    print(f"Event ID 4625 - failed logons:     {counts['4625']}")


def main():
    before_path = Path("before_security.csv")
    after_path = Path("after_security.csv")
    output_path = Path("output/logon_events_report.csv")

    for file_path in [before_path, after_path]:
        if not file_path.exists():
            print(f"ERROR: File not found: {file_path.resolve()}")
            print("Make sure the CSV files are in C:\\windows-log-detector.")
            return

    try:
        before_events = read_security_csv(before_path)
        after_events = read_security_csv(after_path)
    except (OSError, ValueError, csv.Error) as error:
        print(f"ERROR: Could not read a CSV export: {error}")
        return

    all_events = before_events + after_events
    write_events_csv(all_events, output_path)

    print_summary("BEFORE SECURITY LOG", before_events)
    print_summary("AFTER SECURITY LOG", after_events)

    before_failed = sum(
        event["event_id"] == "4625"
        for event in before_events
    )
    after_failed = sum(
        event["event_id"] == "4625"
        for event in after_events
    )

    before_successful = sum(
        event["event_id"] == "4624"
        for event in before_events
    )
    after_successful = sum(
        event["event_id"] == "4624"
        for event in after_events
    )

    print("\n=== COMPARISON ===")
    print(f"New successful-logon events: {after_successful - before_successful}")
    print(f"New failed-logon events:     {after_failed - before_failed}")

    if after_failed > before_failed:
        print(
            "\nALERT: The after log contains more failed-logon events "
            "(Event ID 4625) than the before log."
        )
    else:
        print(
            "\nNo increase in failed-logon events was detected between "
            "the two exports."
        )

    print(f"\nFiltered report saved to:\n{output_path.resolve()}")


if __name__ == "__main__":
    main()