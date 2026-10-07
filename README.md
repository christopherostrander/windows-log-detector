# Windows Security Logon Event Detector

A Python-based blue-team log analysis project that scans exported Windows
Security event logs for successful and failed logon activity.

## Overview

This project analyzes exported Windows Security log data in CSV format and
identifies authentication events using:

- Event ID 4624: Successful logon
- Event ID 4625: Failed logon

The tool compares a baseline ("before") export with an "after" export from a
controlled VMware Windows 11 lab. It highlights increases in failed logons and
creates a filtered CSV report for review.

## Features

- Reads exported Windows Security CSV files.
- Filters successful logons (4624) and failed logons (4625).
- Displays before/after event counts and count differences.
- Supports configurable input and output file paths.
- Supports a configurable failed-logon review threshold.
- Provides built-in command-line help.
- Validates missing input files and invalid thresholds.
- Prevents the report from overwriting either input file.
- Handles CSV-reading and report-writing errors.
- Creates a combined filtered CSV event report.

## Why I Built This

Windows authentication events are valuable to SOC analysts and incident
responders because repeated failed logons can indicate password guessing,
misconfiguration, a locked-out account, or other suspicious authentication
activity.

This project was built to practice:

- Python scripting and CSV parsing
- Windows Event Viewer and Security logs
- Basic detection engineering
- Security alert reporting
- Safe, isolated lab testing
- Documentation and analyst-style investigation workflow

## Lab Environment

| Component | Purpose |
|---|---|
| Host Windows computer | Python development and log analysis |
| VMware Workstation | Virtualization platform |
| Windows 11 VM | Controlled log generation |
| Event Viewer | Security-log review and export |
| VS Code | Python development environment |
| Python 3.13 | Script execution |

All test activity was performed in an isolated, authorized lab environment.
No production, employer, school, or third-party logs are included.

## Project Workflow

```text
Windows 11 VM
    ↓
Generate authorized test logon activity
    ↓
Export Security logs before and after testing
    ↓
Transfer sanitized CSV exports to host
    ↓
Python parser filters Event IDs 4624 and 4625
    ↓
Compare baseline and after-test counts
    ↓
Write filtered CSV report and print summary
```

## Detection Logic

| Event ID | Meaning | How this project uses it |
|---|---|---|
| 4624 | Successful logon | Counts successful logon events in each export |
| 4625 | Failed logon | Counts failed logon events and checks the after export against a configurable threshold |

The script performs two checks:

1. **Count comparison:** Displays the difference between the before and after
   counts for successful and failed logons. An increase in failed logons
   produces an informational message.
2. **Threshold check:** Prints a review message when the failed-logon count
   in the after export meets or exceeds the configured threshold.

The default threshold is 3. For example:

```powershell
python scan_exported_logs.py --threshold 5
```

This command triggers a review message if the after export contains at least
5 failed-logon events.

The threshold applies to the entire after export. It does not currently
group failures by account, source IP, or time window.

The CSV output contains matching events from both input files. Review
messages are printed in the terminal; they are not written as separate
alert records in the CSV.

## Installation

1. Install Python. This project was developed and tested with Python 3.13.
2. Clone this repository.
3. Open the project folder in VS Code.
4. Confirm that VS Code has selected a Python interpreter.
5. Place sanitized CSV files in the project folder using the default names
   `before_security.csv` and `after_security.csv`, or provide their paths
   with the `--before` and `--after` options.
No third-party Python packages are required for the CSV version.

## Example Output

```text
=== BEFORE SECURITY LOG ===
Matching logon events: 320
Event ID 4624 - successful logons: 320
Event ID 4625 - failed logons:     0

=== AFTER SECURITY LOG ===
Matching logon events: 380
Event ID 4624 - successful logons: 376
Event ID 4625 - failed logons:     4

=== COUNT COMPARISON ===
Successful-logon count difference (after - before): 56
Failed-logon count difference (after - before): 4

[INFO] The after export contains more failed-logon events than the before export.

=== FAILED-LOGON THRESHOLD CHECK ===
Configured threshold: 3
Failed logons in after export: 4
[REVIEW] Failed-logon count reached the configured threshold. Review the events for context.
```
## Usage

Run commands from the project directory.

### Default settings

```powershell
python scan_exported_logs.py
```

By default, the script reads:

- `before_security.csv`
- `after_security.csv`

It saves the filtered event report to:

- `output/logon_events_report.csv`

The default failed-logon threshold is 3.

### Custom settings

```powershell
python scan_exported_logs.py --before before_security.csv --after after_security.csv --threshold 5 --output output/custom_report.csv
```

### Help

```powershell
python scan_exported_logs.py --help
```

### Command-line options

| Option | Description | Default |
|---|---|---|
| `--before` | Baseline Security-log CSV | `before_security.csv` |
| `--after` | Security-log CSV collected after testing | `after_security.csv` |
| `--threshold` | Minimum failed-logon count in the after export that triggers a review message | `3` |
| `--output` | Filtered CSV report location | `output/logon_events_report.csv` |

## Limitations

- The first version parses CSV exports rather than native `.evtx` files.
- CSV column names may vary by Windows version, Event Viewer language, and
  export format.
- Event ID 4625 alone does not prove an attack; failed logons can occur because
  of mistyped passwords, expired credentials, saved credentials, services, or
  configuration errors.
- The current version compares event counts and does not yet correlate by
  account, source IP, logon type, or time window.
- The project uses controlled lab data and is not a replacement for a SIEM,
  EDR, or enterprise incident-response process.
- Before and after exports may contain overlapping events. The combined
  report does not currently deduplicate them.
- Count differences are not proof of newly generated events, especially
  if the exports cover different time ranges or filters.

## Planned Improvements

- Add native `.evtx` parsing with `python-evtx`
- Extract account name, source IP, workstation name, and logon type
- Detect repeated failed logons from one account or source within a time window
- Add a "failed logon followed by successful logon" correlation rule
- Add severity levels and structured alert records
- Add JSON output in addition to CSV
- Add unit tests using sanitized sample logs
- Add Windows Firewall log parsing for denied connections
- Map detection logic to MITRE ATT&CK techniques where appropriate

## Screenshots

### Windows Security log evidence

Filtered Event Viewer output from the isolated Windows 11 VM. The log includes controlled successful logons (Event ID 4624) and failed logons (Event ID 4625).

![Filtered Windows Security events](assets/screenshots/event-viewer-filtered.png)

### Detector execution

The Python script compares before/after Security-log counts and checks
failed-logon activity against a configurable review threshold.

![Detector terminal output](assets/screenshots/run-output.png)

### Filtered event report

The tool writes matching successful and failed logon events from both
exports to a CSV file for analyst review. Threshold review messages appear
in the terminal rather than as separate records in this report.

![Generated alert report](assets/screenshots/report-output.png)





## Author

Christopher Ostrander

Bachelor's Degree in Cybersecurity 

https://www.linkedin.com/in/christopherostrander/

https://github.com/christopherostrander