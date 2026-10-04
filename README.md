# Cyber-Threat-Checker

A cybersecurity project built with PowerShell and Python to collect endpoint artifacts and analyse remote IP addresses using the VirusTotal API.

## What it does
- Collects running processes and TCP connections
- Exports collected artifacts to JSON
- Extracts remote IP addresses
- Checks IP reputation using VirusTotal
- Generates a JSON analysis report

## Technologies
- PowerShell
- Python
- VirusTotal API
- JSON
- REST APIs

## Project files
- `collect_artifacts.ps1` – collects endpoint process and network data
- `analyze_artifacts.py` – analyses the collected artifacts and queries VirusTotal
- `analysis_report.json` – sample output from the project
- `project_report.docx` – project documentation
