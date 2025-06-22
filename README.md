# YARA Standalone - Webshell Scanner

**YARA Standalone** is a lightweight, offline tool for scanning webroot folders to detect webshells and other suspicious files using YARA rules.

This tool is intended for SOC analysts, incident responders, and forensic investigators who need to inspect `.php`, `.asp`, `.html`, `.jsp`, and similar files for signs of compromise — without requiring internet access or installation.

---

## Getting Started

1. Place the files you want to scan into the following folder:  
   `input\webroot`

2. Run the tool by executing:  
   `run_yara_scan.bat`

3. After the scan, results will be saved in the `reports` folder as both `.html` and `.txt` files.

---

## Project Structure

```text
YARA_STANDALONE/
├── input/
│   └── webroot/              # Files to scan go here
├── modules/
│   ├── yara_scanner.exe   # Standalone executable
│   ├── yara_scanner.py    # (Optional) Source code
│   └── yara_webshell_rules/  # YARA rule files
├── template/                 # HTML report templates
├── reports/                  # Output reports (auto-generated)
└── run_yara_scan.bat         # Launcher script



---

## Rule Management

You can customize detection logic by modifying the `.yar` rule files in:  
`modules/yara_webshell_rules/`

- Add your own `.yar` files to extend detection.
- Remove or update existing rules as needed.

> No rebuild is required — the scanner will dynamically load all `.yar` files on each run.

---

## Output

The tool generates the following reports in the `reports/` folder:

- **HTML Report** - A styled, grouped summary of rule matches with metadata.
- **Text Report** - A plain-text version for terminal review or log archiving.

---

## Optional: Running from Source

If you'd prefer to run the tool using Python:

```bash
cd modules
python 
---

## Rule Management

You can customize detection logic by modifying the `.yar` rule files in:  
`modules/yara_webshell_rules/`

- Add your own `.yar` files to extend detection.
- Remove or update existing rules as needed.

> No rebuild is required — the scanner will dynamically load all `.yar` files on each run.

---

## Output

The tool generates the following reports in the `reports/` folder:

- **HTML Report** - A styled, grouped summary of rule matches with metadata.
- **Text Report** - A plain-text version for terminal review or log archiving.

Reports are timestamped and do not overwrite previous results.

---

## Optional: Running from Source

If you'd prefer to run the tool using Python:
python yara_scanner.py

