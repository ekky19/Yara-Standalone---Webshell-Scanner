````markdown
# YARA STANDALONE - Webshell Scanner

**YARA STANDALONE** is a lightweight, offline tool for scanning webroot folders to detect webshells and other suspicious files using YARA rules.

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
│   ├── yara_standalone.exe   # Standalone executable
│   ├── yara_standalone.py    # (Optional) Source code
│   └── yara_webshell_rules/  # YARA rule files
├── template/                 # HTML report templates
├── reports/                  # Output reports (auto-generated)
└── run_yara_scan.bat         # Launcher script
````

---

## Rule Management

You can customize detection by modifying the rule files in:
`modules/yara_webshell_rules/`

* Add your own `.yar` files to enhance or adapt detection logic
* Remove or edit existing rules as needed

> ✅ No rebuild is required — the scanner will dynamically load all `.yar` files in that folder at runtime.

---

## Output

The scanner generates two types of reports for each scan, stored in the `reports` folder:

* **HTML Report** – A styled, grouped report showing matched YARA rules and metadata.
* **Text Report** – A plain-text version suitable for terminal viewing or logging.

All reports are timestamped and won't overwrite previous results.

---

## Optional: Running from Source

If you'd rather run the scanner using Python:

```bash
cd modules
python yara_standalone.py
```

Requirements (if using Python):

```
pip install yara-python jinja2 colorama
```

---

## Optional: Rebuilding the Executable

If you modify the script and want to rebuild the `.exe`:

```bash
pyinstaller --onefile modules/yara_standalone.py --name yara_standalone
```

> Do **not** bundle the `input`, `template`, `reports`, or `yara_webshell_rules` folders — these are read from disk at runtime.

---

## License

This project is licensed under the MIT License.
