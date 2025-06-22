```markdown
# YARA STANDALONE - Webshell Scanner

**YARA STANDALONE** is a lightweight, offline tool for scanning webroot folders to detect webshells and other suspicious files using YARA rules.

This tool is built for SOC analysts, incident responders, and forensic investigators who need to analyze `.php`, `.asp`, `.html`, `.jsp`, or similar files for signs of compromise.

---

## Getting Started

1. Place the files you want to scan into the following folder:  
   `input\webroot`

2. Run the tool by executing:  
   `run_yara_scan.bat`

3. After the scan, results will be saved in the `reports` folder as both `.html` and `.txt` files.

---

## Project Structure

```

YARA\_STANDALONE/
├── input/webroot/                # Drop target files here
├── modules/
│   ├── yara\_standalone.exe       # Standalone executable
│   ├── yara\_standalone.py        # (Optional) Source code
│   └── yara\_webshell\_rules/      # YARA rule files
├── template/                     # HTML report templates
├── reports/                      # Output reports
└── run\_yara\_scan.bat             # Windows launcher

````

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

```bash
cd modules
python yara_standalone.py
````

> Requires Python 3 and the following packages:
> `yara-python`, `jinja2`, `colorama`

---

## Optional: Rebuilding the Executable

If you make code changes and want to rebuild the `.exe`:

```bash
pyinstaller --onefile modules/yara_standalone.py --name yara_standalone
```

> Do not bundle the `input`, `template`, `reports`, or `yara_webshell_rules` folders — they are accessed from disk.

---

## License

This project is released under the MIT License.

