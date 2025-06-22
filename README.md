```markdown
# YARA STANDALONE - Webshell Scanner

**YARA STANDALONE** is a lightweight, offline tool for scanning webroot folders to detect webshells and other suspicious files using YARA rules.

This tool is built for SOC analysts, incident responders, and forensic investigators who need to analyze `.php`, `.asp`, `.html`, `.jsp`, or other script-based files for signs of compromise — without requiring installation or internet access.

---

## Getting Started

1. Place the files you want to scan into the following folder:

```

input\webroot

```

2. Run the tool by executing:

```

run\_yara\_scan.bat

```

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

YARA rules are stored in `modules/yara_webshell_rules/`. You can:

- Add your own YARA rules by placing `.yar` files in that folder
- Remove or update the existing ones as needed

No rebuild is required. The scanner will load all `.yar` files in that folder automatically at runtime.

---

## Output

The tool generates two types of reports for each scan:

- **HTML Report** — A styled, readable report showing grouped rule matches and metadata
- **Text Report** — A plain-text version for quick inspection or logging

Reports are timestamped and saved in the `reports/` directory.

---

## Optional: Running from Source

If you'd like to run the script manually (instead of using the `.exe`):

```bash
cd modules
python yara_standalone.py
````

> Note: This requires Python 3 and the following packages:
> `yara-python`, `jinja2`, `colorama`

---

## Optional: Building the Executable

To rebuild the executable (e.g., if modifying the script):

```bash
pyinstaller --onefile modules/yara_standalone.py --name yara_standalone
```

> Do not bundle the `input`, `template`, `reports`, or `yara_webshell_rules` folders — they are accessed from disk.

---

## License

This project is open-source under the MIT License. YARA rules are sourced from trusted public repositories including THOR, Velociraptor, and php-malware-finder. You are free to extend or adapt the rules for your own detection needs.

```
