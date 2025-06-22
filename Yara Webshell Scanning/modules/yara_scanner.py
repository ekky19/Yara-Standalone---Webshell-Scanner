import os
import sys
import yara
import hashlib
from datetime import datetime
from colorama import Fore, Style, init
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict

# Initialize color output in terminal
init(autoreset=True, convert=True)

# Detect root folder properly (works in .py and .exe)
def get_project_root():
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller exe → EXE is in modules/
        return os.path.abspath(os.path.join(os.path.dirname(sys.executable), ".."))
    else:
        # Running as .py → script is in modules/
        return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

PROJECT_ROOT = get_project_root()

# External resources
TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "template")
TARGET_DIR   = os.path.join(PROJECT_ROOT, "input", "webroot")
OUTPUT_DIR   = os.path.join(PROJECT_ROOT, "reports")

# Internal (bundled) rules
def get_resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # PyInstaller unpacked temp
    except AttributeError:
        base_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_path, relative_path)

RULE_DIR = os.path.join(get_project_root(), "modules", "yara_webshell_rules")
HTML_TEMPLATE_FILE = "yara_report_template.jinja2"

# Load and compile YARA rules from all .yar files
def load_yara_rules():
    yara_files = {}
    for filename in os.listdir(RULE_DIR):
        if filename.endswith(".yar"):
            namespace = os.path.splitext(filename)[0]
            yara_files[namespace] = os.path.join(RULE_DIR, filename)
    try:
        rules = yara.compile(filepaths=yara_files)
        return rules
    except Exception as e:
        print(Fore.RED + f"[!] YARA compile error: {e}" + Style.RESET_ALL)
        return None

# Scan target files and return match metadata
def scan_files(rules):
    matches = []
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "rb") as f:
                    data = f.read()
                    sha256 = hashlib.sha256(data).hexdigest()
                    file_matches = rules.match(data=data)
                    for m in file_matches:
                        matches.append({
                            "file": os.path.basename(full_path),
                            "rule": m.rule,
                            "yara_file": f"{m.namespace}.yar",
                            "sha256": sha256,
                            "meta": m.meta
                        })
                        print(Fore.YELLOW + f"[+] Match: {m.rule} → {full_path}" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"[!] Error reading {full_path}: {e}" + Style.RESET_ALL)
    return matches

# Generate the HTML report using a dynamic or single-card layout
def save_html_report(grouped_records, meta_keys_per_file):
    if not grouped_records:
        print(Fore.CYAN + "[*] No YARA matches found for HTML report." + Style.RESET_ALL)
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(OUTPUT_DIR, f"yara_report_dynamic_{timestamp}.html")

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

    # Use fancy card template if only one file scanned
    if len(grouped_records) == 1:
        only_match_list = next(iter(grouped_records.values()))
        template_file = "yara_single_result.jinja2" if len(only_match_list) >= 1 else HTML_TEMPLATE_FILE
    else:
        template_file = HTML_TEMPLATE_FILE

    template = env.get_template(template_file)
    rendered = template.render(grouped_records=grouped_records, meta_keys_per_file=meta_keys_per_file)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    print(Fore.GREEN + f"[+] HTML report saved to {output_path}" + Style.RESET_ALL)

# Generate a readable TXT report of results
def save_results_txt(grouped_records, meta_keys_per_file):
    if not grouped_records:
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(OUTPUT_DIR, f"yara_results_dynamic_{timestamp}.txt")

    with open(output_file, "w", encoding="utf-8") as f:
        for file, recs in grouped_records.items():
            f.write("=" * 80 + "\n")
            f.write(f"Scanned File: {file}\n")
            for match in recs:
                f.write(f"  Rule: {match['rule']}\n")
                f.write(f"  YARA File: {match['yara_file']}\n")
                if match['meta']:
                    for k, v in match['meta'].items():
                        f.write(f"    {k}: {v}\n")
                f.write(f"  SHA-256: {match['sha256']}\n")
                f.write("\n")
            f.write("\n")

    print(Fore.GREEN + f"[+] TXT report saved to {output_file}" + Style.RESET_ALL)

# Main execution block
def main():
    rules = load_yara_rules()
    if rules:
        all_matches = scan_files(rules)

        grouped_matches = {}
        all_meta_keys = set()
        non_empty_meta_keys = defaultdict(bool)
        meta_keys_per_file = {}

        # Group results by file and track non-empty metadata fields
        for m in all_matches:
            grouped_matches.setdefault(m['file'], []).append(m)
            for k, v in m['meta'].items():
                all_meta_keys.add(k)
                if str(v).strip():
                    non_empty_meta_keys[k] = True

        # Determine relevant meta keys per file
        for file, recs in grouped_matches.items():
            meta_keys = set()
            for m in recs:
                for k, v in m['meta'].items():
                    if str(v).strip():
                        meta_keys.add(k)
            meta_keys_per_file[file] = sorted(meta_keys)

        # Generate final reports
        save_html_report(grouped_matches, meta_keys_per_file)
        save_results_txt(grouped_matches, meta_keys_per_file)

if __name__ == "__main__":
    main()
