#!/usr/bin/env python3

"""
Bug Hunter - Authorized Security Recon Automation
Python port of the Bash script with Auto-Update functionality.

Usage:
  python3 automation-script-bug.py example.com
  python3 automation-script-bug.py --update
  python3 automation-script-bug.py --check-update
"""

import os
import re
import shutil
import subprocess
import sys
import socket
import platform
import json
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

TARGET = ""
CONFIG_DIR = Path.home() / ".bug-hunter"
CONFIG_FILE = CONFIG_DIR / "config.json"
UPDATE_LOG = CONFIG_DIR / "update.log"

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
NC = "\033[0m"

# GitHub repository info
GITHUB_OWNER = "Hiteshsuthar400"
GITHUB_REPO = "Automation-Bug-Finding"
GITHUB_SCRIPT = "automation-script-bug.py"
GITHUB_RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/main/{GITHUB_SCRIPT}"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_SCRIPT}"


def log(message: str) -> None:
    print(f"{BLUE}[*]{NC} {message}")


def success(message: str) -> None:
    print(f"{GREEN}[+]{NC} {message}")


def warning(message: str) -> None:
    print(f"{YELLOW}[!]{NC} {message}")


def error(message: str) -> None:
    print(f"{RED}[-]{NC} {message}")


def ensure_config_dir() -> None:
    """Ensure config directory exists."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def get_file_hash(filepath: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_remote_file_hash(url: str) -> str:
    """Get file hash from GitHub."""
    try:
        with urlopen(GITHUB_RELEASES_API) as response:
            data = json.loads(response.read().decode())
            if "sha" in data:
                return data["sha"]
    except (URLError, json.JSONDecodeError):
        pass
    return ""


def download_update() -> bool:
    """Download the latest script from GitHub."""
    try:
        log(f"Downloading latest script from {GITHUB_RAW_URL}")
        with urlopen(GITHUB_RAW_URL) as response:
            content = response.read().decode("utf-8")
        
        script_path = Path(__file__).resolve()
        
        # Create backup
        backup_path = script_path.with_suffix(".bak")
        shutil.copy2(script_path, backup_path)
        log(f"Backup created: {backup_path}")
        
        # Write new version
        script_path.write_text(content, encoding="utf-8")
        script_path.chmod(0o755)
        
        success("Script updated successfully!")
        log(f"Updated: {script_path}")
        log(f"Backup: {backup_path}")
        
        # Log update
        log_update(f"Update completed successfully at {datetime.now()}")
        return True
    except URLError as e:
        error(f"Failed to download update: {e}")
        return False
    except Exception as e:
        error(f"Update failed: {e}")
        return False


def check_update() -> bool:
    """Check if update is available."""
    try:
        log("Checking for updates...")
        with urlopen(GITHUB_RAW_URL) as response:
            remote_content = response.read().decode("utf-8")
        
        local_path = Path(__file__).resolve()
        local_content = local_path.read_text(encoding="utf-8")
        
        if remote_content == local_content:
            success("You are running the latest version!")
            return False
        else:
            warning("A new version is available!")
            log("Run with --update flag to update: python3 automation-script-bug.py --update")
            return True
    except URLError as e:
        error(f"Failed to check for updates: {e}")
        return False
    except Exception as e:
        error(f"Check failed: {e}")
        return False


def log_update(message: str) -> None:
    """Log update activity."""
    ensure_config_dir()
    with open(UPDATE_LOG, "a", encoding="utf-8") as f:
        f.write(f"{message}\n")


def show_update_menu() -> None:
    """Show update menu."""
    print()
    print(f"{CYAN}============================================================{NC}")
    print(f"{CYAN}             UPDATE MENU{NC}")
    print(f"{CYAN}============================================================{NC}")
    print()
    print("1. Check for updates")
    print("2. Update script now")
    print("3. View update log")
    print("4. Back to main menu")
    print()
    choice = input("Select option (1-4): ").strip()
    
    if choice == "1":
        check_update()
    elif choice == "2":
        confirm = input("Do you want to update? (yes/no): ").strip().lower()
        if confirm in ["yes", "y"]:
            if download_update():
                print()
                success("Update complete! Please restart the script.")
                sys.exit(0)
        else:
            log("Update cancelled.")
    elif choice == "3":
        view_update_log()
    elif choice == "4":
        return
    else:
        error("Invalid option!")


def view_update_log() -> None:
    """Display update log."""
    ensure_config_dir()
    if UPDATE_LOG.exists():
        log(f"Update log ({UPDATE_LOG}):")
        print()
        with open(UPDATE_LOG, "r", encoding="utf-8") as f:
            print(f.read())
    else:
        log("No update log found.")


def parse_target(raw_target: str) -> str:
    target = raw_target.strip()
    if not target:
        return ""
    target = target.replace("http://", "", 1)
    target = target.replace("https://", "", 1)
    target = target.split("/", 1)[0]
    return target


def banner() -> None:
    os.system("clear")
    print(f"{CYAN}")
    print("============================================================")
    print("              BUG HUNTER AUTOMATION")
    print("============================================================")
    print(f"{NC}")
    print(f"Target : {TARGET}")
    print(f"Output : {BASE_DIR}")
    print()


def run_tool(tool: str) -> bool:
    if shutil.which(tool):
        return True
    warning(f"{tool} is not installed. Skipping.")
    return False


def run_cmd(description: str, *args: str) -> int:
    log(description)
    log_file = LOG_DIR / "commands.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(log_file, "a", encoding="utf-8") as logfile:
            result = subprocess.run(args, stdout=logfile, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        warning(f"Command not found: {args[0]}")
        return 1

    if result.returncode == 0:
        success(f"{description} completed")
    else:
        warning(f"{description} returned an error")
    return result.returncode


def ensure_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def write_txt(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_unique_lines(path: Path) -> list:
    if not path.exists():
        return []
    lines = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            cleaned = line.strip().replace("\r", "")
            if cleaned:
                lines.append(cleaned)
    return sorted(set(lines))


def append_unique_lines(path: Path, lines: list) -> None:
    if not lines:
        return
    existing = set(read_unique_lines(path))
    merged = sorted(existing | set(lines))
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for line in merged:
            handle.write(line + "\n")


def create_structure() -> None:
    log("Creating target directory structure...")
    for directory in [
        SUB_DIR,
        DNS_DIR,
        PORT_DIR,
        HTTP_DIR,
        SCREEN_DIR,
        DIR_DIR,
        JS_DIR,
        URL_DIR,
        PARAM_DIR,
        API_DIR,
        VULN_DIR,
        WAF_DIR,
        GIT_DIR,
        LOG_DIR,
        WORDLIST_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)

    LOG_DIR.joinpath("commands.log").touch(exist_ok=True)
    success("Directory structure created")


def save_target_info() -> None:
    text = f"""============================================================
TARGET INFORMATION
============================================================

Target:
{TARGET}

Started:
{datetime.now()}

Hostname:
{socket.gethostname()}

Operating System:
{platform.uname()}

Working Directory:
{os.getcwd()}

============================================================
"""
    write_txt(BASE_DIR / "target-info.txt", text)


def subdomain_enum() -> None:
    log("Step 01 - Subdomain enumeration")

    if run_tool("subfinder"):
        run_cmd("Running subfinder", "subfinder", "-d", TARGET, "-silent", "-o", str(SUB_DIR / "subfinder.txt"))

    if run_tool("amass"):
        run_cmd("Running amass", "amass", "enum", "-passive", "-d", TARGET, "-o", str(SUB_DIR / "amass.txt"))

    if run_tool("assetfinder"):
        asset_file = SUB_DIR / "assetfinder.txt"
        with open(asset_file, "w", encoding="utf-8") as handle:
            result = subprocess.run(["assetfinder", "--subs-only", TARGET], stdout=handle, stderr=subprocess.STDOUT, text=True)
            if result.returncode != 0:
                warning("assetfinder returned an error")

    ensure_file(SUB_DIR / "subfinder.txt")
    ensure_file(SUB_DIR / "amass.txt")
    ensure_file(SUB_DIR / "assetfinder.txt")

    all_subdomains = set()
    for file_path in [SUB_DIR / "subfinder.txt", SUB_DIR / "amass.txt", SUB_DIR / "assetfinder.txt"]:
        all_subdomains.update(read_unique_lines(file_path))

    with open(MASTER_SUBDOMAINS, "w", encoding="utf-8") as handle:
        for item in sorted(all_subdomains):
            handle.write(item + "\n")

    success("Subdomains saved to:")
    print(f"    {MASTER_SUBDOMAINS}")


def dns_resolution() -> None:
    log("Step 02 - DNS resolution")

    if run_tool("dnsx"):
        run_cmd("Running dnsx", "dnsx", "-l", str(MASTER_SUBDOMAINS), "-silent", "-a", "-resp", "-o", str(DNS_DIR / "dnsx-results.txt"))
    elif run_tool("httpx"):
        run_cmd("Running httpx", "httpx", "-l", str(MASTER_SUBDOMAINS), "-silent", "-ip", "-o", str(DNS_DIR / "resolved-hosts.txt"))
    else:
        warning("dnsx/httpx unavailable. DNS resolution skipped.")


def port_scan() -> None:
    log("Step 03 - Port scanning")

    if run_tool("nmap"):
        run_cmd("Running nmap", "nmap", "-Pn", "--open", "-sV", "-sC", "-T4", TARGET, "-oN", str(PORT_DIR / "nmap-result.txt"))
    else:
        warning("nmap is not installed.")

    if run_tool("masscan"):
        run_cmd("Running masscan", "masscan", TARGET, "-p1-65535", "--rate", "5000", "-oL", str(PORT_DIR / "masscan-result.txt"))
    else:
        warning("masscan is not installed.")


def http_probe() -> None:
    log("Step 04 - HTTP probing")

    if not run_tool("httpx"):
        return

    run_cmd(
        "Running httpx (full)",
        "httpx",
        "-l",
        str(MASTER_SUBDOMAINS),
        "-silent",
        "-follow-redirects",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-ip",
        "-o",
        str(HTTP_DIR / "httpx-full.txt"),
    )

    run_cmd(
        "Running httpx (live hosts)",
        "httpx",
        "-l",
        str(MASTER_SUBDOMAINS),
        "-silent",
        "-follow-redirects",
        "-o",
        str(LIVE_HOSTS),
    )

    success(f"Live hosts saved to {LIVE_HOSTS}")


def screenshots() -> None:
    log("Step 05 - Web screenshots")

    if run_tool("eyewitness"):
        run_cmd("Running eyewitness", "eyewitness", "-f", str(LIVE_HOSTS), "--web", "-d", str(SCREEN_DIR / "eyewitness"))
    else:
        warning("EyeWitness not installed.")

    if run_tool("aquatone"):
        with open(LOG_DIR / "commands.log", "a", encoding="utf-8") as logfile:
            with open(LIVE_HOSTS, "r", encoding="utf-8", errors="ignore") as hosts_file:
                result = subprocess.run(["cat"], stdin=hosts_file, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            aquatone_proc = subprocess.run(["aquatone", "-out", str(SCREEN_DIR / "aquatone")], input=result.stdout, stdout=logfile, stderr=subprocess.STDOUT, text=True)
            if aquatone_proc.returncode != 0:
                warning("Aquatone returned an error")
    else:
        warning("Aquatone not installed.")


def directory_discovery() -> None:
    log("Step 06 - Directory/content discovery")

    wordlist = ""
    candidates = [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            wordlist = candidate
            break

    if not wordlist:
        warning("No standard directory wordlist found.")
        return

    if run_tool("ffuf"):
        run_cmd(
            "Running ffuf",
            "ffuf",
            "-u",
            f"https://{TARGET}/FUZZ",
            "-w",
            wordlist,
            "-mc",
            "200,204,301,302,307,401,403",
            "-of",
            "json",
            "-o",
            str(DIR_DIR / "ffuf-results.json"),
        )

    if run_tool("gobuster"):
        run_cmd(
            "Running gobuster",
            "gobuster",
            "dir",
            "-u",
            f"https://{TARGET}",
            "-w",
            wordlist,
            "-o",
            str(DIR_DIR / "gobuster-results.txt"),
        )


def url_collection() -> None:
    log("Step 07 - URL collection")

    ensure_file(URL_DIR / "gau.txt")
    ensure_file(URL_DIR / "waybackurls.txt")

    if run_tool("gau"):
        with open(URL_DIR / "gau.txt", "w", encoding="utf-8") as handle:
            result = subprocess.run(["gau", TARGET], stdout=handle, stderr=subprocess.STDOUT, text=True)
            if result.returncode != 0:
                warning("gau returned an error")

    if run_tool("waybackurls"):
        with open(URL_DIR / "waybackurls.txt", "w", encoding="utf-8") as handle:
            result = subprocess.run(["waybackurls"], input=f"{TARGET}\n", stdout=handle, stderr=subprocess.STDOUT, text=True)
            if result.returncode != 0:
                warning("waybackurls returned an error")

    urls = set()
    for file_path in [URL_DIR / "gau.txt", URL_DIR / "waybackurls.txt"]:
        urls.update(read_unique_lines(file_path))

    with open(ALL_URLS, "w", encoding="utf-8") as handle:
        for item in sorted(urls):
            handle.write(item + "\n")

    success(f"URLs saved to {ALL_URLS}")


def javascript_enum() -> None:
    log("Step 08 - JavaScript discovery")

    js_urls = []
    if ALL_URLS.exists():
        with open(ALL_URLS, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                value = line.strip()
                if re.search(r"\.js(?:[?#]|$)", value, re.IGNORECASE):
                    js_urls.append(value)

    with open(JS_DIR / "js-files.txt", "w", encoding="utf-8") as handle:
        for item in sorted(set(js_urls)):
            handle.write(item + "\n")

    success("JavaScript URLs:")
    print(f"    {JS_DIR / 'js-files.txt'}")

    if not JS_DIR.joinpath("js-files.txt").stat().st_size:
        warning("No JavaScript URLs found.")
        return

    if run_tool("httpx"):
        run_cmd(
            "Running httpx for JS files",
            "httpx",
            "-l",
            str(JS_DIR / "js-files.txt"),
            "-silent",
            "-status-code",
            "-content-type",
            "-o",
            str(JS_DIR / "js-httpx.txt"),
        )


def parameter_discovery() -> None:
    log("Step 09 - Parameter discovery")

    if run_tool("paramspider"):
        run_cmd("Running paramspider", "paramspider", "-d", TARGET, "--level", "high", "-o", str(PARAM_DIR / "paramspider.txt"))
    else:
        warning("ParamSpider not installed.")

    if run_tool("arjun"):
        run_cmd("Running arjun", "arjun", "-u", f"https://{TARGET}", "-m", "GET", "-oJ", str(PARAM_DIR / "arjun.json"))
    else:
        warning("Arjun not installed.")


def api_recon() -> None:
    log("Step 10 - API reconnaissance")

    if run_tool("kiterunner"):
        wordlist_path = WORDLIST_DIR / "apis.txt"
        if wordlist_path.exists():
            run_cmd("Running kiterunner", "kr", "scan", f"https://{TARGET}", "-w", str(wordlist_path), ">", str(API_DIR / "kiterunner.txt"))
        else:
            warning("API wordlist missing:")
            print(f"    {wordlist_path}")
    else:
        warning("Kiterunner not installed.")


def security_headers() -> None:
    log("Step 11 - Security header analysis")

    if run_tool("httpx"):
        run_cmd(
            "Running httpx security scan",
            "httpx",
            "-u",
            f"https://{TARGET}",
            "-status-code",
            "-title",
            "-web-server",
            "-tech-detect",
            "-json",
            "-o",
            str(VULN_DIR / "httpx-security.json"),
        )

    if run_tool("nikto"):
        run_cmd("Running nikto", "nikto", "-h", f"https://{TARGET}", "-output", str(VULN_DIR / "nikto.txt"))


def waf_detection() -> None:
    log("Step 12 - WAF detection")

    if run_tool("wafw00f"):
        with open(WAF_DIR / "wafw00f.txt", "w", encoding="utf-8") as handle:
            result = subprocess.run(["wafw00f", f"https://{TARGET}"], stdout=handle, stderr=subprocess.STDOUT, text=True)
            if result.returncode != 0:
                warning("wafw00f returned an error")


def cms_detection() -> None:
    log("Step 13 - CMS detection")

    if run_tool("cmseek"):
        run_cmd("Running cmseek", "cmseek", "-u", f"https://{TARGET}", "--batch", "--output-dir", str(WAF_DIR / "cmseek"))
    else:
        warning("CMSeeK not installed.")


def interesting_urls() -> None:
    log("Step 14 - Interesting URL detection")

    matching_urls = []
    if ALL_URLS.exists():
        with open(ALL_URLS, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                value = line.strip()
                if re.search(r"(\.env|\.git|backup|config|admin|login|api|swagger|graphql|debug|test|dev|staging)", value, re.IGNORECASE):
                    matching_urls.append(value)
        with open(VULN_DIR / "interesting-urls.txt", "w", encoding="utf-8") as handle:
            for item in sorted(set(matching_urls)):
                handle.write(item + "\n")

    matching_params = []
    if ALL_URLS.exists():
        with open(ALL_URLS, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                value = line.strip()
                if re.search(r"(\?|&)(id|url|uri|path|file|page|redirect|next|return|search|q|query|callback|domain)=", value, re.IGNORECASE):
                    matching_params.append(value)
        with open(PARAM_DIR / "interesting-parameters.txt", "w", encoding="utf-8") as handle:
            for item in sorted(set(matching_params)):
                handle.write(item + "\n")

    success("Interesting URLs/parameters extracted.")


def git_exposure_check() -> None:
    log("Step 15 - Checking for exposed Git repository")

    if run_tool("httpx"):
        urls = [
            f"https://{TARGET}/.git/HEAD",
            f"https://{TARGET}/.git/config",
        ]
        with open(GIT_DIR / "git-check.txt", "w", encoding="utf-8") as handle:
            result = subprocess.run(["httpx", "-silent", "-status-code", "-content-type", "-o", str(GIT_DIR / "git-check.txt")], input="\n".join(urls) + "\n", stdout=handle, stderr=subprocess.STDOUT, text=True)
            if result.returncode != 0:
                warning("httpx git exposure check returned an error")


def generate_summary() -> None:
    log("Generating final summary...")

    sub_count = 0
    live_count = 0
    url_count = 0
    js_count = 0
    param_count = 0

    if MASTER_SUBDOMAINS.exists():
        sub_count = sum(1 for _ in open(MASTER_SUBDOMAINS, "r", encoding="utf-8", errors="ignore"))

    if LIVE_HOSTS.exists():
        live_count = sum(1 for _ in open(LIVE_HOSTS, "r", encoding="utf-8", errors="ignore"))

    if ALL_URLS.exists():
        url_count = sum(1 for _ in open(ALL_URLS, "r", encoding="utf-8", errors="ignore"))

    js_file = JS_DIR / "js-files.txt"
    if js_file.exists():
        js_count = sum(1 for _ in open(js_file, "r", encoding="utf-8", errors="ignore"))

    param_file = PARAM_DIR / "interesting-parameters.txt"
    if param_file.exists():
        param_count = sum(1 for _ in open(param_file, "r", encoding="utf-8", errors="ignore"))

    summary = f"""============================================================
BUG HUNTER RECON SUMMARY
============================================================

Target:
{TARGET}

Scan Started:
{datetime.now()}

Scan Finished:
{datetime.now()}

------------------------------------------------------------
COUNTS
------------------------------------------------------------

Subdomains:
{sub_count}

Live HTTP Hosts:
{live_count}

Collected URLs:
{url_count}

JavaScript URLs:
{js_count}

Interesting Parameters:
{param_count}

------------------------------------------------------------
IMPORTANT FILES
------------------------------------------------------------

Subdomains:
{MASTER_SUBDOMAINS}

Live Hosts:
{LIVE_HOSTS}

All URLs:
{ALL_URLS}

Nmap:
{PORT_DIR / 'nmap-result.txt'}

Masscan:
{PORT_DIR / 'masscan-result.txt'}

Directory Discovery:
{DIR_DIR}

JavaScript:
{JS_DIR}

Parameters:
{PARAM_DIR}

API:
{API_DIR}

Vulnerability Checks:
{VULN_DIR}

WAF/CMS:
{WAF_DIR}

Git Exposure:
{GIT_DIR}

Logs:
{LOG_DIR}

============================================================
"""
    write_txt(BASE_DIR / "summary.txt", summary)
    success("Summary created:")
    print(f"    {BASE_DIR / 'summary.txt'}")


def main() -> int:
    global TARGET, BASE_DIR, SUB_DIR, DNS_DIR, PORT_DIR, HTTP_DIR, SCREEN_DIR, DIR_DIR, JS_DIR, URL_DIR, PARAM_DIR, API_DIR, VULN_DIR, WAF_DIR, GIT_DIR, LOG_DIR, WORDLIST_DIR, MASTER_SUBDOMAINS, LIVE_HOSTS, ALL_URLS

    # Handle command line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        
        if arg in ["--update", "-u"]:
            log("Starting update process...")
            if download_update():
                success("Update installed. Please restart the script.")
            return 0
        
        elif arg in ["--check-update", "-c"]:
            return 0 if check_update() else 1
        
        elif arg in ["--update-menu", "-m"]:
            show_update_menu()
            return 0
        
        elif arg in ["--help", "-h"]:
            print()
            print("Bug Hunter - Authorized Security Recon Automation")
            print()
            print("USAGE:")
            print(f"  {sys.argv[0]} <domain>              Run recon on target")
            print(f"  {sys.argv[0]} --check-update (-c)   Check for updates")
            print(f"  {sys.argv[0]} --update (-u)         Download and install update")
            print(f"  {sys.argv[0]} --update-menu (-m)    Show update menu")
            print(f"  {sys.argv[0]} --help (-h)           Show this help message")
            print()
            print("EXAMPLES:")
            print(f"  {sys.argv[0]} example.com")
            print(f"  {sys.argv[0]} --check-update")
            print(f"  {sys.argv[0]} --update")
            print()
            return 0
        
        elif arg.startswith("-"):
            error(f"Unknown option: {arg}")
            print(f"Use '{sys.argv[0]} --help' for usage information")
            return 1

    if len(sys.argv) < 2:
        print()
        print(f"Usage: {sys.argv[0]} <domain>")
        print(f"Example: {sys.argv[0]} example.com")
        print(f"For more options: {sys.argv[0]} --help")
        return 1

    TARGET = parse_target(sys.argv[1])
    if not TARGET:
        error("Target cannot be empty.")
        return 1

    BASE_DIR = Path.cwd() / "targets" / TARGET
    SUB_DIR = BASE_DIR / "01-subdomains"
    DNS_DIR = BASE_DIR / "02-dns"
    PORT_DIR = BASE_DIR / "03-ports"
    HTTP_DIR = BASE_DIR / "04-http"
    SCREEN_DIR = BASE_DIR / "05-screenshots"
    DIR_DIR = BASE_DIR / "06-directories"
    JS_DIR = BASE_DIR / "07-javascript"
    URL_DIR = BASE_DIR / "08-urls"
    PARAM_DIR = BASE_DIR / "09-parameters"
    API_DIR = BASE_DIR / "10-api"
    VULN_DIR = BASE_DIR / "11-vulnerability-checks"
    WAF_DIR = BASE_DIR / "12-waf-cms"
    GIT_DIR = BASE_DIR / "13-git"
    LOG_DIR = BASE_DIR / "logs"
    WORDLIST_DIR = BASE_DIR / "wordlists"

    MASTER_SUBDOMAINS = SUB_DIR / "all-subdomains.txt"
    LIVE_HOSTS = HTTP_DIR / "live-hosts.txt"
    ALL_URLS = URL_DIR / "all-urls.txt"

    banner()
    create_structure()
    save_target_info()

    subdomain_enum()
    dns_resolution()
    port_scan()
    http_probe()
    screenshots()
    directory_discovery()
    url_collection()
    javascript_enum()
    parameter_discovery()
    api_recon()
    security_headers()
    waf_detection()
    cms_detection()
    interesting_urls()
    git_exposure_check()
    generate_summary()

    print()
    print(f"{GREEN}============================================================{NC}")
    print(f"{GREEN}             RECON COMPLETED{NC}")
    print(f"{GREEN}============================================================{NC}")
    print()
    print(f"Target : {TARGET}")
    print(f"Results: {BASE_DIR}")
    print()
    print("Summary:")
    print(f"  {BASE_DIR / 'summary.txt'}")
    print()
    print(f"For updates: {sys.argv[0]} --check-update")
    print()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        raise SystemExit(130)
