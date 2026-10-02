#!/usr/bin/env python3

"""
Automation Bug Finding Script
Automates comprehensive bug bounty reconnaissance and vulnerability scanning.

Usage:
  python3 automation-script-bug.py <domain> [options]
  python3 automation-script-bug.py <domain> --check          Check tool status
  python3 automation-script-bug.py --help                    Show help
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

# Color codes for output
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
NC = "\033[0m"

# Configuration
BASE_DIR = Path.home() / ".bug-hunter"
CONFIG_DIR = BASE_DIR / "config"
RESULTS_DIR = BASE_DIR / "results"
UPDATE_LOG = CONFIG_DIR / "update.log"

GITHUB_REPO = "Hiteshsuthar400/Automation-Bug-Finding"
GITHUB_RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/automation-script-bug.py"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

TARGET = ""
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
SCAN_DIR = RESULTS_DIR / f"scan_{TIMESTAMP}"

# Subdirectories
RECON_DIR = SCAN_DIR / "01_reconnaissance"
DNS_DIR = SCAN_DIR / "02_dns"
HTTP_DIR = SCAN_DIR / "03_http"
SCAN_RESULTS_DIR = SCAN_DIR / "04_scanning"
FUZZ_DIR = SCAN_DIR / "05_fuzzing"
URL_DIR = SCAN_DIR / "06_url_collection"
PARAM_DIR = SCAN_DIR / "07_parameters"
VULN_DIR = SCAN_DIR / "08_vulnerabilities"
WAF_DIR = SCAN_DIR / "09_waf_cms"
SECRET_DIR = SCAN_DIR / "10_secrets"
CLOUD_DIR = SCAN_DIR / "11_cloud"

# Important files
ALL_URLS = SCAN_DIR / "all_urls.txt"
ALL_SUBDOMAINS = SCAN_DIR / "all_subdomains.txt"
ALIVE_SUBDOMAINS = SCAN_DIR / "alive_subdomains.txt"


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
    print(f"{CYAN}{'='*80}{NC}")
    print(f"{CYAN}                    UPDATE AVAILABLE                             {NC}")
    print(f"{CYAN}{'='*80}{NC}")
    print()
    print("A new version of the script is available!")
    print()
    print("Options:")
    print(f"  1. Update now:     python3 automation-script-bug.py --update")
    print(f"  2. Continue:       python3 automation-script-bug.py <domain>")
    print(f"  3. View details:   python3 automation-script-bug.py --check-update")
    print()


def run_tool(tool_name: str) -> bool:
    """Check if a tool is available."""
    return shutil.which(tool_name) is not None


def run_cmd(description: str, *args) -> bool:
    """Run a command and log output."""
    try:
        log(description)
        log(f"Command: {' '.join(str(arg) for arg in args)}")

        # Create parent directories if needed
        for arg in args:
            if isinstance(arg, Path):
                arg.parent.mkdir(parents=True, exist_ok=True)

        # Handle output file
        logfile = None
        if any(str(arg).startswith("/") for arg in args) and any(str(arg).endswith((".txt", ".json", ".csv")) for arg in args):
            # Last Path argument is likely the output file
            for arg in reversed(args):
                if isinstance(arg, Path) or (isinstance(arg, str) and arg.endswith((".txt", ".json", ".csv"))):
                    output_path = Path(arg)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    logfile = open(output_path, "w", encoding="utf-8")
                    break

        result = subprocess.run(args, stdout=logfile if logfile else subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        if logfile:
            logfile.close()

        if result.returncode == 0:
            success(f"{description} completed")
            return True
        else:
            warning(f"{description} returned code {result.returncode}")
            return False

    except Exception as e:
        error(f"{description} failed: {e}")
        return False


def subdomain_enumeration() -> None:
    """Perform subdomain enumeration."""
    log("Step 1 - Subdomain enumeration")

    tools_output = []

    if run_tool("subfinder"):
        log("Running subfinder")
        result = subprocess.run(
            ["subfinder", "-d", TARGET, "-o", str(RECON_DIR / "subfinder.txt")],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            success("Subfinder completed")
        else:
            warning("Subfinder encountered issues")

    if run_tool("assetfinder"):
        log("Running assetfinder")
        with open(RECON_DIR / "assetfinder.txt", "w", encoding="utf-8") as f:
            result = subprocess.run(["assetfinder", TARGET], stdout=f, stderr=subprocess.STDOUT, text=True)

    if run_tool("amass"):
        log("Running amass")
        result = subprocess.run(
            ["amass", "enum", "-d", TARGET, "-o", str(RECON_DIR / "amass.txt")],
            capture_output=True,
            text=True,
        )

    # Combine all subdomains
    all_subdomains = set()
    for file in [RECON_DIR / "subfinder.txt", RECON_DIR / "assetfinder.txt", RECON_DIR / "amass.txt"]:
        if file.exists():
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                all_subdomains.update(line.strip() for line in f if line.strip())

    if all_subdomains:
        with open(ALL_SUBDOMAINS, "w", encoding="utf-8") as f:
            for subdomain in sorted(all_subdomains):
                f.write(subdomain + "\n")
        success(f"Found {len(all_subdomains)} unique subdomains")


def dns_resolution() -> None:
    """Perform DNS resolution."""
    log("Step 2 - DNS resolution and validation")

    if not ALL_SUBDOMAINS.exists():
        warning("Subdomain file not found")
        return

    if run_tool("dnsx"):
        log("Running dnsx for DNS resolution")
        result = subprocess.run(
            ["dnsx", "-list", str(ALL_SUBDOMAINS), "-o", str(DNS_DIR / "resolved.txt")],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            success("DNS resolution completed")

    if run_tool("puredns"):
        log("Running puredns for validation")
        result = subprocess.run(
            ["puredns", "resolve", str(ALL_SUBDOMAINS), "-o", str(DNS_DIR / "puredns.txt")],
            capture_output=True,
            text=True,
        )


def http_probing() -> None:
    """Probe for HTTP/HTTPS services."""
    log("Step 3 - HTTP/HTTPS probing")

    if not ALL_SUBDOMAINS.exists():
        warning("Subdomain file not found")
        return

    if run_tool("httpx"):
        log("Running httpx")
        result = subprocess.run(
            ["httpx", "-list", str(ALL_SUBDOMAINS), "-json", "-o", str(HTTP_DIR / "httpx.json")],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            success("HTTP probing completed")
            # Extract alive URLs
            try:
                with open(HTTP_DIR / "httpx.json", "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if "url" in data:
                                ALIVE_SUBDOMAINS.parent.mkdir(parents=True, exist_ok=True)
                                with open(ALIVE_SUBDOMAINS, "a", encoding="utf-8") as out:
                                    out.write(data["url"] + "\n")
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                warning(f"Failed to parse httpx output: {e}")


def port_scanning() -> None:
    """Perform port scanning."""
    log("Step 4 - Port scanning")

    if run_tool("nmap"):
        log("Running nmap for top 1000 ports")
        with open(SCAN_RESULTS_DIR / "nmap.txt", "w", encoding="utf-8") as f:
            result = subprocess.run(
                ["nmap", "-sV", "-sC", "-oN", str(SCAN_RESULTS_DIR / "nmap_output.txt"), TARGET],
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
            )

    if run_tool("masscan"):
        log("Running masscan for quick port scan")
        result = subprocess.run(
            ["masscan", TARGET, "-p", "1-65535", "--rate=1000", "-oG", str(SCAN_RESULTS_DIR / "masscan.txt")],
            capture_output=True,
            text=True,
        )


def tls_analysis() -> None:
    """Perform TLS certificate analysis."""
    log("Step 5 - TLS Certificate Analysis")

    if run_tool("tlsx"):
        log("Running tlsx for certificate enumeration")
        result = subprocess.run(
            ["tlsx", "-u", f"https://{TARGET}", "-json", "-o", str(HTTP_DIR / "tlsx.json")],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            success("TLS analysis completed")


def directory_fuzzing() -> None:
    """Perform directory fuzzing."""
    log("Step 6 - Directory and content fuzzing")

    if not ALIVE_SUBDOMAINS.exists():
        warning("Alive subdomains file not found")
        return

    if run_tool("ffuf"):
        log("Running ffuf for directory discovery")
        with open(ALIVE_SUBDOMAINS, "r", encoding="utf-8") as f:
            for url in f:
                url = url.strip()
                if url:
                    output_file = FUZZ_DIR / f"ffuf_{url.replace('://', '_').replace('/', '_')}.txt"
                    result = subprocess.run(
                        ["ffuf", "-u", f"{url}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-o", str(output_file)],
                        capture_output=True,
                        text=True,
                    )

    if run_tool("feroxbuster"):
        log("Running feroxbuster")
        with open(ALIVE_SUBDOMAINS, "r", encoding="utf-8") as f:
            for url in f:
                url = url.strip()
                if url:
                    output_file = FUZZ_DIR / f"feroxbuster_{url.replace('://', '_').replace('/', '_')}.json"
                    result = subprocess.run(
                        ["feroxbuster", "-u", url, "--json", "-o", str(output_file)],
                        capture_output=True,
                        text=True,
                    )


def url_collection() -> None:
    """Collect URLs from various sources."""
    log("Step 7 - URL collection from historical data")

    if run_tool("gau"):
        log("Running gau")
        with open(URL_DIR / "gau.txt", "w", encoding="utf-8") as f:
            result = subprocess.run(["gau", TARGET], stdout=f, stderr=subprocess.STDOUT, text=True)

    if run_tool("waybackurls"):
        log("Running waybackurls")
        with open(URL_DIR / "waybackurls.txt", "w", encoding="utf-8") as f:
            result = subprocess.run(["waybackurls", TARGET], stdout=f, stderr=subprocess.STDOUT, text=True)

    if run_tool("katana"):
        log("Running katana for crawling")
        result = subprocess.run(
            ["katana", "-u", f"https://{TARGET}", "-jc", "-json", "-o", str(URL_DIR / "katana.json")],
            capture_output=True,
            text=True,
        )

    if run_tool("hakrawler"):
        log("Running hakrawler")
        with open(URL_DIR / "hakrawler.txt", "w", encoding="utf-8") as f:
            result = subprocess.run(
                ["hakrawler", "-u", f"https://{TARGET}", "-subs"],
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
            )

    # Combine all URLs
    all_urls = set()
    for file in [URL_DIR / "gau.txt", URL_DIR / "waybackurls.txt", URL_DIR / "hakrawler.txt"]:
        if file.exists():
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                all_urls.update(line.strip() for line in f if line.strip())

    if all_urls:
        with open(ALL_URLS, "w", encoding="utf-8") as f:
            for url in sorted(all_urls):
                f.write(url + "\n")
        success(f"Collected {len(all_urls)} unique URLs")


def parameter_discovery() -> None:
    """Discover parameters in URLs."""
    log("Step 8 - Parameter discovery")

    if not ALL_URLS.exists():
        warning("URL file not found")
        return

    if run_tool("paramspider"):
        log("Running ParamSpider")
        result = subprocess.run(
            ["paramspider", "-d", TARGET, "-l", str(PARAM_DIR / "paramspider.txt")],
            capture_output=True,
            text=True,
        )

    if run_tool("arjun"):
        log("Running Arjun")
        with open(ALL_URLS, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()][:10]  # Limit to first 10 for speed

        for url in urls:
            output_file = PARAM_DIR / f"arjun_{url.replace('://', '_').replace('/', '_')}.txt"
            result = subprocess.run(
                ["arjun", "-u", url, "-o", str(output_file)],
                capture_output=True,
                text=True,
            )


def api_enumeration() -> None:
    """Enumerate API endpoints."""
    log("Step 9 - API endpoint discovery")

    API_DIR = SCAN_DIR / "api_endpoints"
    API_DIR.mkdir(parents=True, exist_ok=True)

    if run_tool("kiterunner"):
        log("Running kiterunner")
        wordlist_path = Path.home() / ".kiterunner" / "wordlists" / "api.txt"
        if wordlist_path.exists():
            run_cmd(
                "Running kiterunner",
                "kr",
                "scan",
                f"https://{TARGET}",
                "-w",
                str(wordlist_path),
                "-o",
                str(API_DIR / "kiterunner.json"),
            )
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
    """Detect CMS using CMSeeK."""
    log("Step 13 - CMS detection")

    if run_tool("cmseek"):
        # CMSeeK is a Python script, so we need to call it with python3
        log("Running cmseek for CMS detection")
        WAF_DIR.mkdir(parents=True, exist_ok=True)
        
        try:
            # Try calling cmseek directly first
            result = subprocess.run(
                ["cmseek", "-u", f"https://{TARGET}", "--batch", "--output-dir", str(WAF_DIR / "cmseek")],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                success("cmseek completed")
            else:
                warning(f"cmseek returned error code {result.returncode}")
        except (FileNotFoundError, OSError) as e:
            # If direct execution fails, try with python3
            log("Attempting to run cmseek with python3")
            try:
                # Find cmseek installation path
                cmseek_path = shutil.which("cmseek.py")
                if cmseek_path:
                    result = subprocess.run(
                        ["python3", cmseek_path, "-u", f"https://{TARGET}", "--batch", "--output-dir", str(WAF_DIR / "cmseek")],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    if result.returncode == 0:
                        success("cmseek completed")
                    else:
                        warning(f"cmseek returned error code {result.returncode}")
                else:
                    # Try calling the module
                    result = subprocess.run(
                        ["python3", "-m", "cmseek", "-u", f"https://{TARGET}", "--batch", "--output-dir", str(WAF_DIR / "cmseek")],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    if result.returncode == 0:
                        success("cmseek completed")
                    else:
                        warning(f"cmseek returned error code {result.returncode}")
            except Exception as e2:
                error(f"Failed to run cmseek: {e2}")
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
            f"https://{TARGET}/.git",
            f"https://{TARGET}/.gitignore",
            f"https://{TARGET}/.github",
        ]

        for url in urls:
            result = subprocess.run(
                ["httpx", "-u", url, "-status-code", "-o", str(SECRET_DIR / f"git_{url.split('/')[-1]}.txt")],
                capture_output=True,
                text=True,
            )


def secret_scanning() -> None:
    """Scan for exposed secrets."""
    log("Step 16 - Secret scanning")

    if not ALL_URLS.exists():
        warning("URL file not found")
        return

    if run_tool("gitleaks"):
        log("Running gitleaks")
        result = subprocess.run(
            ["gitleaks", "detect", "-s", TARGET, "-o", str(SECRET_DIR / "gitleaks.json")],
            capture_output=True,
            text=True,
        )


def cloud_enum() -> None:
    """Enumerate cloud storage."""
    log("Step 17 - Cloud storage enumeration")

    if run_tool("cloud_enum"):
        log("Running cloud_enum")
        result = subprocess.run(
            ["cloud_enum", "-k", TARGET, "-o", str(CLOUD_DIR / "cloud_enum.txt")],
            capture_output=True,
            text=True,
        )

    if run_tool("s3scanner"):
        log("Running s3scanner")
        result = subprocess.run(
            ["s3scanner", "-bucket", TARGET, "-o", str(CLOUD_DIR / "s3scanner.txt")],
            capture_output=True,
            text=True,
        )

    if run_tool("slurp"):
        log("Running slurp")
        result = subprocess.run(
            ["slurp", "-domain", TARGET, "-output", str(CLOUD_DIR / "slurp.txt")],
            capture_output=True,
            text=True,
        )


def generate_report() -> None:
    """Generate final report."""
    log("Generating final report")

    report_path = SCAN_DIR / "REPORT.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Bug Bounty Reconnaissance Report\n")
        f.write(f"## Target: {TARGET}\n")
        f.write(f"## Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write(f"## Results Summary\n\n")

        # Count results
        if ALL_SUBDOMAINS.exists():
            with open(ALL_SUBDOMAINS, "r", encoding="utf-8") as rf:
                subdomain_count = len(rf.readlines())
            f.write(f"- **Subdomains Found**: {subdomain_count}\n")

        if ALIVE_SUBDOMAINS.exists():
            with open(ALIVE_SUBDOMAINS, "r", encoding="utf-8") as rf:
                alive_count = len(rf.readlines())
            f.write(f"- **Alive Subdomains**: {alive_count}\n")

        if ALL_URLS.exists():
            with open(ALL_URLS, "r", encoding="utf-8") as rf:
                url_count = len(rf.readlines())
            f.write(f"- **URLs Collected**: {url_count}\n")

        f.write(f"\n## Output Directory\n")
        f.write(f"Results saved to: {SCAN_DIR}\n")

    success(f"Report generated: {report_path}")
    print(f"\n{CYAN}{'='*80}{NC}")
    print(f"{GREEN}Scan completed!{NC}")
    print(f"{CYAN}{'='*80}{NC}")
    print(f"Results: {SCAN_DIR}\n")


def check_tools() -> None:
    """Check status of all tools."""
    import tool_manager
    tool_manager.show_tool_status()


def main() -> int:
    """Main function."""
    global TARGET, SCAN_DIR, RECON_DIR, DNS_DIR, HTTP_DIR, SCAN_RESULTS_DIR
    global FUZZ_DIR, URL_DIR, PARAM_DIR, VULN_DIR, WAF_DIR, SECRET_DIR, CLOUD_DIR
    global ALL_URLS, ALL_SUBDOMAINS, ALIVE_SUBDOMAINS

    parser = argparse.ArgumentParser(description="Automated Bug Bounty Reconnaissance Script")
    parser.add_argument("target", nargs="?", help="Target domain")
    parser.add_argument("--check", action="store_true", help="Check tool installation status")
    parser.add_argument("--check-update", action="store_true", help="Check for script updates")
    parser.add_argument("--update", action="store_true", help="Update script from GitHub")
    parser.add_argument("--help-tools", action="store_true", help="Show tool management help")

    args = parser.parse_args()

    # Handle special commands
    if args.check:
        check_tools()
        return 0

    if args.check_update:
        check_update()
        return 0

    if args.update:
        download_update()
        return 0

    if args.help_tools:
        os.system("python3 tool_manager.py --help")
        return 0

    if not args.target:
        parser.print_help()
        return 1

    TARGET = args.target.replace("https://", "").replace("http://", "").rstrip("/")

    # Create scan directories
    SCAN_DIR.mkdir(parents=True, exist_ok=True)
    RECON_DIR.mkdir(parents=True, exist_ok=True)
    DNS_DIR.mkdir(parents=True, exist_ok=True)
    HTTP_DIR.mkdir(parents=True, exist_ok=True)
    SCAN_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FUZZ_DIR.mkdir(parents=True, exist_ok=True)
    URL_DIR.mkdir(parents=True, exist_ok=True)
    PARAM_DIR.mkdir(parents=True, exist_ok=True)
    VULN_DIR.mkdir(parents=True, exist_ok=True)
    WAF_DIR.mkdir(parents=True, exist_ok=True)
    SECRET_DIR.mkdir(parents=True, exist_ok=True)
    CLOUD_DIR.mkdir(parents=True, exist_ok=True)

    print()
    print(f"{CYAN}{'='*80}{NC}")
    print(f"{CYAN}              BUG BOUNTY RECONNAISSANCE AUTOMATION{NC}")
    print(f"{CYAN}{'='*80}{NC}")
    print()
    print(f"Target: {GREEN}{TARGET}{NC}")
    print(f"Output: {GREEN}{SCAN_DIR}{NC}")
    print()

    try:
        subdomain_enumeration()
        dns_resolution()
        http_probing()
        port_scanning()
        tls_analysis()
        directory_fuzzing()
        url_collection()
        parameter_discovery()
        api_enumeration()
        security_headers()
        waf_detection()
        cms_detection()
        interesting_urls()
        git_exposure_check()
        secret_scanning()
        cloud_enum()
        generate_report()

        return 0

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        return 130
    except Exception as e:
        error(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
        raise SystemExit(130)
