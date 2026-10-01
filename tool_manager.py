#!/usr/bin/env python3

"""
Bug Hunter - Tool Management and Installation
Lists all tools required by the recon script and provides installation support.

Usage:
  python3 tool_manager.py --list              List all tools
  python3 tool_manager.py --check             Check installed tools
  python3 tool_manager.py --install <tool>   Install specific tool
  python3 tool_manager.py --install-all      Install all tools
  python3 tool_manager.py --help              Show help
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Tuple

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
NC = "\033[0m"

# Tools database with installation commands
TOOLS = {
    "subfinder": {
        "description": "Subdomain enumeration tool",
        "category": "Reconnaissance",
        "status": "essential",
        "install_cmd": [
            "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "Manual: https://github.com/projectdiscovery/subfinder"
        ],
        "check_cmd": "subfinder"
    },
    "amass": {
        "description": "In-depth subdomain enumeration",
        "category": "Reconnaissance",
        "status": "essential",
        "install_cmd": [
            "go install -v github.com/owasp-amass/amass/v5/cmd/amass@main",
            "Manual: https://github.com/OWASP/Amass"
        ],
        "check_cmd": "amass"
    },
    "assetfinder": {
        "description": "Find domains and subdomains",
        "category": "Reconnaissance",
        "status": "essential",
        "install_cmd": [
            "go install github.com/tomnomnom/assetfinder@latest",
            "Manual: https://github.com/tomnomnom/assetfinder"
        ],
        "check_cmd": "assetfinder"
    },
    "alterx": {
        "description": "Alternative subdomain discovery tool",
        "category": "Reconnaissance",
        "status": "important",
        "install_cmd": [
            "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest",
            "Manual: https://github.com/projectdiscovery/alterx"
        ],
        "check_cmd": "alterx"
    },
    "dnsx": {
        "description": "DNS resolution and probing",
        "category": "DNS",
        "status": "important",
        "install_cmd": [
            "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "Manual: https://github.com/projectdiscovery/dnsx"
        ],
        "check_cmd": "dnsx"
    },
    "puredns": {
        "description": "DNS resolution and subdomain enumeration",
        "category": "DNS",
        "status": "important",
        "install_cmd": [
            "go install github.com/d3mondev/puredns/v2@latest",
            "Manual: https://github.com/d3mondev/puredns"
        ],
        "check_cmd": "puredns"
    },
    "hakrevdns": {
        "description": "Reverse DNS lookup tool",
        "category": "DNS",
        "status": "important",
        "install_cmd": [
            "go install github.com/hakluke/hakrevdns@latest",
            "Manual: https://github.com/hakluke/hakrevdns"
        ],
        "check_cmd": "hakrevdns"
    },
    "httpx": {
        "description": "HTTP probing and fingerprinting",
        "category": "HTTP",
        "status": "essential",
        "install_cmd": [
            "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "Manual: https://github.com/projectdiscovery/httpx"
        ],
        "check_cmd": "httpx"
    },
    "tlsx": {
        "description": "TLS certificate enumeration and probing",
        "category": "HTTP",
        "status": "important",
        "install_cmd": [
            "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
            "Manual: https://github.com/projectdiscovery/tlsx"
        ],
        "check_cmd": "tlsx"
    },
    "nmap": {
        "description": "Network scanning and enumeration",
        "category": "Scanning",
        "status": "essential",
        "install_cmd": [
            "apt-get install nmap -y  # Debian/Ubuntu",
            "brew install nmap        # macOS",
            "yum install nmap -y      # RHEL/CentOS",
            "Manual: https://nmap.org"
        ],
        "check_cmd": "nmap"
    },
    "masscan": {
        "description": "Fast port scanner",
        "category": "Scanning",
        "status": "important",
        "install_cmd": [
            "apt-get install masscan -y  # Debian/Ubuntu",
            "brew install masscan        # macOS",
            "Manual: https://github.com/robertdavidgraham/masscan"
        ],
        "check_cmd": "masscan"
    },
    "asnmap": {
        "description": "ASN/IP mapping and enumeration",
        "category": "Scanning",
        "status": "important",
        "install_cmd": [
            "go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
            "Manual: https://github.com/projectdiscovery/asnmap"
        ],
        "check_cmd": "asnmap"
    },
    "mapcidr": {
        "description": "CIDR and IP range mapping",
        "category": "Scanning",
        "status": "important",
        "install_cmd": [
            "go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
            "Manual: https://github.com/projectdiscovery/mapcidr"
        ],
        "check_cmd": "mapcidr"
    },
    "ffuf": {
        "description": "Fuzzing framework for directory discovery",
        "category": "Fuzzing",
        "status": "essential",
        "install_cmd": [
            "go install github.com/ffuf/ffuf@latest",
            "Manual: https://github.com/ffuf/ffuf"
        ],
        "check_cmd": "ffuf"
    },
    "gobuster": {
        "description": "Directory/DNS/VHost enumeration",
        "category": "Fuzzing",
        "status": "essential",
        "install_cmd": [
            "go install github.com/OJ/gobuster/v3@latest",
            "Manual: https://github.com/OJ/gobuster"
        ],
        "check_cmd": "gobuster"
    },
    "feroxbuster": {
        "description": "Fast web content discovery tool",
        "category": "Fuzzing",
        "status": "important",
        "install_cmd": [
            "cargo install feroxbuster",
            "Manual: https://github.com/epi052/feroxbuster"
        ],
        "check_cmd": "feroxbuster"
    },
    "gf": {
        "description": "Grep patterns for filtering and searching",
        "category": "Fuzzing",
        "status": "important",
        "install_cmd": [
            "go install github.com/tomnomnom/gf@latest",
            "Manual: https://github.com/tomnomnom/gf"
        ],
        "check_cmd": "gf"
    },
    "gau": {
        "description": "Get all URLs from Wayback Machine, Common Crawl, Alien Vault",
        "category": "URL Collection",
        "status": "important",
        "install_cmd": [
            "go install github.com/lc/gau/v2/cmd/gau@latest",
            "Manual: https://github.com/lc/gau"
        ],
        "check_cmd": "gau"
    },
    "waybackurls": {
        "description": "Fetch all URLs from Wayback Machine",
        "category": "URL Collection",
        "status": "important",
        "install_cmd": [
            "go install github.com/tomnomnom/waybackurls@latest",
            "Manual: https://github.com/tomnomnom/waybackurls"
        ],
        "check_cmd": "waybackurls"
    },
    "hakrawler": {
        "description": "Web crawler for discovering URLs and parameters",
        "category": "URL Collection",
        "status": "important",
        "install_cmd": [
            "go install github.com/hakluke/hakrawler@latest",
            "Manual: https://github.com/hakluke/hakrawler"
        ],
        "check_cmd": "hakrawler"
    },
    "katana": {
        "description": "Advanced web crawler and parameter discovery",
        "category": "URL Collection",
        "status": "important",
        "install_cmd": [
            "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "Manual: https://github.com/projectdiscovery/katana"
        ],
        "check_cmd": "katana"
    },
    "unfurl": {
        "description": "URL parsing and extraction tool",
        "category": "URL Collection",
        "status": "important",
        "install_cmd": [
            "go install github.com/tomnomnom/unfurl@latest",
            "Manual: https://github.com/tomnomnom/unfurl"
        ],
        "check_cmd": "unfurl"
    },
    "eyewitness": {
        "description": "Web application screenshot tool",
        "category": "Screenshots",
        "status": "optional",
        "install_cmd": [
            "pip3 install eyewitness",
            "git clone https://github.com/RedSiege/EyeWitness.git",
            "cd EyeWitness && pip3 install -r requirements.txt"
        ],
        "check_cmd": "eyewitness"
    },
    "aquatone": {
        "description": "Subdomain takeover and screenshot tool",
        "category": "Screenshots",
        "status": "optional",
        "install_cmd": [
            "go install github.com/michenriksen/aquatone@latest",
            "Manual: https://github.com/michenriksen/aquatone"
        ],
        "check_cmd": "aquatone"
    },
    "paramspider": {
        "description": "Parameter discovery tool",
        "category": "Parameters",
        "status": "important",
        "install_cmd": [
            "pip3 install paramspider",
            "git clone https://github.com/0xJs/ParamSpider.git",
            "cd ParamSpider && pip3 install -r requirements.txt"
        ],
        "check_cmd": "paramspider"
    },
    "arjun": {
        "description": "HTTP parameter discovery",
        "category": "Parameters",
        "status": "important",
        "install_cmd": [
            "pip3 install arjun",
            "git clone https://github.com/s0md3v/Arjun.git",
            "cd Arjun && pip3 install -r requirements.txt"
        ],
        "check_cmd": "arjun"
    },
    "kiterunner": {
        "description": "API endpoint discovery",
        "category": "API",
        "status": "important",
        "install_cmd": [
            "go install github.com/assetnote/kiterunner@latest",
            "Manual: https://github.com/assetnote/kiterunner"
        ],
        "check_cmd": "kr"
    },
    "nikto": {
        "description": "Web server vulnerability scanner",
        "category": "Vulnerabilities",
        "status": "important",
        "install_cmd": [
            "apt-get install nikto -y  # Debian/Ubuntu",
            "brew install nikto        # macOS",
            "Manual: https://github.com/sullo/nikto"
        ],
        "check_cmd": "nikto"
    },
    "wafw00f": {
        "description": "WAF detection tool",
        "category": "WAF Detection",
        "status": "important",
        "install_cmd": [
            "pip3 install wafw00f",
            "git clone https://github.com/EnableSecurity/wafw00f.git",
            "cd wafw00f && pip3 install -r requirements.txt"
        ],
        "check_cmd": "wafw00f"
    },
    "cmseek": {
        "description": "CMS detection and fingerprinting",
        "category": "CMS Detection",
        "status": "optional",
        "install_cmd": [
            "git clone https://github.com/Tuhinshubhra/CMSeeK.git",
            "cd CMSeeK && pip3 install -r requirements.txt",
            "python3 cmseek.py --help"
        ],
        "check_cmd": "cmseek"
    },
    "gitleaks": {
        "description": "Secret scanning tool for Git repositories",
        "category": "Secret Scanning",
        "status": "important",
        "install_cmd": [
            "go install github.com/gitleaks/gitleaks/v8@latest",
            "Manual: https://github.com/gitleaks/gitleaks"
        ],
        "check_cmd": "gitleaks"
    },
    "cloud_enum": {
        "description": "Cloud storage enumeration tool",
        "category": "Cloud",
        "status": "important",
        "install_cmd": [
            "pip3 install cloud-enum",
            "git clone https://github.com/initstring/cloud_enum.git",
            "cd cloud_enum && pip3 install -r requirements.txt"
        ],
        "check_cmd": "cloud_enum"
    },
    "slurp": {
        "description": "AWS S3 bucket finder and enumerator",
        "category": "Cloud",
        "status": "important",
        "install_cmd": [
            "go install github.com/0xsha/slurp@latest",
            "Manual: https://github.com/0xsha/slurp"
        ],
        "check_cmd": "slurp"
    },
    "s3scanner": {
        "description": "AWS S3 bucket scanner",
        "category": "Cloud",
        "status": "important",
        "install_cmd": [
            "go install -v github.com/sa7mon/s3scanner@latest",
            "sudo cp /root/go/bin/s3scanner /usr/bin"
        ],
        "check_cmd": "s3scanner"
    },
    "metabigor": {
        "description": "Gather metadata from public sources",
        "category": "OSINT",
        "status": "important",
        "install_cmd": [
            "go install -v github.com/j3ssie/metabigor@latest",
            "Manual: https://github.com/j3ssie/metabigor"
        ],
        "check_cmd": "metabigor"
    }
}

# Tools grouped by category
CATEGORIES = {
    "Reconnaissance": ["subfinder", "amass", "assetfinder", "alterx"],
    "DNS": ["dnsx", "puredns", "hakrevdns"],
    "HTTP": ["httpx", "tlsx"],
    "Scanning": ["nmap", "masscan", "asnmap", "mapcidr"],
    "Fuzzing": ["ffuf", "gobuster", "feroxbuster", "gf"],
    "URL Collection": ["gau", "waybackurls", "hakrawler", "katana", "unfurl"],
    "Screenshots": ["eyewitness", "aquatone"],
    "Parameters": ["paramspider", "arjun"],
    "API": ["kiterunner"],
    "Vulnerabilities": ["nikto"],
    "WAF Detection": ["wafw00f"],
    "CMS Detection": ["cmseek"],
    "Secret Scanning": ["gitleaks"],
    "Cloud": ["cloud_enum", "slurp", "s3scanner"],
    "OSINT": ["metabigor"]
}


def log(message: str) -> None:
    print(f"{BLUE}[*]{NC} {message}")


def success(message: str) -> None:
    print(f"{GREEN}[+]{NC} {message}")


def warning(message: str) -> None:
    print(f"{YELLOW}[!]{NC} {message}")


def error(message: str) -> None:
    print(f"{RED}[-]{NC} {message}")


def is_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed using shutil.which()."""
    if tool_name not in TOOLS:
        return False
    
    tool_cmd = TOOLS[tool_name]["check_cmd"]
    # Use shutil.which() to check if the tool exists in PATH
    return shutil.which(tool_cmd) is not None


def check_all_tools() -> Dict[str, Dict]:
    """Check status of all tools."""
    results = {}
    for tool_name in TOOLS:
        installed = is_tool_installed(tool_name)
        results[tool_name] = {
            "installed": installed,
            "info": TOOLS[tool_name]
        }
    return results


def list_all_tools() -> None:
    """List all tools in a formatted way."""
    print()
    print(f"{CYAN}{'='*80}{NC}")
    print(f"{CYAN}                    BUG HUNTER - TOOLS LIST                      {NC}")
    print(f"{CYAN}{'='*80}{NC}")
    print()
    
    for category, tool_list in CATEGORIES.items():
        print(f"{CYAN}[{category}]{NC}")
        print(f"{'-'*80}")
        
        for tool in tool_list:
            info = TOOLS[tool]
            status_badge = f"{GREEN}[ESSENTIAL]{NC}" if info["status"] == "essential" else \
                           f"{YELLOW}[IMPORTANT]{NC}" if info["status"] == "important" else \
                           f"{BLUE}[OPTIONAL]{NC}"
            
            print(f"  {status_badge} {tool:<20} - {info['description']}")
        print()


def show_tool_status() -> None:
    """Show installation status of all tools."""
    print()
    print(f"{CYAN}{'='*80}{NC}")
    print(f"{CYAN}                  TOOL STATUS CHECK                           {NC}")
    print(f"{CYAN}{'='*80}{NC}")
    print()
    
    status_data = check_all_tools()
    
    # Summary counts
    installed_count = sum(1 for v in status_data.values() if v["installed"])
    total_count = len(status_data)
    missing_count = total_count - installed_count
    
    print(f"Total Tools: {total_count} | Installed: {GREEN}{installed_count}{NC} | Missing: {RED}{missing_count}{NC}")
    print()
    
    print(f"{CYAN}[INSTALLED TOOLS]{NC}")
    print(f"{'-'*80}")
    for tool_name, data in sorted(status_data.items()):
        if data["installed"]:
            status_badge = f"{GREEN}[✓]{NC}" if data["info"]["status"] == "essential" else \
                           f"{GREEN}[✓]{NC}" if data["info"]["status"] == "important" else \
                           f"{GREEN}[✓]{NC}"
            print(f"  {status_badge} {tool_name:<20} - {data['info']['description']}")
    print()
    
    print(f"{CYAN}[MISSING TOOLS]{NC}")
    print(f"{'-'*80}")
    for tool_name, data in sorted(status_data.items()):
        if not data["installed"]:
            status_badge = f"{RED}[✗ ESSENTIAL]{NC}" if data["info"]["status"] == "essential" else \
                           f"{YELLOW}[✗ IMPORTANT]{NC}" if data["info"]["status"] == "important" else \
                           f"{BLUE}[✗ OPTIONAL]{NC}"
            print(f"  {status_badge} {tool_name:<20} - {data['info']['description']}")
    print()


def show_tool_details(tool_name: str) -> None:
    """Show detailed information about a specific tool."""
    if tool_name not in TOOLS:
        error(f"Tool '{tool_name}' not found.")
        return
    
    tool = TOOLS[tool_name]
    installed = is_tool_installed(tool_name)
    
    print()
    print(f"{CYAN}{'='*80}{NC}")
    print(f"{CYAN}TOOL: {tool_name}{NC}")
    print(f"{CYAN}{'='*80}{NC}")
    print()
    
    status_icon = f"{GREEN}[INSTALLED]{NC}" if installed else f"{RED}[NOT INSTALLED]{NC}"
    print(f"Status:      {status_icon}")
    print(f"Description: {tool['description']}")
    print(f"Category:    {tool['category']}")
    print(f"Priority:    {tool['status'].upper()}")
    print()
    
    print(f"{CYAN}Installation Methods:{NC}")
    for i, cmd in enumerate(tool["install_cmd"], 1):
        print(f"  {i}. {cmd}")
    print()
    
    print(f"{CYAN}Verification Command:{NC}")
    print(f"  {tool['check_cmd']}")
    print()


def install_tool(tool_name: str) -> bool:
    """Install a specific tool."""
    if tool_name not in TOOLS:
        error(f"Tool '{tool_name}' not found.")
        return False
    
    if is_tool_installed(tool_name):
        success(f"{tool_name} is already installed.")
        return True
    
    tool = TOOLS[tool_name]
    print()
    print(f"{CYAN}Installing {tool_name}...{NC}")
    print()
    
    show_tool_details(tool_name)
    
    print(f"{YELLOW}INSTALLATION INSTRUCTIONS:{NC}")
    print()
    print(f"Please use one of the following methods to install {tool_name}:")
    print()
    for i, cmd in enumerate(tool["install_cmd"], 1):
        print(f"{YELLOW}Method {i}:{NC}")
        print(f"  {cmd}")
        print()
    
    print(f"{YELLOW}After installation, verify with:{NC}")
    print(f"  {tool['check_cmd']}")
    print()
    
    # Try automatic installation if it's a simple pip or apt command
    if tool["install_cmd"][0].startswith("pip3 install"):
        try:
            warning("Attempting automatic pip installation...")
            subprocess.run(tool["install_cmd"][0], shell=True, check=True)
            if is_tool_installed(tool_name):
                success(f"{tool_name} installed successfully!")
                return True
        except subprocess.CalledProcessError:
            warning("Automatic installation failed. Please install manually using commands above.")
            return False
    
    return False


def create_installation_guide() -> None:
    """Create a comprehensive installation guide file."""
    guide_path = Path.home() / ".bug-hunter" / "INSTALLATION_GUIDE.md"
    guide_path.parent.mkdir(parents=True, exist_ok=True)
    
    content = """# Bug Hunter - Tools Installation Guide

This guide provides installation instructions for all tools used by Bug Hunter.

## Prerequisites

### Required Software
- Python 3.7+
- Go 1.16+ (for most tools)
- Git
- curl/wget
- Rust/Cargo (for feroxbuster)

### Installation on Different Systems

#### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip golang-go git curl build-essential
```

#### macOS
```bash
brew install python go git curl
```

#### RHEL/CentOS
```bash
sudo yum install -y python3 python3-pip golang git curl
```

## Tool Installation

For detailed installation instructions, run:

```bash
python3 tool_manager.py --info <tool-name>
python3 tool_manager.py --guide
```

## Verification

To check all installed tools:

```bash
python3 tool_manager.py --check
```

To list all available tools:

```bash
python3 tool_manager.py --list
```

To view installation details for a specific tool:

```bash
python3 tool_manager.py --info <tool-name>
```

## Troubleshooting

### Go Installation Issues
Make sure Go is in your PATH:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Add to your `.bashrc` or `.zshrc` for permanent effect.

### Python Tool Issues
Update pip:
```bash
pip3 install --upgrade pip
```

### Rust/Cargo Issues (for feroxbuster)
Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Support

For tool-specific issues, refer to:
- Official GitHub repositories
- Tool documentation
- Community forums
"""
    
    guide_path.write_text(content, encoding="utf-8")
    success(f"Installation guide created: {guide_path}")


def show_help() -> None:
    """Display help message."""
    print()
    print("Bug Hunter - Tool Management Utility")
    print()
    print("USAGE:")
    print("  python3 tool_manager.py [OPTION]")
    print()
    print("OPTIONS:")
    print("  --list              List all available tools")
    print("  --check             Check installation status of all tools")
    print("  --info <tool>       Show detailed info about a specific tool")
    print("  --install <tool>    Install a specific tool")
    print("  --install-all       Instructions for installing all tools")
    print("  --guide             Create detailed installation guide")
    print("  --help              Show this help message")
    print()
    print("EXAMPLES:")
    print("  python3 tool_manager.py --list")
    print("  python3 tool_manager.py --check")
    print("  python3 tool_manager.py --info subfinder")
    print("  python3 tool_manager.py --install katana")
    print("  python3 tool_manager.py --guide")
    print()


def main() -> int:
    """Main function."""
    if len(sys.argv) < 2:
        show_help()
        return 1
    
    command = sys.argv[1].lower()
    
    if command in ["--help", "-h"]:
        show_help()
        return 0
    
    elif command in ["--list", "-l"]:
        list_all_tools()
        return 0
    
    elif command in ["--check", "-c"]:
        show_tool_status()
        return 0
    
    elif command in ["--info", "-i"]:
        if len(sys.argv) < 3:
            error("Please specify a tool name")
            return 1
        show_tool_details(sys.argv[2])
        return 0
    
    elif command in ["--install"]:
        if len(sys.argv) < 3:
            error("Please specify a tool name or 'all'")
            return 1
        if sys.argv[2].lower() == "all":
            print()
            print(f"{CYAN}Installation Guide for All Tools:{NC}")
            print()
            create_installation_guide()
            return 0
        else:
            install_tool(sys.argv[2])
            return 0
    
    elif command in ["--install-all", "--install-guide"]:
        print()
        print(f"{CYAN}Installation Guide for All Tools:{NC}")
        print()
        for tool_name in sorted(TOOLS.keys()):
            show_tool_details(tool_name)
        return 0
    
    elif command == "--guide":
        create_installation_guide()
        return 0
    
    else:
        error(f"Unknown command: {command}")
        show_help()
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        raise SystemExit(130)
