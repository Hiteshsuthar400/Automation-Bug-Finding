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
        "check_cmd": "subfinder --version"
    },
    "amass": {
        "description": "In-depth subdomain enumeration",
        "category": "Reconnaissance",
        "status": "essential",
        "install_cmd": [
            "go install -v github.com/OWASP/Amass/v3/...@master",
            "Manual: https://github.com/OWASP/Amass"
        ],
        "check_cmd": "amass -version"
    },
    "assetfinder": {
        "description": "Find domains and subdomains",
        "category": "Reconnaissance",
        "status": "essential",
        "install_cmd": [
            "go install github.com/tomnomnom/assetfinder@latest",
            "Manual: https://github.com/tomnomnom/assetfinder"
        ],
        "check_cmd": "assetfinder --help"
    },
    "dnsx": {
        "description": "DNS resolution and probing",
        "category": "DNS",
        "status": "important",
        "install_cmd": [
            "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "Manual: https://github.com/projectdiscovery/dnsx"
        ],
        "check_cmd": "dnsx --version"
    },
    "httpx": {
        "description": "HTTP probing and fingerprinting",
        "category": "HTTP",
        "status": "essential",
        "install_cmd": [
            "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "Manual: https://github.com/projectdiscovery/httpx"
        ],
        "check_cmd": "httpx --help"
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
        "check_cmd": "nmap --version"
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
        "check_cmd": "masscan --version"
    },
    "ffuf": {
        "description": "Fuzzing framework for directory discovery",
        "category": "Fuzzing",
        "status": "essential",
        "install_cmd": [
            "go install github.com/ffuf/ffuf@latest",
            "Manual: https://github.com/ffuf/ffuf"
        ],
        "check_cmd": "ffuf -h"
    },
    "gobuster": {
        "description": "Directory/DNS/VHost enumeration",
        "category": "Fuzzing",
        "status": "essential",
        "install_cmd": [
            "go install github.com/OJ/gobuster/v3@latest",
            "Manual: https://github.com/OJ/gobuster"
        ],
        "check_cmd": "gobuster version"
    },
    "gau": {
        "description": "Get all URLs from Wayback Machine, Common Crawl, Alien Vault",
        "category": "URL Collection",
        "status": "important",
        "install_cmd": [
            "go install github.com/lc/gau/v2/cmd/gau@latest",
            "Manual: https://github.com/lc/gau"
        ],
        "check_cmd": "gau --version"
    },
    "waybackurls": {
        "description": "Fetch all URLs from Wayback Machine",
        "category": "URL Collection",
        "status": "important",
        "install_cmd": [
            "go install github.com/tomnomnom/waybackurls@latest",
            "Manual: https://github.com/tomnomnom/waybackurls"
        ],
        "check_cmd": "waybackurls --help"
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
        "check_cmd": "eyewitness --help"
    },
    "aquatone": {
        "description": "Subdomain takeover and screenshot tool",
        "category": "Screenshots",
        "status": "optional",
        "install_cmd": [
            "go install github.com/michenriksen/aquatone@latest",
            "Manual: https://github.com/michenriksen/aquatone"
        ],
        "check_cmd": "aquatone --version"
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
        "check_cmd": "paramspider --help"
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
        "check_cmd": "arjun --help"
    },
    "kiterunner": {
        "description": "API endpoint discovery",
        "category": "API",
        "status": "important",
        "install_cmd": [
            "go install github.com/assetnote/kiterunner@latest",
            "Manual: https://github.com/assetnote/kiterunner"
        ],
        "check_cmd": "kr --help"
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
        "check_cmd": "nikto --version"
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
        "check_cmd": "wafw00f --version"
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
        "check_cmd": "cmseek --help"
    }
}

# Tools grouped by category
CATEGORIES = {
    "Reconnaissance": ["subfinder", "amass", "assetfinder"],
    "DNS": ["dnsx"],
    "HTTP": ["httpx"],
    "Scanning": ["nmap", "masscan"],
    "Fuzzing": ["ffuf", "gobuster"],
    "URL Collection": ["gau", "waybackurls"],
    "Screenshots": ["eyewitness", "aquatone"],
    "Parameters": ["paramspider", "arjun"],
    "API": ["kiterunner"],
    "Vulnerabilities": ["nikto"],
    "WAF Detection": ["wafw00f"],
    "CMS Detection": ["cmseek"]
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
    """Check if a tool is installed."""
    if tool_name not in TOOLS:
        return False
    
    check_cmd = TOOLS[tool_name]["check_cmd"]
    try:
        result = subprocess.run(
            check_cmd,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


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

### Installation on Different Systems

#### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip golang-go git curl
```

#### macOS
```bash
brew install python go git curl
```

#### RHEL/CentOS
```bash
sudo yum install -y python3 python3-pip golang git curl
```

## Essential Tools

### 1. subfinder
Subdomain enumeration tool by ProjectDiscovery.

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

**Verification:**
```bash
subfinder --version
```

---

### 2. amass
In-depth subdomain enumeration by OWASP.

```bash
go install -v github.com/OWASP/Amass/v3/...@master
```

**Verification:**
```bash
amass -version
```

---

### 3. assetfinder
Find domains and subdomains.

```bash
go install github.com/tomnomnom/assetfinder@latest
```

**Verification:**
```bash
assetfinder --help
```

---

### 4. httpx
HTTP probing and fingerprinting tool.

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**Verification:**
```bash
httpx --version
```

---

### 5. nmap
Network scanning and enumeration.

**Debian/Ubuntu:**
```bash
sudo apt-get install nmap
```

**macOS:**
```bash
brew install nmap
```

**Verification:**
```bash
nmap --version
```

---

### 6. ffuf
Fuzzing framework for directory discovery.

```bash
go install github.com/ffuf/ffuf@latest
```

**Verification:**
```bash
ffuf -h
```

---

### 7. gobuster
Directory/DNS/VHost enumeration.

```bash
go install github.com/OJ/gobuster/v3@latest
```

**Verification:**
```bash
gobuster version
```

---

## Important Tools

### 1. dnsx
DNS resolution and probing.

```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

---

### 2. masscan
Fast port scanner.

**Debian/Ubuntu:**
```bash
sudo apt-get install masscan
```

**macOS:**
```bash
brew install masscan
```

---

### 3. gau
Get all URLs from various sources.

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

---

### 4. waybackurls
Fetch URLs from Wayback Machine.

```bash
go install github.com/tomnomnom/waybackurls@latest
```

---

### 5. paramspider
Parameter discovery tool.

```bash
pip3 install paramspider
```

Or from source:
```bash
git clone https://github.com/0xJs/ParamSpider.git
cd ParamSpider
pip3 install -r requirements.txt
```

---

### 6. arjun
HTTP parameter discovery.

```bash
pip3 install arjun
```

Or from source:
```bash
git clone https://github.com/s0md3v/Arjun.git
cd Arjun
pip3 install -r requirements.txt
```

---

### 7. kiterunner
API endpoint discovery.

```bash
go install github.com/assetnote/kiterunner@latest
```

---

### 8. nikto
Web server vulnerability scanner.

**Debian/Ubuntu:**
```bash
sudo apt-get install nikto
```

**macOS:**
```bash
brew install nikto
```

---

### 9. wafw00f
WAF detection tool.

```bash
pip3 install wafw00f
```

Or from source:
```bash
git clone https://github.com/EnableSecurity/wafw00f.git
cd wafw00f
pip3 install -r requirements.txt
```

---

## Optional Tools

### 1. eyewitness
Web application screenshot tool.

```bash
pip3 install eyewitness
```

Or from source:
```bash
git clone https://github.com/RedSiege/EyeWitness.git
cd EyeWitness
pip3 install -r requirements.txt
```

---

### 2. aquatone
Subdomain takeover and screenshot tool.

```bash
go install github.com/michenriksen/aquatone@latest
```

---

### 3. cmseek
CMS detection and fingerprinting.

```bash
git clone https://github.com/Tuhinshubhra/CMSeeK.git
cd CMSeeK
pip3 install -r requirements.txt
python3 cmseek.py --help
```

---

## Quick Installation Script

Create an executable script to install all tools:

```bash
#!/bin/bash

# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Go tools
echo "[*] Installing Go-based tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/ffuf/ffuf@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/assetnote/kiterunner@latest
go install github.com/michenriksen/aquatone@latest

# Install system packages
echo "[*] Installing system packages..."
sudo apt-get install -y nmap masscan nikto

# Install Python tools
echo "[*] Installing Python-based tools..."
pip3 install paramspider arjun wafw00f eyewitness

echo "[+] Installation complete!"
```

---

## Verification

To check all installed tools:

```bash
python3 automation-script-bug.py --check
```

To list all available tools:

```bash
python3 tool_manager.py --list
```

---

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

### Permission Denied
Some tools may require sudo. Be cautious:
```bash
sudo apt-get install <tool-name>
```

---

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
    print("  python3 tool_manager.py --install httpx")
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
