#!/usr/bin/env bash

# Exit on interrupt (Ctrl+C)
trap "echo -e '\n\033[1;31m[!] Installation aborted by user.\033[0m'; exit 1" INT

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}[ERROR] 'go' command not found. Please install Go before running this script.${NC}"
    exit 1
fi

# Ensure $GOPATH/bin is in PATH warning
if [[ ":$PATH:" != *":$HOME/go/bin:"* && ":$PATH:" != *":$(go env GOPATH)/bin:"* ]]; then
    echo -e "${YELLOW}[WARNING] Ensure '$(go env GOPATH)/bin' is added to your PATH to run the installed tools directly.${NC}\n"
fi

# Array of target repositories
tools=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/wappalyzergo/cmd/update-fingerprints@latest"
    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    "github.com/projectdiscovery/depx/cmd/depx@latest"
    "github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest"
    "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/projectdiscovery/simplehttpserver/cmd/simplehttpserver@latest"
    "github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
    "github.com/projectdiscovery/network-fingerprint@latest"
    "github.com/owasp-amass/amass/v4/cmd/amass@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/ffuf/ffuf@latest"
    "github.com/assetnote/kiterunner@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/hahwul/dalfox@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    "github.com/haccer/subjack@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/zmap/zgrab2@latest"
    "golang.org/x/vuln/cmd/govulncheck@latest"
    "github.com/securego/gosec/v2/cmd/gosec@latest"
)

total=${#tools[@]}
current=1
failed=()

echo -e "${BLUE}=== Starting Project Discovery Tools Installation (${total} tools) ===${NC}\n"

for tool in "${tools[@]}"; do
    # Extract binary name for logging
    tool_name=$(echo "$tool" | awk -F'/' '{print $(NF-1) == "cmd" ? $NF : $(NF-1)}' | cut -d'@' -f1)
    
    echo -e "${BLUE}[$current/$total] Installing ${tool_name}...${NC}"
    
    if go install -v "$tool"; then
        echo -e "${GREEN}[✔] Successfully installed ${tool_name}${NC}\n"
    else
        echo -e "${RED}[✘] Failed to install ${tool_name}${NC}\n"
        failed+=("$tool")
    fi
    ((current++))
done

# Summary output
echo -e "${BLUE}=== Installation Summary ===${NC}"
if [ ${#failed[@]} -eq 0 ]; then
    echo -e "${GREEN}All ${total} tools were installed successfully!${NC}"
else
    echo -e "${YELLOW}Installed $((total - ${#failed[@]})) of ${total} tools.${NC}"
    echo -e "${RED}Failed installations:${NC}"
    for fail in "${failed[@]}"; do
        echo -e " - ${fail}"
    done
fi
