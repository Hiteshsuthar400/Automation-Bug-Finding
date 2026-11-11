#!/usr/bin/env bash

# ==============================================================================
# Automated Bug Hunting & Recon Pipeline
# ==============================================================================

# Exit on Ctrl+C interrupt
trap "echo -e '\n\033[1;31m[!] Recon script interrupted by user.\033[0m'; exit 1" INT

# Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ -z "$1" ]; then
    echo -e "${RED}Usage: $0 <domain.com>${NC}"
    exit 1
fi

TARGET="$1"
OUTDIR="recon/${TARGET}"
mkdir -p "${OUTDIR}"/{subdomains,ports,urls,vulnerability,screenshots,fingerprints}

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE} Starting Recon Engine for Target: ${GREEN}${TARGET}${NC}"
echo -e "${BLUE} Saving output to: ${YELLOW}${OUTDIR}/${NC}"
echo -e "${BLUE}================================================================${NC}\n"

# ------------------------------------------------------------------------------
# PHASE 1: ASN Mapping & CIDR Calculation
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[+] Phase 1: Network & ASN Mapping...${NC}"
asnmap -i "$TARGET" -silent | anew "${OUTDIR}/fingerprints/asn.txt"
mapcidr -cl "${OUTDIR}/fingerprints/asn.txt" -silent | anew "${OUTDIR}/fingerprints/cidrs.txt"

# ------------------------------------------------------------------------------
# PHASE 2: Subdomain Enumeration & DNS Resolution
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[+] Phase 2: Enumerating Subdomains...${NC}"

# Passive Enumeration
subfinder -d "$TARGET" -silent | anew "${OUTDIR}/subdomains/raw_subs.txt"
assetfinder --subs-only "$TARGET" | anew "${OUTDIR}/subdomains/raw_subs.txt"
amass enum -passive -d "$TARGET" -silent | anew "${OUTDIR}/subdomains/raw_subs.txt"
tldfinder -d "$TARGET" -s | anew "${OUTDIR}/subdomains/raw_subs.txt"
uncover -q "$TARGET" -silent | anew "${OUTDIR}/subdomains/raw_subs.txt"

# DNS Resolution & Brute-Forcing
dnsx -l "${OUTDIR}/subdomains/raw_subs.txt" -silent | anew "${OUTDIR}/subdomains/resolved_subs.txt"
shuffledns -d "$TARGET" -list "${OUTDIR}/subdomains/raw_subs.txt" -r ~/.resolvers.txt -silent | anew "${OUTDIR}/subdomains/resolved_subs.txt"

# Check Subdomain Takeovers
subjack -w "${OUTDIR}/subdomains/resolved_subs.txt" -t 100 -timeout 30 -ssl -c ~/subjack_fingerprints.json -o "${OUTDIR}/vulnerability/subjack.txt" -ssl

# ------------------------------------------------------------------------------
# PHASE 3: Port Scanning & Network Probing
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[+] Phase 3: Port Scanning & CDN Identification...${NC}"
cdncheck -i "${OUTDIR}/subdomains/resolved_subs.txt" -silent -o "${OUTDIR}/fingerprints/cdn_ips.txt"
naabu -l "${OUTDIR}/subdomains/resolved_subs.txt" -top-ports 1000 -silent | anew "${OUTDIR}/ports/open_ports.txt"
tlsx -l "${OUTDIR}/ports/open_ports.txt" -san -cn -silent | anew "${OUTDIR}/fingerprints/tls_info.txt"

# ------------------------------------------------------------------------------
# PHASE 4: Web Probing & Screenshotting
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[+] Phase 4: Web Probing (HTTPX)...${NC}"
httpx -l "${OUTDIR}/subdomains/resolved_subs.txt" -title -tech-detect -status-code -silent -o "${OUTDIR}/ports/live_web.txt"
cat "${OUTDIR}/ports/live_web.txt" | awk '{print $1}' | anew "${OUTDIR}/ports/live_urls.txt"

# Screenshots
gowitness file -f "${OUTDIR}/ports/live_urls.txt" --destination "${OUTDIR}/screenshots/" > /dev/null 2>&1

# ------------------------------------------------------------------------------
# PHASE 5: Historical & Live Endpoint Discovery (Crawling & Spidering)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[+] Phase 5: Endpoint Harvesting & Crawling...${NC}"

# Passive Archives
gau "$TARGET" | anew "${OUTDIR}/urls/raw_urls.txt"
waybackurls "$TARGET" | anew "${OUTDIR}/urls/raw_urls.txt"
urlfinder -d "$TARGET" -silent | anew "${OUTDIR}/urls/raw_urls.txt"

# Active Crawling
katana -list "${OUTDIR}/ports/live_urls.txt" -silent | anew "${OUTDIR}/urls/raw_urls.txt"
gospider -s "${OUTDIR}/ports/live_urls.txt" --other-source --concurrent 10 -q | anew "${OUTDIR}/urls/raw_urls.txt"
hakrawler -url "${OUTDIR}/ports/live_urls.txt" -plain | anew "${OUTDIR}/urls/raw_urls.txt"

# URL Processing & Extraction
cat "${OUTDIR}/urls/raw_urls.txt" | unfurl -u keys | anew "${OUTDIR}/urls/param_keys.txt"
cat "${OUTDIR}/urls/raw_urls.txt" | qsreplace "FUZZ" | anew "${OUTDIR}/urls/fuzzable_urls.txt"

# ------------------------------------------------------------------------------
# PHASE 6: Active Vulnerability Scanning & Fuzzing
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[+] Phase 6: Vulnerability Scanning & Parameter Fuzzing...${NC}"

# Nuclei Scanning
nuclei -l "${OUTDIR}/ports/live_urls.txt" -severity low,medium,high,critical -silent -o "${OUTDIR}/vulnerability/nuclei_results.txt"

# XSS Testing
dalfox file "${OUTDIR}/urls/fuzzable_urls.txt" --silence -o "${OUTDIR}/vulnerability/dalfox_xss.txt"

# CRLF Testing
crlfuzz -l "${OUTDIR}/ports/live_urls.txt" -s -o "${OUTDIR}/vulnerability/crlfuzz_results.txt"

# Web Fuzzing (Content Discovery)
ffuf -u "https://$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -s -o "${OUTDIR}/vulnerability/ffuf.json"

# ------------------------------------------------------------------------------
# PHASE 7: Notifications & Completion
# ------------------------------------------------------------------------------
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}[✔] Recon Complete for ${TARGET}!${NC}"
echo -e "${GREEN}[✔] Results directory tree built at: ${OUTDIR}/${NC}"
echo -e "${GREEN}================================================================${NC}"

# Optional Slack/Discord Notification
if command -v notify &> /dev/null; then
    echo "Recon completed for $TARGET. Total Live URLs: $(wc -l < ${OUTDIR}/ports/live_urls.txt)" | notify -silent
fi
