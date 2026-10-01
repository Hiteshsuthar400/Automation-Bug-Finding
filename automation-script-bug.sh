#!/usr/bin/env bash

# ============================================================
# BUG HUNTER - Authorized Security Recon Automation
# Version: 1.0
#
# Usage:
#   chmod +x bughunter.sh
#   ./bughunter.sh example.com
#
# All results:
#   ./targets/example.com/
#
# ONLY use against systems you own or have explicit permission
# to test.
# ============================================================

set -o pipefail

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    echo
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

# Remove protocol/path if supplied
TARGET="${TARGET#http://}"
TARGET="${TARGET#https://}"
TARGET="${TARGET%%/*}"

BASE_DIR="$(pwd)/targets/$TARGET"

SUB_DIR="$BASE_DIR/01-subdomains"
DNS_DIR="$BASE_DIR/02-dns"
PORT_DIR="$BASE_DIR/03-ports"
HTTP_DIR="$BASE_DIR/04-http"
SCREEN_DIR="$BASE_DIR/05-screenshots"
DIR_DIR="$BASE_DIR/06-directories"
JS_DIR="$BASE_DIR/07-javascript"
URL_DIR="$BASE_DIR/08-urls"
PARAM_DIR="$BASE_DIR/09-parameters"
API_DIR="$BASE_DIR/10-api"
VULN_DIR="$BASE_DIR/11-vulnerability-checks"
WAF_DIR="$BASE_DIR/12-waf-cms"
GIT_DIR="$BASE_DIR/13-git"
LOG_DIR="$BASE_DIR/logs"
WORDLIST_DIR="$BASE_DIR/wordlists"

MASTER_SUBDOMAINS="$SUB_DIR/all-subdomains.txt"
LIVE_HOSTS="$HTTP_DIR/live-hosts.txt"
ALL_URLS="$URL_DIR/all-urls.txt"

# ------------------------------------------------------------
# Colors
# ------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

banner() {
    clear
    echo -e "${CYAN}"
    echo "============================================================"
    echo "              BUG HUNTER AUTOMATION"
    echo "============================================================"
    echo -e "${NC}"
    echo "Target : $TARGET"
    echo "Output : $BASE_DIR"
    echo
}

log() {
    echo -e "${BLUE}[*]${NC} $1"
}

success() {
    echo -e "${GREEN}[+]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[-]${NC} $1"
}

run_tool() {
    local tool="$1"

    if command -v "$tool" >/dev/null 2>&1; then
        return 0
    fi

    warning "$tool is not installed. Skipping."
    return 1
}

run_cmd() {
    local description="$1"
    shift

    log "$description"

    "$@" >> "$LOG_DIR/commands.log" 2>&1

    if [[ $? -eq 0 ]]; then
        success "$description completed"
    else
        warning "$description returned an error"
    fi
}

# ------------------------------------------------------------
# Create directory structure
# ------------------------------------------------------------

create_structure() {

    log "Creating target directory structure..."

    mkdir -p \
        "$SUB_DIR" \
        "$DNS_DIR" \
        "$PORT_DIR" \
        "$HTTP_DIR" \
        "$SCREEN_DIR" \
        "$DIR_DIR" \
        "$JS_DIR" \
        "$URL_DIR" \
        "$PARAM_DIR" \
        "$API_DIR" \
        "$VULN_DIR" \
        "$WAF_DIR" \
        "$GIT_DIR" \
        "$LOG_DIR" \
        "$WORDLIST_DIR"

    touch "$LOG_DIR/commands.log"

    success "Directory structure created"
}

# ------------------------------------------------------------
# Target information
# ------------------------------------------------------------

save_target_info() {

    cat > "$BASE_DIR/target-info.txt" <<EOF
============================================================
TARGET INFORMATION
============================================================

Target:
$TARGET

Started:
$(date)

Hostname:
$(hostname)

Operating System:
$(uname -a)

Working Directory:
$(pwd)

============================================================
EOF
}

# ------------------------------------------------------------
# Step 01 - Subdomain Enumeration
# ------------------------------------------------------------

subdomain_enum() {

    log "Step 01 - Subdomain enumeration"

    if run_tool subfinder; then
        subfinder -d "$TARGET" \
            -silent \
            -o "$SUB_DIR/subfinder.txt" \
            >> "$LOG_DIR/commands.log" 2>&1
    fi

    if run_tool amass; then
        amass enum \
            -passive \
            -d "$TARGET" \
            -o "$SUB_DIR/amass.txt" \
            >> "$LOG_DIR/commands.log" 2>&1
    fi

    if run_tool assetfinder; then
        assetfinder --subs-only "$TARGET" \
            > "$SUB_DIR/assetfinder.txt" \
            2>> "$LOG_DIR/commands.log"
    fi

    touch \
        "$SUB_DIR/subfinder.txt" \
        "$SUB_DIR/amass.txt" \
        "$SUB_DIR/assetfinder.txt"

    cat \
        "$SUB_DIR/subfinder.txt" \
        "$SUB_DIR/amass.txt" \
        "$SUB_DIR/assetfinder.txt" \
        2>/dev/null \
        | sed 's/\r//g' \
        | sed '/^$/d' \
        | sort -u \
        > "$MASTER_SUBDOMAINS"

    success "Subdomains saved to:"
    echo "    $MASTER_SUBDOMAINS"
}

# ------------------------------------------------------------
# Step 02 - DNS Resolution
# ------------------------------------------------------------

dns_resolution() {

    log "Step 02 - DNS resolution"

    if run_tool dnsx; then

        dnsx \
            -l "$MASTER_SUBDOMAINS" \
            -silent \
            -a \
            -resp \
            -o "$DNS_DIR/dnsx-results.txt" \
            >> "$LOG_DIR/commands.log" 2>&1

    elif run_tool httpx; then

        httpx \
            -l "$MASTER_SUBDOMAINS" \
            -silent \
            -ip \
            -o "$DNS_DIR/resolved-hosts.txt" \
            >> "$LOG_DIR/commands.log" 2>&1
    else
        warning "dnsx/httpx unavailable. DNS resolution skipped."
    fi
}

# ------------------------------------------------------------
# Step 03 - Port Scanning
# ------------------------------------------------------------

port_scan() {

    log "Step 03 - Port scanning"

    if run_tool nmap; then

        nmap \
            -Pn \
            --open \
            -sV \
            -sC \
            -T4 \
            "$TARGET" \
            -oN "$PORT_DIR/nmap-result.txt" \
            >> "$LOG_DIR/commands.log" 2>&1

    else
        warning "nmap is not installed."
    fi

    if run_tool masscan; then

        masscan \
            "$TARGET" \
            -p1-65535 \
            --rate 5000 \
            -oL "$PORT_DIR/masscan-result.txt" \
            >> "$LOG_DIR/commands.log" 2>&1

    else
        warning "masscan is not installed."
    fi
}

# ------------------------------------------------------------
# Step 04 - HTTP Probing
# ------------------------------------------------------------

http_probe() {

    log "Step 04 - HTTP probing"

    if ! run_tool httpx; then
        return
    fi

    httpx \
        -l "$MASTER_SUBDOMAINS" \
        -silent \
        -follow-redirects \
        -status-code \
        -title \
        -tech-detect \
        -web-server \
        -ip \
        -o "$HTTP_DIR/httpx-full.txt" \
        >> "$LOG_DIR/commands.log" 2>&1

    httpx \
        -l "$MASTER_SUBDOMAINS" \
        -silent \
        -follow-redirects \
        -o "$LIVE_HOSTS" \
        >> "$LOG_DIR/commands.log" 2>&1

    success "Live hosts saved to $LIVE_HOSTS"
}

# ------------------------------------------------------------
# Step 05 - Screenshots
# ------------------------------------------------------------

screenshots() {

    log "Step 05 - Web screenshots"

    if run_tool eyewitness; then

        eyewitness \
            -f "$LIVE_HOSTS" \
            --web \
            -d "$SCREEN_DIR/eyewitness" \
            >> "$LOG_DIR/commands.log" 2>&1

    else
        warning "EyeWitness not installed."
    fi

    if run_tool aquatone; then

        cat "$LIVE_HOSTS" \
            | aquatone \
            -out "$SCREEN_DIR/aquatone" \
            >> "$LOG_DIR/commands.log" 2>&1

    else
        warning "Aquatone not installed."
    fi
}

# ------------------------------------------------------------
# Step 06 - Directory Discovery
# ------------------------------------------------------------

directory_discovery() {

    log "Step 06 - Directory/content discovery"

    local WORDLIST=""

    if [[ -f /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt ]]; then
        WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    elif [[ -f /usr/share/wordlists/dirb/common.txt ]]; then
        WORDLIST="/usr/share/wordlists/dirb/common.txt"
    else
        warning "No standard directory wordlist found."
        return
    fi

    if run_tool ffuf; then

        ffuf \
            -u "https://$TARGET/FUZZ" \
            -w "$WORDLIST" \
            -mc 200,204,301,302,307,401,403 \
            -of json \
            -o "$DIR_DIR/ffuf-results.json" \
            >> "$LOG_DIR/commands.log" 2>&1

    fi

    if run_tool gobuster; then

        gobuster dir \
            -u "https://$TARGET" \
            -w "$WORDLIST" \
            -o "$DIR_DIR/gobuster-results.txt" \
            >> "$LOG_DIR/commands.log" 2>&1

    fi
}

# ------------------------------------------------------------
# Step 07 - URL Collection
# ------------------------------------------------------------

url_collection() {

    log "Step 07 - URL collection"

    touch "$URL_DIR/gau.txt"
    touch "$URL_DIR/waybackurls.txt"

    if run_tool gau; then

        gau "$TARGET" \
            > "$URL_DIR/gau.txt" \
            2>> "$LOG_DIR/commands.log"

    fi

    if run_tool waybackurls; then

        echo "$TARGET" \
            | waybackurls \
            > "$URL_DIR/waybackurls.txt" \
            2>> "$LOG_DIR/commands.log"

    fi

    cat \
        "$URL_DIR/gau.txt" \
        "$URL_DIR/waybackurls.txt" \
        2>/dev/null \
        | sort -u \
        > "$ALL_URLS"

    success "URLs saved to $ALL_URLS"
}

# ------------------------------------------------------------
# Step 08 - JavaScript Discovery
# ------------------------------------------------------------

javascript_enum() {

    log "Step 08 - JavaScript discovery"

    grep -Ei '\.js([?#]|$)' "$ALL_URLS" \
        | sort -u \
        > "$JS_DIR/js-files.txt"

    success "JavaScript URLs:"
    echo "    $JS_DIR/js-files.txt"

    if [[ ! -s "$JS_DIR/js-files.txt" ]]; then
        warning "No JavaScript URLs found."
        return
    fi

    if run_tool httpx; then

        httpx \
            -l "$JS_DIR/js-files.txt" \
            -silent \
            -status-code \
            -content-type \
            -o "$JS_DIR/js-httpx.txt" \
            >> "$LOG_DIR/commands.log" 2>&1

    fi
}

# ------------------------------------------------------------
# Step 09 - Parameter Discovery
# ------------------------------------------------------------

parameter_discovery() {

    log "Step 09 - Parameter discovery"

    if run_tool paramspider; then

        paramspider \
            -d "$TARGET" \
            --level high \
            -o "$PARAM_DIR/paramspider.txt" \
            >> "$LOG_DIR/commands.log" 2>&1

    else
        warning "ParamSpider not installed."
    fi

    if run_tool arjun; then

        arjun \
            -u "https://$TARGET" \
            -m GET \
            -oJ "$PARAM_DIR/arjun.json" \
            >> "$LOG_DIR/commands.log" 2>&1

    else
        warning "Arjun not installed."
    fi
}

# ------------------------------------------------------------
# Step 10 - API Recon
# ------------------------------------------------------------

api_recon() {

    log "Step 10 - API reconnaissance"

    if run_tool kiterunner; then

        if [[ -f "$WORDLIST_DIR/apis.txt" ]]; then

            kr scan \
                "https://$TARGET" \
                -w "$WORDLIST_DIR/apis.txt" \
                > "$API_DIR/kiterunner.txt" \
                2>> "$LOG_DIR/commands.log"

        else
            warning "API wordlist missing:"
            echo "    $WORDLIST_DIR/apis.txt"
        fi

    else
        warning "Kiterunner not installed."
    fi
}

# ------------------------------------------------------------
# Step 11 - Security Headers
# ------------------------------------------------------------

security_headers() {

    log "Step 11 - Security header analysis"

    if run_tool httpx; then

        httpx \
            -u "https://$TARGET" \
            -status-code \
            -title \
            -web-server \
            -tech-detect \
            -json \
            -o "$VULN_DIR/httpx-security.json" \
            >> "$LOG_DIR/commands.log" 2>&1
    fi

    if run_tool nikto; then

        nikto \
            -h "https://$TARGET" \
            -output "$VULN_DIR/nikto.txt" \
            >> "$LOG_DIR/commands.log" 2>&1

    fi
}

# ------------------------------------------------------------
# Step 12 - WAF Detection
# ------------------------------------------------------------

waf_detection() {

    log "Step 12 - WAF detection"

    if run_tool wafw00f; then

        wafw00f \
            "https://$TARGET" \
            > "$WAF_DIR/wafw00f.txt" \
            2>> "$LOG_DIR/commands.log"

    fi
}

# ------------------------------------------------------------
# Step 13 - CMS Detection
# ------------------------------------------------------------

cms_detection() {

    log "Step 13 - CMS detection"

    if run_tool cmseek; then

        cmseek \
            -u "https://$TARGET" \
            --batch \
            --output-dir "$WAF_DIR/cmseek" \
            >> "$LOG_DIR/commands.log" 2>&1

    else
        warning "CMSeeK not installed."
    fi
}

# ------------------------------------------------------------
# Step 14 - Passive Secret/Interesting URL Detection
# ------------------------------------------------------------

interesting_urls() {

    log "Step 14 - Interesting URL detection"

    grep -Ei \
        '(\.env|\.git|backup|config|admin|login|api|swagger|graphql|debug|test|dev|staging)' \
        "$ALL_URLS" \
        | sort -u \
        > "$VULN_DIR/interesting-urls.txt"

    grep -Ei \
        '(\?|&)(id|url|uri|path|file|page|redirect|next|return|search|q|query|callback|domain)=' \
        "$ALL_URLS" \
        | sort -u \
        > "$PARAM_DIR/interesting-parameters.txt"

    success "Interesting URLs/parameters extracted."
}

# ------------------------------------------------------------
# Step 15 - Git Exposure Check
# ------------------------------------------------------------

git_exposure_check() {

    log "Step 15 - Checking for exposed Git repository"

    if run_tool httpx; then

        printf '%s\n' \
            "https://$TARGET/.git/HEAD" \
            "https://$TARGET/.git/config" \
            | httpx \
                -silent \
                -status-code \
                -content-type \
                -o "$GIT_DIR/git-check.txt" \
                >> "$LOG_DIR/commands.log" 2>&1

    fi
}

# ------------------------------------------------------------
# Step 16 - Generate Summary
# ------------------------------------------------------------

generate_summary() {

    log "Generating final summary..."

    SUB_COUNT=0
    LIVE_COUNT=0
    URL_COUNT=0
    JS_COUNT=0
    PARAM_COUNT=0

    [[ -f "$MASTER_SUBDOMAINS" ]] \
        && SUB_COUNT=$(wc -l < "$MASTER_SUBDOMAINS")

    [[ -f "$LIVE_HOSTS" ]] \
        && LIVE_COUNT=$(wc -l < "$LIVE_HOSTS")

    [[ -f "$ALL_URLS" ]] \
        && URL_COUNT=$(wc -l < "$ALL_URLS")

    [[ -f "$JS_DIR/js-files.txt" ]] \
        && JS_COUNT=$(wc -l < "$JS_DIR/js-files.txt")

    [[ -f "$PARAM_DIR/interesting-parameters.txt" ]] \
        && PARAM_COUNT=$(wc -l < "$PARAM_DIR/interesting-parameters.txt")

    cat > "$BASE_DIR/summary.txt" <<EOF
============================================================
BUG HUNTER RECON SUMMARY
============================================================

Target:
$TARGET

Scan Started:
$(head -n 1 "$BASE_DIR/target-info.txt" 2>/dev/null)

Scan Finished:
$(date)

------------------------------------------------------------
COUNTS
------------------------------------------------------------

Subdomains:
$SUB_COUNT

Live HTTP Hosts:
$LIVE_COUNT

Collected URLs:
$URL_COUNT

JavaScript URLs:
$JS_COUNT

Interesting Parameters:
$PARAM_COUNT

------------------------------------------------------------
IMPORTANT FILES
------------------------------------------------------------

Subdomains:
$MASTER_SUBDOMAINS

Live Hosts:
$LIVE_HOSTS

All URLs:
$ALL_URLS

Nmap:
$PORT_DIR/nmap-result.txt

Masscan:
$PORT_DIR/masscan-result.txt

Directory Discovery:
$DIR_DIR/

JavaScript:
$JS_DIR/

Parameters:
$PARAM_DIR/

API:
$API_DIR/

Vulnerability Checks:
$VULN_DIR/

WAF/CMS:
$WAF_DIR/

Git Exposure:
$GIT_DIR/

Logs:
$LOG_DIR/

============================================================
EOF

    success "Summary created:"
    echo "    $BASE_DIR/summary.txt"
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

main() {

    banner

    create_structure
    save_target_info

    subdomain_enum
    dns_resolution
    port_scan
    http_probe
    screenshots
    directory_discovery
    url_collection
    javascript_enum
    parameter_discovery
    api_recon
    security_headers
    waf_detection
    cms_detection
    interesting_urls
    git_exposure_check

    generate_summary

    echo
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}             RECON COMPLETED${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo
    echo "Target : $TARGET"
    echo "Results: $BASE_DIR"
    echo
    echo "Summary:"
    echo "  $BASE_DIR/summary.txt"
    echo
}

main "$@"
