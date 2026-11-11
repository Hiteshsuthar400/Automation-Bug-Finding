#!/usr/bin/env python3
"""Python replacement for golang-tools.sh."""
from __future__ import annotations
import argparse, os, shutil, subprocess
from pathlib import Path
TOOLS=[
("nuclei","github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),("update-fingerprints","github.com/projectdiscovery/wappalyzergo/cmd/update-fingerprints@latest"),("cdncheck","github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"),("mapcidr","github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"),("naabu","github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),("httpx","github.com/projectdiscovery/httpx/cmd/httpx@latest"),("subfinder","github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),("tlsx","github.com/projectdiscovery/tlsx/cmd/tlsx@latest"),("depx","github.com/projectdiscovery/depx/cmd/depx@latest"),("vulnx","github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest"),("uncover","github.com/projectdiscovery/uncover/cmd/uncover@latest"),("katana","github.com/projectdiscovery/katana/cmd/katana@latest"),("interactsh-client","github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),("simplehttpserver","github.com/projectdiscovery/simplehttpserver/cmd/simplehttpserver@latest"),("tldfinder","github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest"),("asnmap","github.com/projectdiscovery/asnmap/cmd/asnmap@latest"),("urlfinder","github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"),("shuffledns","github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"),("dnsx","github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),("pdtm","github.com/projectdiscovery/pdtm/cmd/pdtm@latest"),("network-fingerprint","github.com/projectdiscovery/network-fingerprint@latest"),("amass","github.com/owasp-amass/amass/v4/cmd/amass@latest"),("assetfinder","github.com/tomnomnom/assetfinder@latest"),("hakrawler","github.com/hakluke/hakrawler@latest"),("gau","github.com/lc/gau/v2/cmd/gau@latest"),("waybackurls","github.com/tomnomnom/waybackurls@latest"),("gospider","github.com/jaeles-project/gospider@latest"),("ffuf","github.com/ffuf/ffuf@latest"),("kiterunner","github.com/assetnote/kiterunner@latest"),("unfurl","github.com/tomnomnom/unfurl@latest"),("qsreplace","github.com/tomnomnom/qsreplace@latest"),("dalfox","github.com/hahwul/dalfox@latest"),("crlfuzz","github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"),("subjack","github.com/haccer/subjack@latest"),("anew","github.com/tomnomnom/anew@latest"),("gowitness","github.com/sensepost/gowitness@latest"),("notify","github.com/projectdiscovery/notify/cmd/notify@latest"),("zgrab2","github.com/zmap/zgrab2@latest"),("govulncheck","golang.org/x/vuln/cmd/govulncheck@latest"),("gosec","github.com/securego/gosec/v2/cmd/gosec@latest")]
def gobin():
    x=os.environ.get("GOBIN")
    return Path(x) if x else Path(subprocess.check_output(["go","env","GOPATH"],text=True).strip())/"bin"
def main():
    ap=argparse.ArgumentParser(description="Install Go tools from the original installer")
    ap.add_argument("--check",action="store_true"); ap.add_argument("--install"); ap.add_argument("--install-all",action="store_true"); ap.add_argument("--skip-existing",action="store_true")
    a=ap.parse_args()
    if not shutil.which("go"): print("[ERROR] 'go' command not found."); return 1
    names=dict(TOOLS)
    if a.check:
        for n,_ in TOOLS: print(f"{'OK':8} {n}" if shutil.which(n) else f"{'MISSING':8} {n}")
        return 0
    if a.install:
        if a.install not in names: print(f"[ERROR] Unknown tool: {a.install}"); return 2
        selected=[(a.install,names[a.install])]
    elif a.install_all: selected=TOOLS
    else: ap.print_help(); return 0
    failed=[]
    for n,pkg in selected:
        if a.skip_existing and shutil.which(n): print(f"[SKIP] {n} already installed"); continue
        print(f"[INSTALL] {n}: go install {pkg}")
        if subprocess.run(["go","install","-v",pkg]).returncode != 0: failed.append(n)
    print(f"\nGo binary directory: {gobin()}")
    print(f"Installed: {len(selected)-len(failed)}/{len(selected)}")
    if failed: print("Failed: "+", ".join(failed)); return 1
    return 0
if __name__=="__main__": raise SystemExit(main())
