#!/usr/bin/env python3
"""Safe authorized reconnaissance runner."""
from __future__ import annotations
import argparse, json, re, shutil, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

VERSION="2.2.0"
ROOT=Path.home()/".bug-hunter"/"results"

def clean_target(v):
    v=re.sub(r"^https?://","",v.strip(),flags=re.I)
    return v.split("/",1)[0].split("?",1)[0].split("#",1)[0].rstrip(".")

def valid_target(v):
    if not v or any(c in v for c in " /@"): return False
    if re.fullmatch(r"(?:d{1,3}.){3}d{1,3}",v): return all(int(x)<=255 for x in v.split("."))
    return bool(re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?.)+[a-z]{2,63}",v,re.I))

def tool(n): return shutil.which(n)

def run(label,cmd,out=None,log=None,timeout=300):
    if not tool(cmd[0]): print(f"[!] {cmd[0]} missing; skipped {label}"); return False
    print(f"[*] {label}")
    try:
        p=subprocess.run(cmd,text=True,capture_output=True,timeout=timeout)
        if log: log.open("a",encoding="utf-8").write("\n$ "+" ".join(cmd)+"\n"+p.stdout+p.stderr)
        if out: out.parent.mkdir(parents=True,exist_ok=True); out.write_text(p.stdout,encoding="utf-8")
        print("[+] completed" if p.returncode==0 else f"[!] exit {p.returncode}")
        return p.returncode==0
    except Exception as e: print(f"[!] {label}: {e}"); return False

def unique(files,out):
    s=set()
    for f in files:
        if f.exists(): s.update(x.strip() for x in f.read_text(errors="ignore").splitlines() if x.strip())
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text("\n".join(sorted(s))+"\n" if s else "",encoding="utf-8")

def main():
    ap=argparse.ArgumentParser(description="Authorized non-destructive security reconnaissance")
    ap.add_argument("target",nargs="?"); ap.add_argument("--check",action="store_true"); ap.add_argument("--timeout",type=int,default=300)
    a=ap.parse_args()
    names=["subfinder","assetfinder","amass","dnsx","httpx","nmap","gau","waybackurls","katana","ffuf","paramspider","arjun","nikto","wafw00f","cmseek","kiterunner"]
    if a.check:
        for n in names: print(f"{n:14} {'OK' if tool(n) else 'MISSING'}")
        return 0
    if not a.target: ap.error("target is required")
    target=clean_target(a.target)
    if not valid_target(target): ap.error("invalid hostname or IPv4 target")
    scan=ROOT/f"{target}_{time.strftime('%Y%m%d_%H%M%S')}"; scan.mkdir(parents=True)
    for d in ["01-subdomains","02-dns","03-ports","04-http","05-screenshots","06-directories","07-javascript","08-urls","09-parameters","10-api","11-vulnerability-checks","12-waf-cms","13-git","wordlists"]: (scan/d).mkdir()
    log=scan/"commands.log"; start=datetime.now(timezone.utc).isoformat()
    (scan/"target-info.txt").write_text(f"Target: {target}\nStarted: {start}\nVersion: {VERSION}\n",encoding="utf-8")
    print(f"[*] Target: {target}")
    sub=scan/"01-subdomains"
    run("Subfinder",["subfinder","-d",target,"-silent","-o",str(sub/"subfinder.txt")],log=log,timeout=a.timeout)
    run("Assetfinder",["assetfinder","--subs-only",target],sub/"assetfinder.txt",log,a.timeout)
    run("Amass passive",["amass","enum","-passive","-d",target,"-o",str(sub/"amass.txt")],log=log,timeout=a.timeout)
    master=scan/"all_subdomains.txt"; unique([sub/"subfinder.txt",sub/"assetfinder.txt",sub/"amass.txt"],master)
    run("DNSX",["dnsx","-l",str(master),"-silent","-a","-resp","-o",str(scan/"02-dns/dnsx-results.txt")],log=log,timeout=a.timeout)
    run("HTTPX",["httpx","-l",str(master),"-silent","-follow-redirects","-status-code","-title","-tech-detect","-web-server","-ip","-o",str(scan/"04-http/httpx-full.txt")],log=log,timeout=a.timeout)
    live=scan/"04-http/live-hosts.txt"; run("HTTPX live URLs",["httpx","-l",str(master),"-silent","-follow-redirects","-o",str(live)],log=log,timeout=a.timeout)
    run("Nmap",["nmap","-Pn","--open","-sV","-sC","-T4",target,"-oN",str(scan/"03-ports/nmap-result.txt")],log=log,timeout=max(a.timeout,600))
    urls=scan/"08-urls"; run("GAU",["gau",target],urls/"gau.txt",log,a.timeout); run("Waybackurls",["waybackurls",target],urls/"waybackurls.txt",log,a.timeout); run("Katana",["katana","-u",f"https://{target}","-silent"],urls/"katana.txt",log,max(a.timeout,600)); all_urls=scan/"all_urls.txt"; unique([urls/"gau.txt",urls/"waybackurls.txt",urls/"katana.txt"],all_urls)
    js=scan/"07-javascript/js-files.txt"; js.parent.mkdir(exist_ok=True); js.write_text("\n".join(sorted(x for x in all_urls.read_text(errors="ignore").splitlines() if re.search(r"\.js(?:[?#]|$)",x,re.I)))+"\n",encoding="utf-8")
    word=Path("/usr/share/wordlists/dirb/common.txt")
    if not word.exists(): word=Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    if word.exists(): run("FFUF",["ffuf","-u",f"https://{target}/FUZZ","-w",str(word),"-mc","200,204,301,302,307,401,403","-of","json","-o",str(scan/"06-directories/ffuf.json")],log=log,timeout=max(a.timeout,600))
    run("ParamSpider",["paramspider","-d",target,"--level","high","-o",str(scan/"09-parameters/paramspider.txt")],log=log,timeout=max(a.timeout,600))
    run("Arjun",["arjun","-u",f"https://{target}","-m","GET","-oJ",str(scan/"09-parameters/arjun.json")],log=log,timeout=max(a.timeout,600))
    run("WAFW00F",["wafw00f",f"https://{target}"],scan/"12-waf-cms/wafw00f.txt",log=log)
    run("Nikto",["nikto","-h",f"https://{target}","-output",str(scan/"11-vulnerability-checks/nikto.txt")],log=log,timeout=max(a.timeout,600))
    run("CMSeeK",["cmseek","-u",f"https://{target}","--batch","--output-dir",str(scan/"12-waf-cms/cmseek")],log=log,timeout=max(a.timeout,600))
    interesting=[u for u in all_urls.read_text(errors="ignore").splitlines() if re.search(r"(\.env|\.git|backup|config|admin|login|api|swagger|graphql|debug|staging)",u,re.I)]
    (scan/"11-vulnerability-checks/interesting-urls.txt").write_text("\n".join(sorted(set(interesting)))+"\n",encoding="utf-8")
    counts={"subdomains":sum(1 for _ in master.open()) if master.exists() else 0,"live_urls":sum(1 for _ in live.open()) if live.exists() else 0,"urls":sum(1 for _ in all_urls.open()) if all_urls.exists() else 0,"javascript":sum(1 for _ in js.open()) if js.exists() else 0}
    end=datetime.now(timezone.utc).isoformat(); data={"version":VERSION,"target":target,"started":start,"finished":end,"counts":counts}; (scan/"REPORT.json").write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8"); (scan/"REPORT.md").write_text(f"# Recon Report\n\nTarget: {target}\nVersion: {VERSION}\n\nCounts: {json.dumps(counts)}\n",encoding="utf-8")
    print(f"[+] Results: {scan}"); return 0
if __name__=="__main__": raise SystemExit(main())
