# Automation Bug Finding — Python Edition

Version: **2.2.0**

Python-only reconnaissance and non-destructive security-assessment runner for assets you are explicitly authorized to test.

## Python files

- automation-script-bug.py — main CLI entry point
- automation_script_bug.py — reconnaissance engine
- bbts.py — compatibility entry point
- bug-bounty.py — safe compatibility entry point
- golang-tools.py — Python replacement for the original Go installer
- tool_manager.py — tool inventory and installer

All legacy .sh entry points have been removed.

## Quick start

```bash
python3 automation-script-bug.py --check
python3 automation-script-bug.py example.com
python3 automation-script-bug.py example.com --timeout 600
```

## Go tools

```bash
python3 golang-tools.py --check
python3 golang-tools.py --install httpx
python3 golang-tools.py --install-all --skip-existing
```

The Python Go installer keeps the tool list from the original golang-tools.sh.

## Compatibility commands

```bash
python3 bbts.py example.com
python3 bug-bounty.py example.com
```

The legacy bug-bounty.sh contained reverse-shell generation and an interactive Metasploit section. Those exploit/payload actions are intentionally not included in the Python replacement.

## Output

Results are stored below:

`~/.bug-hunter/results/<target>_<timestamp>/`

Typical output includes subdomains, DNS results, HTTP probing, Nmap results, historical URLs, JavaScript candidates, parameters, WAF/CMS checks, security-check output, commands.log, REPORT.md and REPORT.json.

## Authorization

Run the framework only against systems you own or have explicit permission to test.
