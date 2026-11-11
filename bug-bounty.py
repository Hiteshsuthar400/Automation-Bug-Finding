#!/usr/bin/env python3
"""Safe replacement for the legacy bug-bounty entry point.

The old shell script included exploit payload generation and an interactive
Metasploit session. This replacement intentionally runs the safe
reconnaissance engine only.
"""
from automation_script_bug import main
if __name__ == "__main__": raise SystemExit(main())
