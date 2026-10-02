# Automation Bug Finding Framework

An automated, lightweight reconnaissance and initial security assessment wrapper designed for Debian-based environments (including ChromeOS Crostini / Penguin). This tool orchestrates multiple CLI security utilities written in Go and Python into a single execution workflow for continuous target testing.

---

## 🛠️ Integrated Recon Architecture

The pipeline integrates and executes tools in structured stages:

1. **Subdomain Enumeration:** `subfinder`, `amass`
2. **DNS Resolution & Probing:** `dnsx`, `httpx`
3. **Port Scanning:** `nmap`, `masscan`
4. **URL & Endpoint Collection:** `gau`, `waymore`, `katana`
5. **JavaScript Analysis:** `jsleak`, `httpx`
6. **Parameter Discovery:** `arjun`, `paramspider`
7. **Content & Directory Discovery:** `feroxbuster`, `kiterunner`
8. **CMS & Tech Identification:** `cmseek`
9. **Vulnerability & Security Checks:** `nuclei`, `nikto`

---

## 📋 System Prerequisites

Ensure your system has **Python 3.10+** and **Go 1.21+** installed and added to your system PATH.

### System Dependencies
```bash
sudo apt update && sudo apt install -y \
    git \
    python3 \
    python3-pip \
    golang \
    curl \
    unzip \
    nmap \
    masscan \
    nikto
