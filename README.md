# ADVISION

**ADVISION** — Active Directory & DNS auditing utility for authorized red-team / blue-team work, lab research, and internal security assessments.

> ⚠️ **Legal & Ethical Notice**
> Do **not** run this tool against systems you do not own or do not have **explicit written permission** to test. Unauthorized use is illegal and unethical. Use in a lab or with documented authorization only.

---

## What it is

ADVISION is a single-file Python utility (`adv.py` or similar) that performs LDAP/AD enumeration and quick checks:

* LDAP naming context enumeration and PDF report generation
* AD hierarchy enumeration
* Schema and GPO enumeration
* Domain password policy retrieval (WinRM/PowerShell)
* SIDHistory lookup (WinRM)
* Basic DNS misconfiguration checks (zone transfer, reverse lookup, DNSSEC, SRV records)
* SMB connectivity & share checks
* DCOM/SCM connectivity checks (Impacket)

The script prints results to console and can generate `ldapenumerationresults.pdf`.

---

## Features

* LDAP enumeration (optional user-only filter)
* PDF report output of LDAP results
* WinRM-powered password policy & SID history retrieval
* AD hierarchy output (parent/child structure)
* LDAP schema and GPO enumeration
* DNS misconfiguration checks targeted at a specific DNS server (e.g., DC IP)
* SMB share enumeration using `smbprotocol`
* DCOM/SCM test using Impacket DCE/RPC

---

## Requirements

* Python 3.8+ (3.10 or 3.11 recommended)
* The script expects the following modules (install via pip). See `requirements.txt` example below.

System notes:

* Some libraries (Impacket, smbprotocol) may require OS-level packages or compilation on Linux.
* WinRM functionality requires target Windows hosts with WinRM enabled and reachable.

---

## Installation

1. Clone the repo:

```bash
git clone <repo-url>
cd <repo-dir>
```

2. Create and activate a virtual environment:

```bash
# Unix / macOS
python -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
```

3. Install Python packages from `requirements.txt`:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## Usage

**Basic LDAP enumeration (generate PDF):**

```bash
python adv.py --server 10.0.0.5 --domain EXAMPLE --username audituser --password 'P@ssw0rd' --filter all
```

**Flags & options**

* `-ip, --server` : LDAP server IP (required)
* `-p, --port` : LDAP port (default `389`)
* `-d, --domain` : NTLM domain for authentication (required)
* `-u, --username` : username (required)
* `-P, --password` : password (required)
* `-f, --filter` : `all` (default) or `users`
* `-v, --verbose` : debug logging
* `-pwp, --passwordpolicy` : retrieve domain password policy (WinRM)
* `-H, --hierarchy` : retrieve AD hierarchy
* `--schema` : retrieve LDAP schema info
* `-gpo, --gpo` : enumerate GPOs
* `-dns, --dns` : run DNS misconfiguration checks (prompts for domain and DC IP)
* `--sidhistory` : retrieve SIDHistory for a specified user (prompts)
* `--smb` : test SMB and enumerate shares
* `--dcom` : test DCOM/SCM connectivity




