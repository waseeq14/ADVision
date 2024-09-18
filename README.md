# LDAP and Network Enumeration Tool

This script is a comprehensive utility for enumerating and assessing information from LDAP servers, performing DNS misconfiguration checks, and testing DCOM and SMB connections. It integrates various functionalities including LDAP enumeration, password policy retrieval, SID history, DNS checks, and more.
![output](https://github.com/user-attachments/assets/ef884830-e777-486c-957f-d735683b063a)


## Features

- **LDAP Enumeration**
  - Retrieve naming contexts and perform searches.
  - Retrieve domain password policy.
  - Retrieve Active Directory hierarchy.
  - Retrieve LDAP schema information.
  - Enumerate Group Policy Objects (GPOs).

- **DNS Misconfiguration Checks**
  - Check for zone transfer vulnerability.
  - Check for open resolver vulnerability.
  - Check for missing reverse lookup zones.
  - Check DNSSEC configuration.
  - Check if Dynamic DNS is enabled.
  - Enumerate common DNS records (A, MX, TXT, CNAME, SRV).

- **DCOM Connectivity Testing**
  - Test DCOM connectivity and retrieve services from the Service Control Manager (SCM).

- **SMB Connectivity Testing**
  - Test SMB connectivity and share enumeration (not implemented in the provided code but suggested).

## Prerequisites

- Python 3.6 or later
- Required Python packages:
  - `ldap3`
  - `winrm`
  - `dnspython`
  - `fpdf`
  - `smbprotocol` (for SMB testing)
  - `impacket` ( If you are installing `impacket` on Windows, **disable your antivirus software temporarily**. Some antivirus programs may interfere with the installation process.)

You can install the required packages using pip:

```bash
pip install ldap3 winrm dnspython fpdf smbprotocol impacket
Usage
To use the script, run it from the command line with the necessary arguments. Below is the general syntax:
python script.py [options]
Command-Line Arguments
-ip, --server: IP address of the LDAP server (required).
-p, --port: Port number for LDAP (default is 389).
-d, --domain: Domain for NTLM authentication (required).
-u, --username: Username for NTLM authentication (required).
-P, --password: Password for NTLM authentication (required).
-pwp, --passwordpolicy: Retrieve domain password policy.
-H, --hierarchy: Retrieve Active Directory hierarchy.
--schema: Retrieve LDAP schema information.
-f, --filter: Filter option for LDAP enumeration (default is "all").
-gpo, --gpo: Enumerate Group Policy Objects (GPOs).
--dns: Perform DNS misconfiguration checks.
--sidhistory: Retrieve SID history for a user.
--smb: Test SMB connectivity and share enumeration (not implemented in the provided code but suggested).
--dcom: Test DCOM connectivity.
Example
To retrieve LDAP naming contexts and filter for users:
python script.py -ip -d example.com -u admin -P password -f users
To check DNS misconfigurations:
python script.py -ip -d example.com --dns

