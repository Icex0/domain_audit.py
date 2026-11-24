![domain_audit](images/domainaudit_logo.svg)

Active Directory security auditing tool. Python port of [`domain_audit.ps1`](https://github.com/0xJs/domain_audit) with additional checks and improvements.

## Requirements

- Python 3.10+
- Network access to target Domain Controller
- Valid AD credentials
- **netexec** - Install with: `pipx install --force git+https://github.com/Pennyw0rth/NetExec`
- **certipy** - Install with: `pipx install --force certipy-ad`

## Installation

### With UV (Recommended)

```bash
# Install UV if you don't have it (Linux & macOS)
curl -LsSf https://astral.sh/uv/install.sh | sh

# For Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Install domain-audit system-wide
# Run this from the project root directory
uv tool install --force .

# Now you can run domain-audit from anywhere!
domain-audit --help
```

### Alternative: With pip

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install
pip install .
```

### Docker

```bash
# Build the Docker image
docker build -t domain-audit .

# Run audit (results saved to ./results)
docker run --rm -it -v $(pwd)/results:/data domain-audit -d contoso.com -dc 10.0.0.1 -u domainuser -p 'Password123!'
```

## Usage

```bash
# Run full audit
domain-audit -d contoso.com -dc 10.0.0.1 -u domainuser -p 'Password123!'

# Use LDAPS
domain-audit -d contoso.com -dc 10.0.0.1 -u domainuser -p 'Password123!' --ldaps

# Skip BloodHound collection
domain-audit -d contoso.com -dc 10.0.0.1 -u domainuser -p 'Password123!' --skip-bloodhound

# Skip Kerberoasting/AS-REP roasting
domain-audit -d contoso.com -dc 10.0.0.1 -u domainuser -p 'Password123!' --skip-roasting

# List available checks
domain-audit -L

# Run specific check
domain-audit --check adcs -d contoso.com -dc 10.0.0.1 -u domainuser -p 'Password123!'
```

## What It Does

### Enumeration
- Users, groups, computers, OUs, GPOs
- Domain Controllers and domain SID
- Privileged users (Domain Admins, Enterprise Admins, etc.)
- Domain trusts

### Security Checks

Checks report what was actually verified: confirmed issues go to `findings/`, cases that can't be determined reliably (for example local policy that a low-privileged user can't read) go to `checks/` for manual review.

**Domain & Password Policy**
- Domain functional level assessment
- Default password policy (length, complexity, lockout, reversible encryption)
- Kerberos policy (only longer-than-default or never-expiring ticket lifetimes are reported)
- Fine-Grained Password Policies via the effective PSO (`msDS-ResultantPSO`, includes group-applied PSOs); spray list of users without a PSO
- Share of enabled users that are (nested) Domain/Enterprise Admins

**LAPS**
- Schema detection (Legacy LAPS vs Windows LAPS)
- Deployment coverage (excluding DCs, RODCs and disabled computers)
- LAPS password readability for the current user (`ms-Mcs-AdmPwd`, `msLAPS-Password`, readable `msLAPS-EncryptedPassword`)
- LAPS policy configuration for Windows LAPS and legacy LAPS, using each one's value names and defaults

**Kerberos Attacks**
- Kerberoastable accounts, including privileged accounts by nested Administrators/Domain Admins/Enterprise Admins membership (SQL Server service accounts flagged)
- AS-REP roastable accounts (DONT_REQ_PREAUTH)
- Extracts hashes for offline cracking via Impacket

**Delegation**
- Unconstrained delegation on users and computers
- Constrained delegation (S4U2Self/S4U2Proxy)
- Resource-Based Constrained Delegation (RBCD)
- BadSuccessor: non-admins that can create dMSAs in OUs (Windows Server 2025)

**User Attributes**
- PASSWD_NOTREQD flag (accounts that can have empty passwords)
- DONT_EXPIRE_PASSWORD flag
- Reversible encryption enabled
- DES-only Kerberos encryption
- Password keywords in user/group/computer descriptions (for manual review)
- userPassword attribute exposed (cleartext or hashed passwords)

**Privileged Accounts & Groups**
- Protected Users membership (nested) and NOT_DELEGATED flag on enabled admin accounts
- Password age for privileged users (>180 days) and KRBTGT
- Non-admin members (nested users, groups, computers) of Account Operators, Server Operators, Backup Operators, Print Operators, Remote Management Users, Hyper-V Administrators, DnsAdmins, Schema Admins, Key Admins, Enterprise Key Admins and Group Policy Creator Owners
- Non-admins with the RDP logon right on domain controllers (`dc-rdp`)
- `ESX Admins` group (CVE-2024-37085, informational)

**Stale Objects**
- Inactive computers and users (no logon in 365+ days, based on the replicated `lastLogonTimestamp`)
- End-of-life operating systems, including Windows 10/11 end of servicing per edition and LTSC
- Pre-Windows 2000 Compatible Access and ANONYMOUS LOGON group membership
- Pre-created (pre-Windows 2000) computer accounts, with a safe test of the default password (one Kerberos attempt per account, lockout-aware)
- Users can add computer accounts (MachineAccountQuota combined with who holds "Add workstations to domain" on the DCs)

**Trusts**
- Domain trust enumeration (direction, type, attributes)
- SID filtering on outbound/bidirectional external trusts, SID history enabled on forest trusts, TGT delegation across trusts

**ADIDNS**
- Who can create DNS records (correct ACL parsing incl. object ACEs; Authenticated Users, Domain Users, Domain Computers and more)
- Domain Computers-only zones judged by whether users can create computer accounts
- Wildcard record detection (finding only when users can create records)
- Zones allowing nonsecure dynamic updates (forward zones as finding, reverse zones as lower-impact check)

**Certificates (ADCS)**
- PKI Enrollment Server enumeration
- Certificate Authority detection
- **Vulnerable certificate template detection via certipy** (ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC7, ESC8, ESC9, ESC10, ESC11, ESC13, ESC14, ESC15)

**Exchange**
- Default Exchange group detection (nested membership)
- WriteDACL/WriteOwner of Exchange groups on the domain object, read from the ACL (PrivExchange; detects whether the 2019 fix is applied)
- Organization Management membership

**Azure**
- Azure AD Connect detection
- AZUREADSSOACC security (Seamless SSO):
  - Unconstrained delegation disabled on account
  - Constrained delegation disabled (account can't delegate to other services)
  - Resource-based constrained delegation (RBCD) disabled on account
  - No other accounts can delegate to AZUREADSSOACC
  - Kerberos decryption key age (30-day renewal recommendation)

**SCCM / SCOM**
- SCCM System Management container detection
- SCOM management servers (`MSOMHSvc` SPN) and SDK service accounts (`MSOMSdkSvc` SPN)

**Backup**
- Veeam Backup & Replication server joined to the domain (`VeeamBackupSvc` SPN on a computer or service account, or TCP 9392 open on a Veeam infrastructure host; Veeam advises against joining it to the production domain)
- Domain-joined Veeam proxies/repositories (`VeeamTransportSvc`/`VeeamDeploySvc`) for review: backups on a domain-joined repository are reachable from the domain

**Group Policy (evaluated per computer)**

GPO-based checks take links, enforced links, block inheritance, security filtering and disabled computer settings into account; WMI filters, site links and same-level conflicts are reported for manual verification.
- WSUS over HTTP (with `UseWUServer`), per affected computer
- LLMNR not disabled, per computer
- LM hash storage enabled (`NoLMHash=0`)

**DC Vulnerabilities**
- Zerologon (CVE-2020-1472) - Domain takeover vulnerability
- NoPac (CVE-2021-42278/CVE-2021-42287) - Privilege escalation to Domain Admin

**NTLM Security**
- NTLMv1 support (LmCompatibilityLevel; only level 5 makes DCs refuse NTLMv1)
- NTLM restriction and audit policies (RestrictNTLMInDomain, AuditNTLMInDomain, RestrictSendingNTLMTraffic, RestrictReceivingNTLMTraffic, AuditReceivingNTLMTraffic)

**Network Services**
- IP resolution and /24 range calculation
- Port scanning (SMB, WinRM, RDP, MSSQL, HTTP)
- SMB signing enforcement and SMBv1 detection
- SMB null session (only when shares, users or the password policy can be enumerated) and guest access
- Domain admin sessions on non-DCs (nested Domain Admins)
- SMB/WinRM/MSSQL access checks via NetExec; RDP logon access only reported when the installed NetExec confirms the logon
- RDP NLA disabled detection
- WebClient service (for review, as a precondition for HTTP coercion and relay to LDAP) and CVE detection (NetExec `enum_cve`, incl. NTLM reflection)
- PrintSpooler on Domain Controllers

**LDAP Security**
- LDAP anonymous bind detection (unauthenticated access to domain data)
- LDAP signing requirements
- LDAPS channel binding configuration

**File Shares**
- SYSVOL: Group Policy Preferences passwords (`cpassword`, decrypted) and autologon passwords (`Registry.xml`)
- SYSVOL GPP values and GPO logon/startup scripts, and NETLOGON scripts: password keywords and credential command lines (`net use /user:`, `net user <name> <password>`, `-AsPlainText`, `PSCredential`, `schtasks /rp`, `psexec -p`, `sqlcmd -P`, `MapNetworkDrive` with a password), reported with the matching value or line for review

- Shares readable/writable by the current user on all SMB hosts (NetExec `--shares`, ACL-based write check); writable SYSVOL/NETLOGON as a finding
- MDT/WDS deployment shares (`DeploymentShare$`, `REMINST`): credentials in `Bootstrap.ini`, `CustomSettings.ini` and task sequence `Unattend.xml` (decoded); boot images listed for manual review

**SQL Server**
- MSSQL server discovery
- MSSQL sysadmin role detection
- Encryption configuration
- Linked servers (incl. login mappings) and impersonation
- Privilege escalation paths to sysadmin for the current user (impersonation chains, db_owner of a TRUSTWORTHY database; NetExec `mssql_priv`, enumeration only)
- Extended Protection / channel binding not required (NTLM relay to MSSQL); unverifiable when encryption isn't forced
- Login inventory (`enum_logins`, informational) and enabled `sa` login (for manual review)
- `xp_cmdshell` enabled

### External Tool Integration
- **Impacket** - Kerberoasting, AS-REP roasting, SMB/SYSVOL access, LSA user rights, security descriptor parsing
- **NetExec** - SMB enumeration, LDAP checks, SQL enumeration
- **Certipy** - ADCS certificate template vulnerability detection

## Startup Checks

The tool automatically verifies at startup:

1. **DNS Configuration** - Checks if DNS is set to the DC IP, attempts to auto-configure if running as root/admin
2. **netexec Availability** - Verifies `nxc`/`netexec` is installed and that required modules exist
3. **NetExec version** - Warns when the installed NetExec predates NetExec main from Oct 2026 (false LDAP signing results when NTLM is disabled, unconfirmed RDP access, missing `enum_cve` checks)
4. **certipy Availability** - Verifies `certipy` is installed

If a required tool is missing, the tool provides installation instructions and exits.

## Output

Results are written to `{domain}-{date}/` with three folders:

```
contoso.com-20260201/
├── findings/    # Issues to report (red)
├── checks/      # Requires manual review (yellow)
└── data/        # Raw enumeration data
```

## TODO

- [ ] Support Kerberos authentication
- [ ] Better netexec error handling
- [ ] Support more MSSQL checks from PowerUpSQL
