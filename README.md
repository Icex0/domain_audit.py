# Domain Audit

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
docker run --rm -it -v $(pwd)/results:/data domain-audit -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!'
```

## Usage

```bash
# Run full audit
domain-audit -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!'

# Use LDAPS
domain-audit -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!' --ldaps

# Skip BloodHound collection
domain-audit -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!' --skip-bloodhound

# Skip Kerberoasting/AS-REP roasting
domain-audit -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!' --skip-roasting

# List available checks
domain-audit -L

# Run specific check
domain-audit --check adcs -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!'
```

## What It Does

### Enumeration
- Users, groups, computers, OUs, GPOs
- Domain Controllers and domain SID
- Privileged users (Domain Admins, Enterprise Admins, etc.)
- Domain trusts

### Security Checks

**Domain & Password Policy**
- Domain functional level assessment
- Default password policy (length, complexity, lockout)
- Fine-Grained Password Policies (FGPP) enumeration
- Kerberos policy settings (ticket lifetime, encryption types)

**LAPS**
- Schema detection (Legacy LAPS vs Windows LAPS)
- Deployment coverage across computer objects
- Computers without LAPS enabled
- LAPS password readability check (current user permissions)
- LAPS policy configuration (AdminAccountName, PasswordComplexity, PasswordLength, PasswordAgeDays, PwdExpirationProtectionEnabled, AdmPwdEnabled)

**Kerberos Attacks**
- Kerberoastable accounts (SPNs on user accounts)
- AS-REP roastable accounts (DONT_REQ_PREAUTH)
- Extracts hashes for offline cracking via Impacket

**Delegation**
- Unconstrained delegation on users and computers
- Constrained delegation (S4U2Self/S4U2Proxy)
- Resource-Based Constrained Delegation (RBCD)

**User Attributes**
- PASSWD_NOTREQD flag (accounts that can have empty passwords)
- DONT_EXPIRE_PASSWORD flag
- Reversible encryption enabled
- DES-only Kerberos encryption
- Sensitive data in user/group/computer descriptions
- userPassword attribute exposed (cleartext or hashed passwords)

**Privileged Accounts**
- Protected Users group membership
- NOT_DELEGATED flag on admin accounts
- Password age for privileged users (>180 days)
- KRBTGT password age
- Membership of highly privileged groups (Account Operators, Backup Operators, Print Operators, DNS Admins, Schema Admins)

**Stale Objects**
- Inactive computers and users (no logon in 6+ months)
- End-of-life operating systems (Server 2008/2012, Windows 7/10 EOL builds)
- Pre-Windows 2000 Compatible Access group membership
- ANONYMOUS LOGON (S-1-5-7) group membership detection (warns when combined with Authenticated Users)
- Pre-Windows 2000 computer password spraying list generation
- Domain join permissions (ms-DS-MachineAccountQuota)

**Trusts**
- Domain trust enumeration
- Trust direction and type analysis
- SID filtering status (SID history injection risk)

**ADIDNS**
- Zone permissions for authenticated users
- Wildcard record detection

**Certificates (ADCS)**
- PKI Enrollment Server enumeration
- Certificate Authority detection
- **Vulnerable certificate template detection via certipy** (ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC7, ESC8, ESC9, ESC10, ESC11, ESC13, ESC14, ESC15)

**Exchange**
- Default Exchange group detection
- Exchange Windows Permissions WriteDACL escalation path (PrivExchange)
- Organization Management privilege escalation risk

**Azure**
- Azure AD Connect detection
- AZUREADSSOACC security (Seamless SSO):
  - Unconstrained delegation disabled on account
  - Constrained delegation disabled (account can't delegate to other services)
  - Resource-based constrained delegation (RBCD) disabled on account
  - No other accounts can delegate to AZUREADSSOACC
  - Kerberos decryption key age (30-day renewal recommendation)

**SCCM**
- SCCM System Management container detection

**WSUS**
- WSUS server configuration via GPO (SYSVOL)
- HTTP vs HTTPS detection (HTTP is vulnerable to MITM attacks via WSUSpect/wsuks)

**DC Vulnerabilities**
- Zerologon (CVE-2020-1472) - Domain takeover vulnerability
- NoPac (CVE-2021-42278/CVE-2021-42287) - Privilege escalation to Domain Admin

**NTLM Security**
- NTLMv1 support detection (LmCompatibilityLevel 0/1/2 vulnerable to downgrade/relay attacks)
- NTLM restriction policies (RestrictNTLMInDomain, RestrictSendingNTLMTraffic, RestrictReceivingNTLMTraffic)
- LLMNR enabled detection (vulnerable to Responder credential capture)

**Network Services**
- IP resolution and /24 range calculation
- Port scanning (SMB, WinRM, RDP, MSSQL, HTTP)
- SMB signing enforcement
- SMBv1 detection
- SMB null session authentication check
- SMB guest access check
- Domain admin sessions on non-DCs
- SMB/RDP/WinRM/MSSQL access checks (local admin access via netexec)
- RDP NLA disabled detection
- WebClient service detection
- NTLM reflection vulnerability detection
- PrintSpooler on Domain Controllers

**LDAP Security**
- LDAP anonymous bind detection (unauthenticated access to domain data)
- LDAP signing requirements
- LDAPS channel binding configuration

**File Shares**
- SYSVOL password searches (GPP, scripts)
- NETLOGON script analysis for credentials

**SQL Server**
- MSSQL server discovery
- MSSQL sysadmin role detection
- Encryption configuration
- Linked server enumeration
- Impersonation checks

### External Tool Integration
- **Impacket** - Kerberoasting, AS-REP roasting, authentication
- **NetExec** - SMB enumeration, LDAP checks, SQL enumeration
- **Certipy** - ADCS certificate template vulnerability detection

## Startup Checks

The tool automatically verifies at startup:

1. **DNS Configuration** - Checks if DNS is set to the DC IP, attempts to auto-configure if running as root/admin
2. **netexec Availability** - Verifies `nxc`/`netexec` is installed
3. **certipy Availability** - Verifies `certipy` is installed

If any check fails, the tool provides installation instructions and exits.

## Output

Results are written to `{domain}-{date}/` with three folders:

```
contoso.com-20260201/
├── findings/    # Issues to report (red)
├── checks/      # Requires manual review (yellow)
└── data/        # Raw enumeration data
```
