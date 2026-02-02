# Domain Audit

Active Directory security auditing tool. Python port of [`domain_audit.ps1`](https://github.com/0xJs/domain_audit).

## Requirements

- Python 3.10+
- Network access to target Domain Controller
- Valid AD credentials (password or NTLM hash)
- **netexec** - Install with: `pipx install git+https://github.com/Pennyw0rth/NetExec`
- **certipy** - Install with: `pipx install certipy-ad`

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

## Usage

```bash
# Run full audit
domain-audit run -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!'

# Pass-the-hash
domain-audit run -d contoso.com -dc 10.0.0.1 -u admin -H aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Use LDAPS
domain-audit run -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!' --ldaps

# Skip BloodHound collection
domain-audit run -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!' --skip-bloodhound

# Skip Kerberoasting/AS-REP roasting
domain-audit run -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!' --skip-roasting
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
- Deployment coverage across computer objects
- Legacy LAPS vs Windows LAPS detection
- GPO deployment check
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
- Legacy Exchange permissions

**Azure**
- Azure AD Connect detection

**SCCM**
- SCCM System Management container detection

**Network Services**
- IP resolution and /24 range calculation
- Port scanning (SMB, WinRM, RDP, MSSQL, HTTP)
- SMB signing enforcement
- SMBv1 detection
- WebClient service detection
- PrintSpooler on Domain Controllers

**LDAP Security**
- LDAP signing requirements
- LDAPS channel binding configuration

**File Shares**
- SYSVOL password searches (GPP, scripts)
- NETLOGON script analysis for credentials

**SQL Server**
- MSSQL server discovery
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
