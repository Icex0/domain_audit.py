# Domain Audit Python Implementation Plan

## Overview

This document outlines the Python implementation of the `domain_audit.ps1` PowerShell script. The script is ~5000 lines with 44+ functions organized into logical categories.

### Cross-Platform Notes

- **Development Platform**: macOS (Unix-based)
- **Target Runtime**: Kali Linux (primary), other Linux distributions
- **Cross-Platform**: Python code is cross-platform. No platform-specific code expected.
- **External Tools**: All dependencies (impacket, ldap3, netexec, bloodhound) are Python-based and work on Linux.

## Architecture

```
domain_audit/
├── domain_audit.py           # Main entry point (CLI)
├── requirements.txt          # Dependencies
├── config.py                 # Configuration and constants
├── utils/
│   ├── __init__.py
│   ├── logger.py            # Logging utilities
│   ├── output.py            # Output directory management
│   ├── ldap.py              # LDAP connection handler
│   └── helpers.py           # Misc utilities
├── core/
│   ├── __init__.py
│   ├── auth.py              # Authentication (Impacket wrapper)
│   ├── connection.py        # AD connection management
│   └── exceptions.py        # Custom exceptions
├── modules/
│   ├── __init__.py
│   ├── enumeration.py       # ADEnum, Trust, Azure enum
│   ├── checks/              # Security checks package
│   │   ├── __init__.py      # SecurityChecker aggregator
│   │   ├── domain.py        # Domain functional level
│   │   ├── password.py      # Password policy, FGPP, Kerberos
│   │   ├── laps.py          # LAPS deployment
│   │   ├── description.py   # Description fields (Phase 5)
│   │   ├── roasting.py      # Kerberoasting (Phase 5)
│   │   ├── delegation.py    # Delegation (Phase 5)
│   │   └── user_attrs.py    # User attributes (Phase 5)
│   ├── attacks.py           # Kerberoasting, AS-REP, etc.
│   └── network.py           # SMB, port scanning
├── tools/
│   ├── __init__.py
│   ├── powermad.py          # Powermad (ADIDNS) wrapper
│   ├── bloodhound.py        # BloodHound.py wrapper
│   ├── impacket_cli.py      # Impacket scripts wrapper
│   └── netexec_cli.py       # NetExec wrapper
└── output/
    ├── __init__.py
    ├── formatters.py        # CSV, JSON formatters
    └── report.py            # Report generation
```

## Tool Mappings (PowerShell → Python)

| PowerShell Tool | Python Equivalent | Purpose |
|----------------|-------------------|---------|
| PowerView.ps1 | Custom LDAP queries | AD enumeration |
| PowerUpSQL.ps1 | `mssqlclient.py` (impacket) + netexec | MSSQL enumeration |
| Impacket | impacket library | Authentication, Kerberoasting |
| Powermad.ps1 | Custom implementation | ADIDNS attacks |
| Sharphound.ps1 | bloodhound.py | BloodHound data collection |
| GPRegistryPolicy | `python-registry` or custom | GPO parsing |
| CME/NetExec | netexec | SMB enumeration |
| Invoke-Portscan | python-nmap | Port scanning |
| LdapRelayScan | [LdapRelayScan](https://github.com/zyn3rgy/LdapRelayScan) | LDAP security checks |

## Implementation Phases

### Phase 1: Core Framework
- [ ] `domain_audit.py` - CLI with Click/Typer
- [ ] `config.py` - Configuration management
- [ ] `utils/logger.py` - Structured logging with color support
- [ ] `utils/output.py` - Output directory creation
- [ ] `core/auth.py` - Credential management and validation
- [ ] `core/connection.py` - LDAP connection handling

**Milestones**: CLI working, logging with colors, directory structure created

### Phase 2: Authentication Module
- [x] `core/auth.py` - Impacket integration for AD auth
- [x] Credential object creation
- [x] AD authentication test function
- [x] Support for NTLM/Kerberos authentication

**Dependencies**: `impacket`, `ldap3`

### Phase 3: Enumeration Module
- [ ] `modules/enumeration.py` - Core enumeration functions
- [x] Users enumeration (samaccountname, description, mail, SPN, UAC, lastlogon, pwdlastset)
- [x] Groups enumeration
- [x] Computers enumeration
- [x] GPO enumeration
- [x] OU enumeration
- [x] Domain Controllers enumeration
- [x] Domain SID retrieval
- [x] Privileged users enumeration (Domain/Enterprise Admins, etc.)

**Maps to**: `Invoke-ADEnum`, `Invoke-ADGetGroupNames`

### Phase 4: Security Checks - Part 1
- [x] `modules/checks/` - Security checks package
  - [x] `domain.py` - Domain functional level check
  - [x] `password.py` - Password policy, FGPP, Kerberos checks
  - [x] `laps.py` - LAPS deployment check
- [x] `Invoke-ADCheckDomainFunctionalLevel` - Domain functional level check
- [x] `Invoke-ADCheckPasspol` - Password policy check
- [x] `Invoke-ADCheckFineGrainedPasswordPolicy` - Fine-grained password policies
- [x] `Invoke-ADCheckPasspolKerberos` - Kerberos policy check
- [x] `Invoke-ADCheckLAPS` - LAPS deployment and configuration check

### Phase 5: Security Checks - Part 2
- [x] `modules/checks/description.py` - Sensitive info in description fields
- [x] `modules/checks/roasting.py` - Kerberoastable and AS-REP roastable accounts
- [x] `modules/checks/delegation.py` - Constrained/Unconstrained delegation
- [x] `modules/checks/user_attrs.py` - PASSWD_NOTREQD, password guessing

### Phase 6: Security Checks - Part 3
- [x] `modules/checks/outdated.py` - Outdated/inactive computers, privileged objects, domain join, Pre-Windows 2000

### Phase 7: ADIDNS and Exchange
- [x] `tools/powermad.py` - ADIDNS enumeration
- [x] `modules/checks/adidns.py` - ADIDNS permissions check
- [x] `modules/checks/exchange.py` - Exchange permissions and config
- [x] `modules/checks/adcs.py` - Certificate Services check

### Phase 8: Network and SMB
- [x] `modules/checks/network.py` - Network enumeration, IP resolution, port scanning, SMB checks, WebClient
- [x] `Invoke-ADGetIPInfo` - Resolve computer IPs and calculate /24 ranges
- [x] `Invoke-ADGetPortInfo` - Port scanning (TCP connect on common Windows ports)
- [x] `Invoke-ADCheckSMB` - SMB enumeration (signing, SMBv1)
- [x] `Invoke-ADCheckWebclient` - WebClient service check

### Phase 9: LDAP and SYSVOL
- [x] `Invoke-ADCheckLDAP` - LDAP signing and binding (via netexec)
- [x] `Invoke-ADCheckSysvolPassword` - SYSVOL password search
- [x] `Invoke-ADCheckNetlogonPassword` - NETLOGON password search
- [x] `Invoke-ADCheckPrintspoolerDC` - PrintSpooler on DCs

### Phase 10: Trust and Azure
- [x] `Invoke-ADEnumTrust` - Domain trust enumeration
- [x] `Invoke-ADEnumAzure` - Azure AD Connect checks

### Phase 11: BloodHound Integration
- [x] `modules/checks/bloodhound.py` - BloodHound wrapper using bloodhound-python
- [x] Default collection method (faster, essential data)
- [x] All, sessions, ACL collection methods available

### Phase 12: SQL and Advanced
- [x] `Invoke-ADCheckSQL` - SQL enumeration via netexec (enum_links, enum_impersonate)
- [ ] `Invoke-ADCheckAccess` - Access checks (SMB, RDP, WINRM, MSSQL local admin/access via netexec)

### Phase 13: Output and Reporting
- [ ] `output/formatters.py` - JSON output
- [ ] `output/report.html` - Consolidated HTML report generation

### Phase 14: Polish and Integration
- [ ] Documentation and examples

## Data Structures

### Domain Data
```python
@dataclass
class DomainInfo:
    name: str
    sid: str
    functional_level: str
    user_count: int
    group_count: int
    computer_count: int
    dc_count: int
```

### Check Result
```python
@dataclass
class CheckResult:
    name: str
    status: str  # 'PASS', 'FAIL', 'WARNING', 'INFO'
    message: str
    data: Any
    output_file: Optional[str]
```

### Credentials
```python
@dataclass
class Credentials:
    domain: str
    username: str
    password: str
    lm_hash: Optional[str]
    nt_hash: Optional[str]
    use_kerberos: bool = False
```

## Output Structure

```
{output_dir}/{domain}-{date}/
├── findings/          # Security findings (red)
├── checks/           # Manual checks needed (yellow)
└── data/             # Raw enumeration data (white)
```

## Key Dependencies

```
impacket>=0.11.0
ldap3>=2.9.1
click>=8.0.0
rich>=13.0.0
python-nmap>=0.7.1
pyyaml>=6.0
pycryptodome>=3.20.0
dnspython>=2.4.0
```

## Usage Examples

```bash
# Setup virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run all checks
python run.py run -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!'

# Skip BloodHound
python run.py run -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!' --skip-bloodhound

# Skip roasting attacks
python run.py run -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!' --skip-roasting

# Specific check
python run.py check -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!' laps

# Pass the hash
python run.py run -d contoso.com -dc 10.0.0.1 -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

## Development Notes

1. **Modular Design**: Each check is independent with clear interfaces
2. **Error Handling**: Graceful degradation when checks fail
3. **Caching**: Cache LDAP queries to avoid repeated requests
4. **Concurrency**: Use async/threading for network operations
5. **Progress**: Show progress for long-running operations
6. **Output**: Consistent CSV/JSON output for all data
7. **Logging**: Color-coded output matching PowerShell version

## File Mapping Reference

| PowerShell Function | Python Module | Status |
|--------------------|---------------|--------|
| `Invoke-ADCheckAll` | `domain_audit.py::main()` | Phase 14 |
| `Create-CredentialObject` | `core/auth.py::Credentials` | Phase 2 |
| `Test-ADAuthentication` | `core/auth.py::test_auth()` | Phase 2 |
| `New-OutputDirectory` | `utils/output.py::create_output_dir()` | Phase 1 |
| `Invoke-ADEnum` | `modules/enumeration.py` | Phase 3 |
| `Invoke-ADGetGroupNames` | `modules/enumeration.py::get_privileged_groups()` | Phase 3 |
| `Invoke-ADCheckDomainFunctionalLevel` | `modules/checks.py::check_domain_level()` | Phase 4 |
| `Invoke-ADCheckPasspol` | `modules/checks.py::check_password_policy()` | Phase 4 |
| `Invoke-ADCheckLAPS` | `modules/checks.py::check_laps()` | Phase 4 |
| `Invoke-ADCheckRoasting` | `modules/attacks.py::check_roasting()` | Phase 5 |
| `Invoke-ADCheckDelegation` | `modules/checks.py::check_delegation()` | Phase 5 |
| `Invoke-ADCheckADIDNS` | `tools/powermad.py` | Phase 7 |
| `Invoke-ADCheckSMB` | `modules/network.py::check_smb()` | Phase 8 |
| `Invoke-BloodHound` | `tools/bloodhound.py` | Phase 11 |

---

*Last Updated: 2026-01-31*
*Next Step: Phase 1 - Core Framework*
