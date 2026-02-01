"""Core configuration and constants for domain_audit."""

from dataclasses import dataclass
from typing import Optional, List
from pathlib import Path

# Domain functional levels mapping
DOMAIN_FUNCTIONAL_LEVELS = {
    0: "Windows 2000 native",
    1: "Windows 2003 interim",
    2: "Windows 2003",
    3: "Windows 2008",
    4: "Windows 2008 R2",
    5: "Windows 2012",
    6: "Windows 2012 R2",
    7: "Windows 2016",
    8: "Windows 2019",
    9: "Windows 2022",
    10: "Windows 2025"
}

# Well-known SIDs
WELL_KNOWN_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-580": "Remote Management Users",
    "S-1-5-32-578": "Hyper-V Administrators",
}

# Relative identifiers for domain-specific groups
DOMAIN_RIDS = {
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}

LDAP_PORT = 389
LDAPS_PORT = 636
SMB_PORT = 445

DEFAULT_OUTPUT_DIRS = {
    "findings": "findings",
    "checks": "checks",
    "data": "data"
}

ADMIN_THRESHOLD_PERCENTAGE = 5.0

# EOL Operating System patterns and versions
EOL_OS_PATTERNS = [
    'Windows 7',
    'Windows 8',
    'Windows Server 2008',
    'Windows Server 2003',
    'XP'
]

# Windows 10 End of Service versions (build numbers)
WIN10_EOS_VERSIONS = ['19043', '19042', '19041', '18363', '18362', '17134', '16299', '15063', '10586']
WIN10_VERSION_NAMES = {
    '19043': '21H1',
    '19041': '2004',
    '18363': '1909',
    '18362': '1903',
    '17134': '1803',
    '16299': '1709',
    '15063': '1703',
    '10586': '1511'
}

# Windows 11 End of Service versions (build numbers)
WIN11_EOS_VERSIONS = ['22000', '22621']
WIN11_VERSION_NAMES = {
    '22000': '21H2',
    '22621': '22H2'
}

# SYSVOL password search keywords (checked in XML files under Policies)
SYSVOL_PASSWORD_KEYWORDS = [
    'password',
    'pwd',
    'pass',
    'secret',
    'credential',
    'token',
    'auth',
    'wachtwoord',
    'ww',
    'authentication'
]

# NETLOGON password search keywords (checked in all files)
NETLOGON_PASSWORD_KEYWORDS = [
    'pass',
    'password',
    'pwd',
    'secret',
    'credential',
    'token',
    'auth',
    'wachtwoord',
    'ww',
    'authentication'
]


@dataclass
class Config:
    """Application configuration."""
    domain: str
    server: str
    username: str
    password: str
    output_directory: Optional[Path] = None
    use_ldaps: bool = False
    use_kerberos: bool = False
    lm_hash: Optional[str] = None
    nt_hash: Optional[str] = None
    verbose: bool = False
    skip_bloodhound: bool = False
    skip_roasting: bool = False
    
    @property
    def domain_fqdn(self) -> str:
        """Return fully qualified domain name."""
        return self.domain.lower()
    
    @property
    def dc_host(self) -> str:
        """Return DC host for connection string."""
        return self.server
