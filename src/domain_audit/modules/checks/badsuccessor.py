"""BadSuccessor (dMSA) check.

With a Windows Server 2025 DC, an account that can create a delegated Managed
Service Account (dMSA) in an OU can link it to another account and act as that
account (Akamai, May 2025). Creating a dMSA needs, on the OU: CreateChild for all
objects or for msDS-DelegatedManagedServiceAccount, GenericAll, or WriteDACL /
WriteOwner / ownership (to grant itself those rights).

Since the August 2025 update (CVE-2025-53779) the KDC requires a mutual link, so
direct escalation to any account is blocked; the technique still works on
accounts the attacker already controls. The DC patch level is reported by the
network check (enum_cve, CVE-2025-53779).

NetExec's badsuccessor module is not used: it only evaluates plain ACEs (type 0),
so delegated "create dMSA" rights (object ACEs) are missed.
"""

import uuid
from pathlib import Path
from typing import Dict, List, Set

from impacket.ldap import ldaptypes

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
from ...utils.acl import (ADS_RIGHT_DS_CREATE_CHILD, SD_FLAGS_OWNER_GROUP_DACL, WRITE_DAC, WRITE_OWNER,
                          right_decisions)
from ...utils.user_rights import DCUserRights

# Not "normal users": admins/system, plus principals that only appear on
# inherit-style ACEs (CREATOR OWNER, SELF) - handled before classification.
IGNORED_SIDS = {'S-1-3-0', 'S-1-5-10'}


class BadSuccessorChecker:
    """Finds OUs where non-admins can create dMSAs (BadSuccessor)."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], domain: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.rights = DCUserRights(ldap_conn, self.logger, domain)

    def _dmsa_class_guid(self):
        try:
            config_dn = self.ldap.get_config_dn()
        except Exception:
            config_dn = f"CN=Configuration,{self.base_dn}"
        self.ldap.connection.search(f"CN=Schema,{config_dn}", '(lDAPDisplayName=msDS-DelegatedManagedServiceAccount)',
                                    attributes=['schemaIDGUID'])
        if not self.ldap.connection.entries:
            return None
        return str(uuid.UUID(bytes_le=self.ldap.connection.entries[0]['schemaIDGUID'].raw_values[0]))

    def _ou_principals(self, sd_raw: bytes, dmsa_guid: str) -> Set[str]:
        """SIDs that can create a dMSA in this OU, or can grant themselves that right."""
        sids = {sid for sid, ok in right_decisions(sd_raw, ADS_RIGHT_DS_CREATE_CHILD, dmsa_guid).items() if ok}
        sids |= {sid for sid, ok in right_decisions(sd_raw, WRITE_DAC | WRITE_OWNER).items() if ok}
        owner = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw)['OwnerSid']
        if owner:
            sids.add(owner.formatCanonical())   # the owner can always rewrite the DACL
        return sids - IGNORED_SIDS

    def check_badsuccessor(self):
        self.logger.info("---Checking for BadSuccessor (dMSA creation rights on OUs)---")
        try:
            dmsa_guid = self._dmsa_class_guid()
            if not dmsa_guid:
                self.logger.success("[+] No dMSA class in the schema (no Windows Server 2025 schema) - BadSuccessor not applicable")
                return

            dcs = self.ldap.query(self.base_dn,
                                  '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                                  ['sAMAccountName', 'operatingSystem'])
            dc2025 = [d.get('sAMAccountName', '') for d in dcs if '2025' in (d.get('operatingSystem') or '')]

            entries = [e for e in self.ldap.connection.extend.standard.paged_search(
                search_base=self.base_dn, search_filter='(objectClass=organizationalUnit)',
                attributes=['distinguishedName', 'nTSecurityDescriptor'], controls=SD_FLAGS_OWNER_GROUP_DACL,
                paged_size=500, generator=False) if e.get('type') == 'searchResEntry']

            by_principal: Dict[str, List[str]] = {}
            unreadable = 0
            for entry in entries:
                raw = entry.get('raw_attributes', {}).get('nTSecurityDescriptor') or []
                if not raw:
                    unreadable += 1
                    continue
                for sid in self._ou_principals(raw[0], dmsa_guid):
                    by_principal.setdefault(sid, []).append(entry['dn'])

            findings: List[str] = []
            for sid, ous in sorted(by_principal.items()):
                for description in self.rights.non_admin_principals({sid}):
                    findings.append(f"{description}")
                    findings.extend(f"    OU: {ou}" for ou in sorted(ous))

            if unreadable:
                self.logger.warning(f"[!] Could not read the security descriptor of {unreadable} OU(s) - results incomplete")

            if not findings:
                self.logger.success(f"[+] No non-admin principals can create dMSAs in any of the {len(entries)} OUs")
                return

            if dc2025:
                self.logger.finding(
                    f"Non-admins can create dMSAs in OUs and there are Windows Server 2025 DCs ({', '.join(dc2025)}) - "
                    "BadSuccessor; full escalation if the DCs lack the Aug 2025 update (CVE-2025-53779, see enum_cve)"
                )
                target = self.output_paths['findings'] / 'badsuccessor_dmsa_ou_permissions.txt'
            else:
                self.logger.warning("[!] Non-admins can create dMSAs in OUs, but no Windows Server 2025 DC was found - "
                                    "becomes exploitable once a 2025 DC is added")
                target = self.output_paths['checks'] / 'badsuccessor_dmsa_ou_permissions.txt'
            write_lines([f"Windows Server 2025 DCs: {', '.join(dc2025) or 'none'}",
                         "Principals that can create dMSAs (CreateChild all/dMSA, GenericAll, WriteDACL, WriteOwner or owner):",
                         ""] + findings, target)
        except Exception as e:
            self.logger.error(f"[-] Error checking BadSuccessor: {e}")
