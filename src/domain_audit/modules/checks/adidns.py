"""ADIDNS security checks."""

from typing import Dict, Optional
from pathlib import Path

import ldap3

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
from ...utils.acl import ADS_RIGHT_DS_CREATE_CHILD, right_decisions
from ...tools.powermad import ADIDNSEnumerator

# schemaIDGUID of the dnsNode class (DNS records are dnsNode child objects)
DNS_NODE_CLASS_GUID = 'e0fa1e8c-9b45-11d0-afdd-00c04fd930c9'


def _low_privilege_sids(domain_sid: Optional[str]) -> Dict[str, str]:
    sids = {
        'S-1-5-11': 'Authenticated Users',
        'S-1-1-0': 'Everyone',
        'S-1-5-7': 'Anonymous Logon',
        'S-1-5-32-545': 'Users',
    }
    if domain_sid:
        sids[f'{domain_sid}-513'] = 'Domain Users'
        sids[f'{domain_sid}-515'] = 'Domain Computers'
    return sids


def evaluate_create_child(sd_raw: bytes, principals: Dict[str, str]) -> Dict[str, bool]:
    """Return {sid: allowed} for principals that have an ACE granting/denying
    the right to create dnsNode children on the zone itself (see utils.acl)."""
    return right_decisions(sd_raw, ADS_RIGHT_DS_CREATE_CHILD, DNS_NODE_CLASS_GUID, principals.keys())


class ADIDNSChecker:
    """Checks for ADIDNS permissions and configuration."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], domain: str = None,
                 username: str = None, password: str = None, hashes: str = None):
        self.username = username
        self.password = password
        self.hashes = hashes
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain or ldap_conn.config.domain

        # Get server from LDAP connection
        self.server = ldap_conn.config.server

    def check_adidns(self):
        """Run all ADIDNS security checks."""
        can_create = self._check_adidns_permissions()
        self._check_adidns_wildcard(can_create)
        self._check_dynamic_updates()

    # [MS-DNSP] 2.3.2.1 dnsProperty: DataLength, NameLength, Flag, Version, Id (all
    # uint32 LE), then Data. Id 0x02 = DSPROPERTY_ZONE_ALLOW_UPDATE with fAllowUpdate:
    # 0 = no dynamic updates, 1 = nonsecure and secure, 2 = secure only.
    DSPROPERTY_ZONE_ALLOW_UPDATE = 0x02
    ZONE_UPDATE_UNSECURE = 0x01

    @classmethod
    def zone_allow_update(cls, properties) -> Optional[int]:
        """Return fAllowUpdate from a zone's raw dNSProperty values, or None."""
        import struct
        for raw in properties or []:
            if len(raw) < 20:
                continue
            data_len, _name_len, _flag, _version, prop_id = struct.unpack('<5I', raw[:20])
            if prop_id == cls.DSPROPERTY_ZONE_ALLOW_UPDATE and data_len:
                return int.from_bytes(raw[20:20 + data_len], 'little')
        return None

    def _check_dynamic_updates(self):
        """Find AD-integrated DNS zones that allow nonsecure dynamic updates.

        With "Nonsecure and secure" anyone who can reach the DNS server - no
        account needed - can register or overwrite records with a plain DNS
        UPDATE. Microsoft recommends "Secure only" for AD-integrated zones.
        """
        self.logger.info("---Checking DNS zones for nonsecure dynamic updates---")
        try:
            try:
                forest_dn = self.ldap.get_config_dn().split(',', 1)[1]
            except Exception:
                forest_dn = self.base_dn
            bases = {
                'domain': f"DC=DomainDnsZones,{self.base_dn}",
                'forest': f"DC=ForestDnsZones,{forest_dn}",
                'legacy (System)': f"CN=MicrosoftDNS,CN=System,{self.base_dn}",
            }
            nonsecure, checked = [], 0
            for label, base in bases.items():
                try:
                    self.ldap.connection.search(base, '(objectClass=dnsZone)', ldap3.SUBTREE,
                                                attributes=['name', 'dNSProperty'])
                except Exception as e:
                    self.logger.debug(f"Could not search {base}: {e}")
                    continue
                for entry in self.ldap.connection.entries:
                    raw = entry['dNSProperty'].raw_values if 'dNSProperty' in entry else []
                    value = self.zone_allow_update(raw)
                    if value is None:
                        continue
                    checked += 1
                    if value == self.ZONE_UPDATE_UNSECURE:
                        nonsecure.append(f"{entry['name'].value} ({label} zone)")
            
            if nonsecure:
                self.logger.finding(f"{len(nonsecure)} DNS zone(s) allow nonsecure dynamic updates: {', '.join(nonsecure)}")
                write_lines(["DNS zones allowing nonsecure dynamic updates (anyone can register/overwrite records):"] +
                            [f"  - {z}" for z in nonsecure] +
                            ["", "Recommendation: set dynamic updates to 'Secure only' for AD-integrated zones."],
                            self.output_paths['findings'] / 'DNS_nonsecure_dynamic_updates.txt')
            elif checked:
                self.logger.success(f"[+] None of the {checked} DNS zones allow nonsecure dynamic updates")
            else:
                self.logger.info("[*] No DNS zone update settings could be read")
        except Exception as e:
            self.logger.error(f"[-] Error checking DNS dynamic update settings: {e}")

    def _check_adidns_permissions(self) -> Optional[bool]:
        """Check whether low-privileged principals can add DNS records to the zone.

        Returns True/False, or None if the zone or its ACL couldn't be read.
        """
        self.logger.info("---Checking ADIDNS permissions---")

        try:
            try:
                domain_sid = self.ldap.get_domain_sid()
            except Exception:
                domain_sid = None
            principals = _low_privilege_sids(domain_sid)

            # Try different partitions to find the DNS zone
            partitions = ["DomainDNSZones", "ForestDNSZones", "System"]

            for partition in partitions:
                try:
                    # Build the search base for this partition
                    if partition == "System":
                        search_base = f"CN={partition}"
                    else:
                        search_base = f"DC={partition}"

                    for dc in self.domain.split('.'):
                        search_base += f",DC={dc}"

                    # Search for the zone with security descriptor
                    self.ldap.connection.search(
                        search_base=search_base,
                        search_filter=f'(&(objectClass=dnsZone)(name={self.domain}))',
                        attributes=['distinguishedName', 'nTSecurityDescriptor'],
                        search_scope=ldap3.SUBTREE,
                        controls=[('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]  # Request DACL
                    )
                except Exception:
                    continue

                if not self.ldap.connection.entries:
                    continue

                entry = self.ldap.connection.entries[0]
                zone_dn = str(entry.entry_dn)
                raw_values = entry['nTSecurityDescriptor'].raw_values
                sd_raw = raw_values[0] if raw_values else None

                if not sd_raw:
                    self.logger.info("[*] Could not read security descriptor - insufficient permissions")
                    return None

                try:
                    decisions = evaluate_create_child(sd_raw, principals)
                except Exception as e:
                    self.logger.info(f"[*] Could not parse security descriptor: {e}")
                    return None

                allowed_sids = [sid for sid, ok in decisions.items() if ok]
                allowed = [principals[sid] + f" ({sid})" for sid in allowed_sids]
                lines = [f"Zone: {self.domain}",
                         f"Partition: {partition}",
                         f"DN: {zone_dn}",
                         "Principals with CreateChild (dnsNode) on the zone:"] + [f"  - {a}" for a in allowed]
                
                if domain_sid and allowed_sids == [f'{domain_sid}-515']:
                    # Only Domain Computers: the recommended hardening for secure dynamic
                    # DNS. Only effective if normal users can't create computer accounts.
                    return self._domain_computers_only(lines)
                
                if allowed:
                    self.logger.finding(f"Low-privileged principals can add DNS records (CreateChild): {', '.join(allowed)}")
                    write_lines(lines, self.output_paths['findings'] / 'ADIDNS_authenticated_users.txt')
                    return True

                self.logger.success("[+] Low-privileged principals cannot add DNS records (no CreateChild permission)")
                return False

            self.logger.info("[*] No ADIDNS zone found (may not exist or insufficient permissions)")
            return None

        except Exception as e:
            self.logger.error(f"[-] Error checking ADIDNS permissions: {e}")
            return None

    def _domain_computers_only(self, lines) -> Optional[bool]:
        """Only Domain Computers can add records (instead of Authenticated Users).

        That stops normal users only when they can't create computer accounts
        (MachineAccountQuota > 0 and SeMachineAccountPrivilege, see
        utils.user_rights.users_can_create_computers). Any computer account an
        attacker controls (e.g. a compromised host) can still add records.
        Returns True/False/None like _check_adidns_permissions.
        """
        from ...utils.user_rights import users_can_create_computers
        try:
            creation = users_can_create_computers(self.ldap, self.logger, self.domain,
                                                  self.username, self.password, self.hashes)
        except Exception as e:
            self.logger.debug(f"Could not determine whether users can create computer accounts: {e}")
            creation = None
        
        lines = lines + ["", "Only Domain Computers can add records (hardening for secure dynamic DNS registration)."]
        if creation is not None and creation.possible:
            self.logger.finding(
                f"Only Domain Computers can add DNS records, but normal users can create computer accounts "
                f"(MachineAccountQuota {creation.quota}) and use one to add records"
            )
            lines += [f"Bypass: MachineAccountQuota is {creation.quota} and 'Add workstations to domain' is held by: "
                      f"{'; '.join(p.split(' - ')[0] for p in creation.principals)}",
                      "Any user can create a computer account (e.g. addcomputer.py / Powermad) and use it to add DNS records."]
            write_lines(lines, self.output_paths['findings'] / 'ADIDNS_authenticated_users.txt')
            return True
        if creation is not None and creation.possible is False:
            self.logger.success("[+] Only Domain Computers can add DNS records and normal users can't create computer accounts")
            self.logger.info("[*] Residual risk: any compromised computer account can still add DNS records")
            write_lines(lines + ["Normal users can't create computer accounts (MachineAccountQuota / 'Add workstations to domain'), "
                                 "so this requires control of an existing computer account."],
                        self.output_paths['checks'] / 'ADIDNS_permissions.txt')
            return False
        self.logger.warning("[!] Only Domain Computers can add DNS records - verify whether normal users can create "
                            "computer accounts (MachineAccountQuota / 'Add workstations to domain')")
        write_lines(lines + ["Whether normal users can create computer accounts could not be determined - verify manually."],
                    self.output_paths['checks'] / 'ADIDNS_permissions.txt')
        return None
    
    def _check_adidns_wildcard(self, can_create: Optional[bool]):
        """Check for ADIDNS wildcard record.

        Without a wildcard ('*') record, any user who can create records can add
        one and receive all otherwise unresolved lookups. That is only a finding
        when low-privileged users can create records.
        """
        self.logger.info("---Checking ADIDNS wildcard record---")

        try:
            enumerator = ADIDNSEnumerator(self.ldap, self.domain, self.server)

            # Try different partitions for wildcard
            partitions = ["DomainDNSZones", "ForestDNSZones", "System"]
            wildcard_exists = False

            for partition in partitions:
                try:
                    if enumerator.check_wildcard_record(self.domain, partition):
                        wildcard_exists = True
                        break
                except Exception:
                    continue

            if wildcard_exists:
                self.logger.success("[+] Wildcard record in ADIDNS exists")
            elif can_create:
                self.logger.finding("No wildcard record in ADIDNS and low-privileged users can add records - wildcard poisoning possible")
                write_lines(
                    ["No wildcard DNS record found and low-privileged users can create records",
                     "- ADIDNS wildcard poisoning is possible"],
                    self.output_paths['findings'] / 'ADIDNS_wildcard_record.txt'
                )
            elif can_create is False:
                self.logger.success("[+] No wildcard record in ADIDNS, but low-privileged users can't add records")
            else:
                self.logger.warning("[!] No wildcard record in ADIDNS - could not determine whether users can add records (verify manually)")
                write_lines(
                    ["No wildcard DNS record found; zone permissions could not be checked - verify manually"],
                    self.output_paths['checks'] / 'ADIDNS_wildcard_record.txt'
                )

        except Exception as e:
            self.logger.error(f"[-] Error checking ADIDNS wildcard: {e}")
