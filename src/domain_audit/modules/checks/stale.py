"""End-of-life operating systems and inactive objects."""

import re
from datetime import date
from ...config import (
    EOL_OS_PATTERNS,
    WIN10_EOS_VERSIONS,
    WIN10_LONG_TERM_SUPPORT,
    WIN10_VERSION_NAMES,
    WIN11_EDITION_LIFECYCLE,
    WIN11_EOS_VERSIONS,
    WIN11_VERSION_NAMES,
)
from ...utils.output import write_csv
from ...utils.timeutil import older_than


class StaleObjectsMixin:
    """Mixin for OutdatedChecker (expects self.ldap, self.output_paths, self.logger, self.base_dn)."""

    @staticmethod
    def _extract_os_build(version: str) -> str:
        """Extract Windows build from AD formats like '10.0 (19045)' or '10.0.19045'."""
        if not version:
            return ''

        parenthesized = re.search(r'\((\d{5})\)', version)
        if parenthesized:
            return parenthesized.group(1)

        parts = version.split('.')
        if len(parts) > 2 and parts[2].isdigit():
            return parts[2]

        standalone = re.search(r'\b(\d{5})\b', version)
        return standalone.group(1) if standalone else ''

    @staticmethod
    def _has_supported_win10_long_term_lifecycle(os: str, build: str) -> bool:
        os_lower = os.lower()
        for release in WIN10_LONG_TERM_SUPPORT:
            if release['build'] != build:
                continue
            if not any(marker.lower() in os_lower for marker in release['markers']):
                continue
            return date.today() <= date.fromisoformat(release['end_date'])
        return False

    @staticmethod
    def _is_win11_eos(os: str, build: str) -> bool:
        """Return True if this Windows 11 build/edition is past its end of servicing."""
        if build in WIN11_EOS_VERSIONS:
            return True
        os_lower = os.lower()
        for release in WIN11_EDITION_LIFECYCLE.get(build, []):
            if any(marker.lower() in os_lower for marker in release['markers']):
                return date.today() > date.fromisoformat(release['end_date'])
        return False

    def _check_outdated_computers(self):
        """Check for EOL operating systems in AD."""
        self.logger.info("---Checking for EOL operating systems---")
        
        try:
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=computer)',
                attributes=['sAMAccountName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp']
            )
            
            if not computers:
                self.logger.info("[*] No computers found")
                return
            
            # Check EOL OS
            eol_computers = []
            for comp in computers:
                os = comp.get('operatingSystem') or ''
                if any(pattern in os for pattern in EOL_OS_PATTERNS):
                    eol_computers.append(comp)
            
            if eol_computers:
                self.logger.finding(f"{len(eol_computers)} computers with EOL operating systems")
                write_csv(eol_computers, self.output_paths['findings'] / 'computers_OS_EOL.txt')
            else:
                self.logger.success("[+] No EOL operating systems found")
            
            # Check Windows 10 End of Service
            win10_eos = []
            for comp in computers:
                os = comp.get('operatingSystem') or ''
                version = comp.get('operatingSystemVersion') or ''
                if 'Windows 10' in os:
                    build = self._extract_os_build(version)
                    if build in WIN10_EOS_VERSIONS and not self._has_supported_win10_long_term_lifecycle(os, build):
                        readable = WIN10_VERSION_NAMES.get(build, build)
                        comp['operatingSystemVersion'] = version.replace(build, readable)
                        win10_eos.append(comp)
            
            if win10_eos:
                self.logger.finding(f"{len(win10_eos)} Windows 10 computers with End of Service versions")
                write_csv(win10_eos, self.output_paths['findings'] / 'computers_W10_EOS.txt')
            else:
                self.logger.success("[+] No Windows 10 End of Service versions found")
            
            # Check Windows 11 End of Service
            win11_eos = []
            for comp in computers:
                os = comp.get('operatingSystem') or ''
                version = comp.get('operatingSystemVersion') or ''
                if 'Windows 11' in os:
                    build = self._extract_os_build(version)
                    if self._is_win11_eos(os, build):
                        readable = WIN11_VERSION_NAMES.get(build, build)
                        comp['operatingSystemVersion'] = version.replace(build, readable)
                        win11_eos.append(comp)
            
            if win11_eos:
                self.logger.finding(f"{len(win11_eos)} Windows 11 computers with End of Service versions")
                write_csv(win11_eos, self.output_paths['findings'] / 'computers_W11_EOS.txt')
            else:
                self.logger.success("[+] No Windows 11 End of Service versions found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking outdated computers: {e}")

    def _check_inactive_objects(self):
        """Check for inactive computers and users (365+ days)."""
        self.logger.info("---Checking for inactive objects---")
        
        try:
            
            # Inactive computers (no logon AND pwdlastset > 365 days)
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=computer)',
                attributes=['sAMAccountName', 'pwdLastSet', 'lastLogonTimestamp', 'whenCreated']
            )
            
            # Filter in Python. lastLogonTimestamp is replicated to all DCs (updated
            # with up to ~14 days lag); lastLogon is per-DC and not replicated, so a
            # logon at another DC would look like no logon at all.
            inactive_computers = []
            for comp in computers:
                last_logon = comp.get('lastLogonTimestamp')
                pwd_last_set = comp.get('pwdLastSet')
                # Check if either is old enough
                if self._is_inactive(last_logon, pwd_last_set, 365, comp.get('whenCreated')):
                    inactive_computers.append(comp)
            
            if inactive_computers:
                self.logger.finding(f"{len(inactive_computers)} computers inactive > 365 days")
                write_csv(inactive_computers, self.output_paths['findings'] / 'computers_inactive.txt')
            else:
                self.logger.success("[+] No inactive computers found")
            
            # Inactive users (no logon AND pwdlastset > 365 days, not disabled)
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'pwdLastSet', 'lastLogonTimestamp', 'whenCreated']
            )
            
            # Filter in Python
            inactive_users = []
            for user in users:
                last_logon = user.get('lastLogonTimestamp')
                pwd_last_set = user.get('pwdLastSet')
                if self._is_inactive(last_logon, pwd_last_set, 365, user.get('whenCreated')):
                    inactive_users.append(user)
            
            if inactive_users:
                self.logger.finding(f"{len(inactive_users)} users inactive > 365 days")
                write_csv(inactive_users, self.output_paths['findings'] / 'users_inactive.txt')
            else:
                self.logger.success("[+] No inactive users found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking inactive objects: {e}")

    @staticmethod
    def _is_inactive(last_logon, pwd_last_set, days=365, when_created=None) -> bool:
        """Inactive = every known timestamp (last logon, password change) is older
        than `days`. Not-set values (missing, 0, 1601) are ignored; if neither is
        known (never logged on, password never set), the creation date decides,
        so a brand-new unused account isn't reported but an old one is."""
        known = [r for r in (older_than(last_logon, days), older_than(pwd_last_set, days)) if r is not None]
        if not known:
            return older_than(when_created, days) is True
        return all(known)
