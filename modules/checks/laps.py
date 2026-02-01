"""LAPS security checks."""

from typing import Dict
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_file, write_lines, write_csv


class LAPSChecker:
    """Checks related to LAPS deployment and configuration."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_laps(self):
        """Check LAPS deployment and configuration."""
        self.logger.info("---Checking if LAPS is deployed---")
        
        try:
            gpos = self.ldap.query(
                search_base=f"CN=Policies,CN=System,{self.base_dn}",
                search_filter='(displayName=*LAPS*)',
                attributes=['displayName', 'gPCFileSysPath']
            )
            
            gpo_file = self.output_paths['data'] / 'laps_gpo.txt'
            
            if gpos:
                count = len(gpos)
                self.logger.success(f"[+] There are {count} GPOs with LAPS in their name")
                write_csv(gpos, gpo_file)
                
                for gpo in gpos:
                    gpo_dn = gpo.get('dn', '')
                    if 'CN={' in gpo_dn:
                        guid = gpo_dn.split('CN={')[1].split('}')[0]
                        
                        linked_ous = self.ldap.query(
                            search_base=self.base_dn,
                            search_filter=f'(gPLink=*{guid}*)',
                            attributes=['name', 'distinguishedName']
                        )
                        
                        if linked_ous:
                            self.logger.success(f"[+] GPO {gpo.get('displayName')} is linked to {len(linked_ous)} OU(s)")
                        else:
                            self.logger.finding(f"GPO {gpo.get('displayName')} isn't linked to any OU")
            else:
                self.logger.finding("There is no GPO with LAPS in their name")
            
            laps_file = self.output_paths['data'] / 'laps_computers_enabled.txt'
            laps_installed = False
            
            try:
                all_computers = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter='(&(objectClass=computer)(operatingSystem=*Windows*))',
                    attributes=['sAMAccountName', 'distinguishedName', 'ms-Mcs-AdmPwd', 'lastLogon', 'whenChanged', 'operatingSystem']
                )
                laps_installed = True
            except Exception:
                all_computers = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter='(&(objectClass=computer)(operatingSystem=*Windows*))',
                    attributes=['sAMAccountName', 'distinguishedName', 'lastLogon', 'whenChanged', 'operatingSystem']
                )
            
            if not laps_installed:
                self.logger.finding("LAPS schema not installed (ms-Mcs-AdmPwd attribute not found)")
                findings_file = self.output_paths['findings'] / 'laps_notenabled.txt'
                write_file("LAPS SCHEMA NOT INSTALLED", findings_file, self.logger)
            else:
                laps_computers = [c for c in all_computers if c.get('ms-Mcs-AdmPwd')]
                no_laps = [c for c in all_computers if not c.get('ms-Mcs-AdmPwd')]
                
                if laps_computers:
                    count = len(laps_computers)
                    self.logger.success(f"[+] There are {count} systems where LAPS is enabled")
                    write_lines([c.get('sAMAccountName', '') for c in laps_computers if c.get('sAMAccountName')], laps_file)
                    
                    readable_passwords = [c for c in laps_computers if c.get('ms-Mcs-AdmPwd')]
                    if readable_passwords:
                        self.logger.finding("The current user could read LAPS passwords")
                        pwd_file = self.output_paths['findings'] / 'laps_passwords_readable.txt'
                        pwd_data = [f"{c.get('sAMAccountName', 'unknown')}: {c.get('ms-Mcs-AdmPwd', '')}" for c in readable_passwords]
                        write_lines(pwd_data, pwd_file)
                    else:
                        self.logger.success("[+] The current user couldn't read any LAPS passwords")
                    
                    if no_laps:
                        no_laps_file = self.output_paths['findings'] / 'laps_computers_disabled.txt'
                        self.logger.finding(f"There are {len(no_laps)} Windows systems where LAPS isn't enabled")
                        write_lines([c.get('sAMAccountName', '') for c in no_laps if c.get('sAMAccountName')], no_laps_file)
                    else:
                        self.logger.success("[+] All Windows systems have LAPS enabled")
                else:
                    self.logger.finding("There are no systems where LAPS is enabled")
                    findings_file = self.output_paths['findings'] / 'laps_notenabled.txt'
                    write_file("LAPS NOT ENABLED ON ANY COMPUTER", findings_file, self.logger)
                
        except Exception as e:
            self.logger.error(f"[-] Error checking LAPS: {e}")
