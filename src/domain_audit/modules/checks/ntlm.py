"""NTLM security checks - NTLMv1 support and NTLM restriction policies."""

import io
import struct
from typing import Dict, List, Optional
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_file, write_lines
from ...utils.registry_pol import parse_pol_file


# LmCompatibilityLevel values and their meanings
LM_COMPATIBILITY_LEVELS = {
    0: "Send LM & NTLM responses",
    1: "Send LM & NTLM - use NTLMv2 session security if negotiated",
    2: "Send NTLM response only",
    3: "Send NTLMv2 response only",
    4: "Send NTLMv2 response only, refuse LM",
    5: "Send NTLMv2 response only, refuse LM & NTLM",
}

# Registry keys for NTLM settings
NTLM_REGISTRY_KEYS = {
    # LmCompatibilityLevel - controls NTLMv1 vs NTLMv2
    'LmCompatibilityLevel': r'SYSTEM\CurrentControlSet\Control\Lsa',
    # Restrict NTLM in domain
    'RestrictNTLMInDomain': r'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
    # Audit NTLM in domain
    'AuditNTLMInDomain': r'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
    # Restrict sending NTLM traffic
    'RestrictSendingNTLMTraffic': r'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
}


class NTLMChecker:
    """Check NTLM security settings including NTLMv1 support and NTLM restrictions."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, username: str = None, password: str = None,
                 domain: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.server = server or ldap_conn.config.server
        self.username = username
        self.password = password
        self.domain = domain or ldap_conn.config.domain
    
    def check_ntlm(self):
        """Run all NTLM-related security checks."""
        self._check_ntlmv1_support()
        self._check_ntlm_restrictions()
    
    def _check_ntlmv1_support(self):
        """Check if NTLMv1 is supported on Domain Controllers.
        
        NTLMv1 is vulnerable to:
        - Downgrade attacks (forcing NTLMv1 instead of NTLMv2)
        - Relay attacks with easier hash cracking
        
        LmCompatibilityLevel values 0, 1, or 2 indicate NTLMv1 is supported.
        Recommended: 3 or higher (NTLMv2 only)
        """
        self.logger.info("---Checking for NTLMv1 support on Domain Controllers---")
        
        if not self.username or not self.password:
            self.logger.warning("[!] NTLMv1 check requires SMB credentials")
            return
        
        try:
            from impacket.smbconnection import SMBConnection, SessionError
        except ImportError:
            self.logger.error("[-] impacket not available for SYSVOL access")
            return
        
        try:
            # Get domain controllers with OS information
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name', 'operatingSystem']
            )
            
            if not dcs:
                self.logger.warning("[!] No domain controllers found")
                return
            
            dc_hostname = dcs[0].get('dNSHostName', self.server)
            
            # Determine default LmCompatibilityLevel based on DC OS versions
            default_vulnerable = self._check_dc_os_defaults(dcs)
            
            # Connect to SYSVOL
            conn = SMBConnection(dc_hostname, dc_hostname)
            conn.login(self.username, self.password, self.domain)
            
            # Get all GPOs that might apply to DCs
            # We check the Default Domain Controllers Policy and other GPOs
            ntlmv1_findings = []
            gpo_settings = []
            
            # Check all GPOs for LmCompatibilityLevel settings
            gpo_policies = self._get_all_gpo_policies(conn)
            
            for gpo_name, gpo_guid, lm_level in gpo_policies:
                if lm_level is not None:
                    level_desc = LM_COMPATIBILITY_LEVELS.get(lm_level, f"Unknown ({lm_level})")
                    gpo_settings.append({
                        'gpo_name': gpo_name,
                        'gpo_guid': gpo_guid,
                        'lm_level': lm_level,
                        'description': level_desc
                    })
                    
                    # LmCompatibilityLevel 0, 1, or 2 means NTLMv1 is supported
                    if lm_level <= 2:
                        ntlmv1_findings.append(f"{gpo_name}: LmCompatibilityLevel={lm_level} ({level_desc})")
            
            conn.logoff()
            
            if ntlmv1_findings:
                self.logger.finding(f"NTLMv1 supported in {len(ntlmv1_findings)} GPO(s) - vulnerable to downgrade/relay attacks")
                
                output_lines = [
                    "NTLMv1 Support Detected",
                    "=" * 50,
                    "",
                    "RISK: NTLMv1 is vulnerable to:",
                    "  - Downgrade attacks (forcing NTLMv1 instead of NTLMv2)",
                    "  - Relay attacks with easier hash cracking",
                    "  - Rainbow table attacks on captured hashes",
                    "",
                    "RECOMMENDATION: Set LmCompatibilityLevel to 3 or higher",
                    "  3 = Send NTLMv2 response only",
                    "  4 = Send NTLMv2 response only, refuse LM",
                    "  5 = Send NTLMv2 response only, refuse LM & NTLM (most secure)",
                    "",
                    "Affected GPOs:",
                ]
                output_lines.extend([f"  - {f}" for f in ntlmv1_findings])
                
                write_file('\n'.join(output_lines),
                          self.output_paths['findings'] / 'ntlmv1_supported.txt',
                          self.logger)
            elif gpo_settings:
                # Found settings but all are secure
                self.logger.success("[+] NTLMv1 is disabled (LmCompatibilityLevel >= 3)")
                
                output_lines = ["LmCompatibilityLevel Settings (Secure)", ""]
                for setting in gpo_settings:
                    output_lines.append(f"{setting['gpo_name']}: Level {setting['lm_level']} - {setting['description']}")
                
                write_file('\n'.join(output_lines),
                          self.output_paths['checks'] / 'ntlmv1_settings.txt',
                          self.logger)
            else:
                # No explicit GPO settings found - check if OS defaults are vulnerable
                if default_vulnerable:
                    self.logger.finding("No LmCompatibilityLevel GPO - DCs running legacy OS with vulnerable defaults")
                    
                    output_lines = [
                        "NTLMv1 Support (OS Default)",
                        "=" * 50,
                        "",
                        "No LmCompatibilityLevel GPO setting found.",
                        "",
                        "RISK: Domain Controllers are running legacy operating systems with vulnerable defaults:",
                    ]
                    for dc_name, os_name, default_level in default_vulnerable:
                        output_lines.append(f"  - {dc_name}: {os_name} (default level {default_level})")
                    
                    output_lines.extend([
                        "",
                        "These OS defaults allow NTLMv1:",
                        "  - Server 2000/XP: Level 1 (NTLMv1)",
                        "  - Server 2003: Level 2 (NTLMv1 with v2 session security)",
                        "",
                        "RECOMMENDATION: Set LmCompatibilityLevel to 3+ via GPO",
                        "Verify by running Responder and coerce the DC to check actual behavior"
                    ])
                    
                    write_file('\n'.join(output_lines),
                              self.output_paths['findings'] / 'ntlmv1_supported.txt',
                              self.logger)
                else:
                    self.logger.warning("[!] No LmCompatibilityLevel GPO found - OS defaults apply")
                    
                    # List actual DC OS versions for clarity
                    dc_os_list = []
                    for dc in dcs:
                        dc_name = dc.get('name', dc.get('dNSHostName', 'Unknown'))
                        os_name = dc.get('operatingSystem', 'Unknown')
                        dc_os_list.append(f"  - {dc_name}: {os_name}")
                    
                    self.logger.info("[*] All DCs have secure OS defaults (level 3 - NTLMv2 only)")
                    
                    output_lines = [
                        "No LmCompatibilityLevel GPO setting found.",
                        "",
                        "Domain Controllers (all have secure defaults):"
                    ]
                    output_lines.extend(dc_os_list)
                    output_lines.extend([
                        "",
                        "OS defaults:",
                        "  - Server 2008 and newer: Level 3 (NTLMv2 only) - Secure",
                        "  - Server 2003: Level 2 (NTLMv1 with v2 session) - Vulnerable",
                        "  - Server 2000/XP: Level 1 (NTLMv1) - Vulnerable",
                        "",
                        "Verify by running Responder and coerce the DC to check if LmCompatibilityLevel",
                        "is set at the local registry level only instead of GPO"
                    ])
                    
                    write_file('\n'.join(output_lines),
                              self.output_paths['checks'] / 'ntlmv1_settings.txt',
                              self.logger
                    )
                
        except Exception as e:
            self.logger.error(f"[-] Error checking NTLMv1 support: {e}")
    
    def _check_ntlm_restrictions(self):
        """Check if NTLM authentication is restricted in the domain.
        
        Checks three separate controls:
        - RestrictNTLMInDomain (DC): Controls pass-through authentication
        - RestrictSendingNTLMTraffic (Clients): Outgoing NTLM to remote servers
        - RestrictReceivingNTLMTraffic (Servers): Incoming NTLM authentication
        
        Ideally NTLM should be disabled and only Kerberos used, but this
        is rarely the case in real environments.
        """
        self.logger.info("---Checking NTLM restriction policies---")
        
        if not self.username or not self.password:
            self.logger.warning("[!] NTLM restriction check requires SMB credentials")
            return
        
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            self.logger.error("[-] impacket not available for SYSVOL access")
            return
        
        try:
            # Get a domain controller
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName']
            )
            
            if not dcs:
                dc_hostname = self.server
            else:
                dc_hostname = dcs[0].get('dNSHostName', self.server)
            
            # Connect to SYSVOL
            conn = SMBConnection(dc_hostname, dc_hostname)
            conn.login(self.username, self.password, self.domain)
            
            # Check all GPOs for NTLM restriction settings
            ntlm_restrictions = self._get_ntlm_restrictions(conn)
            
            conn.logoff()
            
            # Check if actual restrictions are enforced (not just auditing)
            has_restrictions = False
            if ntlm_restrictions:
                has_restrictions = any(r.get('restricted', False) for r in ntlm_restrictions)
            
            if has_restrictions:
                self.logger.success("[+] NTLM restrictions are configured")
                
                output_lines = ["NTLM Restriction Policies", "=" * 50, ""]
                for r in ntlm_restrictions:
                    output_lines.append(f"GPO: {r['gpo_name']}")
                    if r.get('restrict_ntlm_domain') is not None:
                        val = r['restrict_ntlm_domain']
                        desc = self._get_restrict_ntlm_domain_desc(val)
                        output_lines.append(f"  RestrictNTLMInDomain (DC): {val} - {desc}")
                    if r.get('restrict_sending') is not None:
                        val = r['restrict_sending']
                        desc = self._get_restrict_sending_desc(val)
                        output_lines.append(f"  RestrictSendingNTLMTraffic (Clients): {val} - {desc}")
                    if r.get('restrict_receiving') is not None:
                        val = r['restrict_receiving']
                        desc = self._get_restrict_receiving_desc(val)
                        output_lines.append(f"  RestrictReceivingNTLMTraffic (Servers): {val} - {desc}")
                    if r.get('audit_ntlm_domain') is not None:
                        output_lines.append(f"  AuditNTLMInDomain: {r['audit_ntlm_domain']}")
                    output_lines.append("")
                
                write_file('\n'.join(output_lines),
                          self.output_paths['checks'] / 'ntlm_restrictions.txt',
                          self.logger)
            else:
                # No restrictions enforced (either no settings or only audit)
                if ntlm_restrictions:
                    self.logger.info("[*] NTLM audit settings found but no restrictions enforced")
                self.logger.finding("NTLM is not restricted in the domain")
                
                output_lines = [
                    "NTLM Not Restricted",
                    "=" * 50,
                    "",
                    "No NTLM restriction policies were found in GPOs.",
                    "",
                    "RISK: NTLM authentication is enabled domain-wide, which allows:",
                    "  - NTLM relay attacks",
                    "  - Pass-the-hash attacks",
                    "  - Credential capture and offline cracking",
                    "",
                    "RECOMMENDATION: Consider implementing NTLM restrictions:",
                    "  1. Enable NTLM auditing first to identify dependencies",
                    "  2. Add exceptions for required services",
                    "  3. Gradually restrict NTLM traffic",
                    "",
                    "Relevant GPO settings:",
                    "  - Network security: Restrict NTLM: NTLM authentication in this domain",
                    "  - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers",
                    "  - Network security: Restrict NTLM: Audit NTLM authentication in this domain",
                ]
                
                write_file('\n'.join(output_lines),
                          self.output_paths['findings'] / 'ntlm_not_restricted.txt',
                          self.logger)
                
        except Exception as e:
            self.logger.error(f"[-] Error checking NTLM restrictions: {e}")
    
    def _get_all_gpo_policies(self, conn) -> List[tuple]:
        """Get LmCompatibilityLevel from all GPO Registry.pol files.
        
        Returns:
            List of tuples: (gpo_name, gpo_guid, lm_level)
        """
        from impacket.smbconnection import SessionError
        
        results = []
        
        try:
            # List all GPO folders in SYSVOL
            policies_path = f"{self.domain}/Policies"
            policies = conn.listPath('SYSVOL', policies_path)
        except Exception as e:
            self.logger.debug(f"Could not list GPO policies: {e}")
            return results
        
        for policy in policies:
            policy_name = policy.get_longname()
            if policy_name in ['.', '..']:
                continue
            
            share_path = f"{self.domain}/Policies/{policy_name}/Machine/Registry.pol"
            
            try:
                content_buffer = io.BytesIO()
                conn.getFile('SYSVOL', share_path, content_buffer.write)
                content = content_buffer.getvalue()
                
                if content:
                    lm_level = self._parse_lm_compatibility_level(content)
                    if lm_level is not None:
                        # Get GPO display name from LDAP
                        gpo_display_name = self._get_gpo_display_name(policy_name)
                        results.append((gpo_display_name or policy_name, policy_name, lm_level))
                        
            except SessionError:
                # Registry.pol doesn't exist for this GPO
                pass
            except Exception as e:
                self.logger.debug(f"Could not read Registry.pol for {policy_name}: {e}")
        
        return results
    
    def _parse_lm_compatibility_level(self, content: bytes) -> Optional[int]:
        """Parse LmCompatibilityLevel from Registry.pol content."""
        entries = parse_pol_file(content)
        
        for key, value_name, reg_type, size, data in entries:
            # Check for LmCompatibilityLevel in Lsa key
            if 'Control\\Lsa' in key and value_name.lower() == 'lmcompatibilitylevel':
                if reg_type == 4 and len(data) >= 4:  # REG_DWORD
                    return struct.unpack('<I', data[:4])[0]
        
        return None
    
    def _get_ntlm_restrictions(self, conn) -> List[Dict]:
        """Get NTLM restriction settings from all GPO Registry.pol files."""
        from impacket.smbconnection import SessionError
        
        results = []
        
        try:
            policies_path = f"{self.domain}/Policies"
            policies = conn.listPath('SYSVOL', policies_path)
        except Exception as e:
            self.logger.debug(f"Could not list GPO policies: {e}")
            return results
        
        for policy in policies:
            policy_name = policy.get_longname()
            if policy_name in ['.', '..']:
                continue
            
            share_path = f"{self.domain}/Policies/{policy_name}/Machine/Registry.pol"
            
            try:
                content_buffer = io.BytesIO()
                conn.getFile('SYSVOL', share_path, content_buffer.write)
                content = content_buffer.getvalue()
                
                if content:
                    ntlm_settings = self._parse_ntlm_restrictions(content)
                    if ntlm_settings:
                        gpo_display_name = self._get_gpo_display_name(policy_name)
                        ntlm_settings['gpo_name'] = gpo_display_name or policy_name
                        ntlm_settings['gpo_guid'] = policy_name
                        results.append(ntlm_settings)
                        
            except SessionError:
                pass
            except Exception as e:
                self.logger.debug(f"Could not read Registry.pol for {policy_name}: {e}")
        
        return results
    
    def _parse_ntlm_restrictions(self, content: bytes) -> Optional[Dict]:
        """Parse NTLM restriction settings from Registry.pol content.
        
        Values meaning:
        - RestrictNTLMInDomain: 0=Disabled, 1-4=Various deny levels (DC only)
        - RestrictSendingNTLMTraffic: 0=Allow, 1=Audit, 2=Deny (Clients)
        - RestrictReceivingNTLMTraffic: 0=Allow, 1=Deny domain accounts, 2=Deny all (Servers)
        """
        entries = parse_pol_file(content)
        
        settings = {}
        
        for key, value_name, reg_type, size, data in entries:
            # Check for NTLM settings in MSV1_0 or Netlogon\Parameters key
            if 'MSV1_0' not in key and 'Lsa' not in key and 'Netlogon' not in key:
                continue
            
            value_lower = value_name.lower()
            
            if value_lower == 'restrictntlmindomain':
                if reg_type == 4 and len(data) >= 4:
                    val = struct.unpack('<I', data[:4])[0]
                    settings['restrict_ntlm_domain'] = val
                    # 0=Disabled, 1-4=various deny levels (any non-zero is restriction)
                    if val > 0:
                        settings['restricted'] = True
            elif value_lower == 'auditntlmindomain':
                if reg_type == 4 and len(data) >= 4:
                    settings['audit_ntlm_domain'] = struct.unpack('<I', data[:4])[0]
            elif value_lower == 'restrictsendingntlmtraffic':
                if reg_type == 4 and len(data) >= 4:
                    val = struct.unpack('<I', data[:4])[0]
                    settings['restrict_sending'] = val
                    # 2=Deny (1=Audit only, doesn't block)
                    if val >= 2:
                        settings['restricted'] = True
            elif value_lower == 'restrictreceivingntlmtraffic':
                if reg_type == 4 and len(data) >= 4:
                    val = struct.unpack('<I', data[:4])[0]
                    settings['restrict_receiving'] = val
                    # 1=Deny domain accounts, 2=Deny all (either is restriction)
                    if val >= 1:
                        settings['restricted'] = True
        
        return settings if settings else None
    
    def _get_gpo_display_name(self, gpo_guid: str) -> Optional[str]:
        """Get GPO display name from LDAP."""
        try:
            results = self.ldap.query(
                search_base=f"CN=Policies,CN=System,{self.base_dn}",
                search_filter=f"(cn={gpo_guid})",
                attributes=['displayName']
            )
            if results:
                return results[0].get('displayName')
        except Exception:
            pass
        return None
    
    def _get_restrict_ntlm_domain_desc(self, value: int) -> str:
        """Get description for RestrictNTLMInDomain value."""
        descriptions = {
            0: "Disabled (allow all)",
            1: "Deny domain accounts to domain servers",
            2: "Deny domain accounts",
            3: "Deny domain servers",
            4: "Deny all"
        }
        return descriptions.get(value, f"Unknown ({value})")
    
    def _get_restrict_sending_desc(self, value: int) -> str:
        """Get description for RestrictSendingNTLMTraffic value."""
        descriptions = {
            0: "Allow all",
            1: "Audit all (no blocking)",
            2: "Deny all"
        }
        return descriptions.get(value, f"Unknown ({value})")
    
    def _get_restrict_receiving_desc(self, value: int) -> str:
        """Get description for RestrictReceivingNTLMTraffic value."""
        descriptions = {
            0: "Allow all",
            1: "Deny domain accounts",
            2: "Deny all"
        }
        return descriptions.get(value, f"Unknown ({value})")
    
    def _check_dc_os_defaults(self, dcs: List[Dict]) -> List[tuple]:
        """Check if DCs are running legacy OS with vulnerable LmCompatibilityLevel defaults.
        
        Returns list of tuples: (dc_name, os_name, default_level) for vulnerable DCs only.
        """
        vulnerable_dcs = []
        
        for dc in dcs:
            dc_name = dc.get('name', dc.get('dNSHostName', 'Unknown'))
            os_name = dc.get('operatingSystem', 'Unknown')
            
            # Determine default LmCompatibilityLevel based on OS
            default_level = None
            
            if os_name and os_name != 'Unknown':
                os_lower = os_name.lower()
                
                # Server 2000, XP, 2000 Server - default level 1 (NTLMv1)
                if any(x in os_lower for x in ['2000', 'windows xp']):
                    default_level = 1
                
                # Server 2003, 2003 R2 - default level 2 (NTLMv1 with v2 session security)
                elif '2003' in os_lower:
                    default_level = 2
                
                # Vista, 2008 and higher - default level 3 (NTLMv2 only) - secure
                # No need to add to vulnerable list
            
            # Add to vulnerable list if default is 0, 1, or 2
            if default_level is not None and default_level <= 2:
                vulnerable_dcs.append((dc_name, os_name, default_level))
        
        return vulnerable_dcs if vulnerable_dcs else None
