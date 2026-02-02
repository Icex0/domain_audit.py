"""Cross-platform DNS management and dependency checking utilities."""

import os
import platform
import subprocess
import re
import shutil
from typing import Optional, List, Tuple

from .logger import get_logger


def check_certipy_available() -> bool:
    """
    Check if certipy is available on the system.
    
    Returns:
        True if certipy is available, False otherwise
    """
    logger = get_logger()
    
    # Check for 'certipy' command
    if shutil.which('certipy'):
        logger.log_verbose("[+] certipy is available")
        return True
    
    logger.error("[-] certipy is not installed or not in PATH")
    logger.info("[*] Install with: pipx install certipy-ad")
    return False


def check_netexec_available() -> bool:
    """
    Check if netexec (nxc) is available on the system.
    
    Returns:
        True if netexec is available, False otherwise
    """
    logger = get_logger()
    
    # Check for 'nxc' command (netexec binary name)
    if shutil.which('nxc') or shutil.which('netexec'):
        logger.log_verbose("[+] netexec is available")
        return True
    
    logger.error("[-] netexec (nxc) is not installed or not in PATH")
    logger.info("[*] Install with: pipx install git+https://github.com/Pennyw0rth/NetExec")
    return False


def get_current_dns() -> List[str]:
    """
    Get current DNS server(s) configured on the system.
    
    Returns:
        List of DNS server IPs currently configured
    """
    system = platform.system().lower()
    
    if system == "windows":
        return _get_dns_windows()
    elif system == "darwin":
        return _get_dns_macos()
    elif system == "linux":
        return _get_dns_linux()
    else:
        return []


def _get_dns_windows() -> List[str]:
    """Get DNS servers on Windows."""
    dns_servers = []
    try:
        result = subprocess.run(
            ["powershell", "-Command", 
             "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                ip = line.strip()
                if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                    dns_servers.append(ip)
    except Exception:
        pass
    return list(set(dns_servers))


def _get_dns_macos() -> List[str]:
    """Get DNS servers on macOS."""
    dns_servers = []
    try:
        result = subprocess.run(
            ["scutil", "--dns"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'nameserver' in line:
                    match = re.search(r'nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        dns_servers.append(match.group(1))
    except Exception:
        pass
    return list(set(dns_servers))


def _get_dns_linux() -> List[str]:
    """Get DNS servers on Linux."""
    dns_servers = []
    
    # Try systemd-resolve first
    try:
        result = subprocess.run(
            ["resolvectl", "status"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'DNS Servers' in line or 'Current DNS Server' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        dns_servers.append(match.group(1))
            if dns_servers:
                return list(set(dns_servers))
    except Exception:
        pass
    
    # Fallback to /etc/resolv.conf
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.strip().startswith('nameserver'):
                    match = re.search(r'nameserver\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        dns_servers.append(match.group(1))
    except Exception:
        pass
    
    return list(set(dns_servers))


def is_admin() -> bool:
    """Check if running with elevated privileges."""
    system = platform.system().lower()
    
    if system == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def set_dns(dc_ip: str) -> Tuple[bool, str]:
    """
    Set DNS server to the domain controller IP.
    
    Args:
        dc_ip: Domain controller IP address
        
    Returns:
        Tuple of (success, message)
    """
    logger = get_logger()
    system = platform.system().lower()
    
    if not is_admin():
        return False, "Not running with elevated privileges"
    
    if system == "windows":
        return _set_dns_windows(dc_ip)
    elif system == "darwin":
        return _set_dns_macos(dc_ip)
    elif system == "linux":
        return _set_dns_linux(dc_ip)
    else:
        return False, f"Unsupported operating system: {system}"


def _set_dns_windows(dc_ip: str) -> Tuple[bool, str]:
    """Set DNS on Windows for all interfaces."""
    try:
        # Get all network adapters and set DNS for each
        result = subprocess.run(
            ["powershell", "-Command", 
             f"Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object {{ Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses '{dc_ip}' }}"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return True, f"DNS set to {dc_ip} for all interfaces"
        else:
            return False, f"Failed to set DNS: {result.stderr}"
    except Exception as e:
        return False, f"Error setting DNS: {e}"


def _set_dns_macos(dc_ip: str) -> Tuple[bool, str]:
    """Set DNS on macOS for all network services."""
    try:
        # Get list of network services
        result = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return False, "Failed to list network services"
        
        services = []
        for line in result.stdout.strip().split('\n'):
            # Skip the header line and disabled services
            if line and not line.startswith('*') and not line.startswith('An asterisk'):
                services.append(line.strip())
        
        success_count = 0
        for service in services:
            try:
                result = subprocess.run(
                    ["networksetup", "-setdnsservers", service, dc_ip],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    success_count += 1
            except Exception:
                continue
        
        if success_count > 0:
            # Flush DNS cache
            subprocess.run(["dscacheutil", "-flushcache"], capture_output=True, timeout=10)
            subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True, timeout=10)
            return True, f"DNS set to {dc_ip} for {success_count} network service(s)"
        else:
            return False, "Failed to set DNS for any network service"
    except Exception as e:
        return False, f"Error setting DNS: {e}"


def _set_dns_linux(dc_ip: str) -> Tuple[bool, str]:
    """Set DNS on Linux."""
    # Try systemd-resolved first
    try:
        # Check if systemd-resolved is active
        result = subprocess.run(
            ["systemctl", "is-active", "systemd-resolved"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip() == "active":
            # Get the main interface
            interface = _get_main_interface_linux()
            if interface:
                result = subprocess.run(
                    ["resolvectl", "dns", interface, dc_ip],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return True, f"DNS set to {dc_ip} via resolvectl on {interface}"
    except Exception:
        pass
    
    # Fallback: modify /etc/resolv.conf directly
    try:
        # Backup existing resolv.conf
        resolv_path = '/etc/resolv.conf'
        backup_path = '/etc/resolv.conf.domain-audit.bak'
        
        # Read existing content to preserve search domains
        search_line = ""
        try:
            with open(resolv_path, 'r') as f:
                for line in f:
                    if line.strip().startswith('search'):
                        search_line = line
                        break
        except Exception:
            pass
        
        # Write new resolv.conf
        with open(resolv_path, 'w') as f:
            if search_line:
                f.write(search_line)
            f.write(f"nameserver {dc_ip}\n")
        
        return True, f"DNS set to {dc_ip} in /etc/resolv.conf"
    except PermissionError:
        return False, "Permission denied writing to /etc/resolv.conf"
    except Exception as e:
        return False, f"Error setting DNS: {e}"


def _get_main_interface_linux() -> Optional[str]:
    """Get the main network interface on Linux."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def reset_dns() -> Tuple[bool, str]:
    """
    Reset DNS to automatic/DHCP settings.
    
    Returns:
        Tuple of (success, message)
    """
    system = platform.system().lower()
    
    if not is_admin():
        return False, "Not running with elevated privileges"
    
    if system == "windows":
        return _reset_dns_windows()
    elif system == "darwin":
        return _reset_dns_macos()
    elif system == "linux":
        return _reset_dns_linux()
    else:
        return False, f"Unsupported operating system: {system}"


def _reset_dns_windows() -> Tuple[bool, str]:
    """Reset DNS on Windows to DHCP."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return True, "DNS reset to DHCP for all interfaces"
        else:
            return False, f"Failed to reset DNS: {result.stderr}"
    except Exception as e:
        return False, f"Error resetting DNS: {e}"


def _reset_dns_macos() -> Tuple[bool, str]:
    """Reset DNS on macOS to automatic."""
    try:
        result = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return False, "Failed to list network services"
        
        services = []
        for line in result.stdout.strip().split('\n'):
            if line and not line.startswith('*') and not line.startswith('An asterisk'):
                services.append(line.strip())
        
        success_count = 0
        for service in services:
            try:
                result = subprocess.run(
                    ["networksetup", "-setdnsservers", service, "Empty"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    success_count += 1
            except Exception:
                continue
        
        if success_count > 0:
            subprocess.run(["dscacheutil", "-flushcache"], capture_output=True, timeout=10)
            subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True, timeout=10)
            return True, f"DNS reset to automatic for {success_count} network service(s)"
        else:
            return False, "Failed to reset DNS for any network service"
    except Exception as e:
        return False, f"Error resetting DNS: {e}"


def _reset_dns_linux() -> Tuple[bool, str]:
    """Reset DNS on Linux."""
    # Try to restore backup if it exists
    try:
        backup_path = '/etc/resolv.conf.domain-audit.bak'
        resolv_path = '/etc/resolv.conf'
        
        if os.path.exists(backup_path):
            with open(backup_path, 'r') as f:
                content = f.read()
            with open(resolv_path, 'w') as f:
                f.write(content)
            os.remove(backup_path)
            return True, "DNS restored from backup"
    except Exception:
        pass
    
    # Try restarting systemd-resolved
    try:
        result = subprocess.run(
            ["systemctl", "restart", "systemd-resolved"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return True, "DNS reset via systemd-resolved restart"
    except Exception:
        pass
    
    return False, "Could not reset DNS automatically"


def check_and_set_dns(dc_ip: str, domain: str, cmd_args: list = None) -> bool:
    """
    Check if DNS is set to DC IP, if not attempt to set it.
    
    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (for logging)
        
    Returns:
        True if DNS is correctly set (either already was or successfully changed)
    """
    logger = get_logger()
    
    # Get current DNS
    current_dns = get_current_dns()
    logger.log_verbose(f"Current DNS servers: {current_dns}")
    
    # Check if DC IP is already in DNS
    if dc_ip in current_dns:
        logger.info(f"[+] DNS already configured with DC IP {dc_ip}")
        return True
    
    logger.warning(f"[!] DNS is not set to DC IP {dc_ip}")
    logger.warning(f"[!] Current DNS: {', '.join(current_dns) if current_dns else 'None detected'}")
    logger.info(f"[*] Tools may fail to resolve hostnames without proper DNS configuration")
    
    # Check if we have admin privileges
    if not is_admin():
        system = platform.system().lower()
        if system == "windows":
            logger.error("[-] Not running as Administrator. Please run as Administrator to auto-configure DNS")
            logger.info("[*] Or manually set DNS to the DC IP: " + dc_ip)
        elif system == "darwin":
            logger.error("[-] Not running as root. Please run with sudo to auto-configure DNS")
            logger.info(f"[*] Or manually run: sudo networksetup -setdnsservers Wi-Fi {dc_ip}")
        else:
            logger.error("[-] Not running as root. Please run with sudo to auto-configure DNS")
            # Reconstruct the full command if args available
            if cmd_args and len(cmd_args) > 1:
                # Remove script path (first arg) and build full command
                full_args = ' '.join(cmd_args[1:])
                logger.info(f"[*] Use: sudo $(which uv) run {full_args}")
            else:
                logger.info(f"[*] Use: sudo $(which uv) run domain-audit run -d {domain} -dc {dc_ip} ...")
            logger.info(f"[*] Or manually: echo 'nameserver {dc_ip}' | sudo tee /etc/resolv.conf > /dev/null")
        
        # Ask user if they want to continue anyway
        try:
            response = input("\n[?] Continue without setting DNS? This may cause hostname resolution failures (y/n): ")
            if response.lower() != 'y':
                logger.error("[-] Exiting. Please configure DNS and retry.")
                return False
            logger.warning("[!] Continuing without proper DNS configuration...")
            return True
        except (EOFError, KeyboardInterrupt):
            return False
    
    # Attempt to set DNS
    logger.info(f"[+] Running with elevated privileges, setting DNS to {dc_ip}")
    success, message = set_dns(dc_ip)
    
    if success:
        logger.success(f"[+] {message}")
        return True
    else:
        logger.error(f"[-] {message}")
        logger.info("[*] Please manually configure DNS to the DC IP")
        return False
