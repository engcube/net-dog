#!/usr/bin/env python3
"""
Automatic Network Configuration Detection for macOS

This module automatically detects local network configuration including:
- Primary network interface and IP address
- Local network segments (e.g., 192.168.x.0/24, 10.0.x.0/24)
- VPN interfaces (utun, tun, etc.)
- Gateway and routing information

Designed to replace hardcoded network values in network monitoring applications.
"""

import subprocess
import re
import socket
import ipaddress
from typing import Dict, List, Optional, Tuple, NamedTuple
from dataclasses import dataclass
from enum import Enum
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class InterfaceType(Enum):
    """Network interface types"""
    ETHERNET = "ethernet"
    WIFI = "wifi"
    VPN = "vpn"
    LOOPBACK = "loopback"
    BRIDGE = "bridge"
    OTHER = "other"


@dataclass
class NetworkInterface:
    """Represents a network interface"""
    name: str
    ip_address: str
    netmask: str
    network: str
    interface_type: InterfaceType
    is_active: bool
    is_primary: bool
    mac_address: Optional[str] = None
    mtu: Optional[int] = None
    flags: List[str] = None

    def __post_init__(self):
        if self.flags is None:
            self.flags = []


@dataclass
class NetworkConfiguration:
    """Complete network configuration"""
    primary_interface: NetworkInterface
    local_networks: List[str]  # CIDR notation
    vpn_networks: List[str]   # VPN network ranges
    gateway: Optional[str]
    dns_servers: List[str]
    all_interfaces: List[NetworkInterface]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for easy JSON serialization"""
        return {
            'primary_interface': {
                'name': self.primary_interface.name,
                'ip_address': self.primary_interface.ip_address,
                'network': self.primary_interface.network,
                'type': self.primary_interface.interface_type.value
            },
            'local_networks': self.local_networks,
            'vpn_networks': self.vpn_networks,
            'gateway': self.gateway,
            'dns_servers': self.dns_servers,
            'interface_count': len(self.all_interfaces)
        }


class NetworkDetector:
    """
    Automatic network configuration detector for macOS
    
    This class provides comprehensive network detection capabilities:
    - Detects active network interfaces
    - Identifies primary interface and IP
    - Discovers local network segments
    - Detects VPN connections
    - Provides routing information
    """
    
    def __init__(self):
        self.interfaces = []
        self._cache = {}
        
    def detect_network_configuration(self) -> NetworkConfiguration:
        """
        Main method to detect complete network configuration
        
        Returns:
            NetworkConfiguration: Complete network configuration object
        """
        logger.info("Starting network configuration detection...")
        
        # Detect all interfaces
        self.interfaces = self._get_all_interfaces()
        
        # Find primary interface
        primary_interface = self._get_primary_interface()
        
        # Detect local networks
        local_networks = self._get_local_networks()
        
        # Detect VPN networks
        vpn_networks = self._get_vpn_networks()
        
        # Get gateway
        gateway = self._get_default_gateway()
        
        # Get DNS servers
        dns_servers = self._get_dns_servers()
        
        config = NetworkConfiguration(
            primary_interface=primary_interface,
            local_networks=local_networks,
            vpn_networks=vpn_networks,
            gateway=gateway,
            dns_servers=dns_servers,
            all_interfaces=self.interfaces
        )
        
        logger.info(f"Network detection complete. Found {len(self.interfaces)} interfaces")
        return config
    
    def _get_all_interfaces(self) -> List[NetworkInterface]:
        """
        Get all network interfaces using ifconfig
        
        Returns:
            List[NetworkInterface]: List of all detected interfaces
        """
        interfaces = []
        
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.error(f"ifconfig failed: {result.stderr}")
                return interfaces
                
            current_interface = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # New interface starts
                if line and not line.startswith('\t') and not line.startswith(' ') and ':' in line:
                    # Save previous interface if exists
                    if current_interface:
                        interfaces.append(current_interface)
                    
                    # Parse interface name and flags
                    parts = line.split(':')
                    if len(parts) >= 2:
                        interface_name = parts[0].strip()
                        flags_part = parts[1].strip()
                        
                        # Extract flags
                        flags_match = re.search(r'flags=\d+<([^>]+)>', flags_part)
                        flags = flags_match.group(1).split(',') if flags_match else []
                        
                        # Extract MTU
                        mtu_match = re.search(r'mtu (\d+)', flags_part)
                        mtu = int(mtu_match.group(1)) if mtu_match else None
                        
                        current_interface = {
                            'name': interface_name,
                            'flags': flags,
                            'mtu': mtu,
                            'ip_addresses': [],
                            'mac_address': None,
                            'status': 'unknown'
                        }
                
                # Parse interface details
                elif current_interface and line:
                    # IPv4 address (handle both regular and point-to-point)
                    inet_match = re.search(r'inet\s+([\d.]+)(?:\s+-->\s+[\d.]+)?\s+netmask\s+0x([a-fA-F0-9]+)', line)
                    if inet_match:
                        ip = inet_match.group(1)
                        # Convert hex netmask to decimal
                        netmask_hex = inet_match.group(2)
                        netmask = self._hex_to_netmask(netmask_hex)
                        current_interface['ip_addresses'].append((ip, netmask))
                    
                    # MAC address (ether)
                    ether_match = re.search(r'ether\s+([a-fA-F0-9:]+)', line)
                    if ether_match:
                        current_interface['mac_address'] = ether_match.group(1)
                    
                    # Status (active/inactive)
                    status_match = re.search(r'status:\s+(\w+)', line)
                    if status_match:
                        current_interface['status'] = status_match.group(1)
            
            # Don't forget the last interface
            if current_interface:
                interfaces.append(current_interface)
            
            # Convert to NetworkInterface objects
            network_interfaces = []
            for iface_data in interfaces:
                if iface_data['ip_addresses']:
                    for ip, netmask in iface_data['ip_addresses']:
                        # Skip loopback but allow other IPs
                        if ip.startswith('127.') or ip == '0.0.0.0':
                            continue
                            
                        try:
                            network = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
                            interface_type = self._classify_interface(iface_data['name'], ip)
                            
                            # Check if interface is active based on flags and status
                            has_up_running = 'UP' in iface_data['flags'] and 'RUNNING' in iface_data['flags']
                            status_active = iface_data.get('status', 'unknown') == 'active'
                            is_active = has_up_running and (status_active or interface_type == InterfaceType.VPN)
                            
                            network_interface = NetworkInterface(
                                name=iface_data['name'],
                                ip_address=ip,
                                netmask=netmask,
                                network=network,
                                interface_type=interface_type,
                                is_active=is_active,
                                is_primary=False,  # Will be determined later
                                mac_address=iface_data['mac_address'],
                                mtu=iface_data['mtu'],
                                flags=iface_data['flags']
                            )
                            network_interfaces.append(network_interface)
                        except Exception as e:
                            logger.warning(f"Failed to process interface {iface_data['name']}: {e}")
            
            return network_interfaces
            
        except subprocess.TimeoutExpired:
            logger.error("ifconfig command timed out")
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
        
        return interfaces
    
    def _hex_to_netmask(self, hex_mask: str) -> str:
        """
        Convert hex netmask to dotted decimal notation
        
        Args:
            hex_mask: Hex netmask string (e.g., 'ffffff00')
            
        Returns:
            str: Dotted decimal netmask (e.g., '255.255.255.0')
        """
        try:
            # Pad to 8 characters
            hex_mask = hex_mask.zfill(8)
            # Convert to 4 bytes
            bytes_list = [int(hex_mask[i:i+2], 16) for i in range(0, 8, 2)]
            return '.'.join(map(str, bytes_list))
        except Exception:
            return '255.255.255.0'  # Default fallback
    
    def _classify_interface(self, name: str, ip: str) -> InterfaceType:
        """
        Classify interface type based on name and IP
        
        Args:
            name: Interface name
            ip: IP address
            
        Returns:
            InterfaceType: Classified interface type
        """
        name_lower = name.lower()
        
        # VPN interfaces
        if name_lower.startswith(('utun', 'tun', 'tap', 'ppp')):
            return InterfaceType.VPN
        
        # Loopback
        if name_lower.startswith('lo'):
            return InterfaceType.LOOPBACK
        
        # Bridge interfaces
        if name_lower.startswith('bridge'):
            return InterfaceType.BRIDGE
        
        # Ethernet interfaces (en0, en1, etc.)
        if name_lower.startswith(('en', 'eth')):
            # Treat all en* interfaces as ethernet/wifi
            return InterfaceType.WIFI  # Most common for macOS
        
        return InterfaceType.OTHER
    
    def _get_primary_interface(self) -> NetworkInterface:
        """
        Determine the primary network interface
        
        Returns:
            NetworkInterface: Primary interface
        """
        # Strategy: Prefer local network interfaces over VPN interfaces
        
        # First, look for active local network interfaces (en* with common local IPs)
        local_candidates = [iface for iface in self.interfaces 
                           if iface.interface_type in [InterfaceType.ETHERNET, InterfaceType.WIFI] and
                           any(iface.ip_address.startswith(prefix) 
                              for prefix in ['192.168.', '10.0.', '172.'])]
        
        # Check if any of these are active based on route table
        try:
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                interface_match = re.search(r'interface: (\w+)', result.stdout)
                if interface_match:
                    route_interface = interface_match.group(1)
                    
                    # Find this interface in our local candidates first
                    for interface in local_candidates:
                        if interface.name == route_interface:
                            interface.is_primary = True
                            # Force this interface to be active since it's in the route table
                            interface.is_active = True
                            return interface
                    
                    # If not in local candidates, check all interfaces
                    for interface in self.interfaces:
                        if interface.name == route_interface:
                            interface.is_primary = True
                            interface.is_active = True
                            return interface
        except Exception as e:
            logger.warning(f"Could not determine primary interface from route: {e}")
        
        # Fallback: prefer local network interfaces even if status is inactive
        if local_candidates:
            primary = local_candidates[0]
            primary.is_primary = True
            primary.is_active = True  # Force active for primary local interface
            return primary
        
        # If no local interfaces, check for any active interfaces
        active_interfaces = [iface for iface in self.interfaces if iface.is_active]
        if active_interfaces:
            # Prefer non-VPN interfaces
            non_vpn = [iface for iface in active_interfaces if iface.interface_type != InterfaceType.VPN]
            if non_vpn:
                non_vpn[0].is_primary = True
                return non_vpn[0]
            
            # Fall back to VPN if that's all we have
            active_interfaces[0].is_primary = True
            return active_interfaces[0]
        
        # No active interfaces found, create a dummy one
        logger.warning("No network interfaces found")
        return NetworkInterface(
            name="unknown",
            ip_address="127.0.0.1",
            netmask="255.255.255.0",
            network="127.0.0.0/8",
            interface_type=InterfaceType.LOOPBACK,
            is_active=False,
            is_primary=True
        )
    
    def _get_local_networks(self) -> List[str]:
        """
        Get all local network segments
        
        Returns:
            List[str]: List of local networks in CIDR notation
        """
        local_networks = set()
        
        for interface in self.interfaces:
            # Include networks from physical interfaces (en*, bridge*) with local IP ranges
            if (interface.interface_type in [InterfaceType.ETHERNET, InterfaceType.WIFI, InterfaceType.BRIDGE] and
                not interface.ip_address.startswith(('127.', '169.254.')) and
                any(interface.ip_address.startswith(prefix) for prefix in ['192.168.', '10.', '172.'])):
                
                local_networks.add(interface.network)
        
        return sorted(list(local_networks))
    
    def _get_vpn_networks(self) -> List[str]:
        """
        Detect VPN network ranges
        
        Returns:
            List[str]: List of VPN networks
        """
        vpn_networks = []
        
        for interface in self.interfaces:
            if interface.interface_type == InterfaceType.VPN and interface.is_active:
                vpn_networks.append(interface.network)
        
        # Also check for common VPN IP ranges that might not be detected
        common_vpn_ranges = [
            '28.0.0.0/8',    # Common for Clash/V2Ray TUN
            '198.18.0.0/15', # Common VPN range
            '172.16.0.0/12', # Private range sometimes used by VPNs
        ]
        
        for vpn_range in common_vpn_ranges:
            try:
                vpn_network = ipaddress.IPv4Network(vpn_range)
                for interface in self.interfaces:
                    if interface.is_active:
                        try:
                            interface_ip = ipaddress.IPv4Address(interface.ip_address)
                            if interface_ip in vpn_network:
                                vpn_networks.append(interface.network)
                                break
                        except:
                            continue
            except:
                continue
        
        return list(set(vpn_networks))  # Remove duplicates
    
    def _get_default_gateway(self) -> Optional[str]:
        """
        Get the default gateway IP address
        
        Returns:
            Optional[str]: Gateway IP address
        """
        try:
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                gateway_match = re.search(r'gateway: ([\d.]+)', result.stdout)
                if gateway_match:
                    return gateway_match.group(1)
        except Exception as e:
            logger.warning(f"Could not get default gateway: {e}")
        
        return None
    
    def _get_dns_servers(self) -> List[str]:
        """
        Get configured DNS servers
        
        Returns:
            List[str]: List of DNS server IP addresses
        """
        dns_servers = []
        
        try:
            result = subprocess.run(['scutil', '--dns'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Parse DNS configuration
                for line in result.stdout.split('\n'):
                    if 'nameserver' in line and ':' in line:
                        ip_match = re.search(r':\s*([\d.]+)', line)
                        if ip_match:
                            dns_servers.append(ip_match.group(1))
        except Exception as e:
            logger.warning(f"Could not get DNS servers: {e}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_dns = []
        for dns in dns_servers:
            if dns not in seen:
                seen.add(dns)
                unique_dns.append(dns)
        
        return unique_dns
    
    def get_interface_by_name(self, name: str) -> Optional[NetworkInterface]:
        """
        Get interface by name
        
        Args:
            name: Interface name
            
        Returns:
            Optional[NetworkInterface]: Interface if found
        """
        for interface in self.interfaces:
            if interface.name == name:
                return interface
        return None
    
    def get_interfaces_by_type(self, interface_type: InterfaceType) -> List[NetworkInterface]:
        """
        Get all interfaces of a specific type
        
        Args:
            interface_type: Interface type to filter by
            
        Returns:
            List[NetworkInterface]: Matching interfaces
        """
        return [iface for iface in self.interfaces 
                if iface.interface_type == interface_type]
    
    def is_ip_local(self, ip: str) -> bool:
        """
        Check if an IP address is in any of the local networks
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if IP is local
        """
        try:
            ip_addr = ipaddress.IPv4Address(ip)
            
            for network_str in self._get_local_networks():
                network = ipaddress.IPv4Network(network_str)
                if ip_addr in network:
                    return True
        except:
            pass
        
        return False
    
    def is_ip_vpn(self, ip: str) -> bool:
        """
        Check if an IP address is in any VPN network range
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if IP is from VPN
        """
        try:
            ip_addr = ipaddress.IPv4Address(ip)
            
            for network_str in self._get_vpn_networks():
                network = ipaddress.IPv4Network(network_str)
                if ip_addr in network:
                    return True
        except:
            pass
        
        return False
    
    def print_configuration(self, config: NetworkConfiguration) -> None:
        """
        Print network configuration in a readable format
        
        Args:
            config: NetworkConfiguration to print
        """
        print("\n" + "="*60)
        print("🌐 NETWORK CONFIGURATION DETECTION RESULTS")
        print("="*60)
        
        print(f"\n📡 PRIMARY INTERFACE:")
        print(f"   Name: {config.primary_interface.name}")
        print(f"   IP Address: {config.primary_interface.ip_address}")
        print(f"   Network: {config.primary_interface.network}")
        print(f"   Type: {config.primary_interface.interface_type.value}")
        print(f"   MAC: {config.primary_interface.mac_address or 'N/A'}")
        
        print(f"\n🏠 LOCAL NETWORKS ({len(config.local_networks)}):")
        for network in config.local_networks:
            print(f"   • {network}")
        
        if config.vpn_networks:
            print(f"\n🔒 VPN NETWORKS ({len(config.vpn_networks)}):")
            for network in config.vpn_networks:
                print(f"   • {network}")
        
        if config.gateway:
            print(f"\n🚪 GATEWAY: {config.gateway}")
        
        if config.dns_servers:
            print(f"\n🔍 DNS SERVERS ({len(config.dns_servers)}):")
            for dns in config.dns_servers[:3]:  # Show first 3
                print(f"   • {dns}")
        
        print(f"\n📱 ALL INTERFACES ({len(config.all_interfaces)}):")
        for iface in config.all_interfaces:
            status = "🟢" if iface.is_active else "🔴"
            primary = " (PRIMARY)" if iface.is_primary else ""
            mac_info = f" [{iface.mac_address[:8]}...]" if iface.mac_address else ""
            print(f"   {status} {iface.name}: {iface.ip_address}{mac_info} "
                  f"[{iface.interface_type.value}]{primary}")
        
        print("\n" + "="*60)


def detect_network_config() -> NetworkConfiguration:
    """
    Convenience function to detect network configuration
    
    Returns:
        NetworkConfiguration: Detected network configuration
    """
    detector = NetworkDetector()
    return detector.detect_network_configuration()


def get_legacy_config() -> Dict[str, str]:
    """
    Get network configuration in legacy format for backward compatibility
    
    Returns:
        Dict[str, str]: Legacy configuration format
    """
    config = detect_network_config()
    
    # Extract main local network - prefer the primary interface's network
    main_local_network = "192.168.31.0/24"  # fallback
    if (config.primary_interface.interface_type in [InterfaceType.ETHERNET, InterfaceType.WIFI] and
        any(config.primary_interface.ip_address.startswith(prefix) 
            for prefix in ['192.168.', '10.', '172.'])):
        main_local_network = config.primary_interface.network
    elif config.local_networks:
        # Prefer 192.168.x networks, then 10.x networks
        for network in config.local_networks:
            if network.startswith('192.168.'):
                main_local_network = network
                break
        else:
            for network in config.local_networks:
                if network.startswith('10.'):
                    main_local_network = network
                    break
            else:
                main_local_network = config.local_networks[0]
    
    # Extract VPN network pattern (look for the network portion)
    vpn_pattern = "28.0.0.x"  # fallback
    if config.vpn_networks:
        vpn_net = config.vpn_networks[0]
        # Extract the network part for pattern matching
        try:
            network = ipaddress.IPv4Network(vpn_net)
            network_addr = str(network.network_address)
            # Convert to pattern format (e.g., "28.0.0.x")
            parts = network_addr.split('.')
            if len(parts) >= 3:
                vpn_pattern = f"{parts[0]}.{parts[1]}.{parts[2]}.x"
        except:
            pass
    
    return {
        'local_network': main_local_network,
        'vpn_network': vpn_pattern,
        'main_ip': config.primary_interface.ip_address,
        'gateway': config.gateway or "unknown"
    }


if __name__ == "__main__":
    # Example usage
    print("🔍 Detecting network configuration...")
    
    try:
        # Detect configuration
        config = detect_network_config()
        
        # Print detailed configuration
        detector = NetworkDetector()
        detector.print_configuration(config)
        
        print("\n📄 LEGACY FORMAT:")
        legacy = get_legacy_config()
        for key, value in legacy.items():
            print(f"   {key}: {value}")
        
        print("\n💾 JSON FORMAT:")
        print(json.dumps(config.to_dict(), indent=2))
        
    except Exception as e:
        logger.error(f"Network detection failed: {e}")
        print(f"❌ Error: {e}")