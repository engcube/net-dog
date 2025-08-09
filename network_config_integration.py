#!/usr/bin/env python3
"""
Network Configuration Integration Helper

This module provides integration functions to replace hardcoded network values
in existing network monitoring applications with automatically detected values.
"""

from network_detector import detect_network_config, get_legacy_config, NetworkDetector
from typing import Dict, List, Tuple, Optional
import logging
import time
from functools import lru_cache

logger = logging.getLogger(__name__)

# Cache configuration to avoid repeated network detection calls
_config_cache = {}
_config_cache_time = 0
_cache_duration = 60  # Cache for 60 seconds


def get_network_config_for_monitoring() -> Dict[str, str]:
    """
    Get network configuration optimized for network monitoring applications
    Uses caching to avoid repeated expensive network detection calls.
    
    Returns:
        Dict containing:
        - local_network: Primary local network in CIDR format
        - vpn_network_pattern: VPN network pattern for matching (e.g., "28.0.0.x")
        - main_ip: Primary interface IP address
        - gateway: Default gateway IP
        - all_local_networks: All detected local networks
        - all_vpn_networks: All detected VPN networks
    """
    global _config_cache, _config_cache_time
    
    current_time = time.time()
    
    # Return cached config if still valid
    if (_config_cache and 
        current_time - _config_cache_time < _cache_duration):
        return _config_cache
    
    try:
        config = detect_network_config()
        legacy = get_legacy_config()
        
        # Get comprehensive network information
        result = {
            'local_network': legacy['local_network'],
            'vpn_network_pattern': legacy['vpn_network'],
            'main_ip': legacy['main_ip'],
            'gateway': legacy['gateway'],
            'all_local_networks': ','.join(config.local_networks),
            'all_vpn_networks': ','.join(config.vpn_networks),
            'primary_interface': config.primary_interface.name,
            'dns_servers': ','.join(config.dns_servers)
        }
        
        # Update cache
        _config_cache = result
        _config_cache_time = current_time
        
        logger.info(f"Network config detected: {result['main_ip']} on {result['local_network']}")
        return result
        
    except Exception as e:
        logger.error(f"Failed to detect network configuration: {e}")
        # Return fallback values
        fallback = {
            'local_network': '192.168.31.0/24',
            'vpn_network_pattern': '28.0.0.x',
            'main_ip': '192.168.31.31',
            'gateway': '192.168.31.1',
            'all_local_networks': '192.168.31.0/24',
            'all_vpn_networks': '',
            'primary_interface': 'unknown',
            'dns_servers': ''
        }
        
        # Cache fallback too to avoid repeated failures
        _config_cache = fallback
        _config_cache_time = current_time
        
        return fallback


def replace_hardcoded_networks_in_monitor(monitor_instance):
    """
    Update a network monitor instance with detected network configuration
    
    This function replaces hardcoded network values in existing monitoring
    applications like NetworkMonitorV3.
    
    Args:
        monitor_instance: Instance of a network monitor class
    """
    try:
        config = get_network_config_for_monitoring()
        
        # Update local network detection
        if hasattr(monitor_instance, 'local_network'):
            old_network = monitor_instance.local_network
            monitor_instance.local_network = config['local_network']
            logger.info(f"Updated local_network: {old_network} -> {config['local_network']}")
        
        # Update any hardcoded IP addresses in connection filtering
        if hasattr(monitor_instance, '_get_active_connections'):
            # Store the original method
            original_method = monitor_instance._get_active_connections
            
            def enhanced_connections():
                """Enhanced connection method with dynamic network detection"""
                connections = original_method()
                # Could add additional filtering based on detected networks
                return connections
            
            # Replace the method
            monitor_instance._get_active_connections = enhanced_connections
            
        logger.info("Network monitor updated with automatic configuration")
        
    except Exception as e:
        logger.error(f"Failed to update monitor configuration: {e}")


def is_local_ip(ip: str) -> bool:
    """
    Check if an IP address belongs to any detected local network
    
    Args:
        ip: IP address to check
        
    Returns:
        bool: True if IP is in a local network
    """
    # Quick check for obviously non-local IPs
    if ip.startswith(('127.', '169.254.')) or ip in ['8.8.8.8', '1.1.1.1']:
        return False
    
    try:
        config = get_network_config_for_monitoring()
        import ipaddress
        
        ip_addr = ipaddress.IPv4Address(ip)
        
        # Check against detected local networks
        if config['all_local_networks']:
            for network_str in config['all_local_networks'].split(','):
                if network_str.strip():
                    network = ipaddress.IPv4Network(network_str.strip())
                    if ip_addr in network:
                        return True
        
        # Check against primary network
        if config['local_network']:
            network = ipaddress.IPv4Network(config['local_network'])
            if ip_addr in network:
                return True
                
        return False
        
    except Exception:
        # Fallback to common private ranges
        return any(ip.startswith(prefix) for prefix in ['192.168.', '10.', '172.'])


def is_vpn_ip(ip: str) -> bool:
    """
    Check if an IP address belongs to any detected VPN network
    
    Args:
        ip: IP address to check
        
    Returns:
        bool: True if IP is from VPN
    """
    # Quick check for obviously non-VPN IPs
    if ip.startswith(('127.', '169.254.', '192.168.', '10.', '172.')) or ip in ['8.8.8.8', '1.1.1.1']:
        # Special case: check if it's actually a VPN IP that looks like local
        if not ip.startswith(('28.', '198.18.', '100.64.')):
            return False
    
    try:
        config = get_network_config_for_monitoring()
        import ipaddress
        
        ip_addr = ipaddress.IPv4Address(ip)
        
        # Check against detected VPN networks
        if config['all_vpn_networks']:
            for network_str in config['all_vpn_networks'].split(','):
                if network_str.strip():
                    network = ipaddress.IPv4Network(network_str.strip())
                    if ip_addr in network:
                        return True
        
        return False
        
    except Exception:
        # Fallback to common VPN ranges
        return any(ip.startswith(prefix) for prefix in ['28.', '198.18.', '100.64.'])


def get_device_classification(local_ip: str) -> str:
    """
    Classify a local IP address into device categories for monitoring
    
    Args:
        local_ip: Local IP address
        
    Returns:
        str: Device classification ("Clash设备", "直连设备", etc.)
    """
    if is_vpn_ip(local_ip):
        return "Clash设备"  # VPN/Proxy device
    elif is_local_ip(local_ip):
        return "直连设备"  # Direct connection device  
    else:
        return f"设备-{local_ip.split('.')[-1]}"  # Generic device


def print_network_summary():
    """Print a summary of detected network configuration"""
    print("\n🌐 AUTOMATIC NETWORK CONFIGURATION")
    print("="*50)
    
    config = get_network_config_for_monitoring()
    
    print(f"🏠 Primary Network: {config['local_network']}")
    print(f"📱 Primary IP: {config['main_ip']}")
    print(f"🔒 VPN Pattern: {config['vpn_network_pattern']}")
    print(f"🚪 Gateway: {config['gateway']}")
    
    if config['all_local_networks']:
        networks = config['all_local_networks'].split(',')
        print(f"🏘️  All Local Networks: {len(networks)}")
        for net in networks:
            print(f"   • {net}")
    
    if config['all_vpn_networks']:
        vpn_nets = config['all_vpn_networks'].split(',')
        print(f"🔐 VPN Networks: {len(vpn_nets)}")
        for net in vpn_nets:
            print(f"   • {net}")
    
    print("\n💡 Integration Tips:")
    print("   1. Replace hardcoded '192.168.31.0/24' with detected local_network")
    print("   2. Replace hardcoded '28.0.0.x' with detected vpn_network_pattern")  
    print("   3. Replace hardcoded '192.168.31.31' with detected main_ip")
    print("   4. Use is_local_ip() and is_vpn_ip() for dynamic classification")
    
    print("\n📝 Example Code:")
    print("   from network_config_integration import get_network_config_for_monitoring")
    print("   config = get_network_config_for_monitoring()")
    print("   local_network = config['local_network']  # Instead of '192.168.31.0/24'")
    print("="*50)


if __name__ == "__main__":
    # Demonstrate the integration helper
    print_network_summary()
    
    # Test IP classification
    test_ips = ['192.168.31.31', '28.0.0.1', '8.8.8.8', '100.109.249.120']
    print("\n🧪 IP CLASSIFICATION TEST")
    print("-"*30)
    for ip in test_ips:
        local = "✅" if is_local_ip(ip) else "❌"
        vpn = "✅" if is_vpn_ip(ip) else "❌"
        classification = get_device_classification(ip)
        print(f"{ip:15} | Local: {local} | VPN: {vpn} | Type: {classification}")