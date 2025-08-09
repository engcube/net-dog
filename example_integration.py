#!/usr/bin/env python3
"""
Example Integration: Automatic Network Detection in Network Monitor

This example shows how to integrate the automatic network detection
into the existing NetworkMonitorV3 class to replace hardcoded values.
"""

import sys
from network_config_integration import (
    get_network_config_for_monitoring,
    is_local_ip,
    is_vpn_ip,
    get_device_classification
)


def demo_hardcoded_vs_detected():
    """
    Demonstrate the difference between hardcoded and automatically detected values
    """
    print("🔄 HARDCODED vs AUTOMATICALLY DETECTED VALUES")
    print("="*60)
    
    # Old hardcoded values
    hardcoded = {
        'local_network': '192.168.31.0/24',
        'vpn_network': '28.0.0.x',
        'main_ip': '192.168.31.31'
    }
    
    # Automatically detected values
    detected = get_network_config_for_monitoring()
    
    print("📊 COMPARISON:")
    print(f"Local Network:")
    print(f"   Hardcoded: {hardcoded['local_network']}")
    print(f"   Detected:  {detected['local_network']}")
    print(f"   Match: {'✅' if hardcoded['local_network'] == detected['local_network'] else '❌'}")
    
    print(f"\nVPN Network:")
    print(f"   Hardcoded: {hardcoded['vpn_network']}")
    print(f"   Detected:  {detected['vpn_network_pattern']}")
    print(f"   Match: {'✅' if hardcoded['vpn_network'] == detected['vpn_network_pattern'] else '❌'}")
    
    print(f"\nMain IP:")
    print(f"   Hardcoded: {hardcoded['main_ip']}")
    print(f"   Detected:  {detected['main_ip']}")
    print(f"   Match: {'✅' if hardcoded['main_ip'] == detected['main_ip'] else '❌'}")
    
    print("\n🎯 BENEFITS OF AUTOMATIC DETECTION:")
    print("   ✅ Works on any Mac with any network configuration")
    print("   ✅ Automatically adapts to VPN changes") 
    print("   ✅ Detects multiple network interfaces")
    print("   ✅ No manual configuration required")
    print("   ✅ Handles bridge/VM networks")
    
    print("\n" + "="*60)


def demo_enhanced_connection_filtering():
    """
    Demonstrate enhanced connection filtering using automatic detection
    """
    print("🔍 ENHANCED CONNECTION FILTERING")
    print("="*40)
    
    # Sample connection data
    test_connections = [
        {'local_ip': '192.168.31.31', 'foreign_ip': '8.8.8.8'},
        {'local_ip': '28.0.0.1', 'foreign_ip': '1.1.1.1'},
        {'local_ip': '192.168.107.1', 'foreign_ip': '142.250.191.46'},
        {'local_ip': '100.109.249.120', 'foreign_ip': '52.84.229.83'},
    ]
    
    print("🌐 CONNECTION ANALYSIS:")
    print(f"{'Local IP':<17} | {'Classification':<12} | {'Foreign IP':<15} | {'Type'}")
    print("-" * 70)
    
    for conn in test_connections:
        local_ip = conn['local_ip']
        foreign_ip = conn['foreign_ip']
        classification = get_device_classification(local_ip)
        
        # Determine connection type
        if is_vpn_ip(local_ip):
            conn_type = "🔒 VPN Connection"
        elif is_local_ip(local_ip):
            conn_type = "🏠 Local Connection"
        else:
            conn_type = "❓ Unknown"
        
        print(f"{local_ip:<17} | {classification:<12} | {foreign_ip:<15} | {conn_type}")
    
    print("\n💡 This replaces hardcoded IP checks like:")
    print("   OLD: if local_ip.startswith('28.0.0.'):")
    print("   NEW: if is_vpn_ip(local_ip):")
    print("\n   OLD: if local_ip.startswith('192.168.31.'):")
    print("   NEW: if is_local_ip(local_ip):")
    
    print("\n" + "="*40)


def create_enhanced_detect_local_network():
    """
    Show how to create an enhanced _detect_local_network method
    """
    print("⚙️ ENHANCED _detect_local_network() METHOD")
    print("="*45)
    
    # Original hardcoded method
    print("📜 ORIGINAL METHOD:")
    print("""
def _detect_local_network(self) -> str:
    try:
        result = subprocess.run(['route', '-n', 'get', 'default'], 
                              capture_output=True, text=True)
        gateway_match = re.search(r'gateway: ([\\d.]+)', result.stdout)
        if gateway_match:
            gateway = gateway_match.group(1)
            return '.'.join(gateway.split('.')[:-1]) + '.0/24'
        return '192.168.31.0/24'  # HARDCODED FALLBACK
    except:
        return '192.168.31.0/24'  # HARDCODED FALLBACK
    """)
    
    print("\n🚀 ENHANCED METHOD:")
    print("""
def _detect_local_network(self) -> str:
    try:
        from network_config_integration import get_network_config_for_monitoring
        config = get_network_config_for_monitoring()
        return config['local_network']  # AUTOMATICALLY DETECTED
    except:
        return '192.168.31.0/24'  # FALLBACK ONLY IF DETECTION FAILS
    """)
    
    # Test both approaches
    config = get_network_config_for_monitoring()
    
    print(f"\n📊 RESULTS COMPARISON:")
    print(f"   Original (hardcoded): 192.168.31.0/24")
    print(f"   Enhanced (detected):  {config['local_network']}")
    print(f"   Gateway detected:     {config['gateway']}")
    print(f"   All networks:         {config['all_local_networks']}")
    
    print("\n✨ IMPROVEMENTS:")
    print("   • Detects actual network configuration")
    print("   • Works with any router/network setup")
    print("   • Handles multiple subnets")
    print("   • Adapts to network changes")
    
    print("\n" + "="*45)


def show_integration_code():
    """
    Show complete integration code for NetworkMonitorV3
    """
    print("🔧 COMPLETE INTEGRATION CODE")
    print("="*50)
    
    integration_code = '''
# Add this import at the top of network_monitor_v3.py
from network_config_integration import (
    get_network_config_for_monitoring,
    is_local_ip,
    is_vpn_ip,
    get_device_classification
)

# Replace the __init__ method's network detection:
class NetworkMonitorV3:
    def __init__(self):
        # ... existing code ...
        
        # REPLACE THIS LINE:
        # self.local_network = self._detect_local_network()
        
        # WITH THIS:
        self.network_config = get_network_config_for_monitoring()
        self.local_network = self.network_config['local_network']
        
        # ... rest of existing code ...
    
    # ENHANCED: Replace _detect_local_network method
    def _detect_local_network(self) -> str:
        try:
            return self.network_config['local_network']
        except:
            return '192.168.31.0/24'  # Fallback
    
    # ENHANCED: Update connection filtering in _get_active_connections
    def _get_active_connections(self) -> List[Dict]:
        connections = []
        try:
            result = subprocess.run(['netstat', '-n'], capture_output=True, text=True)
            
            for line in result.stdout.split('\\n'):
                if 'tcp4' in line:
                    # ... parsing code ...
                    
                    # REPLACE hardcoded IP checks:
                    # OLD: is_local = local_ip.startswith(('192.168.', '10.', '28.'))
                    # NEW: 
                    is_local = is_local_ip(local_ip) or is_vpn_ip(local_ip)
                    is_foreign = not (is_local_ip(foreign_ip) or is_vpn_ip(foreign_ip))
                    
                    # ... rest of connection processing ...
        except:
            pass
        return connections
    
    # ENHANCED: Update device classification
    def _classify_device_connection(self, local_ip: str) -> str:
        return get_device_classification(local_ip)
'''
    
    print(integration_code)
    print("="*50)


if __name__ == "__main__":
    print("🌐 AUTOMATIC NETWORK DETECTION INTEGRATION DEMO")
    print("="*60)
    print("This demo shows how to replace hardcoded network values")
    print("in NetworkMonitorV3 with automatic detection.")
    print("="*60)
    
    # Run all demonstrations
    demo_hardcoded_vs_detected()
    print("\n")
    
    demo_enhanced_connection_filtering()
    print("\n")
    
    create_enhanced_detect_local_network()
    print("\n")
    
    show_integration_code()
    
    print("\n🎯 NEXT STEPS:")
    print("1. Import network_config_integration in network_monitor_v3.py")
    print("2. Replace hardcoded values with get_network_config_for_monitoring()")
    print("3. Use is_local_ip() and is_vpn_ip() for dynamic classification")
    print("4. Test on different network configurations")
    print("5. Enjoy automatic network adaptation! 🚀")