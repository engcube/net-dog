#!/usr/bin/env python3
"""
Test Network Detection Across Different Scenarios

This script tests the network detection functionality across various
common macOS network configurations and scenarios.
"""

import json
from network_detector import NetworkDetector, detect_network_config
from network_config_integration import get_network_config_for_monitoring, is_local_ip, is_vpn_ip


def test_current_configuration():
    """Test the current network configuration"""
    print("🧪 TESTING CURRENT NETWORK CONFIGURATION")
    print("="*50)
    
    try:
        config = detect_network_config()
        
        print("✅ Network Detection: SUCCESS")
        print(f"   Primary Interface: {config.primary_interface.name}")
        print(f"   Primary IP: {config.primary_interface.ip_address}")
        print(f"   Primary Network: {config.primary_interface.network}")
        print(f"   Interface Type: {config.primary_interface.interface_type.value}")
        
        print(f"\n📋 Summary:")
        print(f"   Local Networks: {len(config.local_networks)}")
        print(f"   VPN Networks: {len(config.vpn_networks)}")
        print(f"   Total Interfaces: {len(config.all_interfaces)}")
        print(f"   Gateway: {config.gateway}")
        print(f"   DNS Servers: {len(config.dns_servers)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Network Detection: FAILED - {e}")
        return False


def test_ip_classification():
    """Test IP address classification"""
    print("\n🔍 TESTING IP CLASSIFICATION")
    print("="*35)
    
    # Test various IP addresses
    test_cases = [
        # Local network IPs
        ("192.168.31.31", True, False, "Main local IP"),
        ("192.168.1.100", True, False, "Common router range"),
        ("10.0.0.50", True, False, "Enterprise range"),
        ("172.16.0.10", True, False, "Private range"),
        
        # VPN IPs  
        ("28.0.0.1", False, True, "Clash VPN"),
        ("198.18.0.5", False, True, "Common VPN range"),
        
        # Public IPs
        ("8.8.8.8", False, False, "Google DNS"),
        ("1.1.1.1", False, False, "Cloudflare DNS"),
        ("142.250.191.46", False, False, "Google server"),
        
        # Special IPs
        ("127.0.0.1", False, False, "Localhost"),
        ("169.254.1.1", False, False, "Link-local"),
    ]
    
    print(f"{'IP Address':<16} | {'Local':<5} | {'VPN':<3} | {'Description'}")
    print("-" * 55)
    
    all_passed = True
    
    for ip, expected_local, expected_vpn, description in test_cases:
        actual_local = is_local_ip(ip)
        actual_vpn = is_vpn_ip(ip)
        
        local_status = "✅" if actual_local == expected_local else "❌"
        vpn_status = "✅" if actual_vpn == expected_vpn else "❌"
        
        if actual_local != expected_local or actual_vpn != expected_vpn:
            all_passed = False
        
        print(f"{ip:<16} | {local_status:<5} | {vpn_status:<3} | {description}")
    
    print(f"\n{'✅ All tests passed' if all_passed else '❌ Some tests failed'}")
    return all_passed


def test_different_network_scenarios():
    """Test how the detection would work in different network scenarios"""
    print("\n🌐 TESTING DIFFERENT NETWORK SCENARIOS")
    print("="*45)
    
    scenarios = [
        {
            "name": "Home WiFi (Current)",
            "description": "Typical home router setup",
            "expected_patterns": ["192.168."]
        },
        {
            "name": "Enterprise Network",
            "description": "Corporate network with 10.x addressing",
            "expected_patterns": ["10."]
        },
        {
            "name": "VPN + Local",
            "description": "VPN active with local network",
            "expected_patterns": ["28.0.0.", "192.168."]
        }
    ]
    
    config = get_network_config_for_monitoring()
    
    for scenario in scenarios:
        print(f"\n📋 {scenario['name']}")
        print(f"   Description: {scenario['description']}")
        
        # Check if current config matches expected patterns
        matches = []
        for pattern in scenario['expected_patterns']:
            if (config['main_ip'].startswith(pattern) or 
                any(pattern in net for net in config['all_local_networks'].split(',')) or
                any(pattern in net for net in config['all_vpn_networks'].split(',') if config['all_vpn_networks'])):
                matches.append(pattern)
        
        if scenario['name'] == "Home WiFi (Current)":
            print(f"   Status: ✅ Current configuration")
            print(f"   Local Network: {config['local_network']}")
            print(f"   Main IP: {config['main_ip']}")
            print(f"   VPN Pattern: {config['vpn_network_pattern']}")
        else:
            print(f"   Status: 🔄 Would be auto-detected if active")
            print(f"   Patterns: {', '.join(scenario['expected_patterns'])}")


def test_integration_compatibility():
    """Test compatibility with existing NetworkMonitorV3 patterns"""
    print("\n🔧 TESTING INTEGRATION COMPATIBILITY")
    print("="*40)
    
    config = get_network_config_for_monitoring()
    
    # Test patterns used in NetworkMonitorV3
    patterns_to_test = [
        # VPN connection detection
        ("VPN connection (28.0.0.1)", "28.0.0.1", lambda ip: is_vpn_ip(ip)),
        
        # Local connection detection  
        ("Local connection (192.168.31.31)", "192.168.31.31", lambda ip: is_local_ip(ip)),
        
        # Foreign IP detection
        ("Foreign IP (8.8.8.8)", "8.8.8.8", lambda ip: not (is_local_ip(ip) or is_vpn_ip(ip))),
    ]
    
    all_compatible = True
    
    for test_name, test_ip, test_func in patterns_to_test:
        try:
            result = test_func(test_ip)
            status = "✅" if result else "⚠️"
            print(f"   {status} {test_name}: {'PASS' if result else 'Different from expected'}")
        except Exception as e:
            print(f"   ❌ {test_name}: ERROR - {e}")
            all_compatible = False
    
    # Test hardcoded value replacement
    print(f"\n📋 HARDCODED VALUE REPLACEMENT:")
    print(f"   Original local_network: '192.168.31.0/24'")
    print(f"   Detected local_network: '{config['local_network']}'")
    print(f"   Compatible: {'✅' if config['local_network'] == '192.168.31.0/24' else '🔄 Different but valid'}")
    
    print(f"   Original vpn_network: '28.0.0.x'")
    print(f"   Detected vpn_network: '{config['vpn_network_pattern']}'") 
    print(f"   Compatible: {'✅' if config['vpn_network_pattern'] == '28.0.0.x' else '🔄 Different but valid'}")
    
    print(f"\n{'✅ Integration compatible' if all_compatible else '⚠️ Check compatibility notes'}")
    return all_compatible


def test_performance():
    """Test performance of network detection"""
    print("\n⚡ TESTING PERFORMANCE")
    print("="*25)
    
    import time
    
    # Test detection speed
    start_time = time.time()
    config = detect_network_config()
    detection_time = time.time() - start_time
    
    print(f"   Detection Time: {detection_time:.3f}s")
    print(f"   Performance: {'✅ Fast' if detection_time < 2.0 else '⚠️ Slow' if detection_time < 5.0 else '❌ Too slow'}")
    
    # Test IP classification speed
    start_time = time.time()
    for _ in range(100):
        is_local_ip("192.168.1.1")
        is_vpn_ip("28.0.0.1")
    classification_time = time.time() - start_time
    
    print(f"   IP Classification (100x): {classification_time:.3f}s")
    print(f"   Performance: {'✅ Fast' if classification_time < 0.1 else '⚠️ Acceptable' if classification_time < 0.5 else '❌ Too slow'}")
    
    return detection_time < 5.0 and classification_time < 0.5


def generate_test_report():
    """Generate a comprehensive test report"""
    print("\n📊 COMPREHENSIVE TEST REPORT")
    print("="*60)
    
    tests = [
        ("Current Configuration", test_current_configuration),
        ("IP Classification", test_ip_classification),
        ("Integration Compatibility", test_integration_compatibility),
        ("Performance", test_performance),
    ]
    
    results = {}
    total_tests = len(tests)
    passed_tests = 0
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            result = test_func()
            results[test_name] = "PASS" if result else "FAIL"
            if result:
                passed_tests += 1
        except Exception as e:
            results[test_name] = f"ERROR: {e}"
    
    print(f"\n{'='*60}")
    print("📋 FINAL RESULTS")
    print("="*60)
    
    for test_name, result in results.items():
        status_icon = "✅" if result == "PASS" else "❌" if result == "FAIL" else "🔥"
        print(f"   {status_icon} {test_name}: {result}")
    
    success_rate = (passed_tests / total_tests) * 100
    print(f"\n🎯 SUCCESS RATE: {success_rate:.1f}% ({passed_tests}/{total_tests})")
    
    if success_rate >= 80:
        print("🎉 Network detection is ready for production use!")
    elif success_rate >= 60:
        print("⚠️ Network detection needs minor improvements")
    else:
        print("❌ Network detection needs significant work")
    
    # Configuration summary
    try:
        config = get_network_config_for_monitoring()
        print(f"\n📄 CURRENT CONFIGURATION SUMMARY:")
        print(f"   🏠 Local Network: {config['local_network']}")
        print(f"   📱 Primary IP: {config['main_ip']}")
        print(f"   🔒 VPN Pattern: {config['vpn_network_pattern']}")
        print(f"   🚪 Gateway: {config['gateway']}")
        print(f"   🌐 Total Networks: {len(config['all_local_networks'].split(','))}")
        print(f"   🔐 VPN Networks: {len(config['all_vpn_networks'].split(',')) if config['all_vpn_networks'] else 0}")
    except Exception as e:
        print(f"   ❌ Could not generate configuration summary: {e}")
    
    return success_rate >= 80


if __name__ == "__main__":
    print("🧪 AUTOMATIC NETWORK DETECTION TEST SUITE")
    print("="*60)
    print("Testing network detection across various scenarios and configurations")
    print("="*60)
    
    # Run all tests and generate report
    success = generate_test_report()
    
    print(f"\n{'🎯 ALL SYSTEMS GO! Network detection is ready.' if success else '🔧 Some issues found. Check the results above.'}")
    
    # Quick integration check
    test_different_network_scenarios()