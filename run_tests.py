#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试套件主入口
运行所有单元测试并生成测试报告
"""

import sys
import os
from test_v2ray_parser import run_parser_tests
from test_unified_service_identifier import run_unified_service_tests

def run_all_tests():
    """运行所有测试套件"""
    print("🚀 网络监控工具测试套件")
    print("=" * 60)
    print("运行所有单元测试以验证代码质量和功能正确性\n")
    
    test_results = []
    
    # 1. V2Ray解析器测试
    print("1️⃣  V2Ray DAT解析器测试")
    print("-" * 30)
    parser_success = run_parser_tests()
    test_results.append(("V2Ray解析器", parser_success))
    print()
    
    # 2. 统一服务识别器测试
    print("2️⃣  统一服务识别器测试")
    print("-" * 30)
    service_success = run_unified_service_tests()
    test_results.append(("统一服务识别器", service_success))
    print()
    
    # 输出总结报告
    print("=" * 60)
    print("🎯 测试总结报告")
    print("=" * 60)
    
    total_tests = len(test_results)
    passed_tests = sum(1 for _, success in test_results if success)
    
    for test_name, success in test_results:
        status = "✅ 通过" if success else "❌ 失败"
        print(f"   {test_name:<20} {status}")
    
    print(f"\n📈 总体结果: {passed_tests}/{total_tests} 测试套件通过")
    
    if passed_tests == total_tests:
        print("🎉 所有测试都已通过！代码质量良好。")
        return True
    else:
        print("⚠️  存在测试失败，请检查相关代码。")
        return False

def run_quick_tests():
    """运行快速测试（跳过耗时的集成测试）"""
    print("⚡ 快速测试模式")
    print("=" * 60)
    
    # 只运行核心功能测试
    from test_unified_service_identifier import TestUnifiedServiceIdentifier
    import unittest
    
    loader = unittest.TestLoader()
    
    # 选择重要的测试方法
    quick_tests = [
        'test_service_info_creation',
        'test_identify_service_by_ip_range', 
        'test_identify_service_by_domain',
        'test_get_enhanced_service_name',
        'test_get_service_category',
        'test_is_media_service'
    ]
    
    suite = unittest.TestSuite()
    for test_name in quick_tests:
        suite.addTest(TestUnifiedServiceIdentifier(test_name))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    
    if success:
        print("\n✅ 快速测试通过！核心功能正常。")
    else:
        print("\n❌ 快速测试失败，请运行完整测试suite。")
    
    return success

def main():
    """主函数"""
    if len(sys.argv) > 1 and sys.argv[1] == "quick":
        success = run_quick_tests()
    else:
        success = run_all_tests()
    
    # 返回适当的退出码
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()