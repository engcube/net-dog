#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray DAT解析器单元测试
测试protobuf解析逻辑的正确性和鲁棒性
"""

import unittest
import tempfile
import os
from v2ray_dat_parser import V2RayDatParser, DomainRule, GeositeEntry, GeoipEntry

class TestV2RayDatParser(unittest.TestCase):
    """V2Ray DAT解析器测试类"""
    
    def setUp(self):
        """测试前准备"""
        self.parser = V2RayDatParser()
    
    def test_parse_domain_rule_basic(self):
        """测试基本域名规则解析"""
        # 测试普通域名
        rule = self.parser._parse_domain_rule("example.com")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_type, "domain")
        self.assertEqual(rule.value, "example.com")
        
        # 测试关键词规则
        rule = self.parser._parse_domain_rule("keyword:google")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_type, "keyword")
        self.assertEqual(rule.value, "google")
        
        # 测试正则表达式规则
        rule = self.parser._parse_domain_rule("regexp:.*\\.example\\.com$")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_type, "regexp")
        self.assertEqual(rule.value, ".*\\.example\\.com$")
        
        # 测试完全匹配规则
        rule = self.parser._parse_domain_rule("full:exact.example.com")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_type, "full")
        self.assertEqual(rule.value, "exact.example.com")
        
        # 测试显式域名规则
        rule = self.parser._parse_domain_rule("domain:example.com")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_type, "domain")
        self.assertEqual(rule.value, "example.com")
    
    def test_parse_domain_rule_with_attributes(self):
        """测试带属性的域名规则解析"""
        rule = self.parser._parse_domain_rule("example.com@cn")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_type, "domain")
        self.assertEqual(rule.value, "example.com")
        self.assertEqual(rule.attributes, ["@cn"])
        
        # 测试多个属性
        rule = self.parser._parse_domain_rule("keyword:google@cn@ads")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_type, "keyword")
        self.assertEqual(rule.value, "google")
        self.assertEqual(rule.attributes, ["@cn", "@ads"])
    
    def test_parse_domain_rule_edge_cases(self):
        """测试边缘情况"""
        # 空字符串
        rule = self.parser._parse_domain_rule("")
        self.assertIsNone(rule)
        
        # None值
        rule = self.parser._parse_domain_rule(None)
        self.assertIsNone(rule)
        
        # 排除规则（以!开头）
        rule = self.parser._parse_domain_rule("!example.com")
        self.assertIsNone(rule)
        
        # 只有前缀没有值
        rule = self.parser._parse_domain_rule("keyword:")
        self.assertIsNone(rule)
    
    def test_read_varint(self):
        """测试varint读取功能"""
        # 测试单字节varint
        data = b'\x08'  # varint 8
        result, bytes_read = self.parser._read_varint(data, 0)
        self.assertEqual(result, 8)
        self.assertEqual(bytes_read, 1)
        
        # 测试多字节varint
        data = b'\x96\x01'  # varint 150
        result, bytes_read = self.parser._read_varint(data, 0)
        self.assertEqual(result, 150)
        self.assertEqual(bytes_read, 2)
        
        # 测试数据不足的情况
        data = b''
        result, bytes_read = self.parser._read_varint(data, 0)
        self.assertIsNone(result)
    
    def test_parse_ip_range(self):
        """测试IP范围解析"""
        # 构造一个简单的CIDR protobuf消息
        # 字段1(IP): 0x0a 0x04 [4 bytes IP], 字段2(前缀): 0x10 [prefix]
        ip_bytes = bytes([192, 168, 1, 0])  # 192.168.1.0
        prefix = 24
        
        # 构造protobuf数据: 字段1(wire type 2) + 长度4 + IP字节 + 字段2(wire type 0) + 前缀
        proto_data = bytes([0x0a, 0x04]) + ip_bytes + bytes([0x10, prefix])
        
        result = self.parser._parse_ip_range(proto_data)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "192.168.1.0")
        self.assertEqual(result[1], 24)
    
    def test_get_fallback_geosite_data(self):
        """测试后备数据生成"""
        fallback_data = self.parser._get_fallback_geosite_data()
        
        # 检查是否包含基本服务
        self.assertIn('GOOGLE', fallback_data)
        self.assertIn('FACEBOOK', fallback_data)
        self.assertIn('BAIDU', fallback_data)
        
        # 检查数据结构正确性
        google_entry = fallback_data['GOOGLE']
        self.assertIsInstance(google_entry, GeositeEntry)
        self.assertEqual(google_entry.category, 'GOOGLE')
        self.assertGreater(len(google_entry.domains), 0)
        
        # 检查域名规则是否正确创建
        first_domain = google_entry.domains[0]
        self.assertIsInstance(first_domain, DomainRule)
        self.assertEqual(first_domain.rule_type, 'domain')
    
    def test_get_statistics(self):
        """测试统计信息功能"""
        stats = self.parser.get_statistics()
        
        # 检查返回的字段
        expected_fields = ['geosite_categories', 'total_domains', 'geoip_countries', 'total_ip_ranges']
        for field in expected_fields:
            self.assertIn(field, stats)
            self.assertIsInstance(stats[field], int)
            self.assertGreaterEqual(stats[field], 0)

class TestDomainRule(unittest.TestCase):
    """域名规则数据类测试"""
    
    def test_domain_rule_creation(self):
        """测试域名规则创建"""
        rule = DomainRule(
            rule_type="keyword",
            value="google",
            attributes=["@cn"]
        )
        
        self.assertEqual(rule.rule_type, "keyword")
        self.assertEqual(rule.value, "google")
        self.assertEqual(rule.attributes, ["@cn"])
    
    def test_domain_rule_defaults(self):
        """测试默认值"""
        rule = DomainRule(rule_type="domain", value="example.com")
        
        self.assertEqual(rule.rule_type, "domain")
        self.assertEqual(rule.value, "example.com")
        self.assertIsNone(rule.attributes)

class TestGeositeEntry(unittest.TestCase):
    """GeoSite条目测试"""
    
    def test_geosite_entry_creation(self):
        """测试GeoSite条目创建"""
        domains = [
            DomainRule("domain", "example.com"),
            DomainRule("keyword", "google")
        ]
        
        entry = GeositeEntry(
            category="TEST",
            domains=domains,
            domain_count=len(domains)
        )
        
        self.assertEqual(entry.category, "TEST")
        self.assertEqual(entry.domain_count, 2)
        self.assertEqual(len(entry.domains), 2)
        self.assertIsInstance(entry.domains[0], DomainRule)

class TestGeoipEntry(unittest.TestCase):
    """GeoIP条目测试"""
    
    def test_geoip_entry_creation(self):
        """测试GeoIP条目创建"""
        ip_ranges = [("192.168.1.0", 24), ("10.0.0.0", 8)]
        total_ips = sum(2**(32-prefix) for _, prefix in ip_ranges)
        
        entry = GeoipEntry(
            country_code="TEST",
            ip_ranges=ip_ranges,
            total_ips=total_ips
        )
        
        self.assertEqual(entry.country_code, "TEST")
        self.assertEqual(len(entry.ip_ranges), 2)
        self.assertEqual(entry.total_ips, 256 + 16777216)  # /24 + /8

def run_parser_tests():
    """运行所有V2Ray解析器测试"""
    print("🧪 运行V2Ray DAT解析器单元测试")
    print("=" * 50)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 添加所有测试类
    test_classes = [
        TestV2RayDatParser,
        TestDomainRule, 
        TestGeositeEntry,
        TestGeoipEntry
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # 输出结果总结
    print(f"\n📊 测试总结:")
    print(f"   运行测试: {result.testsRun}")
    print(f"   成功: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"   失败: {len(result.failures)}")
    print(f"   错误: {len(result.errors)}")
    
    if result.failures:
        print(f"\n❌ 失败的测试:")
        for test, traceback in result.failures:
            print(f"   - {test}: {traceback.split('AssertionError: ')[-1].split('\\n')[0]}")
    
    if result.errors:
        print(f"\n💥 错误的测试:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback.split('\\n')[-2]}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\n{'✅ 所有测试通过!' if success else '❌ 存在测试失败!'}")
    
    return success

if __name__ == "__main__":
    run_parser_tests()