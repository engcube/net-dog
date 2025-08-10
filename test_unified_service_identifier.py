#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一服务识别器单元测试
测试IP地址识别、域名识别和服务分类的准确性
"""

import unittest
import tempfile
import os
import json
from unified_service_identifier import UnifiedServiceIdentifier, ServiceInfo

class TestUnifiedServiceIdentifier(unittest.TestCase):
    """统一服务识别器测试类"""
    
    def setUp(self):
        """测试前准备"""
        # 创建临时缓存文件
        self.temp_cache = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.temp_cache.close()
        
        self.identifier = UnifiedServiceIdentifier(cache_file=self.temp_cache.name)
    
    def tearDown(self):
        """测试后清理"""
        # 清理临时文件
        if os.path.exists(self.temp_cache.name):
            os.unlink(self.temp_cache.name)
    
    def test_service_info_creation(self):
        """测试ServiceInfo数据类"""
        service = ServiceInfo("google", "Google", "search", "us", 0.95)
        
        self.assertEqual(service.name, "google")
        self.assertEqual(service.display_name, "Google")
        self.assertEqual(service.category, "search")
        self.assertEqual(service.country, "us")
        self.assertEqual(service.confidence, 0.95)
    
    def test_service_info_defaults(self):
        """测试ServiceInfo默认值"""
        service = ServiceInfo("test", "Test", "misc", "unknown")
        self.assertEqual(service.confidence, 0.9)  # 默认置信度
    
    def test_identify_service_by_ip_range(self):
        """测试基于IP段的服务识别"""
        # Google DNS
        service = self.identifier.identify_service_by_ip("8.8.8.8")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "google")
        self.assertEqual(service.display_name, "Google DNS")
        
        # Cloudflare DNS
        service = self.identifier.identify_service_by_ip("1.1.1.1")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "cloudflare")
        self.assertEqual(service.display_name, "Cloudflare DNS")
        
        # Niconico
        service = self.identifier.identify_service_by_ip("210.129.120.100")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "niconico")
        self.assertEqual(service.category, "video")
    
    def test_identify_service_by_domain(self):
        """测试基于域名的服务识别"""
        # Niconico
        service = self.identifier.identify_service_by_domain("www.nicovideo.jp")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "niconico")
        self.assertEqual(service.category, "video")
        
        # YouTube
        service = self.identifier.identify_service_by_domain("www.youtube.com")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "youtube")
        self.assertEqual(service.category, "video")
        
        # Google
        service = self.identifier.identify_service_by_domain("www.google.com")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "google")
        self.assertEqual(service.category, "search")
        
        # 不匹配的域名
        service = self.identifier.identify_service_by_domain("unknown.example.com")
        self.assertIsNone(service)
    
    def test_asn_heuristics(self):
        """测试ASN启发式识别"""
        # Google DNS (特殊模式)
        service = self.identifier._identify_by_asn_heuristics("8.8.8.8")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "google")
        
        # Cloudflare (1.1.1.x)
        service = self.identifier._identify_by_asn_heuristics("1.1.1.1")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "cloudflare")
        
        # NTT/Niconico范围
        service = self.identifier._identify_by_asn_heuristics("210.129.1.1")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "ntt")
        
        # 阿里云范围
        service = self.identifier._identify_by_asn_heuristics("47.88.1.1")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "alibaba")
        
        # 不匹配的IP
        service = self.identifier._identify_by_asn_heuristics("192.168.1.1")
        self.assertIsNone(service)
    
    def test_legacy_pattern_match(self):
        """测试传统模式匹配"""
        # YouTube优先级测试
        service = self.identifier._legacy_pattern_match("172.217.1.1")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "youtube")  # YouTube应该有更高优先级
        
        # Amazon AWS
        service = self.identifier._legacy_pattern_match("52.1.1.1")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "amazon")
        
        # 阿里云
        service = self.identifier._legacy_pattern_match("47.74.1.1")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "alibaba")
        
        # 腾讯云
        service = self.identifier._legacy_pattern_match("129.211.1.1")
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "tencent")
    
    def test_get_enhanced_service_name(self):
        """测试增强服务名称获取"""
        # 域名优先级测试
        service_name, display_name = self.identifier.get_enhanced_service_name(
            "8.8.8.8", "www.youtube.com"
        )
        self.assertEqual(service_name, "youtube")  # 域名识别优先于IP
        self.assertEqual(display_name, "YouTube")
        
        # 仅IP识别
        service_name, display_name = self.identifier.get_enhanced_service_name("1.1.1.1")
        self.assertEqual(service_name, "cloudflare")
        self.assertEqual(display_name, "Cloudflare DNS")
        
        # 无法识别
        service_name, display_name = self.identifier.get_enhanced_service_name("192.168.1.1")
        self.assertIsNone(service_name)
        self.assertIsNone(display_name)
    
    def test_identify_ip_legacy_interface(self):
        """测试legacy接口兼容性"""
        # 测试能够识别的IP
        provider, region, confidence = self.identifier.identify_ip("8.8.8.8")
        self.assertEqual(provider, "Google DNS")
        self.assertEqual(region, "海外")
        self.assertGreater(confidence, 0.5)
        
        # 测试中国IP
        provider, region, confidence = self.identifier.identify_ip("47.88.1.1")
        self.assertEqual(provider, "阿里云")
        self.assertEqual(region, "中国")
        self.assertGreater(confidence, 0.5)
        
        # 测试无法识别的IP（兜底逻辑）
        provider, region, confidence = self.identifier.identify_ip("192.168.1.1")
        self.assertIn("网站", provider)  # 应该包含"网站"
        self.assertIn(region, ["中国", "海外"])
        self.assertEqual(confidence, 0.3)  # 兜底置信度
    
    def test_get_service_category(self):
        """测试服务类别获取"""
        # 视频服务
        category = self.identifier.get_service_category("210.129.120.100")
        self.assertEqual(category, "video")
        
        category = self.identifier.get_service_category("1.1.1.1", "www.youtube.com")
        self.assertEqual(category, "video")  # 域名优先
        
        # DNS服务 (Cloudflare DNS被分类为dns而不是cdn)
        category = self.identifier.get_service_category("1.1.1.1")
        self.assertEqual(category, "dns")
        
        # DNS服务 
        category = self.identifier.get_service_category("8.8.8.8")
        self.assertEqual(category, "dns")  # Google DNS被正确分类为dns
        
        # 未知服务
        category = self.identifier.get_service_category("192.168.1.1")
        self.assertIsNone(category)
    
    def test_is_media_service(self):
        """测试媒体服务判断"""
        # Niconico - 视频服务
        self.assertTrue(self.identifier.is_media_service("210.129.120.100"))
        
        # YouTube - 视频服务
        self.assertTrue(self.identifier.is_media_service("1.1.1.1", "www.youtube.com"))
        
        # Cloudflare DNS - DNS服务，非媒体
        self.assertFalse(self.identifier.is_media_service("1.1.1.1"))
        
        # 未知服务
        self.assertFalse(self.identifier.is_media_service("192.168.1.1"))
    
    def test_country_to_region_mapping(self):
        """测试国家到地区的映射"""
        # 中国地区
        self.assertEqual(self.identifier._map_country_to_region("cn"), "中国")
        self.assertEqual(self.identifier._map_country_to_region("hk"), "中国")
        self.assertEqual(self.identifier._map_country_to_region("tw"), "中国")
        self.assertEqual(self.identifier._map_country_to_region("mo"), "中国")
        
        # 海外地区
        self.assertEqual(self.identifier._map_country_to_region("us"), "海外")
        self.assertEqual(self.identifier._map_country_to_region("jp"), "海外")
        self.assertEqual(self.identifier._map_country_to_region("uk"), "海外")
        
        # 大小写不敏感
        self.assertEqual(self.identifier._map_country_to_region("CN"), "中国")
        self.assertEqual(self.identifier._map_country_to_region("US"), "海外")
    
    def test_cache_functionality(self):
        """测试缓存功能"""
        # 第一次调用，应该进行识别并缓存
        provider1, region1, confidence1 = self.identifier.identify_ip("8.8.8.8")
        
        # 检查缓存中是否有数据
        self.assertIn("8.8.8.8", self.identifier.cache)
        cached_data = self.identifier.cache["8.8.8.8"]
        self.assertEqual(cached_data["provider"], provider1)
        self.assertEqual(cached_data["region"], region1)
        
        # 第二次调用，应该从缓存读取
        provider2, region2, confidence2 = self.identifier.identify_ip("8.8.8.8")
        self.assertEqual(provider1, provider2)
        self.assertEqual(region1, region2)
    
    def test_get_statistics(self):
        """测试统计信息"""
        stats = self.identifier.get_statistics()
        
        expected_fields = ['asn_entries', 'ip_range_entries', 'domain_patterns', 'legacy_providers', 'cached_entries']
        for field in expected_fields:
            self.assertIn(field, stats)
            self.assertIsInstance(stats[field], int)
            self.assertGreaterEqual(stats[field], 0)
        
        # 检查一些具体数值
        self.assertGreater(stats['asn_entries'], 0)
        self.assertGreater(stats['ip_range_entries'], 0)
        self.assertGreater(stats['domain_patterns'], 0)
        self.assertGreater(stats['legacy_providers'], 0)
    
    def test_invalid_ip_handling(self):
        """测试无效IP处理"""
        # 无效IP格式
        service = self.identifier.identify_service_by_ip("invalid-ip")
        self.assertIsNone(service)
        
        # 空字符串
        service = self.identifier.identify_service_by_ip("")
        self.assertIsNone(service)
        
        # None值 
        service = self.identifier.identify_service_by_ip(None)
        self.assertIsNone(service)
    
    def test_invalid_domain_handling(self):
        """测试无效域名处理"""
        # 空字符串
        service = self.identifier.identify_service_by_domain("")
        self.assertIsNone(service)
        
        # None值
        service = self.identifier.identify_service_by_domain(None)
        self.assertIsNone(service)
    
    def test_global_aliases(self):
        """测试全局别名向后兼容性"""
        from unified_service_identifier import smart_ip_identifier, service_identifier
        
        # 检查别名指向同一个实例
        self.assertIs(smart_ip_identifier, self.identifier.__class__._instance if hasattr(self.identifier.__class__, '_instance') else unified_service_identifier)
        self.assertIs(service_identifier, smart_ip_identifier)
        
        # 检查别名功能正常
        provider, region, confidence = smart_ip_identifier.identify_ip("8.8.8.8")
        self.assertEqual(provider, "Google DNS")
        
        service_name, display_name = service_identifier.get_enhanced_service_name("1.1.1.1")
        self.assertEqual(service_name, "cloudflare")

def run_unified_service_tests():
    """运行所有统一服务识别器测试"""
    print("🧪 运行统一服务识别器单元测试")
    print("=" * 50)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestUnifiedServiceIdentifier)
    
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
    run_unified_service_tests()