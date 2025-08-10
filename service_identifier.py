#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强的服务识别器
基于IP段、ASN和启发式规则识别网络服务
解决DNS反解析失败时的服务识别问题
"""

import ipaddress
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class ServiceInfo:
    """服务信息"""
    name: str           # 服务名称
    display_name: str   # 显示名称
    category: str       # 服务类别 (video, social, cloud, etc.)
    country: str        # 服务主要地区

class ServiceIdentifier:
    """增强的服务识别器"""
    
    def __init__(self):
        # 构建综合服务数据库
        self.asn_database = self._build_asn_database()
        self.ip_range_database = self._build_ip_range_database()
        self.domain_patterns = self._build_domain_patterns()
        
    def _build_asn_database(self) -> Dict[int, ServiceInfo]:
        """构建ASN到服务的映射数据库"""
        return {
            # 视频和媒体服务
            2914: ServiceInfo("ntt", "NTT通信", "telecom", "jp"),  # NTT Communications - Niconico的主要CDN
            4694: ServiceInfo("idcf", "IDC Frontier", "cloud", "jp"),  # 日本云服务商
            17506: ServiceInfo("ntt-east", "NTT东日本", "telecom", "jp"),
            17673: ServiceInfo("dwango", "DWANGO/Niconico", "video", "jp"),  # Niconico/DWANGO直接ASN
            
            # Google服务
            15169: ServiceInfo("google", "Google", "search", "us"),
            36040: ServiceInfo("youtube", "YouTube", "video", "us"),
            
            # Meta(Facebook)服务  
            32934: ServiceInfo("facebook", "Facebook", "social", "us"),
            
            # Microsoft服务
            8075: ServiceInfo("microsoft", "Microsoft", "cloud", "us"),
            
            # Amazon服务
            16509: ServiceInfo("aws", "Amazon AWS", "cloud", "us"),
            14618: ServiceInfo("amazon", "Amazon", "ecommerce", "us"),
            
            # Cloudflare
            13335: ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
            
            # Twitter
            13414: ServiceInfo("twitter", "Twitter", "social", "us"),
            
            # Apple
            714: ServiceInfo("apple", "Apple", "tech", "us"),
            
            # Netflix
            2906: ServiceInfo("netflix", "Netflix", "video", "us"),
            40027: ServiceInfo("netflix", "Netflix", "video", "us"),
            
            # Telegram
            62041: ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            62014: ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            
            # 中国服务
            4134: ServiceInfo("chinatelecom", "中国电信", "telecom", "cn"),
            4837: ServiceInfo("chinaunicom", "中国联通", "telecom", "cn"),
            9808: ServiceInfo("chinamobile", "中国移动", "telecom", "cn"),
            37963: ServiceInfo("alibaba", "阿里云", "cloud", "cn"),
            45090: ServiceInfo("tencent", "腾讯云", "cloud", "cn"),
            38365: ServiceInfo("baidu", "百度", "search", "cn"),
            
            # 日本其他重要服务
            2516: ServiceInfo("kddi", "KDDI", "telecom", "jp"),
            4713: ServiceInfo("ocn", "OCN", "telecom", "jp"),
            7506: ServiceInfo("gmointernet", "GMO Internet", "hosting", "jp"),
            2497: ServiceInfo("iij", "Internet Initiative Japan", "telecom", "jp"),
        }
    
    def _build_ip_range_database(self) -> Dict[str, ServiceInfo]:
        """构建特定IP段到服务的映射"""
        return {
            # === 日本视频服务 ===
            # Niconico/DWANGO 已知IP段
            "210.129.120.0/21": ServiceInfo("niconico", "Niconico", "video", "jp"),
            "125.6.144.0/20": ServiceInfo("niconico", "Niconico", "video", "jp"),
            "202.248.110.0/24": ServiceInfo("niconico", "Niconico", "video", "jp"),
            "202.248.111.0/24": ServiceInfo("niconico", "Niconico", "video", "jp"),
            "210.155.141.0/24": ServiceInfo("niconico", "Niconico", "video", "jp"),
            
            # === Google/YouTube 服务 ===
            # YouTube专用IP段
            "208.65.152.0/22": ServiceInfo("youtube", "YouTube", "video", "us"),
            "208.117.224.0/19": ServiceInfo("youtube", "YouTube", "video", "us"),
            "173.194.0.0/16": ServiceInfo("google", "Google", "search", "us"),
            "74.125.0.0/16": ServiceInfo("google", "Google", "search", "us"),
            "172.217.0.0/16": ServiceInfo("google", "Google", "search", "us"),
            "216.58.192.0/19": ServiceInfo("google", "Google", "search", "us"),
            "142.250.0.0/15": ServiceInfo("google", "Google", "search", "us"),
            
            # === Cloudflare CDN ===
            "104.16.0.0/12": ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
            "172.64.0.0/13": ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
            "188.114.96.0/20": ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
            "190.93.240.0/20": ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
            "198.41.128.0/17": ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
            "162.158.0.0/15": ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
            
            # === Amazon AWS/CloudFront ===
            "13.32.0.0/15": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            "13.35.0.0/16": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            "52.84.0.0/15": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            "54.182.0.0/16": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            "54.230.0.0/15": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            "99.84.0.0/16": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            "143.204.0.0/16": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            "205.251.192.0/19": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            
            # === Microsoft 服务 ===
            "13.107.42.0/24": ServiceInfo("microsoft", "Microsoft Teams", "communication", "us"),
            "52.96.0.0/14": ServiceInfo("microsoft", "Microsoft 365", "productivity", "us"),
            "40.76.0.0/14": ServiceInfo("microsoft", "Microsoft Azure", "cloud", "us"),
            "20.0.0.0/8": ServiceInfo("microsoft", "Microsoft Azure", "cloud", "us"),
            "157.55.0.0/16": ServiceInfo("microsoft", "Microsoft", "tech", "us"),
            
            # === Meta/Facebook 服务 ===
            "31.13.24.0/21": ServiceInfo("facebook", "Facebook", "social", "us"),
            "31.13.64.0/18": ServiceInfo("facebook", "Facebook", "social", "us"),
            "66.220.144.0/20": ServiceInfo("facebook", "Facebook", "social", "us"),
            "69.63.176.0/20": ServiceInfo("facebook", "Facebook", "social", "us"),
            "69.171.224.0/19": ServiceInfo("facebook", "Facebook", "social", "us"),
            "74.119.76.0/22": ServiceInfo("facebook", "Facebook", "social", "us"),
            "103.4.96.0/22": ServiceInfo("facebook", "Facebook", "social", "us"),
            "129.134.0.0/17": ServiceInfo("facebook", "Facebook", "social", "us"),
            "157.240.0.0/17": ServiceInfo("facebook", "Facebook", "social", "us"),
            "173.252.64.0/18": ServiceInfo("facebook", "Facebook", "social", "us"),
            "179.60.192.0/22": ServiceInfo("facebook", "Facebook", "social", "us"),
            "185.60.216.0/22": ServiceInfo("facebook", "Facebook", "social", "us"),
            
            # === Netflix ===
            "23.246.0.0/18": ServiceInfo("netflix", "Netflix", "video", "us"),
            "37.77.184.0/21": ServiceInfo("netflix", "Netflix", "video", "us"),
            "45.57.0.0/17": ServiceInfo("netflix", "Netflix", "video", "us"),
            "64.120.128.0/17": ServiceInfo("netflix", "Netflix", "video", "us"),
            "66.197.128.0/17": ServiceInfo("netflix", "Netflix", "video", "us"),
            "108.175.32.0/20": ServiceInfo("netflix", "Netflix", "video", "us"),
            "185.2.220.0/22": ServiceInfo("netflix", "Netflix", "video", "us"),
            "185.9.188.0/22": ServiceInfo("netflix", "Netflix", "video", "us"),
            "192.173.64.0/18": ServiceInfo("netflix", "Netflix", "video", "us"),
            "198.38.96.0/19": ServiceInfo("netflix", "Netflix", "video", "us"),
            "198.45.48.0/20": ServiceInfo("netflix", "Netflix", "video", "us"),
            
            # === Twitter/X ===
            "199.16.156.0/22": ServiceInfo("twitter", "Twitter", "social", "us"),
            "199.59.148.0/22": ServiceInfo("twitter", "Twitter", "social", "us"),
            "202.160.128.0/22": ServiceInfo("twitter", "Twitter", "social", "us"),
            "209.237.192.0/19": ServiceInfo("twitter", "Twitter", "social", "us"),
            
            # === Apple 服务 ===
            "17.0.0.0/8": ServiceInfo("apple", "Apple", "tech", "us"),
            "143.0.0.0/16": ServiceInfo("apple", "Apple", "tech", "us"),
            "144.178.0.0/16": ServiceInfo("apple", "Apple", "tech", "us"),
            "192.35.50.0/24": ServiceInfo("apple", "Apple", "tech", "us"),
            "198.183.17.0/24": ServiceInfo("apple", "Apple", "tech", "us"),
            
            # === Telegram ===
            "149.154.160.0/20": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "91.108.4.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "91.108.8.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "91.108.12.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "91.108.16.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "91.108.56.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "95.161.64.0/20": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "149.154.164.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "149.154.168.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "149.154.172.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            
            # === 中国服务 ===
            # 阿里云/淘宝
            "47.88.0.0/13": ServiceInfo("alibaba", "阿里云", "cloud", "cn"),
            "47.254.0.0/16": ServiceInfo("alibaba", "阿里云", "cloud", "cn"),
            "120.25.115.0/24": ServiceInfo("alibaba", "阿里云", "cloud", "cn"),
            "140.205.0.0/16": ServiceInfo("alibaba", "阿里巴巴", "ecommerce", "cn"),
            "198.11.128.0/18": ServiceInfo("alibaba", "阿里巴巴", "ecommerce", "cn"),
            
            # 腾讯云/QQ
            "129.226.0.0/16": ServiceInfo("tencent", "腾讯云", "cloud", "cn"),
            "132.232.0.0/16": ServiceInfo("tencent", "腾讯云", "cloud", "cn"),
            "140.143.0.0/16": ServiceInfo("tencent", "腾讯云", "cloud", "cn"),
            "150.109.0.0/16": ServiceInfo("tencent", "腾讯云", "cloud", "cn"),
            "183.3.224.0/19": ServiceInfo("tencent", "腾讯", "social", "cn"),
            "203.205.128.0/19": ServiceInfo("tencent", "腾讯", "social", "cn"),
            
            # 百度
            "180.149.128.0/17": ServiceInfo("baidu", "百度", "search", "cn"),
            "182.61.0.0/16": ServiceInfo("baidu", "百度", "search", "cn"),
            "220.181.0.0/16": ServiceInfo("baidu", "百度", "search", "cn"),
            
            # Bilibili
            "106.75.64.0/18": ServiceInfo("bilibili", "哔哩哔哩", "video", "cn"),
            "119.3.0.0/16": ServiceInfo("bilibili", "哔哩哔哩", "video", "cn"),
            "150.116.92.0/22": ServiceInfo("bilibili", "哔哩哔哩", "video", "cn"),
            
            # === 日本其他服务 ===
            # LINE
            "203.104.128.0/20": ServiceInfo("line", "LINE", "messaging", "jp"),
            "147.92.128.0/17": ServiceInfo("line", "LINE", "messaging", "jp"),
            
            # Yahoo Japan
            "182.22.16.0/20": ServiceInfo("yahoo-jp", "Yahoo Japan", "portal", "jp"),
            "183.79.0.0/16": ServiceInfo("yahoo-jp", "Yahoo Japan", "portal", "jp"),
            
            # AbemaTV
            "54.65.0.0/16": ServiceInfo("abema", "AbemaTV", "video", "jp"),
            "52.192.0.0/11": ServiceInfo("abema", "AbemaTV", "video", "jp"),
        }
    
    def _build_domain_patterns(self) -> Dict[str, ServiceInfo]:
        """构建域名模式到服务的映射"""
        return {
            # 日本视频服务
            r".*\.nicovideo\.jp$": ServiceInfo("niconico", "Niconico", "video", "jp"),
            r".*\.nimg\.jp$": ServiceInfo("niconico", "Niconico", "video", "jp"),
            r".*\.dwango\.jp$": ServiceInfo("dwango", "DWANGO", "video", "jp"),
            
            # 其他模式...
            r".*\.youtube\.com$": ServiceInfo("youtube", "YouTube", "video", "us"),
            r".*\.googlevideo\.com$": ServiceInfo("youtube", "YouTube", "video", "us"),
        }
    
    def identify_service_by_ip(self, ip: str) -> Optional[ServiceInfo]:
        """基于IP地址识别服务"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # 1. 检查特定IP段数据库 (最高优先级)
            for cidr, service_info in self.ip_range_database.items():
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        return service_info
                except (ipaddress.AddressValueError, ValueError):
                    continue
            
            # 2. 基于ASN的服务识别 (中等优先级)
            asn_result = self._identify_by_asn_heuristics(ip)
            if asn_result:
                return asn_result
            
            # 3. 基于IP的启发式识别 (低优先级)
            heuristic_result = self._identify_by_ip_heuristics(ip)
            if heuristic_result:
                return heuristic_result
                
            return None
            
        except (ipaddress.AddressValueError, ValueError):
            return None
    
    def _identify_by_asn_heuristics(self, ip: str) -> Optional[ServiceInfo]:
        """基于ASN启发式识别服务"""
        try:
            ip_parts = [int(x) for x in ip.split('.')]
            first_octet = ip_parts[0]
            second_octet = ip_parts[1]
            third_octet = ip_parts[2]
            
            # 基于IP地址范围推断可能的ASN和服务
            
            # === Google (AS15169) IP范围模式 ===
            if first_octet == 8 and second_octet == 8:  # 8.8.x.x - Google DNS
                return self.asn_database.get(15169)
            elif first_octet == 172 and second_octet == 217:  # 172.217.x.x
                return self.asn_database.get(15169)
            elif first_octet == 74 and second_octet == 125:  # 74.125.x.x
                return self.asn_database.get(15169)
            
            # === Microsoft (AS8075) IP范围模式 ===
            elif first_octet == 13 and second_octet == 107:  # 13.107.x.x - Microsoft 365
                return self.asn_database.get(8075)
            elif first_octet == 40 and 70 <= second_octet <= 80:  # 40.7x.x.x - Azure
                return self.asn_database.get(8075)
            
            # === Amazon (AS16509) CloudFront 范围模式 ===
            elif first_octet == 13 and 32 <= second_octet <= 35:  # 13.32-35.x.x
                return ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us")
            elif first_octet == 54 and 230 <= second_octet <= 239:  # 54.230-239.x.x
                return ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us")
            
            # === Cloudflare (AS13335) 范围模式 ===
            elif first_octet == 104 and 16 <= second_octet <= 31:  # 104.16-31.x.x
                return self.asn_database.get(13335)
            elif first_octet == 172 and 64 <= second_octet <= 71:  # 172.64-71.x.x
                return self.asn_database.get(13335)
            elif first_octet == 1 and second_octet == 1 and third_octet == 1:  # 1.1.1.x
                return self.asn_database.get(13335)
            
            # === Facebook/Meta (AS32934) 范围模式 ===
            elif first_octet == 31 and second_octet == 13:  # 31.13.x.x
                return self.asn_database.get(32934)
            elif first_octet == 157 and second_octet == 240:  # 157.240.x.x
                return self.asn_database.get(32934)
            
            # === NTT Communications (AS2914) - Niconico's CDN ===
            elif first_octet == 210 and second_octet in [129, 155, 173]:  # NTT范围
                return self.asn_database.get(2914)
            elif first_octet == 202 and second_octet == 248:  # 常见Niconico IP段
                return ServiceInfo("niconico", "Niconico", "video", "jp")
            elif first_octet == 125 and second_octet == 6:  # 另一个Niconico段
                return ServiceInfo("niconico", "Niconico", "video", "jp")
            
            # === Apple (AS714) 范围模式 ===
            elif first_octet == 17:  # 17.x.x.x - Apple保留的大段
                return self.asn_database.get(714)
            
            # === 中国主要ISP ASN模式 ===
            # 中国电信 (AS4134)
            elif first_octet in [202, 203, 218, 219, 220, 221]:
                if second_octet in [96, 97, 98, 99, 100, 101, 102, 103]:
                    return self.asn_database.get(4134)
            
            # 中国联通 (AS4837) 
            elif first_octet in [123, 125, 175]:
                if second_octet in [120, 121, 122, 123, 124, 125]:
                    return self.asn_database.get(4837)
            
            # 阿里云 (AS37963)
            elif first_octet == 47 and 88 <= second_octet <= 95:  # 47.88-95.x.x
                return self.asn_database.get(37963)
            elif first_octet == 140 and second_octet == 205:  # 140.205.x.x - 阿里巴巴
                return self.asn_database.get(37963)
            
            # 腾讯云 (AS45090)
            elif first_octet == 129 and second_octet == 226:  # 129.226.x.x
                return self.asn_database.get(45090)
            elif first_octet == 140 and second_octet == 143:  # 140.143.x.x
                return self.asn_database.get(45090)
            
            return None
            
        except (ValueError, IndexError):
            return None
    
    def _identify_by_ip_heuristics(self, ip: str) -> Optional[ServiceInfo]:
        """基于IP模式的启发式识别 (兜底方案)"""
        try:
            # 日本常见IP段模式识别
            ip_parts = [int(x) for x in ip.split('.')]
            first_octet = ip_parts[0]
            second_octet = ip_parts[1]
            
            # 一些通用的IP段识别
            # 日本地区通用识别
            if first_octet in [126, 163, 210, 211] and 100 <= second_octet <= 200:
                return ServiceInfo("japan-isp", "日本ISP", "telecom", "jp")
            
            # 韩国地区通用识别  
            elif first_octet in [119, 121, 175] and 190 <= second_octet <= 255:
                return ServiceInfo("korea-isp", "韩国ISP", "telecom", "kr")
            
            # 东南亚地区通用识别
            elif first_octet in [103, 118] and 96 <= second_octet <= 128:
                return ServiceInfo("sea-isp", "东南亚ISP", "telecom", "sea")
                    
            return None
            
        except (ValueError, IndexError):
            return None
    
    def identify_service_by_domain(self, domain: str) -> Optional[ServiceInfo]:
        """基于域名识别服务"""
        domain_lower = domain.lower()
        
        for pattern, service_info in self.domain_patterns.items():
            if re.match(pattern, domain_lower):
                return service_info
                
        return None
    
    def get_enhanced_service_name(self, ip: str, domain: str = None) -> Tuple[Optional[str], Optional[str]]:
        """
        获取增强的服务名称
        返回 (service_name, display_name) 元组
        """
        # 1. 优先使用域名识别
        if domain:
            domain_result = self.identify_service_by_domain(domain)
            if domain_result:
                return domain_result.name, domain_result.display_name
        
        # 2. 使用IP识别
        ip_result = self.identify_service_by_ip(ip)
        if ip_result:
            return ip_result.name, ip_result.display_name
        
        # 3. 返回None表示无法识别
        return None, None
    
    def get_service_category(self, ip: str, domain: str = None) -> Optional[str]:
        """获取服务类别"""
        service_info = None
        
        if domain:
            service_info = self.identify_service_by_domain(domain)
        
        if not service_info:
            service_info = self.identify_service_by_ip(ip)
            
        return service_info.category if service_info else None
    
    def is_media_service(self, ip: str, domain: str = None) -> bool:
        """判断是否为媒体服务"""
        category = self.get_service_category(ip, domain)
        return category in ['video', 'streaming', 'media'] if category else False
    
    def get_statistics(self) -> Dict[str, int]:
        """获取识别器统计信息"""
        return {
            'asn_entries': len(self.asn_database),
            'ip_range_entries': len(self.ip_range_database),
            'domain_patterns': len(self.domain_patterns)
        }

# 全局实例
service_identifier = ServiceIdentifier()

# 测试函数
def test_service_identifier():
    """测试服务识别功能"""
    identifier = ServiceIdentifier()
    
    test_cases = [
        # (ip, domain, expected_service)
        ("210.129.120.100", "www.nicovideo.jp", "niconico"),
        ("8.8.8.8", "dns.google", "google"),
        ("1.1.1.1", None, "cloudflare"),
        ("125.6.144.50", None, "niconico-cdn"),
    ]
    
    print("🧪 测试服务识别器")
    print("=" * 50)
    
    for ip, domain, expected in test_cases:
        service_name, display_name = identifier.get_enhanced_service_name(ip, domain)
        category = identifier.get_service_category(ip, domain)
        
        print(f"IP: {ip}")
        if domain:
            print(f"域名: {domain}")
        print(f"识别结果: {service_name} ({display_name})")
        print(f"类别: {category}")
        print(f"预期: {expected}")
        print("-" * 30)

if __name__ == "__main__":
    test_service_identifier()