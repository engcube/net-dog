#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一服务识别器
整合 smart_ip_identifier 和 service_identifier 的功能
提供全面的IP地址和服务识别能力
"""

import socket
import subprocess
import re
import json
import os
import ipaddress
import time
import threading
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from utils import is_china_ip

@dataclass
class ServiceInfo:
    """服务信息"""
    name: str           # 服务内部标识名
    display_name: str   # 用户显示名称
    category: str       # 服务类别 (video, social, cloud, etc.)
    country: str        # 服务主要地区
    confidence: float = 0.9  # 识别置信度

class UnifiedServiceIdentifier:
    """统一服务识别器"""
    
    def __init__(self, cache_file: str = "data/service_cache.json"):
        self.cache_file = cache_file
        self.cache = self._load_cache()
        self.lock = threading.Lock()
        
        # 构建综合数据库
        self.asn_database = self._build_asn_database()
        self.ip_range_database = self._build_ip_range_database()
        self.domain_patterns = self._build_domain_patterns()
        self.legacy_providers = self._build_legacy_providers()
        
    def _load_cache(self) -> Dict:
        """加载缓存的识别结果"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"加载缓存失败: {e}")
        except Exception as e:
            print(f"未知错误加载缓存: {e}")
        return {}
    
    def _save_cache(self):
        """保存缓存"""
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except (IOError, OSError) as e:
            print(f"保存缓存失败: {e}")
        except Exception as e:
            print(f"保存缓存时发生未知错误: {e}")
    
    def _build_asn_database(self) -> Dict[int, ServiceInfo]:
        """构建ASN到服务的映射数据库"""
        return {
            # 视频和媒体服务
            2914: ServiceInfo("ntt", "NTT通信", "telecom", "jp"),  # NTT Communications - Niconico的主要CDN
            4694: ServiceInfo("idcf", "IDC Frontier", "cloud", "jp"),
            17506: ServiceInfo("ntt-east", "NTT东日本", "telecom", "jp"),
            17673: ServiceInfo("dwango", "DWANGO/Niconico", "video", "jp"),
            
            # Google服务
            15169: ServiceInfo("google", "Google", "search", "us"),
            36040: ServiceInfo("youtube", "YouTube", "video", "us"),
            
            # Meta(Facebook)服务  
            32934: ServiceInfo("facebook", "Facebook", "social", "us"),
            
            # Microsoft服务
            8075: ServiceInfo("microsoft", "Microsoft", "cloud", "us"),
            8068: ServiceInfo("microsoft", "Microsoft", "cloud", "us"),
            
            # Amazon服务
            16509: ServiceInfo("amazon", "Amazon AWS", "cloud", "us"),
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
            "210.129.120.0/21": ServiceInfo("niconico", "Niconico", "video", "jp"),
            "125.6.144.0/20": ServiceInfo("niconico", "Niconico", "video", "jp"),
            "202.248.110.0/24": ServiceInfo("niconico", "Niconico", "video", "jp"),
            "202.248.111.0/24": ServiceInfo("niconico", "Niconico", "video", "jp"),
            "210.155.141.0/24": ServiceInfo("niconico", "Niconico", "video", "jp"),
            
            # === Google/YouTube 服务 ===
            "173.194.0.0/16": ServiceInfo("google", "Google", "search", "us"),
            "74.125.0.0/16": ServiceInfo("google", "Google", "search", "us"),
            "172.217.0.0/16": ServiceInfo("google", "Google", "search", "us"),
            "216.58.192.0/19": ServiceInfo("google", "Google", "search", "us"),
            "142.250.0.0/15": ServiceInfo("google", "Google", "search", "us"),
            "8.8.8.0/24": ServiceInfo("google", "Google DNS", "dns", "us"),
            "8.8.4.0/24": ServiceInfo("google", "Google DNS", "dns", "us"),
            
            # === Cloudflare CDN ===
            "104.16.0.0/12": ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
            "172.64.0.0/13": ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
            "1.1.1.0/24": ServiceInfo("cloudflare", "Cloudflare DNS", "dns", "us"),
            "1.0.0.0/24": ServiceInfo("cloudflare", "Cloudflare DNS", "dns", "us"),
            
            # === Amazon AWS/CloudFront ===
            "13.32.0.0/15": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            "54.230.0.0/15": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            "99.84.0.0/16": ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
            
            # === Microsoft 服务 ===
            "13.107.42.0/24": ServiceInfo("microsoft", "Microsoft Teams", "communication", "us"),
            "40.76.0.0/14": ServiceInfo("microsoft", "Microsoft Azure", "cloud", "us"),
            
            # === Meta/Facebook 服务 ===
            "31.13.24.0/21": ServiceInfo("facebook", "Facebook", "social", "us"),
            "157.240.0.0/17": ServiceInfo("facebook", "Facebook", "social", "us"),
            "173.252.64.0/18": ServiceInfo("facebook", "Facebook", "social", "us"),
            
            # === Netflix ===
            "23.246.0.0/18": ServiceInfo("netflix", "Netflix", "video", "us"),
            "37.77.184.0/21": ServiceInfo("netflix", "Netflix", "video", "us"),
            "45.57.0.0/17": ServiceInfo("netflix", "Netflix", "video", "us"),
            
            # === Telegram ===
            "149.154.160.0/20": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "91.108.4.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            "91.108.56.0/22": ServiceInfo("telegram", "Telegram", "messaging", "ru"),
            
            # === Apple 服务 ===
            "17.0.0.0/8": ServiceInfo("apple", "Apple", "tech", "us"),
            
            # === 中国服务 ===
            "47.88.0.0/13": ServiceInfo("alibaba", "阿里云", "cloud", "cn"),
            "129.226.0.0/16": ServiceInfo("tencent", "腾讯云", "cloud", "cn"),
            "220.181.0.0/16": ServiceInfo("baidu", "百度", "search", "cn"),
            "106.75.64.0/18": ServiceInfo("bilibili", "哔哩哔哩", "video", "cn"),
        }
    
    def _build_domain_patterns(self) -> Dict[str, ServiceInfo]:
        """构建域名模式到服务的映射"""
        return {
            r".*\.nicovideo\.jp$": ServiceInfo("niconico", "Niconico", "video", "jp"),
            r".*\.nimg\.jp$": ServiceInfo("niconico", "Niconico", "video", "jp"),
            r".*\.dwango\.jp$": ServiceInfo("dwango", "DWANGO", "video", "jp"),
            r".*\.youtube\.com$": ServiceInfo("youtube", "YouTube", "video", "us"),
            r".*\.googlevideo\.com$": ServiceInfo("youtube", "YouTube", "video", "us"),
            r".*\.google\.com$": ServiceInfo("google", "Google", "search", "us"),
            r".*\.facebook\.com$": ServiceInfo("facebook", "Facebook", "social", "us"),
            r".*\.instagram\.com$": ServiceInfo("facebook", "Instagram", "social", "us"),
        }
    
    def _build_legacy_providers(self) -> Dict[str, Dict]:
        """构建兼容旧smart_ip_identifier的提供商数据"""
        return {
            'alibaba': {
                'keywords': ['alibaba', 'aliyun', 'ecs', 'alicdn'],
                'asn_ranges': ['37963', '45102', '24429'],
                'ip_patterns': [
                    r'^47\.(74|89|91|94|96|98|100|101|103|104|106|107|108|109|110|111|112|113|115)',
                    r'^118\.178\.', r'^139\.196\.', r'^47\.88\.', r'^8\.131\.',
                    r'^101\.36\.', r'^117\.(185|149|135)\.'
                ],
                'service_info': ServiceInfo("alibaba", "阿里云", "cloud", "cn")
            },
            'tencent': {
                'keywords': ['tencent', 'qq', 'qcloud'],
                'asn_ranges': ['45090', '132203'],
                'ip_patterns': [
                    r'^183\.(192|84)\.', r'^221\.181\.', r'^120\.(204|232)\.',
                    r'^129\.211\.', r'^1\.12\.'
                ],
                'service_info': ServiceInfo("tencent", "腾讯云", "cloud", "cn")
            },
            'amazon': {
                'keywords': ['amazon', 'aws', 'ec2', 'cloudfront'],
                'asn_ranges': ['16509', '14618'],
                'ip_patterns': [
                    r'^54\.(46|174|194|230|254|255)\.', r'^52\.', r'^3\.', r'^18\.',
                    r'^34\.(192|194|196|198|200|202|204|206|208|210|212|214|216|218|220|222|224|226|228)\.'
                ],
                'service_info': ServiceInfo("amazon", "Amazon AWS", "cloud", "us")
            },
            'google': {
                'keywords': ['google', '1e100', 'googleusercontent'],
                'asn_ranges': ['15169', '36040'],
                'ip_patterns': [
                    r'^8\.(8|34|35)\.', r'^172\.217\.', r'^216\.58\.', r'^74\.125\.',
                    r'^64\.233\.', r'^142\.250\.', r'^108\.177\.', r'^173\.194\.'
                ],
                'service_info': ServiceInfo("google", "Google", "search", "us")
            },
            'youtube': {
                'keywords': ['googlevideo', 'youtube', 'ytimg'],
                'asn_ranges': ['15169', '36040'],
                'ip_patterns': [
                    r'^172\.217\.', r'^216\.58\.', r'^142\.250\.', r'^74\.125\.',
                    r'^64\.233\.', r'^173\.194\.', r'^108\.177\.'
                ],
                'service_info': ServiceInfo("youtube", "YouTube", "video", "us")
            },
            'apple': {
                'keywords': ['apple', 'icloud'],
                'asn_ranges': ['714'],
                'ip_patterns': [r'^17\.(57|142|172|188|248|249|250|251|252|253|254|255)\.'],
                'service_info': ServiceInfo("apple", "Apple", "tech", "us")
            },
            'microsoft': {
                'keywords': ['microsoft', 'azure', 'hotmail', 'outlook'],
                'asn_ranges': ['8075', '8068'],
                'ip_patterns': [
                    r'^20\.', r'^40\.', r'^52\.(224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239)\.',
                    r'^104\.(40|42|44|46|47|208|209|210|211|214|215)\.'
                ],
                'service_info': ServiceInfo("microsoft", "Microsoft", "cloud", "us")
            }
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
            
            # 2. 基于ASN的服务识别
            asn_result = self._identify_by_asn_heuristics(ip)
            if asn_result:
                return asn_result
            
            # 3. 传统模式匹配识别
            legacy_result = self._legacy_pattern_match(ip)
            if legacy_result:
                return legacy_result
            
            # 4. DNS反查识别
            dns_result = self._dns_analysis(ip)
            if dns_result:
                return dns_result
                
            return None
            
        except (ipaddress.AddressValueError, ValueError):
            return None
    
    def identify_service_by_domain(self, domain: str) -> Optional[ServiceInfo]:
        """基于域名识别服务"""
        if not domain:
            return None
            
        domain_lower = domain.lower()
        
        for pattern, service_info in self.domain_patterns.items():
            if re.match(pattern, domain_lower):
                return service_info
                
        return None
    
    def get_enhanced_service_name(self, ip: str, domain: str = None) -> Tuple[Optional[str], Optional[str]]:
        """获取增强的服务名称，返回 (service_name, display_name) 元组"""
        # 1. 优先使用域名识别
        if domain:
            domain_result = self.identify_service_by_domain(domain)
            if domain_result:
                return domain_result.name, domain_result.display_name
        
        # 2. 使用IP识别
        ip_result = self.identify_service_by_ip(ip)
        if ip_result:
            return ip_result.name, ip_result.display_name
        
        return None, None
    
    def identify_ip(self, ip: str) -> Tuple[str, str, float]:
        """
        兼容旧smart_ip_identifier接口的方法
        返回: (服务商, 地区, 置信度)
        """
        with self.lock:
            # 检查缓存
            cache_key = ip
            if cache_key in self.cache:
                cached = self.cache[cache_key]
                return cached['provider'], cached['region'], cached.get('confidence', 0.8)
        
        service_info = self.identify_service_by_ip(ip)
        
        if service_info:
            provider_name = service_info.display_name
            region = self._map_country_to_region(service_info.country)
            confidence = service_info.confidence
        else:
            # 兜底逻辑
            if is_china_ip(ip):
                provider_name, region, confidence = '中国网站', '中国', 0.3
            else:
                provider_name, region, confidence = '海外网站', '海外', 0.3
        
        # 缓存结果
        with self.lock:
            self.cache[cache_key] = {
                'provider': provider_name,
                'region': region,
                'confidence': confidence,
                'timestamp': time.time()
            }
            
            # 定期保存缓存
            if len(self.cache) % 10 == 0:
                self._save_cache()
        
        return provider_name, region, confidence
    
    def _identify_by_asn_heuristics(self, ip: str) -> Optional[ServiceInfo]:
        """基于ASN启发式识别服务"""
        try:
            ip_parts = [int(x) for x in ip.split('.')]
            first_octet = ip_parts[0]
            second_octet = ip_parts[1]
            
            # 基于IP地址范围推断ASN
            if first_octet == 8 and second_octet == 8:  # Google DNS
                return self.asn_database.get(15169)
            elif first_octet == 1 and second_octet == 1:  # Cloudflare DNS
                return self.asn_database.get(13335)
            elif first_octet == 210 and second_octet in [129, 155]:  # NTT/Niconico
                return self.asn_database.get(2914)
            elif first_octet == 47 and 88 <= second_octet <= 95:  # 阿里云
                return self.asn_database.get(37963)
                
            return None
        except (ValueError, IndexError):
            return None
    
    def _legacy_pattern_match(self, ip: str) -> Optional[ServiceInfo]:
        """传统模式匹配识别"""
        # 优先检查视频服务
        provider_order = ['youtube', 'google', 'amazon', 'alibaba', 'tencent', 'apple', 'microsoft']
        
        for provider in provider_order:
            if provider in self.legacy_providers:
                config = self.legacy_providers[provider]
                for pattern in config['ip_patterns']:
                    if re.match(pattern, ip):
                        return config['service_info']
        
        return None
    
    def _dns_analysis(self, ip: str) -> Optional[ServiceInfo]:
        """通过DNS反查分析服务商"""
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            
            # 检查已知关键词
            keyword_mapping = {
                'google': self.legacy_providers['google']['service_info'],
                'youtube': self.legacy_providers['youtube']['service_info'],
                'googlevideo': self.legacy_providers['youtube']['service_info'],
                'amazon': self.legacy_providers['amazon']['service_info'],
                'cloudfront': ServiceInfo("cloudfront", "Amazon CloudFront", "cdn", "us"),
                'facebook': ServiceInfo("facebook", "Facebook", "social", "us"),
                'alibaba': self.legacy_providers['alibaba']['service_info'],
                'aliyun': self.legacy_providers['alibaba']['service_info'],
                'tencent': self.legacy_providers['tencent']['service_info'],
                'cloudflare': ServiceInfo("cloudflare", "Cloudflare", "cdn", "us"),
                'apple': self.legacy_providers['apple']['service_info'],
                'microsoft': self.legacy_providers['microsoft']['service_info'],
                'nicovideo': ServiceInfo("niconico", "Niconico", "video", "jp"),
                'dwango': ServiceInfo("dwango", "DWANGO", "video", "jp"),
            }
            
            for keyword, service_info in keyword_mapping.items():
                if keyword in hostname:
                    return service_info
                    
        except (socket.herror, socket.gaierror, OSError):
            pass
        except Exception as e:
            print(f"DNS解析出现未知错误: {e}")
        
        return None
    
    def _map_country_to_region(self, country_code: str) -> str:
        """将国家代码映射到地区"""
        china_regions = ['cn', 'hk', 'tw', 'mo']
        if country_code.lower() in china_regions:
            return '中国'
        else:
            return '海外'
    
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
            'domain_patterns': len(self.domain_patterns),
            'legacy_providers': len(self.legacy_providers),
            'cached_entries': len(self.cache)
        }

# 全局实例
unified_service_identifier = UnifiedServiceIdentifier()

# 为了向后兼容，提供旧接口的别名
smart_ip_identifier = unified_service_identifier
service_identifier = unified_service_identifier