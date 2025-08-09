#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能IP识别器
基于多种数据源和启发式算法自动识别IP段
"""

import socket
import subprocess
import re
import json
import os
from typing import Dict, Optional, Tuple
import time
import threading

class SmartIPIdentifier:
    def __init__(self):
        self.cache_file = "data/ip_cache.json"
        self.cache = self._load_cache()
        self.lock = threading.Lock()
        
        # 已知的云服务商ASN（自治系统号）和特征
        self.known_providers = {
            'alibaba': {
                'keywords': ['alibaba', 'aliyun', 'ecs', 'alicdn'],
                'asn_ranges': ['37963', '45102', '24429'],
                'ip_patterns': [
                    r'^47\.(74|89|91|94|96|98|100|101|103|104|106|107|108|109|110|111|112|113|115)',
                    r'^118\.178\.',
                    r'^139\.196\.',
                    r'^47\.88\.',
                    r'^8\.131\.',
                    r'^101\.36\.',
                    r'^117\.(185|149|135)\.'
                ]
            },
            'tencent': {
                'keywords': ['tencent', 'qq', 'qcloud'],
                'asn_ranges': ['45090', '132203'],
                'ip_patterns': [
                    r'^183\.(192|84)\.',
                    r'^221\.181\.',
                    r'^120\.(204|232)\.',
                    r'^129\.211\.',
                    r'^1\.12\.'
                ]
            },
            'amazon': {
                'keywords': ['amazon', 'aws', 'ec2', 'cloudfront'],
                'asn_ranges': ['16509', '14618'],
                'ip_patterns': [
                    r'^54\.(46|174|194|230|254|255)\.',
                    r'^52\.',
                    r'^3\.',
                    r'^18\.',
                    r'^34\.(192|194|196|198|200|202|204|206|208|210|212|214|216|218|220|222|224|226|228)\.'
                ]
            },
            'google': {
                'keywords': ['google', '1e100', 'googleusercontent'],
                'asn_ranges': ['15169', '36040'],
                'ip_patterns': [
                    r'^8\.(8|34|35)\.',
                    r'^172\.217\.',
                    r'^216\.58\.',
                    r'^74\.125\.',
                    r'^64\.233\.',
                    r'^142\.250\.',
                    r'^108\.177\.',
                    r'^173\.194\.'
                ]
            },
            'youtube': {
                'keywords': ['googlevideo', 'youtube', 'ytimg'],
                'asn_ranges': ['15169', '36040'],  # 使用Google的ASN
                'ip_patterns': [
                    # YouTube专用IP段
                    r'^172\.217\.',     # 主要YouTube流媒体IP段
                    r'^216\.58\.',      # YouTube CDN IP段
                    r'^142\.250\.',     # 新的YouTube IP段  
                    r'^74\.125\.',      # YouTube视频服务器
                    r'^64\.233\.',      # 经典YouTube IP段
                    r'^173\.194\.',     # YouTube API服务器
                    r'^108\.177\.',     # YouTube上传服务器
                    # 特定的YouTube IP模式
                    r'^172\.217\.(16[0-9]|1[7-9][0-9]|2[0-5][0-5])\.',  # 172.217.160-255.*
                    r'^216\.58\.(19[2-9]|2[0-4][0-9]|25[0-5])\.',       # 216.58.192-255.*
                    r'^142\.250\.(19[0-9]|2[0-5][0-5])\.',              # 142.250.190-255.*
                ]
            },
            'apple': {
                'keywords': ['apple', 'icloud'],
                'asn_ranges': ['714'],
                'ip_patterns': [
                    r'^17\.(57|142|172|188|248|249|250|251|252|253|254|255)\.'
                ]
            },
            'microsoft': {
                'keywords': ['microsoft', 'azure', 'hotmail', 'outlook'],
                'asn_ranges': ['8075', '8068'],
                'ip_patterns': [
                    r'^20\.',
                    r'^40\.',
                    r'^52\.(224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239)\.',
                    r'^104\.(40|42|44|46|47|208|209|210|211|214|215)\.'
                ]
            }
        }
    
    def _load_cache(self) -> Dict:
        """加载缓存的IP识别结果"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def _save_cache(self):
        """保存缓存"""
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存缓存失败: {e}")
    
    def _pattern_match(self, ip: str) -> Optional[Tuple[str, float]]:
        """基于IP模式匹配识别服务商"""
        # 优先检查YouTube，给YouTube更高的匹配权重
        provider_order = ['youtube', 'google', 'amazon', 'alibaba', 'tencent', 'apple', 'microsoft']
        
        # 先检查优先级列表中的服务
        for provider in provider_order:
            if provider in self.known_providers:
                config = self.known_providers[provider]
                for pattern in config['ip_patterns']:
                    if re.match(pattern, ip):
                        # YouTube获得更高的置信度
                        confidence = 0.95 if provider == 'youtube' else 0.9
                        return provider, confidence
        
        # 再检查其他服务
        for provider, config in self.known_providers.items():
            if provider not in provider_order:
                for pattern in config['ip_patterns']:
                    if re.match(pattern, ip):
                        confidence = 0.9
                        return provider, confidence
        return None
    
    def _dns_analysis(self, ip: str) -> Optional[Tuple[str, float]]:
        """通过DNS反查分析服务商"""
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            
            for provider, config in self.known_providers.items():
                for keyword in config['keywords']:
                    if keyword in hostname:
                        confidence = 0.95  # DNS分析的置信度更高
                        return provider, confidence
            
            # 其他常见服务商关键词
            other_providers = {
                'digitalocean': ['digitalocean', 'droplet'],
                'linode': ['linode', 'members.linode'],
                'cloudflare': ['cloudflare'],
                'akamai': ['akamai'],
                'hinet': ['hinet.net'],  # 台湾中华电信
                'godaddy': ['godaddy'],
                'ovh': ['ovh.net', 'ovh.com']
            }
            
            for provider, keywords in other_providers.items():
                for keyword in keywords:
                    if keyword in hostname:
                        return provider, 0.8
                        
        except:
            pass
        return None
    
    def _whois_analysis(self, ip: str) -> Optional[Tuple[str, float]]:
        """通过whois信息分析（简化版本）"""
        try:
            # 简化的whois分析，基于IP段特征
            first_octet = int(ip.split('.')[0])
            
            # 中国IP段特征
            china_ranges = {
                (1, 1): 'china_telecom',
                (14, 14): 'china_unicom', 
                (27, 27): 'china_telecom',
                (36, 36): 'china_telecom',
                (39, 39): 'china_telecom',
                (42, 42): 'china_telecom',
                (58, 61): 'china_telecom',
                (101, 101): 'alibaba_china',
                (111, 111): 'alibaba_china',
                (112, 125): 'china_ranges',
                (175, 175): 'china_telecom',
                (180, 183): 'china_telecom',
                (202, 203): 'china_telecom',
                (210, 211): 'china_telecom',
                (218, 223): 'china_telecom'
            }
            
            for (start, end), provider in china_ranges.items():
                if start <= first_octet <= end:
                    return provider, 0.6
                    
        except:
            pass
        return None
    
    def identify_ip(self, ip: str) -> Tuple[str, str, float]:
        """
        智能识别IP地址
        返回: (服务商, 地区, 置信度)
        """
        with self.lock:
            # 检查缓存
            cache_key = ip
            if cache_key in self.cache:
                cached = self.cache[cache_key]
                return cached['provider'], cached['region'], cached['confidence']
        
        provider, region, confidence = None, '未知', 0.0
        
        # 1. 模式匹配（最快）
        result = self._pattern_match(ip)
        if result and result[1] > confidence:
            provider, confidence = result
        
        # 2. DNS反查分析
        result = self._dns_analysis(ip)
        if result and result[1] > confidence:
            provider, confidence = result
        
        # 3. 简化的whois分析
        if confidence < 0.7:  # 只有在置信度较低时才进行whois
            result = self._whois_analysis(ip)
            if result and result[1] > confidence:
                provider, confidence = result
        
        # 确定地区
        if provider:
            # 映射服务商名称和地区
            provider_mapping = {
                'alibaba': ('阿里云', '中国'),
                'tencent': ('腾讯云', '中国'),
                'amazon': ('Amazon', '海外'),
                'google': ('Google', '海外'),
                'youtube': ('YouTube', '海外'),  # 添加YouTube专门的映射
                'apple': ('Apple', '海外'),
                'microsoft': ('Microsoft', '海外'),
                'digitalocean': ('DigitalOcean', '海外'),
                'linode': ('Linode', '海外'),
                'cloudflare': ('Cloudflare', '海外'),
                'akamai': ('Akamai CDN', '海外'),
                'hinet': ('中华电信', '中国'),
                'china_telecom': ('中国电信', '中国'),
                'china_unicom': ('中国联通', '中国'),
                'alibaba_china': ('阿里云', '中国'),
                'china_ranges': ('中国网站', '中国')
            }
            
            if provider in provider_mapping:
                provider_name, region = provider_mapping[provider]
            else:
                provider_name = provider.title()
                region = '海外' if not provider.startswith('china') else '中国'
        else:
            # 兜底：基于IP判断地区
            if self._is_china_ip(ip):
                provider_name, region = '中国网站', '中国'
            else:
                provider_name, region = '海外网站', '海外'
            confidence = 0.3
        
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
    
    def _is_china_ip(self, ip: str) -> bool:
        """简化的中国IP判断"""
        try:
            first_octet = int(ip.split('.')[0])
            china_ranges = [1, 14, 27, 36, 39, 42, 49, 58, 59, 60, 61, 
                           101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 
                           175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223]
            return first_octet in china_ranges
        except:
            return False

# 全局实例
smart_ip_identifier = SmartIPIdentifier()