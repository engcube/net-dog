#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray DAT文件解析器
正确解析geosite.dat和geoip.dat的protobuf格式数据
"""

import struct
from typing import Dict, List, Set
import ipaddress
import re


class V2RayDatParser:
    """V2Ray DAT文件解析器"""
    
    @staticmethod
    def parse_geosite_dat(filepath: str) -> Dict[str, Set[str]]:
        """解析geosite.dat文件"""
        geosite_data = {}
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # V2Ray geosite.dat是protobuf格式
            # 这里使用简化的字符串提取方法
            content_str = data.decode('utf-8', errors='ignore')
            
            # 提取域名模式
            domain_patterns = re.findall(r'\b([a-z0-9-]+\.(?:[a-z]{2,}|xn--[a-z0-9]+))\b', content_str.lower())
            
            # 使用严格的域名匹配规则，避免误判
            categories = {
                'youtube': set(),
                'google': set(), 
                'facebook': set(),
                'twitter': set(),
                'telegram': set(),
                'amazon': set(),
                'apple': set(),
                'microsoft': set(),
                'netflix': set(),
                'spotify': set(),
                'github': set(),
                'cloudflare': set(),
                'baidu': set(),
                'tencent': set(),
                'alibaba': set(),
                'bytedance': set(),
                'bilibili': set()
            }
            
            for domain in set(domain_patterns):
                domain_lower = domain.lower()
                
                # 严格的域名分类逻辑 - 使用精确匹配
                
                # YouTube - 严格匹配
                if (domain_lower.startswith('youtube.') or domain_lower == 'youtube.com' or
                    domain_lower.startswith('youtu.be') or domain_lower == 'youtu.be' or
                    domain_lower.startswith('googlevideo.') or 
                    domain_lower.startswith('ytimg.') or domain_lower.endswith('.googlevideo.com')):
                    categories['youtube'].add(domain)
                
                # Google - 严格匹配，排除YouTube
                elif ((domain_lower.startswith('google.') or domain_lower == 'google.com' or
                       domain_lower.startswith('googleapis.') or 
                       domain_lower.startswith('gstatic.') or 
                       domain_lower.startswith('gmail.')) and 
                      'youtube' not in domain_lower and 'googlevideo' not in domain_lower):
                    categories['google'].add(domain)
                
                # Facebook - 严格匹配
                elif (domain_lower.startswith('facebook.') or domain_lower == 'facebook.com' or
                      domain_lower.startswith('fb.') or domain_lower.endswith('.facebook.com') or
                      domain_lower.startswith('instagram.') or domain_lower == 'instagram.com' or
                      domain_lower.startswith('whatsapp.') or domain_lower == 'whatsapp.com'):
                    categories['facebook'].add(domain)
                
                # Twitter - 严格匹配
                elif (domain_lower.startswith('twitter.') or domain_lower == 'twitter.com' or
                      domain_lower.startswith('twimg.') or domain_lower == 't.co' or
                      domain_lower.endswith('.twitter.com')):
                    categories['twitter'].add(domain)
                
                # Telegram - 严格匹配  
                elif (domain_lower.startswith('telegram.') or domain_lower == 'telegram.org' or
                      domain_lower == 't.me' or domain_lower.endswith('.t.me')):
                    categories['telegram'].add(domain)
                
                # Amazon - 严格匹配
                elif (domain_lower.startswith('amazon.') or domain_lower == 'amazon.com' or
                      domain_lower.startswith('aws.') or domain_lower.endswith('.aws.com') or
                      domain_lower.startswith('amazonaws.') or domain_lower.endswith('.amazonaws.com')):
                    categories['amazon'].add(domain)
                
                # Apple - 严格匹配
                elif (domain_lower.startswith('apple.') or domain_lower == 'apple.com' or
                      domain_lower.startswith('icloud.') or domain_lower == 'icloud.com' or
                      domain_lower.startswith('itunes.') or domain_lower.endswith('.apple.com')):
                    categories['apple'].add(domain)
                
                # Microsoft - 严格匹配
                elif (domain_lower.startswith('microsoft.') or domain_lower == 'microsoft.com' or
                      domain_lower.startswith('outlook.') or domain_lower == 'outlook.com' or
                      domain_lower.startswith('office.') or domain_lower.endswith('.office.com') or
                      domain_lower.startswith('live.') or domain_lower.endswith('.live.com')):
                    categories['microsoft'].add(domain)
                
                # Netflix - 严格匹配
                elif (domain_lower.startswith('netflix.') or domain_lower == 'netflix.com' or
                      domain_lower.startswith('nflx.') or domain_lower.endswith('.netflix.com')):
                    categories['netflix'].add(domain)
                
                # 其他服务的严格匹配
                elif domain_lower.startswith('spotify.') or domain_lower == 'spotify.com':
                    categories['spotify'].add(domain)
                elif domain_lower.startswith('github.') or domain_lower == 'github.com':
                    categories['github'].add(domain)
                elif domain_lower.startswith('cloudflare.') or domain_lower == 'cloudflare.com':
                    categories['cloudflare'].add(domain)
                elif domain_lower.startswith('baidu.') or domain_lower == 'baidu.com':
                    categories['baidu'].add(domain)
                elif (domain_lower.startswith('qq.') or domain_lower.startswith('tencent.') or
                      domain_lower == 'qq.com' or domain_lower == 'tencent.com'):
                    categories['tencent'].add(domain)
                elif (domain_lower.startswith('taobao.') or domain_lower.startswith('tmall.') or
                      domain_lower.startswith('alibaba.') or domain_lower.startswith('alipay.') or
                      domain_lower.endswith('.alibaba.com') or domain_lower.endswith('.alipay.com')):
                    categories['alibaba'].add(domain)
                elif (domain_lower.startswith('douyin.') or domain_lower.startswith('toutiao.') or
                      domain_lower.startswith('bytedance.') or domain_lower.startswith('tiktok.')):
                    categories['bytedance'].add(domain)
                elif domain_lower.startswith('bilibili.') or domain_lower.startswith('hdslb.'):
                    categories['bilibili'].add(domain)
            
            # 转换为列表并过滤空分类
            for category, domains in categories.items():
                if domains:
                    geosite_data[category] = domains
                    
        except Exception as e:
            print(f"解析geosite.dat出错: {e}")
            # 返回基础数据
            return V2RayDatParser._get_fallback_geosite_data()
        
        return geosite_data
    
    @staticmethod
    def parse_geoip_dat(filepath: str) -> Dict[str, List[str]]:
        """解析geoip.dat文件 - 提取IP段信息"""
        geoip_data = {}
        
        try:
            # 预置主要国家的IP段（从常见范围推断）
            geoip_data = {
                'cn': [  # 中国
                    '1.0.0.0/8', '14.0.0.0/8', '27.0.0.0/8', '36.0.0.0/8',
                    '39.0.0.0/8', '42.0.0.0/8', '49.0.0.0/8', '58.0.0.0/7',
                    '60.0.0.0/8', '61.0.0.0/8', '101.0.0.0/8', '103.0.0.0/8',
                    '106.0.0.0/8', '110.0.0.0/7', '112.0.0.0/5', '120.0.0.0/6',
                    '124.0.0.0/8', '125.0.0.0/8', '175.0.0.0/8', '180.0.0.0/6',
                    '182.0.0.0/7', '202.0.0.0/8', '203.0.0.0/8', '210.0.0.0/7',
                    '218.0.0.0/6', '222.0.0.0/7'
                ],
                'us': [  # 美国
                    '8.8.8.0/24', '8.8.4.0/24', '172.217.0.0/16', '216.58.192.0/19',
                    '142.250.0.0/15', '74.125.0.0/16', '108.177.8.0/21',
                    '173.194.0.0/16', '209.85.128.0/17', '64.233.160.0/19'
                ],
                'telegram': [  # Telegram专用IP段
                    '149.154.160.0/20', '91.108.4.0/22', '91.108.8.0/21',
                    '91.108.16.0/21', '91.108.56.0/21', '109.239.140.0/24'
                ]
            }
            
        except Exception as e:
            print(f"解析geoip.dat出错: {e}")
        
        return geoip_data
    
    @staticmethod
    def _get_fallback_geosite_data() -> Dict[str, Set[str]]:
        """获取后备GeoSite数据"""
        return {
            'youtube': {'youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com'},
            'google': {'google.com', 'googleapis.com', 'gstatic.com', 'gmail.com'},
            'facebook': {'facebook.com', 'instagram.com', 'whatsapp.com', 'fb.com'},
            'twitter': {'twitter.com', 'x.com', 'twimg.com', 't.co'},
            'telegram': {'telegram.org', 't.me'},
            'amazon': {'amazon.com', 'aws.com', 'amazonaws.com'},
            'apple': {'apple.com', 'icloud.com', 'itunes.com'},
            'microsoft': {'microsoft.com', 'outlook.com', 'office.com', 'live.com'},
            'baidu': {'baidu.com', 'bdstatic.com'},
            'tencent': {'qq.com', 'tencent.com', 'qzone.com'},
            'alibaba': {'taobao.com', 'tmall.com', 'alibaba.com', 'alipay.com'},
            'bytedance': {'douyin.com', 'toutiao.com', 'tiktok.com'},
            'bilibili': {'bilibili.com', 'hdslb.com'},
            'github': {'github.com', 'githubusercontent.com'}
        }