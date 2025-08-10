#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray GeoSite 数据加载器
加载并解析 https://github.com/Loyalsoldier/v2ray-rules-dat 的数据文件
"""

import os
import urllib.request
import json
import time
import struct
import ipaddress
from typing import Dict, List, Optional, Set, Tuple
import threading
from v2ray_dat_parser import V2RayDatParser
from utils import is_china_ip

class GeositeLoader:
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.geosite_data = {}  # {category: [domains]}
        self.geoip_data = {}    # {country: [cidr_ranges]}
        self.domain_to_category = {}  # 快速查找缓存
        self.ip_ranges = {}     # IP范围缓存
        self.lock = threading.Lock()
        self.last_update = 0
        self.update_interval = 24 * 3600  # 24小时更新一次
        
        # 确保数据目录存在
        os.makedirs(data_dir, exist_ok=True)
        
        # 使用新的完整解析器
        self.parser = V2RayDatParser()
        
        # 初始化加载数据
        self._load_data()
    
    def _get_latest_release_url(self) -> Tuple[Optional[str], Optional[str]]:
        """获取最新版本的下载链接"""
        api_url = "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest"
        try:
            with urllib.request.urlopen(api_url, timeout=10) as response:
                data = json.loads(response.read())
                
            geosite_url = None
            geoip_url = None
            
            for asset in data.get('assets', []):
                if asset['name'] == 'geosite.dat':
                    geosite_url = asset['browser_download_url']
                elif asset['name'] == 'geoip.dat':
                    geoip_url = asset['browser_download_url']
            
            return geosite_url, geoip_url
        except Exception as e:
            print(f"获取最新版本失败: {e}")
            # 如果无法获取最新版本，返回None让调用方处理
            return None, None
    
    def _download_file(self, url: str, filename: str) -> bool:
        """下载数据文件"""
        filepath = os.path.join(self.data_dir, filename)
        try:
            print(f"下载 {filename}...")
            with urllib.request.urlopen(url, timeout=30) as response:
                with open(filepath, 'wb') as f:
                    f.write(response.read())
            print(f"{filename} 下载完成")
            return True
        except Exception as e:
            print(f"下载 {filename} 失败: {e}")
            return False
    
    def _parse_geosite_dat(self, filepath: str) -> Dict[str, List[str]]:
        """解析 geosite.dat 文件 - 使用完整解析器"""
        try:
            # 使用新的完整V2Ray DAT解析器
            geosite_entries = self.parser.parse_geosite_dat(filepath)
            
            # 转换为原有格式
            geosite_data = {}
            for category, entry in geosite_entries.items():
                geosite_data[category] = entry.domains
            
            print(f"✅ 成功加载 {len(geosite_data)} 个分类，{sum(len(domains) for domains in geosite_data.values())} 个域名")
            return geosite_data
            
        except Exception as e:
            print(f"解析 geosite.dat 失败: {e}")
            # 返回后备数据
            fallback_entries = self.parser._get_fallback_geosite_data()
            return {category: entry.domains for category, entry in fallback_entries.items()}
    
    def _parse_geoip_dat(self, filepath: str) -> Dict[str, List[str]]:
        """解析 geoip.dat 文件 - 使用完整解析器"""
        try:
            # 使用新的完整V2Ray DAT解析器
            geoip_entries = self.parser.parse_geoip_dat(filepath)
            
            # 转换为原有格式 (国家代码 -> CIDR列表)
            geoip_data = {}
            for country_code, entry in geoip_entries.items():
                cidr_list = []
                for ip, prefix in entry.ip_ranges:
                    cidr_list.append(f"{ip}/{prefix}")
                geoip_data[country_code] = cidr_list
            
            print(f"✅ 成功加载 {len(geoip_data)} 个国家/地区的IP段")
            return geoip_data
            
        except Exception as e:
            print(f"解析 geoip.dat 失败: {e}")
            # 返回基础IP范围数据
            return {
                'cn': ['110.0.0.0/7', '112.0.0.0/5', '120.0.0.0/6'],
                'us': ['8.8.8.0/24', '172.217.0.0/16'],
                'telegram': ['149.154.160.0/20', '91.108.56.0/21']
            }
    
    def _build_lookup_cache(self):
        """构建快速查找缓存 - 支持多分类映射"""
        with self.lock:
            # 构建域名到分类列表的映射
            self.domain_to_category.clear()
            for category, domains in self.geosite_data.items():
                for domain in domains:
                    domain_lower = domain.lower()
                    if domain_lower not in self.domain_to_category:
                        self.domain_to_category[domain_lower] = []
                    self.domain_to_category[domain_lower].append(category)
            
            print(f"加载了 {len(self.domain_to_category)} 个域名映射")
            print(f"支持 {len(self.geosite_data)} 个网站分类")
    
    def _should_update(self) -> bool:
        """检查是否需要更新数据文件"""
        current_time = time.time()
        
        # 检查文件是否存在
        geosite_path = os.path.join(self.data_dir, 'geosite.dat')
        geoip_path = os.path.join(self.data_dir, 'geoip.dat')
        
        if not os.path.exists(geosite_path) or not os.path.exists(geoip_path):
            return True
        
        # 检查文件修改时间，如果文件是最近创建的，不需要重新下载
        try:
            file_mtime = os.path.getmtime(geosite_path)
            if current_time - file_mtime < 3600:  # 1小时内不重复下载
                return False
        except OSError:
            pass
        
        # 检查更新间隔
        return current_time - self.last_update > self.update_interval
    
    def _load_data(self):
        """加载数据文件"""
        try:
            # 检查是否需要更新
            if self._should_update():
                print("检查数据文件更新...")
                geosite_url, geoip_url = self._get_latest_release_url()
                
                # 只有成功获取URL时才尝试下载
                if geosite_url and geoip_url:
                    print("找到最新版本，开始下载...")
                    self._download_file(geosite_url, 'geosite.dat')
                    self._download_file(geoip_url, 'geoip.dat')
                else:
                    print("无法获取最新版本URL，跳过更新")
                
                self.last_update = time.time()
            
            # 解析数据文件
            geosite_path = os.path.join(self.data_dir, 'geosite.dat')
            geoip_path = os.path.join(self.data_dir, 'geoip.dat')
            
            if os.path.exists(geosite_path):
                self.geosite_data = self._parse_geosite_dat(geosite_path)
            
            if os.path.exists(geoip_path):
                self.geoip_data = self._parse_geoip_dat(geoip_path)
            
            # 构建查找缓存
            self._build_lookup_cache()
            
        except Exception as e:
            print(f"加载数据文件失败: {e}")
            # 使用预置的最小数据集
            self._load_fallback_data()
    
    def _load_fallback_data(self):
        """加载后备数据（预置最小数据集）"""
        print("使用预置数据集...")
        
        self.geosite_data = {
            'youtube': ['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com'],
            'google': ['google.com', 'googleapis.com', 'gstatic.com'],
            'facebook': ['facebook.com', 'instagram.com'],
            'baidu': ['baidu.com'],
            'tencent': ['qq.com', 'tencent.com'],
            'alibaba': ['taobao.com', 'tmall.com', 'alipay.com']
        }
        
        self._build_lookup_cache()
    
    def get_domain_category(self, domain: str) -> Optional[str]:
        """获取域名的分类 - 优先返回服务分类而非地理位置分类"""
        domain_lower = domain.lower()
        
        with self.lock:
            matched_categories = []
            
            # 直接匹配
            if domain_lower in self.domain_to_category:
                matched_categories.extend(self.domain_to_category[domain_lower])
            
            # 子域名匹配
            for registered_domain, categories in self.domain_to_category.items():
                if domain_lower.endswith('.' + registered_domain) or domain_lower == registered_domain:
                    for category in categories:
                        if category not in matched_categories:
                            matched_categories.append(category)
            
            if not matched_categories:
                return None
                
            # 优先级排序：服务分类 > 地理位置分类
            service_categories = [cat for cat in matched_categories 
                                if not cat.startswith('GEOLOCATION-') and not cat.startswith('CATEGORY-')]
            
            if service_categories:
                # 优先返回知名服务（更具体的服务优先级更高）
                priority_services = ['YOUTUBE', 'TIKTOK', 'BYTEDANCE', 'GOOGLE', 'FACEBOOK', 'TWITTER', 
                                   'TELEGRAM', 'APPLE', 'MICROSOFT', 'AMAZON', 'NETFLIX', 'SPOTIFY',
                                   'ALIBABA', 'TENCENT', 'BAIDU', 'BILIBILI']
                
                for priority in priority_services:
                    if priority in service_categories:
                        return priority
                        
                # 返回第一个服务分类
                return service_categories[0]
            
            # 如果没有服务分类，返回第一个匹配的分类
            return matched_categories[0]
    
    def get_ip_country(self, ip: str) -> Optional[str]:
        """获取IP的国家/地区 - 使用GeoIP数据"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # 检查所有GeoIP范围
            for country, ip_ranges in self.geoip_data.items():
                for cidr in ip_ranges:
                    try:
                        if ip_obj in ipaddress.ip_network(cidr, strict=False):
                            return country
                    except (ipaddress.AddressValueError, ValueError):
                        continue
            
            # 兜底：使用统一的中国IP检测
            if is_china_ip(ip):
                return 'cn'
            else:
                return None  # 无法确定时返回None而不是假设为'us'
            
        except Exception:
            return None
    
    def get_ip_service(self, ip: str) -> Optional[str]:
        """根据IP获取服务名称（如Telegram）"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # 检查特殊服务的IP范围
            if 'telegram' in self.geoip_data:
                for cidr in self.geoip_data['telegram']:
                    try:
                        if ip_obj in ipaddress.ip_network(cidr, strict=False):
                            return 'telegram'
                    except (ipaddress.AddressValueError, ValueError):
                        continue
            
            return None
        except Exception:
            return None
    
    def get_stats(self) -> Dict:
        """获取数据统计信息"""
        with self.lock:
            return {
                'geosite_categories': len(self.geosite_data),
                'total_domains': len(self.domain_to_category),
                'geoip_countries': len(self.geoip_data),
                'last_update': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.last_update))
            }

# 全局实例
geosite_loader = GeositeLoader()