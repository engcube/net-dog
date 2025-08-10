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
            
            # 直接返回GeositeEntry对象
            print(f"✅ 成功加载 {len(geosite_entries)} 个分类，{sum(len(entry.domains) for entry in geosite_entries.values())} 个域名规则")
            return geosite_entries
            
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
                    # 过滤明显错误的IP段
                    import ipaddress
                    try:
                        # 检查IP是否是私有地址
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_private:
                            # 私有IP段不应该被分配给特定国家（静默跳过）
                            continue
                        
                        # 对于小国家，过滤覆盖范围过大的IP段
                        small_countries = ['AD', 'LI', 'MC', 'SM', 'VA', 'MT', 'CY']  
                        if country_code in small_countries and prefix < 16:  # /16以下太大了
                            continue
                        
                        # 对所有国家，过滤前缀长度过小的段（全球性错误）
                        if prefix < 4:  # /4以下覆盖范围过大，基本不可能是单个国家
                            continue
                            
                    except Exception:
                        pass  # 忽略IP解析错误，继续处理
                        
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
        """构建快速查找缓存 - 新规则系统不需要预建索引"""
        with self.lock:
            # 计算统计信息
            total_rules = 0
            for category, entry in self.geosite_data.items():
                total_rules += len(entry.domains)
            
            print(f"加载了 {total_rules} 个域名规则")
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
        
        # 导入DomainRule和GeositeEntry
        from v2ray_dat_parser import DomainRule, GeositeEntry
        
        fallback_data = {
            'YOUTUBE': ['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com'],
            'GOOGLE': ['google.com', 'googleapis.com', 'gstatic.com'],
            'FACEBOOK': ['facebook.com', 'instagram.com'],
            'BAIDU': ['baidu.com'],
            'TENCENT': ['qq.com', 'tencent.com'],
            'ALIBABA': ['taobao.com', 'tmall.com', 'alipay.com']
        }
        
        self.geosite_data = {}
        for category, domain_strings in fallback_data.items():
            # 将字符串域名转换为DomainRule对象
            domain_rules = []
            for domain_str in domain_strings:
                rule = DomainRule(rule_type='domain', value=domain_str.lower())
                domain_rules.append(rule)
            
            self.geosite_data[category] = GeositeEntry(
                category=category,
                domains=domain_rules,
                domain_count=len(domain_rules)
            )
        
        self._build_lookup_cache()
    
    def get_domain_category(self, domain: str) -> Optional[str]:
        """获取域名的分类 - 支持Domain/Full/Keyword/Regexp规则类型"""
        domain_lower = domain.lower()
        
        with self.lock:
            matched_categories = []
            
            # 遍历所有分类，检查其域名规则
            for category, entry in self.geosite_data.items():
                for domain_rule in entry.domains:
                    if self._match_domain_rule(domain_lower, domain_rule):
                        if category not in matched_categories:
                            matched_categories.append(category)
                        break  # 一个分类匹配即可，进入下一个分类
            
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
    
    def _match_domain_rule(self, domain: str, domain_rule) -> bool:
        """根据规则类型匹配域名"""
        try:
            rule_type = domain_rule.rule_type
            value = domain_rule.value
            
            if rule_type == 'full':
                # 完全匹配
                return domain == value
            elif rule_type == 'keyword':
                # 关键词匹配（包含）
                return value in domain
            elif rule_type == 'regexp':
                # 正则表达式匹配
                import re
                try:
                    return bool(re.search(value, domain))
                except re.error:
                    return False
            elif rule_type == 'domain':
                # 后缀匹配（默认）
                return domain == value or domain.endswith('.' + value)
            else:
                # 未知规则类型，默认使用后缀匹配
                return domain == value or domain.endswith('.' + value)
                
        except Exception:
            return False
    
    def get_ip_country(self, ip: str) -> Optional[str]:
        """获取IP的国家/地区 - 使用GeoIP数据，优先识别特殊服务"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # 定义特殊服务（优先级高于国家）
            special_services = ['CLOUDFLARE', 'GOOGLE', 'TELEGRAM', 'FACEBOOK', 'NETFLIX', 'TWITTER', 'FASTLY', 'CLOUDFRONT']
            
            # 首先检查特殊服务
            for service in special_services:
                if service in self.geoip_data:
                    for cidr in self.geoip_data[service]:
                        try:
                            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                                return service.lower()  # 服务名返回小写
                        except (ipaddress.AddressValueError, ValueError):
                            continue
            
            # 然后检查国家代码
            for country, ip_ranges in self.geoip_data.items():
                # 跳过已经检查过的特殊服务
                if country in special_services:
                    continue
                    
                for cidr in ip_ranges:
                    try:
                        if ip_obj in ipaddress.ip_network(cidr, strict=False):
                            return country.lower()  # 国家代码返回小写
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
        """根据IP获取服务名称（如Google、Telegram、Cloudflare等）"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # 检查所有特殊服务的IP范围（按重要性排序）
            special_services = [
                'cloudflare', 'google', 'telegram', 'facebook', 
                'netflix', 'twitter', 'fastly', 'cloudfront'
            ]
            
            for service in special_services:
                if service.upper() in self.geoip_data:
                    for cidr in self.geoip_data[service.upper()]:
                        try:
                            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                                return service
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