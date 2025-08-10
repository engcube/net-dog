#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络流量监控工具
智能网络流量实时监控和分析
"""

import time
import json
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import threading
import socket

# 导入增强的域名解析器和GeoSite数据
from domain_resolver import domain_resolver
from geosite_loader import geosite_loader
from utils import is_china_ip, get_country_name
from data_collector import create_data_collector

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.align import Align
    from rich.text import Text
    from rich.columns import Columns
    from rich.bar import Bar
except ImportError:
    print("请安装rich库: pip install rich")
    exit(1)

class NetworkMonitor:
    def __init__(self, config_file="config.json"):
        self.console = Console()
        self.data_lock = threading.Lock()
        self.running = False
        self.start_time = datetime.now()  # 记录启动时间
        self.config = self._load_config(config_file)
        
        # 初始化其他属性
        self._initialize_data_structures()
        
    def _load_config(self, config_file):
        """加载配置文件"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            # 返回默认配置
            return {
                "network_settings": {
                    "proxy_ip_ranges": ["28.0.0.0/8"],
                    "local_ip_ranges": ["192.168.31.0/24"],
                    "proxy_device_name": "Clash设备",
                    "proxy_type": "Clash代理",
                    "direct_device_name_template": "直连设备 {ip}"
                },
                "monitoring": {
                    "interface_check_interval": 5,
                    "connection_timeout": 30,
                    "max_recent_connections": 1000
                },
                "display": {
                    "max_unknown_sites_display": 3,
                    "refresh_interval": 1
                }
            }
        
    def _initialize_data_structures(self):
        """初始化所有数据结构"""
        # 简化数据存储 - 避免重复
        self.device_stats = defaultdict(lambda: {
            'ip': '',
            'mac': '',
            'hostname': '',
            'bytes_in': 0,
            'bytes_out': 0,
            'last_seen': datetime.now(),
            'is_local': False  # 区分本地设备和VPN
        })
        
        # 域名统计 - 按设备分组
        self.domain_stats = defaultdict(lambda: defaultdict(lambda: {
            'bytes_up': 0,    # 上行流量
            'bytes_down': 0,  # 下行流量
            'connections': 0,
            'ips': set(),
            'location': '',
            'category': ''
        }))
        
        # 速度计算 - 分上下行
        self.speed_data_up = deque(maxlen=10)    # 保存最近10次的上行速度
        self.speed_data_down = deque(maxlen=10)  # 保存最近10次的下行速度
        self.last_total_bytes_up = 0
        self.last_total_bytes_down = 0
        self.last_speed_time = time.time()
        self.local_network = None  # 稍后初始化
        
        # 连接跟踪（用于流量模式推断）
        self.recent_connections = set()  # 最近的连接IP
        self.connection_history = deque(maxlen=100)  # 连接历史
        
        # 初始化数据收集器
        try:
            self.data_collector = create_data_collector()
            # 初始化网络检测（必须在其他属性初始化完成后）
            self.local_network = self.data_collector.detect_local_network()
        except NotImplementedError as e:
            print(f"❌ 平台不支持: {e}")
            raise
    
    def _resolve_hostname(self, ip: str) -> str:
        """解析IP对应的主机名"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname != ip and '.' in hostname:
                # 简化主机名显示
                return hostname.split('.')[0]
            return hostname
        except:
            pass
        return f"设备-{ip.split('.')[-1]}"
    
    def _get_active_connections(self) -> List[Dict]:
        """获取活跃的网络连接"""
        try:
            # 使用数据收集器获取原始连接数据
            raw_connections = self.data_collector.get_connections()
            connections = []
            seen_connections = set()
            
            for conn in raw_connections:
                local_ip = conn['local_ip']
                foreign_ip = conn['foreign_ip']
                
                # 只关心本地到外网的连接
                is_local = (local_ip.startswith(('192.168.', '10.', '28.')) or 
                          (local_ip.startswith('172.') and 16 <= int(local_ip.split('.')[1]) <= 31))
                is_foreign = not foreign_ip.startswith(('192.168.', '10.', '172.', '127.', '28.', 'fe80', 'fd', '169.254'))
                
                if is_local and is_foreign:
                    conn_key = f"{local_ip}->{foreign_ip}"
                    if conn_key not in seen_connections:
                        seen_connections.add(conn_key)
                        connections.append({
                            'local_ip': local_ip,
                            'foreign_ip': foreign_ip,
                            'protocol': conn.get('protocol', 'tcp')
                        })
            
            return connections
        except:
            return []
    
    def _resolve_domain(self, ip: str) -> str:
        """增强的IP到域名解析"""
        return domain_resolver.resolve_domain(ip)
    
    def _detect_ip_service(self, ip: str) -> Optional[Tuple[str, str]]:
        """通过IP识别服务（如Telegram、Google、Cloudflare等）"""
        try:
            # 先检查国家识别是否为特殊服务
            country = geosite_loader.get_ip_country(ip)
            if country:
                service_map = {
                    'google': 'Google',
                    'cloudflare': 'Cloudflare', 
                    'telegram': 'Telegram',
                    'facebook': 'Facebook',
                    'netflix': 'Netflix',
                    'twitter': 'Twitter',
                    'fastly': 'Fastly',
                    'cloudfront': 'CloudFront'
                }
                if country in service_map:
                    return service_map[country], '海外服务'
                    
            # 备用方法：通过专门的服务识别
            ip_service = geosite_loader.get_ip_service(ip)
            if ip_service and ip_service in service_map:
                return service_map[ip_service], '海外服务'
                
        except Exception:
            pass
        return None
    
    def _check_special_domain_mappings(self, domain_lower: str) -> Optional[Tuple[str, str]]:
        """检查特殊域名映射"""
        special_domains = {
            '1e100.net': ('Google', '海外'),
            'dns.google': ('Google', '海外'), 
            'googleusercontent.com': ('Google', '海外'),
            'googlevideo.com': ('YouTube', '海外'),
            'youtube-nocookie.com': ('YouTube', '海外'),
            'ytimg.com': ('YouTube', '海外'),
            'youtu.be': ('YouTube', '海外'),
            'youtube.com': ('YouTube', '海外'),
            'alidns.com': ('阿里系', '中国'),
            'alicdn.com': ('阿里系', '中国'),
            'dnspod.com': ('腾讯/QQ', '中国'),
            'gtimg.com': ('腾讯/QQ', '中国'),
            'qq.com': ('腾讯/QQ', '中国'),
            'amazonaws.com': ('Amazon', '海外'),
            'cloudfront.net': ('Amazon', '海外'),
            'awsstatic.com': ('Amazon', '海外'),
            'telegram.com': ('Telegram', '海外'),
            'telegram.org': ('Telegram', '海外'),
            'tailscale.com': ('Tailscale', '海外'),
            'akamaitechnologies.com': ('Akamai CDN', '海外'),
            'akamaized.net': ('Akamai CDN', '海外'),
            'cloudflare.com': ('Cloudflare', '海外'),
            'cdninstagram.com': ('Facebook', '海外'),
            'fbcdn.net': ('Facebook', '海外')
        }
        
        for special_domain, (service, location) in special_domains.items():
            if domain_lower.endswith(special_domain) or domain_lower == special_domain:
                return service, location
        
        return None
    
    def _lookup_geosite_database(self, domain_lower: str, ip: str) -> Optional[Tuple[str, str]]:
        """使用GeoSite数据库进行域名分类"""
        try:
            category = geosite_loader.get_domain_category(domain_lower)
            if category:
                # 获取地区信息
                country = geosite_loader.get_ip_country(ip)
                location = '中国' if country == 'cn' else '海外'
                
                # 标准化分类名称
                display_name = self._standardize_category_name(category)
                return display_name, location
        except Exception:
            pass
        return None
    
    def _standardize_category_name(self, category: str) -> str:
        """标准化分类名称"""
        category_map = {
            'youtube': 'YouTube',
            'google': 'Google',
            'facebook': 'Facebook',
            'twitter': 'Twitter/X',
            'telegram': 'Telegram',
            'apple': 'Apple',
            'microsoft': 'Microsoft',
            'amazon': 'Amazon',
            'netflix': 'Netflix',
            'spotify': 'Spotify',
            'github': 'GitHub',
            'cloudflare': 'Cloudflare',
            'baidu': '百度',
            'tencent': '腾讯/QQ',
            'alibaba': '阿里系',
            'bytedance': '抖音/TikTok',
            'tiktok': '抖音/TikTok',
            'bilibili': 'B站'
        }
        
        return category_map.get(category.lower(), category.capitalize())
    
    def _identify_by_ip_ranges(self, domain: str, ip: str) -> Optional[Tuple[str, str]]:
        """通过IP范围启发式识别服务"""
        if not domain or domain == ip:
            return self._check_douyin_ip_ranges(ip)
        return None
    
    def _check_douyin_ip_ranges(self, ip: str) -> Optional[Tuple[str, str]]:
        """检查抖音/字节跳动已知IP段"""
        try:
            octets = [int(x) for x in ip.split('.')]
            first, second, third = octets[0], octets[1], octets[2]
            
            # 抖音/字节跳动常用IP段（基于真实观察）
            if (first == 122 and second == 14 and 220 <= third <= 235) or \
               (first == 123 and second == 14 and 220 <= third <= 235) or \
               (first == 117 and second == 93 and 180 <= third <= 200) or \
               (first == 110 and second == 43 and 0 <= third <= 50) or \
               (first == 36 and second == 51 and 0 <= third <= 255):
                return '抖音/TikTok', '中国'
            
            # TikTok海外IP段
            if (first == 108 and 20 <= second <= 30) or \
               (first == 151 and second == 101):
                return '抖音/TikTok', '海外'
        
        except (ValueError, IndexError):
            pass
        
        return None
    
    def _analyze_traffic_patterns(self, ip: str) -> Optional[Tuple[str, str]]:
        """使用流量模式推断服务类型"""
        try:
            # 检查抖音CDN模式
            douyin_result = self._check_douyin_cdn_patterns(ip)
            if douyin_result:
                return douyin_result
            
            # 检查通用视频服务模式
            video_result = self._check_video_service_patterns(ip)
            if video_result:
                return video_result
            
        except Exception:
            pass
        
        return None
    
    def _check_douyin_cdn_patterns(self, ip: str) -> Optional[Tuple[str, str]]:
        """检查抖音CDN特征"""
        try:
            octets = [int(x) for x in ip.split('.')]
            first, second = octets[0], octets[1]
            
            # 抖音常用的CDN IP范围
            douyin_cdn_patterns = [
                (39, 137), (39, 173), (39, 135), (117, 135),
                (36, 156), (183, 192), (111, 62), (221, 181), (120, 202)
            ]
            
            for cdn_first, cdn_second in douyin_cdn_patterns:
                if first == cdn_first and second == cdn_second:
                    if hasattr(self, 'recent_connections'):
                        prefix_match = f'{first}.{second}'
                        similar_count = sum(1 for conn_ip in self.recent_connections 
                                          if conn_ip.startswith(prefix_match))
                        
                        if similar_count >= 2:
                            return '抖音/TikTok', '中国'
                    
                    return '疑似抖音/TikTok', '中国'
        
        except (ValueError, IndexError):
            pass
        
        return None
    
    def _check_video_service_patterns(self, ip: str) -> Optional[Tuple[str, str]]:
        """检查通用视频服务模式"""
        try:
            octets = [int(x) for x in ip.split('.')]
            first = octets[0]
            
            if hasattr(self, 'recent_connections'):
                ip_prefix = '.'.join(ip.split('.')[:2])
                similar_ips = [conn_ip for conn_ip in self.recent_connections 
                             if conn_ip.startswith(ip_prefix) and conn_ip != ip]
                
                if len(similar_ips) >= 3:
                    # 中国IP段的启发式检测
                    china_ip_ranges = [110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
                                     120, 121, 122, 123, 124, 125, 36, 39, 42, 49, 58, 59, 60, 61]
                    if first in china_ip_ranges:
                        return '视频服务', '中国'
        
        except (ValueError, IndexError):
            pass
        
        return None
    
    def _try_smart_ip_identification(self, ip: str) -> Optional[Tuple[str, str]]:
        """尝试智能IP识别"""
        try:
            from unified_service_identifier import unified_service_identifier
            provider, region, confidence = unified_service_identifier.identify_ip(ip)
            
            if confidence > 0.5:
                return provider, region
        
        except Exception:
            pass
        
        return None
    
    def _fallback_geographic_classification(self, ip: str) -> Tuple[str, str]:
        """兜底：根据IP地理位置分类"""
        try:
            country = geosite_loader.get_ip_country(ip)
            if country == 'cn':
                return '中国网站', '中国'
            elif country:
                # 检查是否为特殊服务
                service_map = {
                    'google': 'Google',
                    'cloudflare': 'Cloudflare', 
                    'telegram': 'Telegram',
                    'facebook': 'Facebook',
                    'netflix': 'Netflix',
                    'twitter': 'Twitter',
                    'fastly': 'Fastly',
                    'cloudfront': 'CloudFront'
                }
                
                if country in service_map:
                    # 特殊服务显示
                    service_name = service_map[country]
                    return f'{service_name}服务', '海外服务'
                else:
                    # 普通国家显示具体国家名称
                    country_name = get_country_name(country)
                    return f'{country_name}网站', country_name
            else:
                # 如果无法确定具体国家，仍显示"海外"
                return '海外网站', '海外'
        except Exception:
            # 最终兜底
            is_china = is_china_ip(ip)
            return ('中国网站' if is_china else '海外网站'), ('中国' if is_china else '海外')
    
    def _categorize_domain(self, domain: str, ip: str) -> Tuple[str, str]:
        """分类域名，返回(类别, 地区) - 重构为更小的函数"""
        domain_lower = domain.lower().replace('(未知网站)', '')
        
        # 1. 优先通过IP识别服务
        result = self._detect_ip_service(ip)
        if result:
            return result
        
        # 2. 特殊域名映射
        result = self._check_special_domain_mappings(domain_lower)
        if result:
            return result
        
        # 3. 使用GeoSite数据库
        result = self._lookup_geosite_database(domain_lower, ip)
        if result:
            return result
        
        # 4. IP范围启发式识别
        result = self._identify_by_ip_ranges(domain, ip)
        if result:
            return result
        
        # 5. 使用流量模式推断
        result = self._analyze_traffic_patterns(ip)
        if result:
            return result
        
        # 6. 智能IP识别
        result = self._try_smart_ip_identification(ip)
        if result:
            return result
        
        # 7. 兜底方案
        return self._fallback_geographic_classification(ip)
    
    # 旧的硬编码分类方法已移除，现在完全使用GeoSite数据
    
    def _collect_network_data(self):
        """收集网络数据：ARP表、活跃连接和接口统计"""
        return (
            self.data_collector.get_arp_table(),
            self._get_active_connections(),
            self.data_collector.get_interface_stats()
        )
    
    def _update_device_records(self, arp_devices, connections):
        """更新设备记录，包括ARP设备和虚拟设备"""
        current_devices = set()
        
        # 处理ARP表中的设备
        for ip, mac in arp_devices.items():
            device_key = ip
            current_devices.add(device_key)
            
            if device_key not in self.device_stats:
                self.device_stats[device_key] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': self._resolve_hostname(ip),
                    'bytes_in': 0,
                    'bytes_out': 0,
                    'last_seen': datetime.now(),
                    'is_local': True
                }
            else:
                self.device_stats[device_key]['last_seen'] = datetime.now()
        
        # 创建虚拟设备（VPN和直连）
        self._create_virtual_devices(connections, current_devices, arp_devices)
        
        return current_devices
    
    def _create_virtual_devices(self, connections, current_devices, arp_devices):
        """创建虚拟设备（Clash VPN设备和直连设备）"""
        # 从配置文件读取IP范围前缀
        proxy_prefixes = [ip_range.split('/')[0].rsplit('.', 1)[0] + '.' for ip_range in self.config['network_settings']['proxy_ip_ranges']]
        local_prefixes = [ip_range.split('/')[0].rsplit('.', 1)[0] + '.' for ip_range in self.config['network_settings']['local_ip_ranges']]
        
        vpn_connections = [conn for conn in connections if any(conn['local_ip'].startswith(prefix) for prefix in proxy_prefixes)]
        local_connections = [conn for conn in connections if any(conn['local_ip'].startswith(prefix) for prefix in local_prefixes)]
        
        # 创建Clash设备（TUN模式）
        if vpn_connections:
            clash_key = "Clash设备"
            current_devices.add(clash_key)
            if clash_key not in self.device_stats:
                proxy_ip_display = proxy_prefixes[0] + 'x' if proxy_prefixes else '28.0.0.x'
                self.device_stats[clash_key] = {
                    'ip': proxy_ip_display,
                    'mac': 'virtual',
                    'hostname': f'Clash代理({len(vpn_connections)}个连接)',
                    'bytes_in': 0,
                    'bytes_out': 0,
                    'last_seen': datetime.now(),
                    'is_local': False
                }
            else:
                self.device_stats[clash_key]['hostname'] = f'Clash代理({len(vpn_connections)}个连接)'
                self.device_stats[clash_key]['last_seen'] = datetime.now()
        
        # 创建直连设备（绕过Clash的流量）
        if local_connections:
            direct_key = "直连设备"
            current_devices.add(direct_key)
            if direct_key not in self.device_stats:
                # 使用配置文件中的本地IP范围
                main_ip = self.config['network_settings']['local_ip_ranges'][0].split('/')[0] if local_prefixes else '192.168.31.31'
                hostname = 'local-device'
                self.device_stats[direct_key] = {
                    'ip': f'{main_ip}(多端口)',
                    'mac': arp_devices.get(main_ip, 'unknown'),
                    'hostname': f'{hostname}({len(local_connections)}个直连)',
                    'bytes_in': 0,
                    'bytes_out': 0,
                    'last_seen': datetime.now(),
                    'is_local': True
                }
            else:
                self.device_stats[direct_key]['hostname'] = f'mmini({len(local_connections)}个直连)'
                self.device_stats[direct_key]['last_seen'] = datetime.now()
    
    def _calculate_traffic_deltas(self, interface_stats, last_interface_stats):
        """计算接口流量增量"""
        total_period_traffic_in = 0
        total_period_traffic_out = 0
        
        for interface, stats in interface_stats.items():
            if interface in last_interface_stats:
                bytes_in_diff = max(0, stats['bytes_in'] - last_interface_stats[interface]['bytes_in'])
                bytes_out_diff = max(0, stats['bytes_out'] - last_interface_stats[interface]['bytes_out'])
                total_period_traffic_in += bytes_in_diff
                total_period_traffic_out += bytes_out_diff
        
        return total_period_traffic_in, total_period_traffic_out
    
    def _process_connections_and_domains(self, connections, current_devices, arp_devices):
        """处理连接并进行域名分类"""
        device_connections = defaultdict(int)
        domain_connections = defaultdict(set)
        
        for conn in connections:
            local_ip = conn['local_ip']
            foreign_ip = conn['foreign_ip']
            
            # 跟踪连接IP（用于流量模式推断）
            self.recent_connections.add(foreign_ip)
            self.connection_history.append((foreign_ip, time.time()))
            
            # 确定设备
            device_key = self._determine_device_key(local_ip, current_devices, arp_devices)
            device_connections[device_key] += 1
            
            # 处理域名和网站分类
            website_name = self._process_domain_classification(foreign_ip, device_key)
            domain_connections[website_name].add(device_key)
        
        return device_connections, domain_connections
    
    def _determine_device_key(self, local_ip, current_devices, arp_devices):
        """确定连接对应的设备键"""
        # 从配置文件读取IP范围前缀
        proxy_prefixes = [ip_range.split('/')[0].rsplit('.', 1)[0] + '.' for ip_range in self.config['network_settings']['proxy_ip_ranges']]
        local_prefixes = [ip_range.split('/')[0].rsplit('.', 1)[0] + '.' for ip_range in self.config['network_settings']['local_ip_ranges']]
        
        if any(local_ip.startswith(prefix) for prefix in proxy_prefixes):
            return "Clash设备"
        elif any(local_ip.startswith(prefix) for prefix in local_prefixes):
            return "直连设备"
        else:
            device_key = local_ip
            if device_key not in current_devices:
                current_devices.add(device_key)
                self.device_stats[device_key] = {
                    'ip': local_ip,
                    'mac': arp_devices.get(local_ip, 'unknown'),
                    'hostname': f'设备-{local_ip.split(".")[-1]}',
                    'bytes_in': 0,
                    'bytes_out': 0,
                    'last_seen': datetime.now(),
                    'is_local': True
                }
            return device_key
    
    def _process_domain_classification(self, foreign_ip, device_key):
        """处理域名解析和分类"""
        raw_domain = self._resolve_domain(foreign_ip)
        category, location = self._categorize_domain(raw_domain, foreign_ip)
        
        # 优先使用网站分类作为显示名称，实现服务合并
        if category and category not in ['中国网站', '海外网站']:
            website_name = category
        else:
            if raw_domain != foreign_ip and not raw_domain.endswith('(未知网站)'):
                website_name = raw_domain
            else:
                website_name = f"{foreign_ip}(未知网站)"
        
        # 更新网站信息
        if website_name not in self.domain_stats[device_key]:
            self.domain_stats[device_key][website_name] = {
                'bytes_up': 0,
                'bytes_down': 0,
                'connections': 0,
                'ips': {foreign_ip},
                'location': location,
                'category': category
            }
        else:
            self.domain_stats[device_key][website_name]['category'] = category
            self.domain_stats[device_key][website_name]['location'] = location
            self.domain_stats[device_key][website_name]['ips'].add(foreign_ip)
        
        return website_name
    
    def _allocate_traffic_to_devices(self, total_period_traffic, device_connections, current_devices):
        """分配流量到设备"""
        if total_period_traffic > 0 and device_connections:
            total_connections = sum(device_connections.values())
            
            for device_key, conn_count in device_connections.items():
                if device_key in current_devices:
                    traffic_share = (conn_count / total_connections) * total_period_traffic
                    increment_in = traffic_share * 0.6
                    increment_out = traffic_share * 0.4
                    
                    self.device_stats[device_key]['bytes_in'] += increment_in
                    self.device_stats[device_key]['bytes_out'] += increment_out
    
    def _allocate_traffic_to_websites(self, total_period_traffic_in, total_period_traffic_out, domain_connections):
        """分配流量到网站"""
        if total_period_traffic_in + total_period_traffic_out > 0 and domain_connections:
            website_weights = self._calculate_website_weights(domain_connections)
            total_weight = sum(website_weights.values())
            
            if total_weight > 0:
                for website_name, connected_devices in domain_connections.items():
                    website_weight = website_weights[website_name] / total_weight
                    
                    total_website_down = total_period_traffic_in * website_weight
                    total_website_up = total_period_traffic_out * website_weight
                    
                    device_count = len(connected_devices)
                    per_device_down = total_website_down / device_count if device_count > 0 else 0
                    per_device_up = total_website_up / device_count if device_count > 0 else 0
                    
                    for device_key in connected_devices:
                        if device_key in self.domain_stats:
                            self.domain_stats[device_key][website_name]['bytes_down'] += per_device_down
                            self.domain_stats[device_key][website_name]['bytes_up'] += per_device_up
                            self.domain_stats[device_key][website_name]['connections'] = len(self.domain_stats[device_key][website_name]['ips'])
    
    def _calculate_website_weights(self, domain_connections):
        """计算网站权重（考虑IP多样性）"""
        website_weights = {}
        
        for website_name, connected_devices in domain_connections.items():
            # 获取该网站的实际IP数量
            unique_ips = set()
            for device_key in connected_devices:
                if device_key in self.domain_stats and website_name in self.domain_stats[device_key]:
                    unique_ips.update(self.domain_stats[device_key][website_name]['ips'])
            
            device_count = len(connected_devices)
            ip_diversity = len(unique_ips)
            
            # 使用哈希因子避免完全相同的权重
            import hashlib
            name_hash = int(hashlib.md5(website_name.encode()).hexdigest()[:8], 16)
            hash_factor = 0.9 + (name_hash % 100) / 500
            
            weight = (device_count + ip_diversity * 0.5) * hash_factor
            website_weights[website_name] = weight
        
        return website_weights
    
    def _update_speed_calculations(self):
        """更新速度计算"""
        current_time = time.time()
        time_delta = current_time - self.last_speed_time
        
        if time_delta > 0:
            total_up_traffic = sum(d['bytes_out'] for d in self.device_stats.values())
            total_down_traffic = sum(d['bytes_in'] for d in self.device_stats.values())
            
            period_up_traffic = total_up_traffic - self.last_total_bytes_up
            period_down_traffic = total_down_traffic - self.last_total_bytes_down
            
            current_speed_up = period_up_traffic / time_delta if period_up_traffic > 0 else 0
            current_speed_down = period_down_traffic / time_delta if period_down_traffic > 0 else 0
            
            self.speed_data_up.append(current_speed_up)
            self.speed_data_down.append(current_speed_down)
            
            self.last_total_bytes_up = total_up_traffic
            self.last_total_bytes_down = total_down_traffic
            self.last_speed_time = current_time
    
    def _perform_cache_cleanup(self, last_cache_clean):
        """执行缓存清理"""
        current_time = time.time()
        if current_time - last_cache_clean > 300:  # 5分钟
            domain_resolver.clear_cache()
            
            # 清理旧的IP格式域名数据
            with self.data_lock:
                old_keys = [k for k in self.domain_stats.keys() 
                           if k.count('.') >= 3 and '(未知网站)' in k]
                for old_key in old_keys:
                    del self.domain_stats[old_key]
            
            return current_time
        return last_cache_clean
    
    def _monitor_traffic(self):
        """后台监控线程 - 重构为更小的函数"""
        last_interface_stats = {}
        last_cache_clean = time.time()
        
        while self.running:
            try:
                # 1. 收集网络数据
                arp_devices, connections, interface_stats = self._collect_network_data()
                
                with self.data_lock:
                    # 2. 更新设备记录
                    current_devices = self._update_device_records(arp_devices, connections)
                    
                    # 3. 计算流量增量
                    total_period_traffic_in, total_period_traffic_out = self._calculate_traffic_deltas(
                        interface_stats, last_interface_stats)
                    total_period_traffic = total_period_traffic_in + total_period_traffic_out
                    
                    # 4. 处理连接和域名分类
                    device_connections, domain_connections = self._process_connections_and_domains(
                        connections, current_devices, arp_devices)
                    
                    # 5. 分配流量到设备
                    self._allocate_traffic_to_devices(total_period_traffic, device_connections, current_devices)
                    
                    # 6. 分配流量到网站
                    self._allocate_traffic_to_websites(total_period_traffic_in, total_period_traffic_out, domain_connections)
                    
                    # 7. 更新速度计算
                    self._update_speed_calculations()
                
                # 8. 更新接口统计
                last_interface_stats = interface_stats.copy()
                
                # 9. 执行缓存清理
                last_cache_clean = self._perform_cache_cleanup(last_cache_clean)
                
                time.sleep(3)
                
            except Exception as e:
                time.sleep(1)
    
    def _format_bytes(self, bytes_val: float) -> str:
        """格式化字节数"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f}{unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f}TB"
    
    def _format_speed(self, bytes_per_second: float) -> str:
        """格式化速度显示"""
        if bytes_per_second < 1024:
            return f"{bytes_per_second:.1f}B/s"
        elif bytes_per_second < 1024 * 1024:
            return f"{bytes_per_second / 1024:.1f}KB/s"
        elif bytes_per_second < 1024 * 1024 * 1024:
            return f"{bytes_per_second / (1024 * 1024):.1f}MB/s"
        else:
            return f"{bytes_per_second / (1024 * 1024 * 1024):.1f}GB/s"
    
    def _create_device_table(self) -> Table:
        """创建设备流量表 - 分上下行显示"""
        table = Table(title="🖥️  设备流量统计", show_header=True, expand=True)
        table.add_column("设备IP", style="cyan", justify="left", ratio=3)
        table.add_column("主机名", style="blue", justify="left", ratio=3) 
        table.add_column("上行", style="red", justify="right", ratio=2)
        table.add_column("下行", style="green", justify="right", ratio=2)
        table.add_column("状态", style="dim", justify="center", ratio=1)
        
        with self.data_lock:
            # 计算每个设备的网站流量汇总，与网站访问统计保持一致
            device_totals = {}
            for device_key, device_sites in self.domain_stats.items():
                if device_key in self.device_stats:
                    total_up = 0
                    total_down = 0
                    for website_name, stats in device_sites.items():
                        total_up += stats['bytes_up']
                        total_down += stats['bytes_down']
                    
                    device_totals[device_key] = {
                        'bytes_up': total_up,
                        'bytes_down': total_down,
                        'total': total_up + total_down,
                        'device_info': self.device_stats[device_key]
                    }
            
            # 按总流量排序
            sorted_devices = sorted(
                device_totals.items(),
                key=lambda x: x[1]['total'],
                reverse=True
            )[:10]
            
            for device_key, device_data in sorted_devices:
                if device_data['total'] > 10:  # 降低设备显示门槛
                    device_info = device_data['device_info']
                    
                    # 设备IP显示 - 优先显示设备key(IP地址)
                    device_ip = device_key
                    if len(device_ip) > 14:
                        device_display = device_ip[:11] + "..."
                    else:
                        device_display = device_ip
                    
                    # 主机名显示
                    hostname = device_info.get('hostname', '未知设备')
                    if len(hostname) > 12:
                        hostname_display = hostname[:10] + ".."
                    else:
                        hostname_display = hostname
                    
                    bytes_up = device_data['bytes_up']
                    bytes_down = device_data['bytes_down']
                    
                    # 活跃状态简化显示
                    is_active = (datetime.now() - device_info['last_seen']).seconds < 60
                    activity_status = "🟢" if is_active else "🔴"
                    
                    table.add_row(
                        device_display,
                        hostname_display,
                        self._format_bytes(bytes_up),
                        self._format_bytes(bytes_down),
                        activity_status
                    )
        
        return table
    
    def _create_integrated_table(self) -> Table:
        """创建整合的网站访问统计表 - 包含网络概况和设备分组"""
        
        # 计算概况信息 - 基于实际显示的设备数据
        with self.data_lock:
            # 计算有网站访问数据的活跃设备数量
            active_devices_with_sites = len([device_key for device_key in self.domain_stats.keys() 
                                           if device_key in self.device_stats and self.domain_stats[device_key]])
            
            # 计算网站流量汇总作为网络总计（与设备显示保持一致）
            total_traffic_up = 0
            total_traffic_down = 0
            active_domains = 0
            
            for device_key, device_sites in self.domain_stats.items():
                if device_key in self.device_stats and device_sites:
                    for website_name, stats in device_sites.items():
                        if stats['bytes_up'] + stats['bytes_down'] > 100:  # 只计算有意义的流量
                            total_traffic_up += stats['bytes_up']
                            total_traffic_down += stats['bytes_down']
                            active_domains += 1
            
            # 计算平均速度 - 分上下行
            if self.speed_data_up and self.speed_data_down:
                avg_speed_up = sum(self.speed_data_up) / len(self.speed_data_up)
                avg_speed_down = sum(self.speed_data_down) / len(self.speed_data_down)
                current_speed_up = list(self.speed_data_up)[-1] if self.speed_data_up else 0
                current_speed_down = list(self.speed_data_down)[-1] if self.speed_data_down else 0
            else:
                avg_speed_up = avg_speed_down = 0
                current_speed_up = current_speed_down = 0
        
        # 计算运行时间
        uptime = datetime.now() - self.start_time
        uptime_str = f"{int(uptime.total_seconds() // 3600):02d}:{int((uptime.total_seconds() % 3600) // 60):02d}:{int(uptime.total_seconds() % 60):02d}"
        
        # 创建标题信息
        title_info = (f"🏠 {self.local_network} | 📱 {active_devices_with_sites}台活跃设备 | 🌐 {active_domains}个站点 | "
                     f"⏰ {self.start_time.strftime('%H:%M:%S')} | ⏱️ {uptime_str}")
        
        table = Table(title=f"{title_info}", show_header=True, expand=True)
        table.add_column("设备/网站", style="cyan", ratio=5)
        table.add_column("地区", style="yellow", ratio=1)
        table.add_column("上行", style="red", ratio=2)
        table.add_column("下行", style="green", ratio=2)
        table.add_column("连接", style="dim", ratio=1)
        
        with self.data_lock:
            # 首先添加网络概况总计行
            table.add_row(
                f"📊 [bold]网络总计[/bold] ({self._format_speed(current_speed_up)}↑ {self._format_speed(current_speed_down)}↓)",
                "",
                f"[bold red]{self._format_bytes(total_traffic_up)}[/bold red]",
                f"[bold green]{self._format_bytes(total_traffic_down)}[/bold green]",
                f"{active_devices_with_sites}台"
            )
            
            # 添加平均速度行
            table.add_row(
                f"📈 [bold]平均速度[/bold] ({self._format_speed(avg_speed_up)}↑ {self._format_speed(avg_speed_down)}↓)",
                "",
                f"启动时长: {uptime_str}",
                "",
                ""
            )
            
            # 添加分隔空行
            table.add_row("", "", "", "", "")
            
            # 继续原来的设备分组逻辑...
            self._add_device_groups_to_table(table)
        
        return table
    
    def _add_device_groups_to_table(self, table: Table):
        """将设备分组数据添加到表格"""
        # 复用原来的设备分组逻辑
        device_groups = []
        for device_key, device_info in self.device_stats.items():
            if device_key in self.domain_stats and self.domain_stats[device_key]:
                device_sites = self.domain_stats[device_key]
                device_name = device_info.get('hostname', device_key)
                
                # 收集该设备的所有网站并聚合未知站点
                sites = []
                unknown_domestic_sites = []  # 国内未知站点
                unknown_foreign_sites = []   # 海外未知站点
                device_total_up = 0
                device_total_down = 0
                
                for website_name, stats in device_sites.items():
                    total_traffic = stats['bytes_up'] + stats['bytes_down']
                    if total_traffic > 100:  # 只显示有意义的流量
                        device_total_up += stats['bytes_up']
                        device_total_down += stats['bytes_down']
                        
                        # 判断是否为未知站点
                        if '(未知网站)' in website_name:
                            location = stats.get('location', '未知')
                            if location == '中国':
                                unknown_domestic_sites.append({
                                    'ip': website_name.split('(')[0],
                                    'stats': stats,
                                    'total_traffic': total_traffic
                                })
                            else:
                                unknown_foreign_sites.append({
                                    'ip': website_name.split('(')[0],
                                    'stats': stats,
                                    'total_traffic': total_traffic
                                })
                        else:
                            # 已知站点直接加入
                            sites.append({
                                'website_name': website_name,
                                'stats': stats,
                                'total_traffic': total_traffic
                            })
                
                # 处理未知站点聚合
                if unknown_domestic_sites:
                    # 聚合国内未知站点
                    unknown_domestic_sites.sort(key=lambda x: x['total_traffic'], reverse=True)
                    total_up = sum(s['stats']['bytes_up'] for s in unknown_domestic_sites)
                    total_down = sum(s['stats']['bytes_down'] for s in unknown_domestic_sites)
                    top_ips = [s['ip'] for s in unknown_domestic_sites[:3]]  # 显示前3个IP
                    
                    sites.append({
                        'website_name': f"国内未知站点 ({len(unknown_domestic_sites)}IP)",
                        'stats': {
                            'bytes_up': total_up,
                            'bytes_down': total_down,
                            'connections': sum(s['stats']['connections'] for s in unknown_domestic_sites),
                            'ips': set(s['ip'] for s in unknown_domestic_sites),
                            'location': '中国',
                            'category': '未知站点',
                            'top_ips': top_ips
                        },
                        'total_traffic': total_up + total_down
                    })
                
                if unknown_foreign_sites:
                    # 聚合海外未知站点
                    unknown_foreign_sites.sort(key=lambda x: x['total_traffic'], reverse=True)
                    total_up = sum(s['stats']['bytes_up'] for s in unknown_foreign_sites)
                    total_down = sum(s['stats']['bytes_down'] for s in unknown_foreign_sites)
                    top_ips = [s['ip'] for s in unknown_foreign_sites[:3]]  # 显示前3个IP
                    
                    sites.append({
                        'website_name': f"海外未知站点 ({len(unknown_foreign_sites)}IP)",
                        'stats': {
                            'bytes_up': total_up,
                            'bytes_down': total_down,
                            'connections': sum(s['stats']['connections'] for s in unknown_foreign_sites),
                            'ips': set(s['ip'] for s in unknown_foreign_sites),
                            'location': '海外',
                            'category': '未知站点',
                            'top_ips': top_ips
                        },
                        'total_traffic': total_up + total_down
                    })
                
                # 按流量排序该设备的网站，限制显示前10个
                sites.sort(key=lambda x: x['total_traffic'], reverse=True)
                sites = sites[:10]  # 每个设备只显示前10个站点
                
                if sites:  # 只添加有数据的设备
                    device_groups.append({
                        'device_key': device_key,
                        'device_name': device_name,
                        'sites': sites,
                        'total_up': device_total_up,
                        'total_down': device_total_down,
                        'total_traffic': device_total_up + device_total_down,
                        'device_info': device_info
                    })
        
        # 按设备固定排序
        def device_sort_key(device_group):
            device_name = device_group['device_name']
            device_key = device_group['device_key']
            
            if device_name != device_key and not device_name.replace('.', '').isdigit():
                return (0, device_name.lower())
            else:
                try:
                    ip_parts = [int(x) for x in device_key.split('.')]
                    return (1, ip_parts)
                except:
                    return (2, device_key)
        
        device_groups.sort(key=device_sort_key)
        
        # 展开所有行用于分页（跳过网络概况行）
        all_rows = []
        for device_group in device_groups:
            device_name = device_group['device_name']
            
            if device_name == device_group['device_key']:
                display_device_name = device_name
            elif device_name and not device_name.replace('.', '').isdigit():
                display_device_name = device_name
            else:
                display_device_name = device_group['device_key']
            
            all_rows.append({
                'type': 'device_header',
                'device_name': display_device_name,
                'total_up': device_group['total_up'],
                'total_down': device_group['total_down'],
                'site_count': len(device_group['sites'])
            })
            
            for site in device_group['sites']:
                all_rows.append({
                    'type': 'site',
                    'website_name': site['website_name'],
                    'stats': site['stats']
                })
                
                if '未知站点' in site['stats'].get('category', '') and 'top_ips' in site['stats']:
                    top_ips = site['stats']['top_ips'][:3]
                    for i, ip in enumerate(top_ips):
                        all_rows.append({
                            'type': 'unknown_ip',
                            'ip': ip,
                            'is_last': i == len(top_ips) - 1
                        })
            
            if device_group != device_groups[-1]:
                all_rows.append({'type': 'separator'})
        
        # 渲染所有设备行
        for row in all_rows:
            if row['type'] == 'device_header':
                device_name = row['device_name']
                if len(device_name) > 20:
                    device_name = device_name[:17] + "..."
                
                table.add_row(
                    f"📱 [bold magenta]{device_name}[/bold magenta] ({row['site_count']}站点)",
                    "",
                    f"[bold red]{self._format_bytes(row['total_up'])}[/bold red]",
                    f"[bold green]{self._format_bytes(row['total_down'])}[/bold green]",
                    str(row['site_count'])
                )
            
            elif row['type'] == 'site':
                stats = row['stats']
                website_name = row['website_name']
                
                if '未知站点' in stats.get('category', ''):
                    display_name = f"  └─ {website_name}"
                    if len(display_name) > 30:
                        display_name = display_name[:27] + "..."
                elif 'ips' in stats and len(stats['ips']) > 1:
                    ip_count = len(stats['ips'])
                    display_name = f"  └─ {website_name} ({ip_count}IP)"
                else:
                    display_name = f"  └─ {website_name}"
                
                if len(display_name) > 30:
                    if '(' in website_name and '未知网站' in website_name:
                        base_name = website_name.split('(')[0]
                        display_name = f"  └─ {base_name[:22]}..."
                    else:
                        display_name = f"  └─ {website_name[:22]}..."
                
                location_display = stats['location'][:7] if stats['location'] else '未知'
                connections = stats.get('connections', 0)
                
                table.add_row(
                    display_name,
                    location_display,
                    self._format_bytes(stats['bytes_up']),
                    self._format_bytes(stats['bytes_down']),
                    f"{connections:>3d}" if connections > 0 else "-"
                )
            
            elif row['type'] == 'unknown_ip':
                ip_display = f"    ├─ {row['ip']}" if not row['is_last'] else f"    └─ {row['ip']}"
                
                table.add_row(
                    ip_display,
                    "",
                    "",
                    "",
                    ""
                )
            
            elif row['type'] == 'separator':
                table.add_row("", "", "", "", "")
        
        # 底部信息
        total_rows = len(all_rows) if 'all_rows' in locals() else 0
        if total_rows == 0:
            table.add_row("暂无设备数据", "", "", "", "")
    
    def _create_domain_table(self) -> Table:
        """创建按设备分组的网站访问表 - 固定设备排序"""
        
        table = Table(title="🌐 网站访问统计 (按设备分组)", show_header=True)
        table.add_column("设备/网站", style="cyan", width=35)
        table.add_column("地区", style="yellow", width=8)
        table.add_column("上行", style="red", width=10)
        table.add_column("下行", style="green", width=10)
        table.add_column("连接", style="dim", width=6)
        
        with self.data_lock:
            # 只处理真正的设备（在device_stats中的）
            device_groups = []
            for device_key, device_info in self.device_stats.items():
                if device_key in self.domain_stats and self.domain_stats[device_key]:
                    device_sites = self.domain_stats[device_key]
                    device_name = device_info.get('hostname', device_key)
                    
                    # 收集该设备的所有网站并聚合未知站点
                    sites = []
                    unknown_domestic_sites = []  # 国内未知站点
                    unknown_foreign_sites = []   # 海外未知站点
                    device_total_up = 0
                    device_total_down = 0
                    
                    for website_name, stats in device_sites.items():
                        total_traffic = stats['bytes_up'] + stats['bytes_down']
                        if total_traffic > 100:  # 只显示有意义的流量
                            device_total_up += stats['bytes_up']
                            device_total_down += stats['bytes_down']
                            
                            # 判断是否为未知站点
                            if '(未知网站)' in website_name:
                                location = stats.get('location', '未知')
                                if location == '中国':
                                    unknown_domestic_sites.append({
                                        'ip': website_name.split('(')[0],
                                        'stats': stats,
                                        'total_traffic': total_traffic
                                    })
                                else:
                                    unknown_foreign_sites.append({
                                        'ip': website_name.split('(')[0],
                                        'stats': stats,
                                        'total_traffic': total_traffic
                                    })
                            else:
                                # 已知站点直接加入
                                sites.append({
                                    'website_name': website_name,
                                    'stats': stats,
                                    'total_traffic': total_traffic
                                })
                    
                    # 处理未知站点聚合
                    if unknown_domestic_sites:
                        # 聚合国内未知站点
                        unknown_domestic_sites.sort(key=lambda x: x['total_traffic'], reverse=True)
                        total_up = sum(s['stats']['bytes_up'] for s in unknown_domestic_sites)
                        total_down = sum(s['stats']['bytes_down'] for s in unknown_domestic_sites)
                        top_ips = [s['ip'] for s in unknown_domestic_sites[:3]]  # 显示前3个IP
                        
                        sites.append({
                            'website_name': f"国内未知站点 ({len(unknown_domestic_sites)}IP)",
                            'stats': {
                                'bytes_up': total_up,
                                'bytes_down': total_down,
                                'connections': sum(s['stats']['connections'] for s in unknown_domestic_sites),
                                'ips': set(s['ip'] for s in unknown_domestic_sites),
                                'location': '中国',
                                'category': '未知站点',
                                'top_ips': top_ips
                            },
                            'total_traffic': total_up + total_down
                        })
                    
                    if unknown_foreign_sites:
                        # 聚合海外未知站点
                        unknown_foreign_sites.sort(key=lambda x: x['total_traffic'], reverse=True)
                        total_up = sum(s['stats']['bytes_up'] for s in unknown_foreign_sites)
                        total_down = sum(s['stats']['bytes_down'] for s in unknown_foreign_sites)
                        top_ips = [s['ip'] for s in unknown_foreign_sites[:3]]  # 显示前3个IP
                        
                        sites.append({
                            'website_name': f"海外未知站点 ({len(unknown_foreign_sites)}IP)",
                            'stats': {
                                'bytes_up': total_up,
                                'bytes_down': total_down,
                                'connections': sum(s['stats']['connections'] for s in unknown_foreign_sites),
                                'ips': set(s['ip'] for s in unknown_foreign_sites),
                                'location': '海外',
                                'category': '未知站点',
                                'top_ips': top_ips
                            },
                            'total_traffic': total_up + total_down
                        })
                    
                    # 按流量排序该设备的网站，限制显示前10个
                    sites.sort(key=lambda x: x['total_traffic'], reverse=True)
                    sites = sites[:10]  # 每个设备只显示前10个站点
                    
                    if sites:  # 只添加有数据的设备
                        device_groups.append({
                            'device_key': device_key,
                            'device_name': device_name,
                            'sites': sites,
                            'total_up': device_total_up,
                            'total_down': device_total_down,
                            'total_traffic': device_total_up + device_total_down,
                            'device_info': device_info
                        })
            
            # 按设备固定排序：先按设备类型（有主机名的优先），再按IP地址
            def device_sort_key(device_group):
                device_name = device_group['device_name']
                device_key = device_group['device_key']
                
                # 优先级：有意义主机名的设备 > IP地址设备
                if device_name != device_key and not device_name.replace('.', '').isdigit():
                    return (0, device_name.lower())  # 有主机名，按主机名排序
                else:
                    # 按IP地址排序
                    try:
                        ip_parts = [int(x) for x in device_key.split('.')]
                        return (1, ip_parts)  # IP设备，按IP数值排序
                    except:
                        return (2, device_key)  # 其他情况
            
            device_groups.sort(key=device_sort_key)
            
            # 展开所有行用于分页
            all_rows = []
            for device_group in device_groups:
                device_name = device_group['device_name']
                
                # 优化设备名称显示
                if device_name == device_group['device_key']:
                    # 如果主机名就是IP，只显示IP
                    display_device_name = device_name
                elif device_name and not device_name.replace('.', '').isdigit():
                    # 如果有有效主机名，显示主机名
                    display_device_name = device_name
                else:
                    # 其他情况显示IP
                    display_device_name = device_group['device_key']
                
                # 设备标题行
                all_rows.append({
                    'type': 'device_header',
                    'device_name': display_device_name,
                    'total_up': device_group['total_up'],
                    'total_down': device_group['total_down'],
                    'site_count': len(device_group['sites'])
                })
                
                # 该设备的网站行
                for site in device_group['sites']:
                    all_rows.append({
                        'type': 'site',
                        'website_name': site['website_name'],
                        'stats': site['stats']
                    })
                    
                    # 如果是未知站点聚合，添加具体IP行
                    if '未知站点' in site['stats'].get('category', '') and 'top_ips' in site['stats']:
                        top_ips = site['stats']['top_ips'][:3]
                        for i, ip in enumerate(top_ips):
                            all_rows.append({
                                'type': 'unknown_ip',
                                'ip': ip,
                                'is_last': i == len(top_ips) - 1
                            })
                
                # 在每个设备组后添加空行分隔（除了最后一个设备）
                if device_group != device_groups[-1]:
                    all_rows.append({
                        'type': 'separator'
                    })
            
            # 渲染所有表格行
            for row in all_rows:
                if row['type'] == 'device_header':
                    # 设备标题行 - 加粗显示
                    device_name = row['device_name']
                    if len(device_name) > 20:
                        device_name = device_name[:17] + "..."
                    
                    table.add_row(
                        f"📱 [bold magenta]{device_name}[/bold magenta] ({row['site_count']}站点)",
                        "",
                        f"[bold red]{self._format_bytes(row['total_up'])}[/bold red]",
                        f"[bold green]{self._format_bytes(row['total_down'])}[/bold green]",
                        str(row['site_count'])
                    )
                
                elif row['type'] == 'site':
                    # 网站行 - 缩进显示
                    stats = row['stats']
                    website_name = row['website_name']
                    
                    # 网站名称显示优化
                    if '未知站点' in stats.get('category', ''):
                        # 特殊处理未知站点聚合 - 简化显示，具体IP在下面单独行显示
                        display_name = f"  └─ {website_name}"
                        if len(display_name) > 26:
                            display_name = display_name[:23] + "..."
                    elif 'ips' in stats and len(stats['ips']) > 1:
                        ip_count = len(stats['ips'])
                        display_name = f"  └─ {website_name} ({ip_count}IP)"
                    else:
                        display_name = f"  └─ {website_name}"
                    
                    if len(display_name) > 26:
                        if '(' in website_name and '未知网站' in website_name:
                            base_name = website_name.split('(')[0]
                            display_name = f"  └─ {base_name[:18]}..."
                        else:
                            display_name = f"  └─ {website_name[:18]}..."
                    
                    location_display = stats['location'][:7] if stats['location'] else '未知'
                    connections = stats.get('connections', 0)
                    
                    table.add_row(
                        display_name,
                        location_display,
                        self._format_bytes(stats['bytes_up']),
                        self._format_bytes(stats['bytes_down']),
                        f"{connections:>3d}" if connections > 0 else "-"
                    )
                
                elif row['type'] == 'unknown_ip':
                    # 未知站点的具体IP行
                    ip_display = f"    ├─ {row['ip']}" if not row['is_last'] else f"    └─ {row['ip']}"
                    
                    table.add_row(
                        ip_display,
                        "",
                        "",
                        "",
                        ""
                    )
                
                elif row['type'] == 'separator':
                    # 设备间分隔空行
                    table.add_row(
                        "",
                        "",
                        "",
                        "",
                        ""
                    )
            
            # 底部信息
            total_rows = len(all_rows) if 'all_rows' in locals() else 0
            if total_rows == 0:
                table.add_row("暂无数据", "", "", "", "")
        
        return table
    
    
    def _create_summary_panel(self) -> Panel:
        """创建摘要面板 - 增强版"""
        with self.data_lock:
            active_devices = len([d for d in self.device_stats.values() 
                                if (datetime.now() - d['last_seen']).seconds < 60])
            total_traffic_up = sum(d['bytes_out'] for d in self.device_stats.values())
            total_traffic_down = sum(d['bytes_in'] for d in self.device_stats.values())
            total_traffic = total_traffic_up + total_traffic_down
            active_domains = sum(len([site for site, stats in device_sites.items() 
                                     if stats['bytes_up'] + stats['bytes_down'] > 0]) 
                                for device_sites in self.domain_stats.values())
            
            current_connections = 0  # 当前连接数在新版本中不再显示
            
            # 计算平均速度 - 分上下行
            if self.speed_data_up and self.speed_data_down:
                avg_speed_up = sum(self.speed_data_up) / len(self.speed_data_up)
                avg_speed_down = sum(self.speed_data_down) / len(self.speed_data_down)
                current_speed_up = list(self.speed_data_up)[-1] if self.speed_data_up else 0
                current_speed_down = list(self.speed_data_down)[-1] if self.speed_data_down else 0
            else:
                avg_speed_up = avg_speed_down = 0
                current_speed_up = current_speed_down = 0
        
        # 计算运行时间
        uptime = datetime.now() - self.start_time
        uptime_str = f"{int(uptime.total_seconds() // 3600):02d}:{int((uptime.total_seconds() % 3600) // 60):02d}:{int(uptime.total_seconds() % 60):02d}"
        
        cache_stats = domain_resolver.get_cache_stats()
        geosite_stats = geosite_loader.get_stats()
        
        summary = f"""
🏠 本地网络: {self.local_network}
📱 活跃设备: {active_devices} 台
📤 上行流量: {self._format_bytes(total_traffic_up)}
📥 下行流量: {self._format_bytes(total_traffic_down)}
🔺 实时上行: {self._format_speed(current_speed_up)}
🔻 实时下行: {self._format_speed(current_speed_down)}
📈 平均上行: {self._format_speed(avg_speed_up)}
📉 平均下行: {self._format_speed(avg_speed_down)}
🌐 访问域名: {active_domains}
💾 DNS缓存: {cache_stats['total_cached']}条
🗂️  GeoSite: {geosite_stats['total_domains']}域名
⏰ 启动时间: {self.start_time.strftime('%H:%M:%S')}
⏱️  运行时长: {uptime_str}
"""
        
        return Panel(summary, title="📋 网络概况", style="blue")
    
    def create_layout(self) -> Layout:
        """创建主界面布局 - 统一的网站访问统计"""
        layout = Layout()
        
        # 单列布局：只显示整合后的网站访问统计
        layout.update(self._create_integrated_table())
        
        return layout
    
    def start(self):
        """启动监控"""
        self.running = True
        
        monitor_thread = threading.Thread(target=self._monitor_traffic, daemon=True)
        monitor_thread.start()
        
        try:
            with Live(self.create_layout(), refresh_per_second=1, screen=True) as live:
                while True:
                    time.sleep(1)
                    live.update(self.create_layout())
        except KeyboardInterrupt:
            self.running = False
            self.console.print("\n[yellow]监控已停止[/yellow]")

def main():
    console = Console()
    
    console.print(Panel.fit(
        "🚀 [bold blue]网络流量监控工具[/bold blue]\n"
        "智能网络流量实时监控和分析\n"
        "按 [bold red]Ctrl+C[/bold red] 退出",
        style="green"
    ))
    
    console.print("[yellow]注意: 需要管理员权限才能获取完整的网络统计信息[/yellow]\n")
    
    monitor = NetworkMonitor()
    monitor.start()

if __name__ == "__main__":
    main()