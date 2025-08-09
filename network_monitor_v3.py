#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络流量监控工具 V3
修复流量统计不一致和设备重复问题
"""

import subprocess
import time
import json
import re
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import threading
import socket
import struct

# 导入增强的域名解析器和GeoSite数据
from domain_resolver import domain_resolver
from geosite_loader import geosite_loader

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

class NetworkMonitorV3:
    def __init__(self):
        self.console = Console()
        self.data_lock = threading.Lock()
        self.running = False
        self.start_time = datetime.now()  # 记录启动时间
        
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
        self.local_network = self._detect_local_network()
        
        # 翻页控制 - 动态调整条目数量
        self.domain_page = 0
        self.domains_per_page = self._calculate_domains_per_page()
        self.last_key_time = 0
        
    def _calculate_domains_per_page(self) -> int:
        """根据终端大小动态计算每页显示条目数"""
        try:
            import os
            # 获取终端尺寸
            rows, cols = os.get_terminal_size()
            # 预留空间：标题(3行) + 表头(3行) + 底部信息(3行) + 边距(6行) = 15行
            available_rows = max(10, rows - 15)
            # 每个数据行占用1行，最少10条，最多50条
            return min(50, max(10, available_rows))
        except:
            # 默认值
            return 25
    
    def _detect_local_network(self) -> str:
        """检测本地网络段"""
        try:
            result = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True)
            gateway_match = re.search(r'gateway: ([\d.]+)', result.stdout)
            if gateway_match:
                gateway = gateway_match.group(1)
                return '.'.join(gateway.split('.')[:-1]) + '.0/24'
            return '192.168.31.0/24'
        except:
            return '192.168.31.0/24'
    
    def _get_arp_table(self) -> Dict[str, str]:
        """获取ARP表，返回 {ip: mac}"""
        devices = {}
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                match = re.search(r'\(([\d.]+)\)\s+at\s+([a-f0-9:]+)', line.lower())
                if match:
                    ip, mac = match.groups()
                    devices[ip] = mac
        except Exception as e:
            print(f"ARP table error: {e}")
        return devices
    
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
        connections = []
        try:
            result = subprocess.run(['netstat', '-n'], capture_output=True, text=True)
            seen_connections = set()  # 避免重复连接
            
            for line in result.stdout.split('\n'):
                if 'tcp4' in line:
                    parts = line.split()
                    if len(parts) >= 6 and parts[5] == 'ESTABLISHED':
                        local_addr = parts[3]
                        foreign_addr = parts[4]
                        
                        # 处理不同格式的地址（IP:端口 或 IP.端口）
                        def extract_ip(addr):
                            if ':' in addr:
                                return addr.split(':')[0]
                            elif '.' in addr:
                                # 对于形如 192.168.31.31.65302 的格式，取前4段作为IP
                                parts = addr.split('.')
                                if len(parts) >= 4:
                                    return '.'.join(parts[:4])
                            return addr
                        
                        local_ip = extract_ip(local_addr)
                        foreign_ip = extract_ip(foreign_addr)
                        
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
                                    'protocol': 'tcp'
                                })
        except:
            pass
        return connections
    
    def _resolve_domain(self, ip: str) -> str:
        """增强的IP到域名解析"""
        return domain_resolver.resolve_domain(ip)
    
    def _handle_keypress(self):
        """处理键盘输入翻页"""
        import select
        import sys
        
        # 非阻塞式读取键盘输入
        if select.select([sys.stdin], [], [], 0)[0]:
            try:
                key = sys.stdin.read(1)
                current_time = time.time()
                
                # 防止重复按键
                if current_time - self.last_key_time > 0.3:
                    if key == 'n' or key == ' ':  # 下一页
                        self.domain_page += 1
                        self.last_key_time = current_time
                    elif key == 'p' or key == 'b':  # 上一页
                        self.domain_page = max(0, self.domain_page - 1)
                        self.last_key_time = current_time
                    elif key == 'r':  # 重置到第一页
                        self.domain_page = 0
                        self.last_key_time = current_time
                    elif key == 'c':  # 清理旧域名数据
                        with self.data_lock:
                            old_keys = [k for k in self.domain_stats.keys() 
                                       if k.count('.') >= 3 and ('(未知网站)' in k or k.replace('.', '').isdigit())]
                            for old_key in old_keys:
                                del self.domain_stats[old_key]
                        domain_resolver.clear_cache()
                        self.last_key_time = current_time
                    elif key == 'x':  # 重置所有流量统计
                        with self.data_lock:
                            # 重置域名统计（保留IP和分类信息，只清空流量）
                            for device_key in self.domain_stats:
                                for website_name in self.domain_stats[device_key]:
                                    self.domain_stats[device_key][website_name]['bytes_up'] = 0
                                    self.domain_stats[device_key][website_name]['bytes_down'] = 0
                            # 重置设备统计
                            for device_key in self.device_stats:
                                self.device_stats[device_key]['bytes_in'] = 0
                                self.device_stats[device_key]['bytes_out'] = 0
                        self.last_key_time = current_time
            except:
                pass
    
    def _categorize_domain(self, domain: str, ip: str) -> Tuple[str, str]:
        """分类域名，返回(类别, 地区) - 完全使用GeoSite数据"""
        domain_lower = domain.lower().replace('(未知网站)', '')
        
        # 1. 优先通过IP识别服务（如Telegram）- 更准确
        try:
            ip_service = geosite_loader.get_ip_service(ip)
            if ip_service:
                service_map = {
                    'telegram': 'Telegram'
                }
                display_name = service_map.get(ip_service, ip_service.capitalize())
                return display_name, '海外'
        except Exception:
            pass
        
        # 2. 特殊域名映射（补充GeoSite数据中缺失的）
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
        
        # 3. 使用GeoSite数据库进行域名分类
        try:
            category = geosite_loader.get_domain_category(domain_lower)
            if category:
                # 获取地区信息
                country = geosite_loader.get_ip_country(ip)
                location = '中国' if country == 'cn' else '海外'
                
                # 标准化分类名称
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
                    'bilibili': 'B站'
                }
                
                display_name = category_map.get(category, category.capitalize())
                return display_name, location
        except Exception:
            pass
        
        # 3. 智能IP识别（基于多数据源和机器学习）
        try:
            from smart_ip_identifier import smart_ip_identifier
            provider, region, confidence = smart_ip_identifier.identify_ip(ip)
            
            # 只有在置信度较高时才使用识别结果
            if confidence > 0.5:
                return provider, region
                
        except Exception:
            pass
        
        # 4. 兜底：根据IP判断地区
        try:
            country = geosite_loader.get_ip_country(ip)
            if country == 'cn':
                return '中国网站', '中国'
            else:
                return '海外网站', '海外'
        except Exception:
            # 最终兜底：使用简化的IP检测
            is_china = self._is_china_ip(ip)
            return ('中国网站' if is_china else '海外网站'), ('中国' if is_china else '海外')
    
    # 旧的硬编码分类方法已移除，现在完全使用GeoSite数据
    
    def _is_china_ip(self, ip: str) -> bool:
        """检查是否为中国IP"""
        try:
            first_octet = int(ip.split('.')[0])
            china_ranges = [1, 14, 27, 36, 39, 42, 49, 58, 59, 60, 61, 
                           101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 
                           175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223]
            return first_octet in china_ranges
        except (ValueError, IndexError):
            return False
    
    def _get_interface_stats(self) -> Dict:
        """获取网络接口统计"""
        stats = {}
        try:
            result = subprocess.run(['netstat', '-ib'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if line.strip() and not line.startswith('Name'):
                    parts = line.split()
                    if len(parts) >= 10:
                        interface = parts[0]
                        if (interface.startswith(('en', 'utun')) and 
                            not interface.startswith('lo') and
                            '*' not in interface):
                            try:
                                if parts[6].isdigit() and parts[9].isdigit():
                                    bytes_in = int(parts[6])
                                    bytes_out = int(parts[9])
                                    
                                    if bytes_in > 0 or bytes_out > 0:
                                        stats[interface] = {
                                            'bytes_in': bytes_in,
                                            'bytes_out': bytes_out
                                        }
                            except (ValueError, IndexError):
                                continue
        except:
            pass
        return stats
    
    def _monitor_traffic(self):
        """后台监控线程"""
        last_interface_stats = {}
        last_cache_clean = time.time()
        
        while self.running:
            try:
                # 获取当前数据
                arp_devices = self._get_arp_table()
                connections = self._get_active_connections()
                interface_stats = self._get_interface_stats()
                
                with self.data_lock:
                    # 更新设备信息（去重）
                    current_devices = set()
                    
                    # 处理ARP表中的设备
                    for ip, mac in arp_devices.items():
                        device_key = ip  # 使用IP作为设备键
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
                    
                    # 不需要单独处理VPN设备，在连接处理中已经处理了
                    
                    # 计算接口流量变化 - 分别统计上行和下行
                    total_period_traffic_in = 0
                    total_period_traffic_out = 0
                    for interface, stats in interface_stats.items():
                        if interface in last_interface_stats:
                            bytes_in_diff = max(0, stats['bytes_in'] - last_interface_stats[interface]['bytes_in'])
                            bytes_out_diff = max(0, stats['bytes_out'] - last_interface_stats[interface]['bytes_out'])
                            total_period_traffic_in += bytes_in_diff
                            total_period_traffic_out += bytes_out_diff
                    
                    total_period_traffic = total_period_traffic_in + total_period_traffic_out
                    
                    # 初始化主要设备（确保VPN设备被创建）
                    vpn_connections = [conn for conn in connections if conn['local_ip'].startswith('28.0.0.')]
                    local_connections = [conn for conn in connections if conn['local_ip'].startswith('192.168.31.')]
                    
                    # 创建Clash设备（TUN模式）
                    if vpn_connections:
                        clash_key = "Clash设备"
                        current_devices.add(clash_key)
                        if clash_key not in self.device_stats:
                            self.device_stats[clash_key] = {
                                'ip': '28.0.0.x',
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
                            main_ip = '192.168.31.31'
                            hostname = 'mmini'
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
                    
                    # 统计连接并分配流量
                    device_connections = defaultdict(int)
                    domain_connections = defaultdict(set)
                    
                    for conn in connections:
                        local_ip = conn['local_ip']
                        foreign_ip = conn['foreign_ip']
                        
                        # 确定设备
                        if local_ip.startswith('28.0.0.'):
                            device_key = "Clash设备"
                        elif local_ip.startswith('192.168.31.'):
                            device_key = "直连设备"
                        else:
                            device_key = local_ip
                            # 为其他设备创建记录
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
                        
                        device_connections[device_key] += 1
                        
                        # 处理域名和网站分类 - 增强逻辑
                        raw_domain = self._resolve_domain(foreign_ip)
                        category, location = self._categorize_domain(raw_domain, foreign_ip)
                        
                        # 优先使用网站分类作为显示名称，实现服务合并
                        if category and category not in ['中国网站', '海外网站']:
                            # 对于已识别的服务，使用服务名作为聚合键（不包含IP）
                            website_name = category  # 直接使用服务名，如 "Telegram", "Amazon"
                        else:
                            # 如果没有具体分类，优先使用域名
                            if raw_domain != foreign_ip and not raw_domain.endswith('(未知网站)'):
                                # 使用解析出的真实域名，保持原格式
                                website_name = raw_domain
                            else:
                                # 对于未知网站，保持原来的格式
                                website_name = f"{foreign_ip}(未知网站)"
                        
                        # 按设备和网站名称聚合
                        domain_connections[website_name].add(device_key)
                        
                        # 更新网站信息 - 按设备分组
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
                            # 更新现有条目的分类信息和IP列表
                            self.domain_stats[device_key][website_name]['category'] = category
                            self.domain_stats[device_key][website_name]['location'] = location
                            self.domain_stats[device_key][website_name]['ips'].add(foreign_ip)
                    
                    # 分配流量（累计方式，不使用平滑）
                    if total_period_traffic > 0 and device_connections:
                        total_connections = sum(device_connections.values())
                        
                        for device_key, conn_count in device_connections.items():
                            if device_key in current_devices:
                                # 计算应分配的流量（仅分配增量）
                                traffic_share = (conn_count / total_connections) * total_period_traffic
                                increment_in = traffic_share * 0.6
                                increment_out = traffic_share * 0.4
                                
                                # 累计流量（不覆盖，只增加）
                                self.device_stats[device_key]['bytes_in'] += increment_in
                                self.device_stats[device_key]['bytes_out'] += increment_out
                        
                        # 网站流量累计 - 按设备分组的改进分配算法
                        if total_period_traffic > 0:
                            
                            # 为每个设备的每个网站单独计算流量
                            for website_name, connected_devices in domain_connections.items():
                                connection_count = len(connected_devices)
                                
                                for device_key in connected_devices:
                                    if device_key in self.domain_stats:
                                        site_stats = self.domain_stats[device_key][website_name]
                                        ip_count = len(site_stats['ips'])
                                        
                                        # 基于实际连接活跃度的动态权重计算
                                        connection_activity = connection_count  # 该网站的连接数
                                        ip_diversity = len(site_stats['ips'])  # IP多样性
                                        
                                        # 权重完全基于观测到的网络活跃度
                                        # 连接数越多 = 使用越活跃 = 流量越大
                                        total_domain_connections = sum(len(devices) for devices in domain_connections.values())
                                        if total_domain_connections > 0:
                                            activity_weight = connection_activity / total_domain_connections
                                        else:
                                            activity_weight = 1.0 / len(connected_devices)  # 平均分配
                                        
                                        # IP多样性加权：多IP的服务通常是CDN，流量更大
                                        diversity_bonus = min(1.0 + (ip_diversity - 1) * 0.1, 2.0)  # 最多2倍加权
                                        
                                        # 最终权重：活跃度 × IP多样性 × 设备分配权重
                                        base_weight = (1.0 / len(connected_devices)) * activity_weight * diversity_bonus
                                        
                                        # 基于网卡实际上下行流量比例分配
                                        if total_period_traffic > 0:
                                            # 使用真实的网卡上下行比例
                                            actual_down_ratio = total_period_traffic_in / total_period_traffic
                                            actual_up_ratio = total_period_traffic_out / total_period_traffic
                                            
                                            # 按真实比例分配该网站的流量
                                            allocated_traffic_down = (total_period_traffic_in * 0.1 * base_weight)
                                            allocated_traffic_up = (total_period_traffic_out * 0.1 * base_weight)
                                        else:
                                            allocated_traffic_down = 0
                                            allocated_traffic_up = 0
                                        
                                        # 累计网站流量 - 使用网卡真实数据
                                        self.domain_stats[device_key][website_name]['bytes_down'] += allocated_traffic_down
                                        self.domain_stats[device_key][website_name]['bytes_up'] += allocated_traffic_up
                                        self.domain_stats[device_key][website_name]['connections'] = connection_count
                    
                    # 计算实时速度 - 分上下行
                    current_time = time.time()
                    time_delta = current_time - self.last_speed_time
                    
                    if time_delta > 0:
                        # 计算上行和下行速度
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
                        
                    
                
                last_interface_stats = interface_stats.copy()
                
                # 定期清理DNS缓存和旧域名数据（每5分钟）
                current_time = time.time()
                if current_time - last_cache_clean > 300:  # 5分钟
                    domain_resolver.clear_cache()
                    
                    # 清理旧的IP格式域名数据（保留有效的网站名称数据）
                    with self.data_lock:
                        old_keys = [k for k in self.domain_stats.keys() 
                                   if k.count('.') >= 3 and '(未知网站)' in k]  # IP格式的键
                        for old_key in old_keys:
                            del self.domain_stats[old_key]
                    
                    last_cache_clean = current_time
                
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
        # 处理键盘输入
        self._handle_keypress()
        
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
        
        # 计算当前页数信息  
        start_idx = self.domain_page * self.domains_per_page
        end_idx = start_idx + self.domains_per_page
        
        table = Table(title=f"{title_info} (第{self.domain_page + 1}页)", show_header=True, expand=True)
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
            self._add_device_groups_to_table(table, start_idx, end_idx)
        
        return table
    
    def _add_device_groups_to_table(self, table: Table, start_idx: int, end_idx: int):
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
        
        # 分页显示（考虑已添加的概况行）
        total_rows = len(all_rows)
        # 调整分页起始位置，因为前面已经添加了3行概况信息
        adjusted_start = max(0, start_idx - 3)
        adjusted_end = max(0, end_idx - 3)
        
        paged_rows = all_rows[adjusted_start:adjusted_end]
        
        # 渲染设备行
        for row in paged_rows:
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
        
        # 底部翻页信息
        if total_rows == 0:
            table.add_row("暂无设备数据", "", "", "", "")
        elif total_rows > self.domains_per_page:
            table.add_row(
                f"共{len(device_groups)}设备, {total_rows + 3}条记录 (第{self.domain_page + 1}页)",
                "键盘: N/P", 
                "R:重置",
                "C:清理 X:重置流量", 
                ""
            )
    
    def _create_domain_table(self) -> Table:
        """创建按设备分组的网站访问表 - 固定设备排序"""
        # 处理键盘输入
        self._handle_keypress()
        
        # 计算当前页数信息  
        start_idx = self.domain_page * self.domains_per_page
        end_idx = start_idx + self.domains_per_page
        
        table = Table(title=f"🌐 网站访问统计 (按设备分组 - 第{self.domain_page + 1}页) [N:下一页 P:上一页 R:重置 C:清理 X:重置流量]", show_header=True)
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
            
            # 分页显示
            total_rows = len(all_rows)
            max_page = (total_rows - 1) // self.domains_per_page if total_rows > 0 else 0
            self.domain_page = min(self.domain_page, max_page)
            
            paged_rows = all_rows[start_idx:end_idx]
            
            # 渲染表格
            for row in paged_rows:
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
            
            # 底部翻页信息
            if total_rows == 0:
                table.add_row("暂无数据", "", "", "", "")
            elif total_rows > self.domains_per_page:
                table.add_row(
                    f"共{len(device_groups)}设备, {total_rows}条记录 (第{self.domain_page + 1}/{max_page + 1}页)",
                    "键盘: N/P", 
                    f"{end_idx}/{total_rows}",
                    "R:重置 C:清理", ""
                )
        
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
        "🚀 [bold blue]网络流量监控工具 V3[/bold blue]\n"
        "修复流量统计和设备重复问题\n"
        "按 [bold red]Ctrl+C[/bold red] 退出",
        style="green"
    ))
    
    console.print("[yellow]注意: 需要管理员权限才能获取完整的网络统计信息[/yellow]\n")
    
    monitor = NetworkMonitorV3()
    monitor.start()

if __name__ == "__main__":
    main()