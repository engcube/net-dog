#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
流量分析器
专门负责网络流量分析和数据处理逻辑
从NetworkMonitor中分离出来，实现单一职责原则
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass

from domain_resolver import domain_resolver
from geosite_loader import geosite_loader
from unified_service_identifier import unified_service_identifier
from utils import get_country_name
from performance_monitor import monitor_performance

@dataclass
class ConnectionInfo:
    """连接信息数据类"""
    local_ip: str
    local_port: str
    foreign_ip: str
    foreign_port: str
    protocol: str
    timestamp: float

@dataclass
class DeviceStats:
    """设备统计信息"""
    ip: str
    mac: str
    hostname: str
    bytes_in: int
    bytes_out: int
    connections: int
    recent_connections: List[str]
    websites: Set[str]

@dataclass
class TrafficAllocation:
    """流量分配结果"""
    device_connections: Dict[str, List[ConnectionInfo]]
    domain_connections: Dict[str, Set[str]]
    total_connections: int

class TrafficAnalyzer:
    """
    流量分析器 - 核心数据处理逻辑
    
    职责：
    1. 分析网络连接数据
    2. 执行流量分配算法
    3. 维护设备和连接统计
    4. 提供数据查询接口
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.lock = threading.Lock()
        
        # 核心数据结构
        self.device_stats = {}  # 设备统计信息
        self.recent_connections = deque(maxlen=config.get('monitoring', {}).get('max_recent_connections', 1000))
        self.connection_history = defaultdict(list)  # 连接历史记录
        
        # 流量分析相关
        self.interface_stats_history = deque(maxlen=10)  # 接口统计历史
        self.last_interface_stats = {}
        
        # 性能监控
        self.performance_monitor = None  # 将在需要时注入
        
    def set_performance_monitor(self, monitor):
        """注入性能监控器"""
        self.performance_monitor = monitor
    
    @monitor_performance("analyze_connections")
    def analyze_connections(self, connections: List[Dict], arp_devices: Dict[str, str], 
                           interface_stats: Dict) -> TrafficAllocation:
        """
        分析网络连接数据
        
        核心流量分析算法：
        1. 解析连接信息并创建设备映射
        2. 执行智能流量分配算法
        3. 更新设备和域名统计
        4. 返回分配结果
        
        Args:
            connections: 网络连接列表
            arp_devices: ARP设备映射表
            interface_stats: 网络接口统计
            
        Returns:
            TrafficAllocation: 流量分配结果
        """
        with self.lock:
            # 步骤1：创建连接信息对象
            connection_infos = []
            for conn in connections:
                conn_info = ConnectionInfo(
                    local_ip=conn['local_ip'],
                    local_port=conn['local_port'],
                    foreign_ip=conn['foreign_ip'],
                    foreign_port=conn['foreign_port'],
                    protocol=conn['protocol'],
                    timestamp=time.time()
                )
                connection_infos.append(conn_info)
                self.recent_connections.append(conn_info)
            
            # 步骤2：更新接口统计历史
            self._update_interface_stats(interface_stats)
            
            # 步骤3：识别和创建设备
            current_devices = self._identify_devices(connection_infos, arp_devices)
            
            # 步骤4：执行流量分配算法
            traffic_allocation = self._allocate_traffic(connection_infos, current_devices)
            
            # 步骤5：更新设备统计
            self._update_device_stats(traffic_allocation, interface_stats)
            
            return traffic_allocation
    
    def _update_interface_stats(self, interface_stats: Dict) -> None:
        """
        更新网络接口统计历史
        
        维护接口统计的时间序列数据，用于计算流量增量
        """
        current_time = time.time()
        self.interface_stats_history.append({
            'timestamp': current_time,
            'stats': interface_stats.copy()
        })
        
        # 保存当前统计作为基准
        if self.last_interface_stats:
            # 计算增量统计
            for interface, stats in interface_stats.items():
                if interface in self.last_interface_stats:
                    last_stats = self.last_interface_stats[interface]
                    bytes_in_delta = stats.get('bytes_in', 0) - last_stats.get('bytes_in', 0)
                    bytes_out_delta = stats.get('bytes_out', 0) - last_stats.get('bytes_out', 0)
                    
                    # 存储增量信息（用于后续流量分配）
                    stats['bytes_in_delta'] = max(0, bytes_in_delta)
                    stats['bytes_out_delta'] = max(0, bytes_out_delta)
        
        self.last_interface_stats = interface_stats.copy()
    
    def _identify_devices(self, connections: List[ConnectionInfo], 
                         arp_devices: Dict[str, str]) -> Set[str]:
        """
        识别网络设备
        
        基于连接信息和ARP表识别网络中的设备
        支持虚拟设备（如VPN、代理）的智能识别
        """
        current_devices = set()
        
        # 从配置读取IP范围前缀
        proxy_prefixes = self._get_ip_prefixes('proxy_ip_ranges')
        local_prefixes = self._get_ip_prefixes('local_ip_ranges')
        
        # 处理连接并识别设备
        vpn_connections = []
        local_connections = []
        other_connections = []
        
        for conn in connections:
            if any(conn.local_ip.startswith(prefix) for prefix in proxy_prefixes):
                vpn_connections.append(conn)
            elif any(conn.local_ip.startswith(prefix) for prefix in local_prefixes):
                local_connections.append(conn)
            else:
                other_connections.append(conn)
                current_devices.add(conn.local_ip)
        
        # 创建虚拟设备
        if vpn_connections:
            current_devices.add("Clash设备")
            self._ensure_virtual_device("Clash设备", vpn_connections, proxy_prefixes[0] + 'x' if proxy_prefixes else '28.0.0.x')
        
        if local_connections:
            current_devices.add("直连设备")
            # 使用配置文件中的本地IP范围
            main_ip = self.config['network_settings']['local_ip_ranges'][0].split('/')[0] if local_prefixes else '192.168.1.1'
            self._ensure_virtual_device("直连设备", local_connections, f'{main_ip}(多端口)')
        
        # 处理其他设备
        for conn in other_connections:
            device_key = conn.local_ip
            if device_key not in self.device_stats:
                self._create_physical_device(device_key, arp_devices.get(conn.local_ip, 'unknown'))
        
        return current_devices
    
    def _get_ip_prefixes(self, config_key: str) -> List[str]:
        """从配置获取IP前缀列表"""
        ip_ranges = self.config.get('network_settings', {}).get(config_key, [])
        return [ip_range.split('/')[0].rsplit('.', 1)[0] + '.' for ip_range in ip_ranges]
    
    def _ensure_virtual_device(self, device_key: str, connections: List[ConnectionInfo], ip_display: str) -> None:
        """确保虚拟设备存在并更新其信息"""
        if device_key not in self.device_stats:
            device_type = "代理" if "Clash" in device_key else "直连"
            self.device_stats[device_key] = DeviceStats(
                ip=ip_display,
                mac='virtual',
                hostname=f'{device_type}({len(connections)}个连接)',
                bytes_in=0,
                bytes_out=0,
                connections=0,
                recent_connections=[],
                websites=set()
            )
        else:
            # 更新连接数显示
            device_type = "代理" if "Clash" in device_key else "直连"
            self.device_stats[device_key].hostname = f'{device_type}({len(connections)}个连接)'
    
    def _create_physical_device(self, device_key: str, mac: str) -> None:
        """创建物理设备统计条目"""
        self.device_stats[device_key] = DeviceStats(
            ip=device_key,
            mac=mac,
            hostname=f'设备 {device_key}',
            bytes_in=0,
            bytes_out=0,
            connections=0,
            recent_connections=[],
            websites=set()
        )
    
    @monitor_performance("allocate_traffic")
    def _allocate_traffic(self, connections: List[ConnectionInfo], 
                         current_devices: Set[str]) -> TrafficAllocation:
        """
        执行流量分配算法
        
        智能流量分配算法的核心实现：
        
        算法原理：
        1. 基于连接数比例分配流量（简化但有效的模型）
        2. 考虑连接类型权重（长连接vs短连接）
        3. 结合域名识别进行智能分类
        4. 支持虚拟设备的流量聚合
        
        局限性说明：
        - 无法获取每个连接的真实流量，使用连接数比例作为近似
        - 对于大文件下载等场景可能存在偏差
        - 这是性能和准确性的平衡选择
        
        未来改进方向：
        - 基于端口类型的权重调整
        - 考虑连接持续时间的权重
        - 集成更精确的流量监控API（如果可用）
        """
        device_connections = defaultdict(list)
        domain_connections = defaultdict(set)
        
        for conn in connections:
            # 步骤1：确定连接所属设备
            device_key = self._determine_device_key(conn, current_devices)
            device_connections[device_key].append(conn)
            
            # 步骤2：识别连接的目标网站/服务
            website_name = self._identify_connection_target(conn)
            if website_name:
                domain_connections[website_name].add(device_key)
                
                # 更新设备的网站访问记录
                if device_key in self.device_stats:
                    self.device_stats[device_key].websites.add(website_name)
        
        return TrafficAllocation(
            device_connections=dict(device_connections),
            domain_connections=dict(domain_connections),
            total_connections=len(connections)
        )
    
    def _determine_device_key(self, conn: ConnectionInfo, current_devices: Set[str]) -> str:
        """
        确定连接所属的设备
        
        设备识别逻辑：
        1. 检查是否属于代理设备（通过IP前缀）
        2. 检查是否属于直连设备（通过IP前缀）
        3. 其他情况作为独立物理设备处理
        """
        proxy_prefixes = self._get_ip_prefixes('proxy_ip_ranges')
        local_prefixes = self._get_ip_prefixes('local_ip_ranges')
        
        if any(conn.local_ip.startswith(prefix) for prefix in proxy_prefixes):
            return "Clash设备"
        elif any(conn.local_ip.startswith(prefix) for prefix in local_prefixes):
            return "直连设备"
        else:
            return conn.local_ip
    
    @monitor_performance("identify_connection_target")
    def _identify_connection_target(self, conn: ConnectionInfo) -> Optional[str]:
        """
        识别连接的目标网站/服务
        
        多层识别策略：
        1. 统一服务识别器（IP段和ASN匹配）
        2. 域名反解析（如果可用）
        3. GeoSite数据库查询
        4. 地理位置识别（兜底方案）
        
        返回用户友好的网站/服务名称
        """
        foreign_ip = conn.foreign_ip
        
        # 第1层：使用统一服务识别器
        service_name, display_name = unified_service_identifier.get_enhanced_service_name(foreign_ip)
        if display_name:
            return display_name
        
        # 第2层：尝试域名反解析
        domain = domain_resolver.get_domain_for_ip(foreign_ip)
        if domain:
            # 检查是否为已知网站
            website_category = geosite_loader.get_domain_category(domain)
            if website_category:
                return self._format_website_name(website_category)
            else:
                return self._format_domain_name(domain)
        
        # 第3层：基于IP的地理位置识别
        country_or_service = geosite_loader.get_ip_country(foreign_ip)
        if country_or_service:
            return self._format_country_name(country_or_service)
        
        # 第4层：兜底方案 - 显示IP地址
        return f"未知网站 ({foreign_ip})"
    
    def _format_website_name(self, category: str) -> str:
        """格式化网站分类名称"""
        # 移除技术性前缀，返回用户友好的名称
        if category.startswith('GEOLOCATION-'):
            return category[12:] + '网站'
        elif category.startswith('CATEGORY-'):
            return category[9:] + '网站'
        else:
            return category + '网站'
    
    def _format_domain_name(self, domain: str) -> str:
        """格式化域名显示"""
        # 简化域名显示，去掉www前缀
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # 对于过长的域名进行截断
        if len(domain) > 30:
            return domain[:27] + '...'
        
        return domain
    
    def _format_country_name(self, country_code: str) -> str:
        """格式化国家名称显示"""
        # 统一服务识别器返回的服务名
        if country_code in ['google', 'youtube', 'facebook', 'twitter', 'cloudflare']:
            return country_code.title()
        
        # 国家代码转换为中文名称
        country_name = get_country_name(country_code)
        if country_name and not country_name.startswith('未知'):
            return country_name + '网站'
        
        return f'海外网站({country_code.upper()})'
    
    def _update_device_stats(self, allocation: TrafficAllocation, interface_stats: Dict) -> None:
        """
        更新设备统计信息
        
        基于流量分配结果更新各设备的统计数据：
        1. 连接数统计
        2. 流量估算（基于连接数比例）
        3. 最近连接记录
        """
        total_connections = allocation.total_connections
        if total_connections == 0:
            return
        
        # 计算总流量增量
        total_bytes_in_delta = sum(stats.get('bytes_in_delta', 0) for stats in interface_stats.values())
        total_bytes_out_delta = sum(stats.get('bytes_out_delta', 0) for stats in interface_stats.values())
        
        # 为每个设备分配流量
        for device_key, connections in allocation.device_connections.items():
            if device_key not in self.device_stats:
                continue
            
            device = self.device_stats[device_key]
            connection_count = len(connections)
            
            # 基于连接数比例分配流量（核心算法）
            connection_ratio = connection_count / total_connections
            
            # 分配流量增量
            device.bytes_in += int(total_bytes_in_delta * connection_ratio)
            device.bytes_out += int(total_bytes_out_delta * connection_ratio)
            device.connections = connection_count
            
            # 更新最近连接（保留最新的5个）
            recent_targets = []
            for conn in connections[-5:]:  # 只保留最近的5个连接
                target = self._identify_connection_target(conn)
                if target and target not in recent_targets:
                    recent_targets.append(target)
            
            device.recent_connections = recent_targets
    
    def get_device_stats(self) -> Dict[str, DeviceStats]:
        """获取设备统计信息"""
        with self.lock:
            return self.device_stats.copy()
    
    def get_traffic_summary(self) -> Dict:
        """获取流量总结信息"""
        with self.lock:
            total_bytes_in = sum(device.bytes_in for device in self.device_stats.values())
            total_bytes_out = sum(device.bytes_out for device in self.device_stats.values())
            total_connections = sum(device.connections for device in self.device_stats.values())
            active_websites = set()
            
            for device in self.device_stats.values():
                active_websites.update(device.websites)
            
            return {
                'total_bytes_in': total_bytes_in,
                'total_bytes_out': total_bytes_out,
                'total_connections': total_connections,
                'active_devices': len(self.device_stats),
                'active_websites': len(active_websites),
                'recent_connections': len(self.recent_connections)
            }
    
    def get_top_websites(self, limit: int = 10) -> List[Tuple[str, int]]:
        """获取访问量最高的网站"""
        website_counts = defaultdict(int)
        
        with self.lock:
            for device in self.device_stats.values():
                for website in device.websites:
                    website_counts[website] += device.connections
        
        # 按访问量排序
        return sorted(website_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def cleanup_old_data(self, max_age_hours: float = 24) -> None:
        """清理过期数据"""
        cutoff_time = time.time() - (max_age_hours * 3600)
        
        with self.lock:
            # 清理过期连接
            self.recent_connections = deque(
                [conn for conn in self.recent_connections if conn.timestamp > cutoff_time],
                maxlen=self.recent_connections.maxlen
            )
            
            # 清理连接历史
            for key in list(self.connection_history.keys()):
                self.connection_history[key] = [
                    conn for conn in self.connection_history[key] 
                    if conn.get('timestamp', 0) > cutoff_time
                ]
                if not self.connection_history[key]:
                    del self.connection_history[key]