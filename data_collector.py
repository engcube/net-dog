#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据收集器抽象层
为跨平台支持提供统一接口
"""

import subprocess
import re
import platform
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional


class BaseDataCollector(ABC):
    """数据收集器抽象基类"""
    
    @abstractmethod
    def get_arp_table(self) -> Dict[str, str]:
        """获取ARP表，返回 {ip: mac}"""
        pass
    
    @abstractmethod
    def get_connections(self) -> List[Dict]:
        """获取网络连接列表"""
        pass
    
    @abstractmethod
    def get_interface_stats(self) -> Dict:
        """获取网络接口统计信息"""
        pass
    
    @abstractmethod
    def detect_local_network(self) -> str:
        """检测本地网络段"""
        pass


class DarwinDataCollector(BaseDataCollector):
    """macOS (Darwin) 数据收集器"""
    
    def get_arp_table(self) -> Dict[str, str]:
        """获取ARP表，返回 {ip: mac}"""
        devices = {}
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.strip():
                    # 解析 (192.168.31.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
                    match = re.search(r'\(([^)]+)\) at ([a-fA-F0-9:]{17})', line)
                    if match:
                        ip, mac = match.groups()
                        devices[ip] = mac
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            print(f"获取ARP表失败: {e}")
        return devices
    
    def get_connections(self) -> List[Dict]:
        """获取网络连接列表"""
        connections = []
        try:
            result = subprocess.run(['netstat', '-n'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line and ('tcp4' in line or 'tcp6' in line):
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[3]
                        foreign_addr = parts[4]
                        
                        # 解析地址和端口 - 处理 IP.PORT 格式
                        # 例如: 28.0.0.1.62657 或 192.168.31.31.58581
                        local_parts = local_addr.rsplit('.', 1)
                        foreign_parts = foreign_addr.rsplit('.', 1)
                        
                        if len(local_parts) == 2 and len(foreign_parts) == 2:
                            local_ip = local_parts[0]
                            local_port = local_parts[1]
                            foreign_ip = foreign_parts[0]
                            foreign_port = foreign_parts[1]
                            
                            # 验证IP格式（应该有3个点）
                            if local_ip.count('.') == 3 and foreign_ip.count('.') == 3:
                                connections.append({
                                    'local_ip': local_ip,
                                    'local_port': local_port,
                                    'foreign_ip': foreign_ip,
                                    'foreign_port': foreign_port,
                                    'protocol': 'tcp'
                                })
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            print(f"获取网络连接失败: {e}")
        return connections
    
    def get_interface_stats(self) -> Dict:
        """获取网络接口统计"""
        stats = {}
        try:
            result = subprocess.run(['netstat', '-ib'], capture_output=True, text=True)
            for line in result.stdout.split('\n')[1:]:  # 跳过表头
                parts = line.split()
                if len(parts) >= 10:
                    interface = parts[0]
                    if interface and interface != 'lo0':  # 排除回环接口
                        try:
                            bytes_in = int(parts[6])
                            bytes_out = int(parts[9])
                            stats[interface] = {
                                'bytes_in': bytes_in,
                                'bytes_out': bytes_out
                            }
                        except (ValueError, IndexError):
                            continue
        except (subprocess.SubprocessError, OSError) as e:
            print(f"获取接口统计失败: {e}")
        return stats
    
    def detect_local_network(self) -> str:
        """检测本地网络段"""
        try:
            result = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True)
            gateway_match = re.search(r'gateway: ([\d.]+)', result.stdout)
            if gateway_match:
                gateway = gateway_match.group(1)
                return '.'.join(gateway.split('.')[:-1]) + '.0/24'
            return '192.168.1.0/24'  # 默认值
        except (subprocess.SubprocessError, OSError, IndexError) as e:
            print(f"检测本地网络失败: {e}")
            return '192.168.1.0/24'


class LinuxDataCollector(BaseDataCollector):
    """Linux 数据收集器（占位符实现）"""
    
    def get_arp_table(self) -> Dict[str, str]:
        raise NotImplementedError("Linux 支持尚未实现，请在 macOS 上运行此工具")
    
    def get_connections(self) -> List[Dict]:
        raise NotImplementedError("Linux 支持尚未实现，请在 macOS 上运行此工具")
    
    def get_interface_stats(self) -> Dict:
        raise NotImplementedError("Linux 支持尚未实现，请在 macOS 上运行此工具")
    
    def detect_local_network(self) -> str:
        raise NotImplementedError("Linux 支持尚未实现，请在 macOS 上运行此工具")


class WindowsDataCollector(BaseDataCollector):
    """Windows 数据收集器（占位符实现）"""
    
    def get_arp_table(self) -> Dict[str, str]:
        raise NotImplementedError("Windows 支持尚未实现，请在 macOS 上运行此工具")
    
    def get_connections(self) -> List[Dict]:
        raise NotImplementedError("Windows 支持尚未实现，请在 macOS 上运行此工具")
    
    def get_interface_stats(self) -> Dict:
        raise NotImplementedError("Windows 支持尚未实现，请在 macOS 上运行此工具")
    
    def detect_local_network(self) -> str:
        raise NotImplementedError("Windows 支持尚未实现，请在 macOS 上运行此工具")


def create_data_collector() -> BaseDataCollector:
    """根据当前平台创建对应的数据收集器"""
    system = platform.system().lower()
    
    if system == 'darwin':
        return DarwinDataCollector()
    elif system == 'linux':
        return LinuxDataCollector()
    elif system == 'windows':
        return WindowsDataCollector()
    else:
        raise NotImplementedError(f"不支持的操作系统: {system}。目前只支持 macOS。")