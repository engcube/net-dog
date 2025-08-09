#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
域名解析增强模块
集成v2ray-rules-dat和本地缓存
"""

import socket
import ipaddress
import json
import os
import time
from typing import Dict, Optional, Tuple, Set
import threading
import urllib.request
import struct

class EnhancedDomainResolver:
    def __init__(self):
        self.dns_cache = {}  # {ip: (domain, timestamp)}
        self.ip_to_site_cache = {}  # {ip: site_name}
        self.cache_ttl = 3600  # 1小时缓存
        self.lock = threading.Lock()
        
        # 不再使用硬编码IP范围，完全依赖GeoSite数据
    
    def _ip_in_range(self, ip: str, cidr_ranges: list) -> bool:
        """检查IP是否在指定CIDR范围内"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in cidr_ranges:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
        except (ipaddress.AddressValueError, ValueError):
            pass
        return False
    
    def _resolve_by_ip_range(self, ip: str) -> Optional[str]:
        """通过GeoSite IP数据推断网站名称"""
        try:
            from geosite_loader import geosite_loader
            
            # 检查是否为特殊服务的IP（如Telegram）
            service = geosite_loader.get_ip_service(ip)
            if service:
                return f"{service}.com"
            
            return None
        except ImportError:
            return None
    
    def _dns_resolve_with_timeout(self, ip: str, timeout: float = 0.5) -> Optional[str]:
        """带超时的DNS反向查询"""
        old_timeout = socket.getdefaulttimeout()
        try:
            # 设置socket超时
            socket.setdefaulttimeout(timeout)
            
            result = socket.gethostbyaddr(ip)[0]
            
            if result != ip and '.' in result:
                # 简化域名显示
                parts = result.split('.')
                if len(parts) >= 2:
                    return '.'.join(parts[-2:])
            return result
            
        except (socket.herror, socket.gaierror, socket.timeout, OSError, Exception):
            return None
        finally:
            # 确保总是恢复原始超时设置
            socket.setdefaulttimeout(old_timeout)
    
    def resolve_domain(self, ip: str) -> str:
        """增强的域名解析方法 - 集成GeoSite数据"""
        if not ip or ip == '0.0.0.0':
            return ip
            
        current_time = time.time()
        
        with self.lock:
            # 检查缓存
            if ip in self.dns_cache:
                cached_domain, timestamp = self.dns_cache[ip]
                if current_time - timestamp < self.cache_ttl:
                    return cached_domain
        
        # 解析策略（按优先级）
        domain = None
        
        # 1. 先尝试IP范围匹配（最快）
        domain = self._resolve_by_ip_range(ip)
        if domain:
            with self.lock:
                self.dns_cache[ip] = (domain, current_time)
            return domain
        
        # 2. 快速DNS反向查询（超时0.5秒）
        domain = self._dns_resolve_with_timeout(ip, timeout=0.5)
        if domain and domain != ip:
            # 2.1 尝试通过GeoSite数据进一步识别网站
            try:
                from geosite_loader import geosite_loader
                category = geosite_loader.get_domain_category(domain)
                if category:
                    # 使用分类名作为显示名称
                    display_name = f"{category}.com" if not domain.endswith('.com') else domain
                    with self.lock:
                        self.dns_cache[ip] = (display_name, current_time)
                    return display_name
            except ImportError:
                pass
            
            with self.lock:
                self.dns_cache[ip] = (domain, current_time)
            return domain
        
        # 3. 兜底：返回IP地址
        fallback_domain = f"{ip}(未知网站)"
        with self.lock:
            self.dns_cache[ip] = (fallback_domain, current_time)
        
        return fallback_domain
    
    def clear_cache(self):
        """清理过期缓存"""
        current_time = time.time()
        with self.lock:
            expired_ips = [
                ip for ip, (_, timestamp) in self.dns_cache.items()
                if current_time - timestamp > self.cache_ttl
            ]
            for ip in expired_ips:
                del self.dns_cache[ip]
    
    def get_cache_stats(self) -> Dict:
        """获取缓存统计信息"""
        with self.lock:
            return {
                'total_cached': len(self.dns_cache),
                'cache_ttl': self.cache_ttl
            }

# 全局实例
domain_resolver = EnhancedDomainResolver()