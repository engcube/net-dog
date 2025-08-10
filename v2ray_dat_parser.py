#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray DAT文件解析器 - 完整版
充分利用geosite.dat和geoip.dat中的所有数据
支持protobuf格式的正确解析
"""

import struct
import ipaddress
import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass


@dataclass
class GeositeEntry:
    """GeoSite条目"""
    category: str
    domains: List[str]
    domain_count: int


@dataclass
class GeoipEntry:
    """GeoIP条目"""
    country_code: str
    ip_ranges: List[Tuple[str, int]]  # (network, prefix_length)
    total_ips: int


class V2RayDatParser:
    """V2Ray DAT文件解析器 - 完整实现"""
    
    def __init__(self):
        self.geosite_cache = None
        self.geoip_cache = None
        
    def parse_geosite_dat(self, filepath: str) -> Dict[str, GeositeEntry]:
        """
        解析geosite.dat文件，提取所有分类和域名
        返回完整的分类->域名映射
        """
        if self.geosite_cache is not None:
            return self.geosite_cache
            
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            print(f"🔍 解析geosite.dat文件 ({len(data)/1024/1024:.1f}MB)")
            
            entries = {}
            offset = 0
            
            while offset < len(data) - 10:  # 留一些缓冲空间
                try:
                    # 尝试解析protobuf消息
                    entry = self._parse_geosite_entry(data, offset)
                    if entry:
                        offset = entry[0]  # 新offset
                        category, domains = entry[1], entry[2]
                        
                        if category and domains:
                            entries[category] = GeositeEntry(
                                category=category,
                                domains=domains,
                                domain_count=len(domains)
                            )
                    else:
                        offset += 1  # 继续搜索
                        
                except Exception:
                    offset += 1  # 解析失败，继续
                    
            print(f"✅ 成功解析 {len(entries)} 个分类")
            
            # 显示解析统计
            total_domains = sum(entry.domain_count for entry in entries.values())
            print(f"📊 总计 {total_domains} 个域名")
            
            self.geosite_cache = entries
            return entries
            
        except Exception as e:
            print(f"❌ 解析geosite.dat失败: {e}")
            return self._get_fallback_geosite_data()
    
    def _parse_geosite_entry(self, data: bytes, offset: int) -> Optional[Tuple[int, str, List[str]]]:
        """解析单个geosite条目"""
        try:
            # protobuf wire format: tag + length + data
            # 寻找消息开始标记 (0x0a 表示字段1，wire type 2)
            if offset >= len(data) - 2:
                return None
                
            if data[offset] != 0x0a:  # 不是消息开始
                return None
                
            # 读取消息长度
            length_offset = offset + 1
            message_length, length_bytes = self._read_varint(data, length_offset)
            if message_length is None or message_length > 1024 * 1024:  # 超过1MB的消息跳过
                return None
                
            message_start = length_offset + length_bytes
            message_end = message_start + message_length
            
            if message_end > len(data):
                return None
                
            # 解析消息内容
            category, domains = self._parse_geosite_message(data[message_start:message_end])
            
            if category:
                return (message_end, category, domains)
                
        except Exception:
            pass
            
        return None
    
    def _parse_geosite_message(self, message_data: bytes) -> Tuple[Optional[str], List[str]]:
        """解析geosite消息内容"""
        category = None
        domains = []
        offset = 0
        
        while offset < len(message_data):
            try:
                # 读取字段标签
                tag, tag_bytes = self._read_varint(message_data, offset)
                if tag is None:
                    break
                    
                offset += tag_bytes
                field_num = tag >> 3
                wire_type = tag & 0x7
                
                if wire_type == 2:  # 字符串/字节
                    length, length_bytes = self._read_varint(message_data, offset)
                    if length is None:
                        break
                        
                    offset += length_bytes
                    if offset + length > len(message_data):
                        break
                        
                    field_data = message_data[offset:offset + length]
                    offset += length
                    
                    # 字段1通常是分类名，字段2是域名规则列表
                    if field_num == 1:
                        try:
                            category = field_data.decode('utf-8')
                        except UnicodeDecodeError:
                            pass
                    elif field_num == 2:
                        # 这是一个嵌套的域名规则消息
                        domain = self._parse_domain_rule(field_data)
                        if domain:
                            domains.append(domain)
                else:
                    # 跳过其他类型的字段
                    offset += 1
                    
            except Exception:
                break
                
        return category, domains
    
    def _parse_domain_rule(self, rule_data: bytes) -> Optional[str]:
        """解析域名规则"""
        offset = 0
        domain = None
        
        while offset < len(rule_data):
            try:
                tag, tag_bytes = self._read_varint(rule_data, offset)
                if tag is None:
                    break
                    
                offset += tag_bytes
                field_num = tag >> 3
                wire_type = tag & 0x7
                
                if wire_type == 2:  # 字符串
                    length, length_bytes = self._read_varint(rule_data, offset)
                    if length is None:
                        break
                        
                    offset += length_bytes
                    if offset + length > len(rule_data):
                        break
                        
                    field_data = rule_data[offset:offset + length]
                    offset += length
                    
                    if field_num == 2:  # 域名字段
                        try:
                            domain = field_data.decode('utf-8')
                            # 清理域名格式
                            domain = self._clean_domain(domain)
                            if domain:
                                return domain
                        except UnicodeDecodeError:
                            pass
                else:
                    offset += 1
                    
            except Exception:
                break
                
        return domain
    
    def _clean_domain(self, domain: str) -> Optional[str]:
        """清理和验证域名格式"""
        if not domain:
            return None
            
        # 移除前缀标记
        domain = re.sub(r'^[!~+]', '', domain)
        
        # 移除正则表达式标记
        domain = re.sub(r'^\$.*\$$', '', domain)
        
        # 移除路径部分
        domain = domain.split('/')[0]
        
        # 验证域名格式
        if '.' not in domain:
            return None
            
        # 简单的域名验证
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return domain.lower()
            
        return None
    
    def _read_varint(self, data: bytes, offset: int) -> Tuple[Optional[int], int]:
        """读取protobuf变长整数"""
        result = 0
        shift = 0
        bytes_read = 0
        
        while offset + bytes_read < len(data):
            byte = data[offset + bytes_read]
            bytes_read += 1
            
            result |= (byte & 0x7F) << shift
            
            if (byte & 0x80) == 0:  # 最高位为0表示结束
                return result, bytes_read
                
            shift += 7
            if shift >= 64:  # 防止无限循环
                break
                
        return None, bytes_read
    
    def parse_geoip_dat(self, filepath: str) -> Dict[str, GeoipEntry]:
        """
        解析geoip.dat文件，提取所有国家的IP段
        返回国家代码->IP段映射
        """
        if self.geoip_cache is not None:
            return self.geoip_cache
            
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            print(f"🔍 解析geoip.dat文件 ({len(data)/1024/1024:.1f}MB)")
            
            entries = {}
            offset = 0
            
            while offset < len(data) - 10:
                try:
                    entry = self._parse_geoip_entry(data, offset)
                    if entry:
                        offset = entry[0]
                        country_code, ip_ranges = entry[1], entry[2]
                        
                        if country_code and ip_ranges:
                            entries[country_code] = GeoipEntry(
                                country_code=country_code,
                                ip_ranges=ip_ranges,
                                total_ips=sum(2**(32-prefix) for _, prefix in ip_ranges)
                            )
                    else:
                        offset += 1
                        
                except Exception:
                    offset += 1
                    
            print(f"✅ 成功解析 {len(entries)} 个国家/地区")
            
            self.geoip_cache = entries
            return entries
            
        except Exception as e:
            print(f"❌ 解析geoip.dat失败: {e}")
            return {}
    
    def _parse_geoip_entry(self, data: bytes, offset: int) -> Optional[Tuple[int, str, List[Tuple[str, int]]]]:
        """解析单个geoip条目"""
        try:
            if offset >= len(data) - 2:
                return None
                
            if data[offset] != 0x0a:
                return None
                
            length_offset = offset + 1
            message_length, length_bytes = self._read_varint(data, length_offset)
            if message_length is None or message_length > 1024 * 1024:
                return None
                
            message_start = length_offset + length_bytes
            message_end = message_start + message_length
            
            if message_end > len(data):
                return None
                
            country_code, ip_ranges = self._parse_geoip_message(data[message_start:message_end])
            
            if country_code:
                return (message_end, country_code, ip_ranges)
                
        except Exception:
            pass
            
        return None
    
    def _parse_geoip_message(self, message_data: bytes) -> Tuple[Optional[str], List[Tuple[str, int]]]:
        """解析geoip消息内容"""
        country_code = None
        ip_ranges = []
        offset = 0
        
        while offset < len(message_data):
            try:
                tag, tag_bytes = self._read_varint(message_data, offset)
                if tag is None:
                    break
                    
                offset += tag_bytes
                field_num = tag >> 3
                wire_type = tag & 0x7
                
                if wire_type == 2:  # 字符串/字节
                    length, length_bytes = self._read_varint(message_data, offset)
                    if length is None:
                        break
                        
                    offset += length_bytes
                    if offset + length > len(message_data):
                        break
                        
                    field_data = message_data[offset:offset + length]
                    offset += length
                    
                    if field_num == 1:  # 国家代码
                        try:
                            country_code = field_data.decode('utf-8')
                        except UnicodeDecodeError:
                            pass
                    elif field_num == 2:  # IP范围
                        ip_range = self._parse_ip_range(field_data)
                        if ip_range:
                            ip_ranges.append(ip_range)
                else:
                    offset += 1
                    
            except Exception:
                break
                
        return country_code, ip_ranges
    
    def _parse_ip_range(self, range_data: bytes) -> Optional[Tuple[str, int]]:
        """解析IP范围"""
        if len(range_data) < 5:  # 至少需要IP(4字节)+前缀(1字节)
            return None
            
        try:
            # IP地址通常在前4个字节
            ip_bytes = range_data[:4]
            ip_addr = ipaddress.IPv4Address(ip_bytes)
            
            # 前缀长度通常在第5个字节
            if len(range_data) > 4:
                prefix_len = range_data[4]
                if 0 <= prefix_len <= 32:
                    return (str(ip_addr), prefix_len)
                    
        except Exception:
            pass
            
        return None
    
    def get_domain_category(self, domain: str) -> Optional[str]:
        """根据域名查找对应的分类"""
        if not self.geosite_cache:
            return None
            
        domain = domain.lower()
        
        # 精确匹配
        for category, entry in self.geosite_cache.items():
            if domain in entry.domains:
                return category
                
        # 子域名匹配
        for category, entry in self.geosite_cache.items():
            for site_domain in entry.domains:
                if domain.endswith('.' + site_domain) or domain == site_domain:
                    return category
                    
        return None
    
    def get_ip_country(self, ip_str: str) -> Optional[str]:
        """根据IP地址查找对应的国家代码"""
        if not self.geoip_cache:
            return None
            
        try:
            ip = ipaddress.IPv4Address(ip_str)
            
            for country_code, entry in self.geoip_cache.items():
                for network_ip, prefix_len in entry.ip_ranges:
                    try:
                        network = ipaddress.IPv4Network(f"{network_ip}/{prefix_len}", strict=False)
                        if ip in network:
                            return country_code
                    except Exception:
                        continue
                        
        except Exception:
            pass
            
        return None
    
    def _get_fallback_geosite_data(self) -> Dict[str, GeositeEntry]:
        """当解析失败时的备用数据"""
        fallback_categories = {
            'GOOGLE': ['google.com', 'youtube.com', 'gmail.com'],
            'FACEBOOK': ['facebook.com', 'instagram.com', 'whatsapp.com'],
            'AMAZON': ['amazon.com', 'aws.amazon.com'],
            'APPLE': ['apple.com', 'icloud.com'],
            'MICROSOFT': ['microsoft.com', 'outlook.com'],
            'ALIBABA': ['alibaba.com', 'taobao.com'],
            'TENCENT': ['qq.com', 'weixin.qq.com'],
            'BAIDU': ['baidu.com'],
            'BILIBILI': ['bilibili.com']
        }
        
        entries = {}
        for category, domains in fallback_categories.items():
            entries[category] = GeositeEntry(
                category=category,
                domains=domains,
                domain_count=len(domains)
            )
            
        return entries
    
    def get_statistics(self) -> Dict[str, int]:
        """获取解析统计信息"""
        stats = {
            'geosite_categories': 0,
            'total_domains': 0,
            'geoip_countries': 0,
            'total_ip_ranges': 0
        }
        
        if self.geosite_cache:
            stats['geosite_categories'] = len(self.geosite_cache)
            stats['total_domains'] = sum(entry.domain_count for entry in self.geosite_cache.values())
            
        if self.geoip_cache:
            stats['geoip_countries'] = len(self.geoip_cache)
            stats['total_ip_ranges'] = sum(len(entry.ip_ranges) for entry in self.geoip_cache.values())
            
        return stats


# 测试函数
def test_parser():
    """测试解析器功能"""
    parser = V2RayDatParser()
    
    print("🚀 测试V2Ray DAT文件解析器")
    print("=" * 50)
    
    # 测试geosite解析
    geosite_data = parser.parse_geosite_dat('data/geosite.dat')
    
    # 显示前20个分类
    print("\n📋 前20个分类:")
    for i, (category, entry) in enumerate(list(geosite_data.items())[:20]):
        print(f"{i+1:2d}. {category}: {entry.domain_count} 个域名")
        
    # 测试geoip解析
    print("\n" + "=" * 50)
    geoip_data = parser.parse_geoip_dat('data/geoip.dat')
    
    # 显示前10个国家
    print("\n🌍 前10个国家/地区:")
    for i, (country, entry) in enumerate(list(geoip_data.items())[:10]):
        print(f"{i+1:2d}. {country}: {len(entry.ip_ranges)} 个IP段")
        
    # 显示统计信息
    stats = parser.get_statistics()
    print(f"\n📊 解析统计:")
    print(f"   - GeoSite分类数: {stats['geosite_categories']}")
    print(f"   - 总域名数: {stats['total_domains']}")
    print(f"   - GeoIP国家数: {stats['geoip_countries']}")
    print(f"   - 总IP段数: {stats['total_ip_ranges']}")
    
    return parser


if __name__ == "__main__":
    test_parser()