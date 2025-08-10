#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用工具函数
"""

def is_china_ip(ip: str) -> bool:
    """检查是否为中国IP"""
    try:
        first_octet = int(ip.split('.')[0])
        china_ranges = [1, 14, 27, 36, 39, 42, 49, 58, 59, 60, 61, 
                       101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 
                       175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223]
        return first_octet in china_ranges
    except (ValueError, IndexError):
        return False