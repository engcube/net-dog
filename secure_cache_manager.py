#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全缓存管理器
提供安全的数据缓存和隐私保护功能
"""

import json
import os
import time
import threading
import hashlib
from typing import Dict, Optional, Any
from dataclasses import dataclass
import logging

@dataclass
class CacheEntry:
    """缓存条目数据类"""
    data: Any
    timestamp: float
    access_count: int = 0
    last_access: float = 0.0

class SecureCacheManager:
    """安全缓存管理器"""
    
    def __init__(self, cache_file: str, config: Dict):
        self.cache_file = cache_file
        self.config = config
        self.cache = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        
        # 安全配置
        self.max_entries = config.get('performance', {}).get('max_cache_entries', 1000)
        self.cleanup_interval = config.get('performance', {}).get('cache_cleanup_interval', 300)
        self.max_age = config.get('monitoring', {}).get('dns_cache_timeout', 3600)
        self.enable_caching = config.get('performance', {}).get('enable_caching', True)
        
        # 隐私保护设置
        self.anonymize_ips = config.get('privacy', {}).get('anonymize_ips', False)
        self.auto_cleanup_on_exit = config.get('privacy', {}).get('auto_cleanup_on_exit', False)
        
        # 加载现有缓存
        if self.enable_caching:
            self._load_cache()
            
        # 启动清理线程
        if self.cleanup_interval > 0:
            self._start_cleanup_thread()
    
    def _load_cache(self) -> None:
        """安全加载缓存文件"""
        try:
            if os.path.exists(self.cache_file):
                # 检查文件权限
                stat = os.stat(self.cache_file)
                if stat.st_mode & 0o077:  # 检查是否其他用户可读写
                    self.logger.warning(f"缓存文件权限不安全: {self.cache_file}")
                
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    raw_cache = json.load(f)
                
                # 转换为CacheEntry对象
                for key, value in raw_cache.items():
                    if isinstance(value, dict) and 'timestamp' in value:
                        # 新格式：包含时间戳的完整缓存条目
                        self.cache[key] = CacheEntry(
                            data=value.get('data', value),
                            timestamp=value.get('timestamp', time.time()),
                            access_count=value.get('access_count', 0),
                            last_access=value.get('last_access', time.time())
                        )
                    else:
                        # 旧格式：直接的数据值
                        self.cache[key] = CacheEntry(
                            data=value,
                            timestamp=time.time(),
                            access_count=0,
                            last_access=time.time()
                        )
                
                self.logger.info(f"加载缓存: {len(self.cache)} 个条目")
                
        except (json.JSONDecodeError, IOError, OSError) as e:
            self.logger.error(f"加载缓存失败: {e}")
            self.cache = {}
        except Exception as e:
            self.logger.error(f"加载缓存时发生未知错误: {e}")
            self.cache = {}
    
    def _save_cache(self) -> None:
        """安全保存缓存文件"""
        if not self.enable_caching:
            return
            
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            
            # 准备序列化数据
            serializable_cache = {}
            for key, entry in self.cache.items():
                serializable_cache[key] = {
                    'data': entry.data,
                    'timestamp': entry.timestamp,
                    'access_count': entry.access_count,
                    'last_access': entry.last_access
                }
            
            # 写入临时文件然后重命名（原子操作）
            temp_file = self.cache_file + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(serializable_cache, f, ensure_ascii=False, indent=2)
            
            # 设置安全权限（仅当前用户可读写）
            os.chmod(temp_file, 0o600)
            
            # 原子重命名
            os.rename(temp_file, self.cache_file)
            
        except (IOError, OSError) as e:
            self.logger.error(f"保存缓存失败: {e}")
        except Exception as e:
            self.logger.error(f"保存缓存时发生未知错误: {e}")
    
    def _anonymize_key(self, key: str) -> str:
        """匿名化缓存键（用于隐私保护）"""
        if not self.anonymize_ips:
            return key
        
        # 使用SHA-256哈希进行匿名化
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存项"""
        if not self.enable_caching:
            return None
            
        cache_key = self._anonymize_key(key)
        
        with self.lock:
            if cache_key in self.cache:
                entry = self.cache[cache_key]
                
                # 检查是否过期
                if time.time() - entry.timestamp > self.max_age:
                    del self.cache[cache_key]
                    return None
                
                # 更新访问统计
                entry.access_count += 1
                entry.last_access = time.time()
                
                return entry.data
            
            return None
    
    def put(self, key: str, value: Any) -> None:
        """存储缓存项"""
        if not self.enable_caching:
            return
            
        cache_key = self._anonymize_key(key)
        
        with self.lock:
            # 检查缓存大小限制
            if len(self.cache) >= self.max_entries and cache_key not in self.cache:
                self._evict_oldest()
            
            # 存储新条目
            self.cache[cache_key] = CacheEntry(
                data=value,
                timestamp=time.time(),
                access_count=1,
                last_access=time.time()
            )
            
            # 定期保存
            if len(self.cache) % 10 == 0:
                self._save_cache()
    
    def _evict_oldest(self) -> None:
        """清理最旧的缓存条目"""
        if not self.cache:
            return
            
        # 找到最久未访问的条目
        oldest_key = min(self.cache.keys(), 
                        key=lambda k: self.cache[k].last_access)
        del self.cache[oldest_key]
        
        self.logger.debug(f"清理过期缓存条目: {oldest_key}")
    
    def cleanup_expired(self) -> int:
        """清理过期条目，返回清理的数量"""
        if not self.enable_caching:
            return 0
            
        current_time = time.time()
        expired_keys = []
        
        with self.lock:
            for key, entry in self.cache.items():
                if current_time - entry.timestamp > self.max_age:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.cache[key]
        
        if expired_keys:
            self.logger.info(f"清理了 {len(expired_keys)} 个过期缓存条目")
            self._save_cache()
        
        return len(expired_keys)
    
    def _start_cleanup_thread(self) -> None:
        """启动后台清理线程"""
        def cleanup_worker():
            while True:
                time.sleep(self.cleanup_interval)
                try:
                    self.cleanup_expired()
                except Exception as e:
                    self.logger.error(f"清理缓存时出错: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        self.logger.info("启动缓存清理后台线程")
    
    def clear_all(self) -> None:
        """清空所有缓存"""
        with self.lock:
            self.cache.clear()
        
        # 删除缓存文件
        try:
            if os.path.exists(self.cache_file):
                os.remove(self.cache_file)
                self.logger.info("已清空所有缓存数据")
        except OSError as e:
            self.logger.error(f"删除缓存文件失败: {e}")
    
    def get_privacy_report(self) -> Dict:
        """生成隐私报告"""
        with self.lock:
            total_entries = len(self.cache)
            
            # 统计数据类型
            data_types = {}
            for entry in self.cache.values():
                data_type = type(entry.data).__name__
                data_types[data_type] = data_types.get(data_type, 0) + 1
            
            # 计算数据年龄分布
            current_time = time.time()
            age_distribution = {'<1h': 0, '1-24h': 0, '>24h': 0}
            
            for entry in self.cache.values():
                age_hours = (current_time - entry.timestamp) / 3600
                if age_hours < 1:
                    age_distribution['<1h'] += 1
                elif age_hours < 24:
                    age_distribution['1-24h'] += 1
                else:
                    age_distribution['>24h'] += 1
        
        return {
            'total_entries': total_entries,
            'data_types': data_types,
            'age_distribution': age_distribution,
            'cache_file_exists': os.path.exists(self.cache_file),
            'cache_file_size': os.path.getsize(self.cache_file) if os.path.exists(self.cache_file) else 0,
            'anonymized': self.anonymize_ips,
            'auto_cleanup_enabled': self.cleanup_interval > 0
        }
    
    def get_statistics(self) -> Dict:
        """获取缓存统计信息"""
        with self.lock:
            if not self.cache:
                return {'cache_entries': 0, 'cache_hit_ratio': 0.0}
            
            total_accesses = sum(entry.access_count for entry in self.cache.values())
            
            return {
                'cache_entries': len(self.cache),
                'max_entries': self.max_entries,
                'total_accesses': total_accesses,
                'average_accesses': total_accesses / len(self.cache) if self.cache else 0,
                'enabled': self.enable_caching
            }
    
    def __del__(self):
        """析构函数：清理资源"""
        if hasattr(self, 'auto_cleanup_on_exit') and self.auto_cleanup_on_exit:
            self.clear_all()
        elif hasattr(self, 'enable_caching') and self.enable_caching:
            self._save_cache()