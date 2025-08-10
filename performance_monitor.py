#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
性能监控模块
监控系统性能并提供优化建议
"""

import time
import psutil
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import deque

@dataclass
class PerformanceMetric:
    """性能指标数据类"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    network_io: Dict[str, int]
    operation_times: Dict[str, float]

class PerformanceMonitor:
    """性能监控器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.metrics_history = deque(maxlen=100)  # 保留最近100个性能数据点
        self.operation_times = {}  # 操作执行时间记录
        self.lock = threading.Lock()
        
        # 性能阈值配置
        self.thresholds = {
            'cpu_high': 80.0,      # CPU使用率高阈值
            'memory_high': 85.0,   # 内存使用率高阈值
            'operation_slow': 2.0,  # 操作执行慢阈值（秒）
            'ui_render_slow': 0.5   # UI渲染慢阈值（秒）
        }
        
    def start_operation_timer(self, operation_name: str) -> None:
        """开始计时某个操作"""
        with self.lock:
            self.operation_times[operation_name] = time.time()
    
    def end_operation_timer(self, operation_name: str) -> float:
        """结束计时并返回耗时"""
        with self.lock:
            if operation_name in self.operation_times:
                start_time = self.operation_times[operation_name]
                elapsed = time.time() - start_time
                del self.operation_times[operation_name]
                return elapsed
            return 0.0
    
    def collect_metrics(self) -> PerformanceMetric:
        """收集当前性能指标"""
        try:
            # 获取系统性能数据
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            network = psutil.net_io_counters()
            
            metric = PerformanceMetric(
                timestamp=time.time(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                network_io={
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv
                },
                operation_times=dict(self.operation_times)  # 复制当前操作时间
            )
            
            with self.lock:
                self.metrics_history.append(metric)
            
            return metric
            
        except Exception as e:
            print(f"收集性能指标失败: {e}")
            return None
    
    def get_performance_summary(self) -> Dict:
        """获取性能总结"""
        if not self.metrics_history:
            return {}
        
        with self.lock:
            recent_metrics = list(self.metrics_history)[-10:]  # 最近10个数据点
        
        if not recent_metrics:
            return {}
        
        # 计算平均值
        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        
        # 检查性能问题
        issues = []
        recommendations = []
        
        if avg_cpu > self.thresholds['cpu_high']:
            issues.append(f"CPU使用率过高 ({avg_cpu:.1f}%)")
            recommendations.append("建议增加数据采集间隔或减少并发处理")
        
        if avg_memory > self.thresholds['memory_high']:
            issues.append(f"内存使用率过高 ({avg_memory:.1f}%)")
            recommendations.append("建议启用缓存清理或减少缓存大小")
        
        return {
            'avg_cpu_percent': avg_cpu,
            'avg_memory_percent': avg_memory,
            'issues': issues,
            'recommendations': recommendations,
            'metrics_collected': len(self.metrics_history)
        }
    
    def should_enable_performance_mode(self) -> bool:
        """判断是否应该启用性能优化模式"""
        summary = self.get_performance_summary()
        
        if not summary:
            return False
        
        # 如果CPU或内存使用率过高，建议启用性能模式
        return (
            summary.get('avg_cpu_percent', 0) > self.thresholds['cpu_high'] or
            summary.get('avg_memory_percent', 0) > self.thresholds['memory_high']
        )
    
    def get_optimization_suggestions(self) -> List[str]:
        """获取性能优化建议"""
        suggestions = []
        summary = self.get_performance_summary()
        
        if not summary:
            return suggestions
        
        if summary.get('avg_cpu_percent', 0) > 60:
            suggestions.append("考虑将数据采集间隔从3秒调整为5秒")
            
        if summary.get('avg_memory_percent', 0) > 70:
            suggestions.append("启用缓存自动清理功能")
            suggestions.append("减少最大缓存条目数量")
            
        if len(self.metrics_history) > 0:
            latest = self.metrics_history[-1]
            if any(t > self.thresholds['operation_slow'] for t in latest.operation_times.values()):
                suggestions.append("某些操作执行较慢，考虑异步处理")
        
        return suggestions

# 性能监控装饰器
def monitor_performance(operation_name: str):
    """性能监控装饰器"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # 假设第一个参数是self，且有performance_monitor属性
            if args and hasattr(args[0], 'performance_monitor'):
                monitor = args[0].performance_monitor
                monitor.start_operation_timer(operation_name)
                try:
                    result = func(*args, **kwargs)
                    elapsed = monitor.end_operation_timer(operation_name)
                    
                    # 如果操作执行时间超过阈值，记录警告
                    if elapsed > 2.0:
                        print(f"⚠️  操作 '{operation_name}' 耗时 {elapsed:.2f}秒，可能需要优化")
                    
                    return result
                except Exception as e:
                    monitor.end_operation_timer(operation_name)
                    raise e
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator

class TableRenderCache:
    """表格渲染缓存优化"""
    
    def __init__(self, max_size: int = 100):
        self.cache = {}
        self.access_times = {}
        self.max_size = max_size
        self.lock = threading.Lock()
    
    def get_cache_key(self, data_hash: str, table_type: str) -> str:
        """生成缓存键"""
        return f"{table_type}_{data_hash}"
    
    def get(self, cache_key: str):
        """获取缓存内容"""
        with self.lock:
            if cache_key in self.cache:
                self.access_times[cache_key] = time.time()
                return self.cache[cache_key]
            return None
    
    def put(self, cache_key: str, table_content):
        """存储缓存内容"""
        with self.lock:
            # 如果缓存已满，清理最久未访问的条目
            if len(self.cache) >= self.max_size:
                oldest_key = min(self.access_times, key=self.access_times.get)
                del self.cache[oldest_key]
                del self.access_times[oldest_key]
            
            self.cache[cache_key] = table_content
            self.access_times[cache_key] = time.time()
    
    def clear(self):
        """清空缓存"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
    
    def get_stats(self) -> Dict:
        """获取缓存统计信息"""
        with self.lock:
            return {
                'cache_size': len(self.cache),
                'max_size': self.max_size,
                'hit_ratio': getattr(self, '_hit_count', 0) / max(getattr(self, '_total_requests', 1), 1)
            }