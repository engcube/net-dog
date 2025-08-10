#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UI管理器
专门负责用户界面的构建和渲染
使用Rich库实现现代化终端UI
"""

import time
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta

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
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
except ImportError:
    raise ImportError("请安装rich库: pip install rich")

from traffic_analyzer import TrafficAnalyzer, DeviceStats
from performance_monitor import PerformanceMonitor, TableRenderCache
from utils import get_country_name

class UIManager:
    """
    UI管理器 - 专门负责界面渲染
    
    职责：
    1. 构建Rich UI组件
    2. 管理界面布局
    3. 优化渲染性能
    4. 提供用户交互反馈
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.console = Console()
        self.start_time = datetime.now()
        
        # UI配置
        self.max_table_rows = config.get('display', {}).get('max_table_rows', 50)
        self.max_unknown_sites = config.get('display', {}).get('max_unknown_sites_display', 3)
        self.enable_incremental_updates = config.get('display', {}).get('enable_incremental_updates', True)
        
        # 渲染缓存（性能优化）
        self.render_cache = TableRenderCache(max_size=20)
        self.last_render_hash = {}
        
        # 性能监控
        self.performance_monitor: Optional[PerformanceMonitor] = None
        
    def set_performance_monitor(self, monitor: PerformanceMonitor):
        """注入性能监控器"""
        self.performance_monitor = monitor
    
    def create_main_layout(self, traffic_analyzer: TrafficAnalyzer) -> Layout:
        """
        创建主界面布局
        
        布局结构：
        ┌─────────────────────────────────────┐
        │              标题栏                  │
        ├─────────────────────────────────────┤
        │              统计面板                │
        ├─────────────────────────────────────┤
        │         设备流量表（左）  │  网站访问表（右） │
        └─────────────────────────────────────┘
        """
        # 开始性能监控
        if self.performance_monitor:
            self.performance_monitor.start_operation_timer("create_main_layout")
        
        try:
            # 创建主布局
            layout = Layout()
            
            # 定义布局区域
            layout.split_column(
                Layout(name="header", size=3),      # 标题区域
                Layout(name="stats", size=4),       # 统计区域  
                Layout(name="main"),                # 主内容区域
                Layout(name="footer", size=2)       # 底部状态栏
            )
            
            # 主内容区域分为左右两列
            layout["main"].split_row(
                Layout(name="devices"),             # 设备列表
                Layout(name="websites")             # 网站列表
            )
            
            # 填充各个区域的内容
            layout["header"] = self._create_header_panel()
            layout["stats"] = self._create_stats_panel(traffic_analyzer)
            layout["devices"] = self._create_devices_panel(traffic_analyzer)
            layout["websites"] = self._create_websites_panel(traffic_analyzer)
            layout["footer"] = self._create_footer_panel()
            
            return layout
            
        finally:
            if self.performance_monitor:
                elapsed = self.performance_monitor.end_operation_timer("create_main_layout")
                if elapsed > 0.5:  # 如果渲染超过500ms，记录警告
                    print(f"⚠️  界面渲染较慢: {elapsed:.2f}秒")
    
    def _create_header_panel(self) -> Panel:
        """创建标题面板"""
        title = Text()
        title.append("🌐 网络流量监控工具", style="bold blue")
        title.append(" | ", style="dim")
        title.append("实时网络活动分析", style="italic")
        
        return Panel(
            Align.center(title),
            style="bold",
            border_style="blue"
        )
    
    def _create_stats_panel(self, traffic_analyzer: TrafficAnalyzer) -> Panel:
        """创建统计面板"""
        stats = traffic_analyzer.get_traffic_summary()
        
        # 运行时长
        uptime = datetime.now() - self.start_time
        uptime_str = str(uptime).split('.')[0]  # 去掉微秒
        
        # 格式化流量数据
        total_in_mb = stats.get('total_bytes_in', 0) / (1024 * 1024)
        total_out_mb = stats.get('total_bytes_out', 0) / (1024 * 1024)
        
        # 创建统计文本
        stats_text = Text()
        stats_text.append("📊 运行时长: ", style="bold")
        stats_text.append(f"{uptime_str}", style="green")
        stats_text.append(" | ")
        
        stats_text.append("📱 活跃设备: ", style="bold")
        stats_text.append(f"{stats.get('active_devices', 0)}", style="cyan")
        stats_text.append(" | ")
        
        stats_text.append("🌍 访问网站: ", style="bold")
        stats_text.append(f"{stats.get('active_websites', 0)}", style="yellow")
        stats_text.append(" | ")
        
        stats_text.append("🔗 连接数: ", style="bold")
        stats_text.append(f"{stats.get('total_connections', 0)}", style="magenta")
        
        stats_text.append("\n")
        stats_text.append("📥 下载: ", style="bold")
        stats_text.append(f"{total_in_mb:.1f} MB", style="green")
        stats_text.append(" | ")
        
        stats_text.append("📤 上传: ", style="bold")
        stats_text.append(f"{total_out_mb:.1f} MB", style="red")
        
        # 添加性能信息（如果可用）
        if self.performance_monitor:
            perf_summary = self.performance_monitor.get_performance_summary()
            if perf_summary:
                stats_text.append(" | ")
                stats_text.append("💾 CPU: ", style="bold")
                stats_text.append(f"{perf_summary.get('avg_cpu_percent', 0):.1f}%", 
                                style="red" if perf_summary.get('avg_cpu_percent', 0) > 80 else "green")
                stats_text.append(" | ")
                stats_text.append("🧠 内存: ", style="bold")
                stats_text.append(f"{perf_summary.get('avg_memory_percent', 0):.1f}%",
                                style="red" if perf_summary.get('avg_memory_percent', 0) > 85 else "green")
        
        return Panel(stats_text, title="实时统计", border_style="green")
    
    def _create_devices_panel(self, traffic_analyzer: TrafficAnalyzer) -> Panel:
        """创建设备流量面板"""
        device_stats = traffic_analyzer.get_device_stats()
        
        # 检查是否可以使用缓存
        devices_hash = hash(str(sorted(device_stats.items())))
        cache_key = self.render_cache.get_cache_key(str(devices_hash), "devices")
        
        if self.enable_incremental_updates:
            cached_table = self.render_cache.get(cache_key)
            if cached_table and self.last_render_hash.get("devices") == devices_hash:
                return Panel(cached_table, title="📱 设备流量", border_style="cyan")
        
        # 创建设备表格
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("设备", style="cyan", no_wrap=True, width=20)
        table.add_column("IP地址", style="dim", width=15)
        table.add_column("连接数", justify="right", style="yellow", width=8)
        table.add_column("下载", justify="right", style="green", width=10)
        table.add_column("上传", justify="right", style="red", width=10)
        table.add_column("最近访问", style="blue", width=25)
        
        # 按连接数排序设备
        sorted_devices = sorted(
            device_stats.items(), 
            key=lambda x: x[1].connections, 
            reverse=True
        )
        
        # 限制显示行数以提升性能
        display_devices = sorted_devices[:self.max_table_rows]
        
        for device_name, device in display_devices:
            # 格式化流量显示
            bytes_in_mb = device.bytes_in / (1024 * 1024)
            bytes_out_mb = device.bytes_out / (1024 * 1024)
            
            # 格式化最近访问
            recent_str = ", ".join(device.recent_connections[:3])  # 只显示前3个
            if len(recent_str) > 25:
                recent_str = recent_str[:22] + "..."
            
            # 设备名称显示优化
            display_name = device_name
            if len(display_name) > 18:
                display_name = display_name[:15] + "..."
            
            table.add_row(
                display_name,
                device.ip,
                str(device.connections),
                f"{bytes_in_mb:.1f}MB",
                f"{bytes_out_mb:.1f}MB",
                recent_str or "无"
            )
        
        # 如果有更多设备未显示，添加提示行
        if len(sorted_devices) > self.max_table_rows:
            table.add_row(
                "...",
                f"还有 {len(sorted_devices) - self.max_table_rows} 个设备",
                "...",
                "...",
                "...",
                "..."
            )
        
        # 缓存渲染结果
        if self.enable_incremental_updates:
            self.render_cache.put(cache_key, table)
            self.last_render_hash["devices"] = devices_hash
        
        return Panel(table, title="📱 设备流量", border_style="cyan")
    
    def _create_websites_panel(self, traffic_analyzer: TrafficAnalyzer) -> Panel:
        """创建网站访问面板"""
        top_websites = traffic_analyzer.get_top_websites(limit=self.max_table_rows)
        
        # 检查缓存
        websites_hash = hash(str(top_websites))
        cache_key = self.render_cache.get_cache_key(str(websites_hash), "websites")
        
        if self.enable_incremental_updates:
            cached_table = self.render_cache.get(cache_key)
            if cached_table and self.last_render_hash.get("websites") == websites_hash:
                return Panel(cached_table, title="🌍 热门网站", border_style="yellow")
        
        # 创建网站访问表格
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("排名", justify="center", style="dim", width=6)
        table.add_column("网站/服务", style="cyan", width=30)
        table.add_column("访问量", justify="right", style="yellow", width=10)
        table.add_column("类型", style="green", width=12)
        table.add_column("热度", width=15)
        
        if not top_websites:
            table.add_row("暂无数据", "", "", "", "")
        else:
            # 计算最大访问量用于热度条
            max_visits = max(count for _, count in top_websites) if top_websites else 1
            
            for rank, (website, visit_count) in enumerate(top_websites, 1):
                # 确定网站类型
                website_type = self._classify_website(website)
                
                # 格式化网站名称
                display_name = website
                if len(display_name) > 28:
                    display_name = display_name[:25] + "..."
                
                # 创建热度条
                heat_ratio = visit_count / max_visits
                heat_bar = "█" * int(heat_ratio * 10) + "░" * (10 - int(heat_ratio * 10))
                
                # 排名显示
                rank_style = "gold1" if rank <= 3 else "white"
                
                table.add_row(
                    f"{rank}",
                    display_name,
                    str(visit_count),
                    website_type,
                    heat_bar,
                    style=rank_style if rank <= 3 else None
                )
        
        # 缓存结果
        if self.enable_incremental_updates:
            self.render_cache.put(cache_key, table)
            self.last_render_hash["websites"] = websites_hash
        
        return Panel(table, title="🌍 热门网站", border_style="yellow")
    
    def _classify_website(self, website: str) -> str:
        """分类网站类型"""
        website_lower = website.lower()
        
        # 视频网站
        if any(keyword in website_lower for keyword in ['youtube', 'bilibili', 'niconico', 'netflix', 'video']):
            return "🎬 视频"
        
        # 社交网站
        if any(keyword in website_lower for keyword in ['facebook', 'twitter', 'instagram', 'qq', 'wechat']):
            return "👥 社交"
        
        # 搜索引擎
        if any(keyword in website_lower for keyword in ['google', 'baidu', 'bing']):
            return "🔍 搜索"
        
        # 云服务
        if any(keyword in website_lower for keyword in ['aws', 'cloudflare', 'azure', 'aliyun', '腾讯云']):
            return "☁️ 云服务"
        
        # 购物网站
        if any(keyword in website_lower for keyword in ['amazon', 'taobao', 'tmall', 'jd']):
            return "🛒 购物"
        
        # 新闻网站
        if any(keyword in website_lower for keyword in ['news', '新闻', 'cnn', 'bbc']):
            return "📰 新闻"
        
        # 游戏
        if any(keyword in website_lower for keyword in ['steam', 'game', '游戏']):
            return "🎮 游戏"
        
        # 默认
        return "🌐 网站"
    
    def _create_footer_panel(self) -> Panel:
        """创建底部状态栏"""
        footer_text = Text()
        footer_text.append("按 ", style="dim")
        footer_text.append("Ctrl+C", style="bold red")
        footer_text.append(" 退出监控", style="dim")
        footer_text.append(" | ", style="dim")
        footer_text.append("数据每3秒刷新一次", style="dim")
        
        # 添加性能优化提示
        if self.performance_monitor:
            suggestions = self.performance_monitor.get_optimization_suggestions()
            if suggestions:
                footer_text.append(" | ", style="dim")
                footer_text.append("💡 ", style="yellow")
                footer_text.append(suggestions[0][:30] + "..." if len(suggestions[0]) > 30 else suggestions[0], 
                                 style="yellow")
        
        return Panel(
            Align.center(footer_text),
            style="dim"
        )
    
    def create_loading_screen(self) -> Layout:
        """创建加载界面"""
        layout = Layout()
        
        # 创建加载信息
        loading_text = Text()
        loading_text.append("🚀 正在启动网络监控工具...\n\n", style="bold blue", justify="center")
        loading_text.append("• 初始化数据收集器\n", style="green")
        loading_text.append("• 加载GeoSite数据库\n", style="green") 
        loading_text.append("• 启动域名解析器\n", style="green")
        loading_text.append("• 配置性能监控\n", style="green")
        loading_text.append("\n请稍候...", style="dim", justify="center")
        
        layout.update(Panel(
            Align.center(loading_text),
            title="初始化中",
            border_style="blue"
        ))
        
        return layout
    
    def create_error_screen(self, error_message: str) -> Layout:
        """创建错误界面"""
        layout = Layout()
        
        error_text = Text()
        error_text.append("❌ 发生错误\n\n", style="bold red", justify="center")
        error_text.append(f"错误信息: {error_message}\n\n", style="red")
        error_text.append("可能的解决方法:\n", style="bold")
        error_text.append("• 检查网络连接\n", style="yellow")
        error_text.append("• 确保具有足够权限\n", style="yellow")
        error_text.append("• 重新启动程序\n", style="yellow")
        error_text.append("\n按 Ctrl+C 退出", style="dim", justify="center")
        
        layout.update(Panel(
            Align.center(error_text),
            title="错误",
            border_style="red"
        ))
        
        return layout
    
    def get_render_stats(self) -> Dict:
        """获取渲染统计信息"""
        cache_stats = self.render_cache.get_stats()
        
        return {
            'cache_size': cache_stats['cache_size'],
            'cache_hit_ratio': cache_stats['hit_ratio'],
            'max_table_rows': self.max_table_rows,
            'incremental_updates_enabled': self.enable_incremental_updates,
            'last_render_hashes': len(self.last_render_hash)
        }
    
    def optimize_for_performance(self) -> None:
        """启用性能优化模式"""
        self.max_table_rows = min(20, self.max_table_rows)
        self.enable_incremental_updates = True
        self.render_cache.clear()  # 清理缓存重新开始
        print("🚀 已启用UI性能优化模式")
    
    def reset_performance_mode(self) -> None:
        """重置为正常模式"""
        self.max_table_rows = self.config.get('display', {}).get('max_table_rows', 50)
        self.enable_incremental_updates = self.config.get('display', {}).get('enable_incremental_updates', True)
        print("↩️ 已重置为正常显示模式")