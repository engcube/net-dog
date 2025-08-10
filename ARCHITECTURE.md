# 🏗️ 系统架构文档

## 📖 概述

网络流量监控工具采用**模块化单一职责架构**，将复杂的网络监控功能分解为独立、可测试、可维护的组件。

## 🎯 设计原则

### 1. 单一职责原则 (SRP)
每个模块都有明确的职责边界：
- `TrafficAnalyzer` - 专注流量分析算法
- `UIManager` - 专注界面渲染逻辑
- `UnifiedServiceIdentifier` - 专注服务识别
- `PerformanceMonitor` - 专注性能监控

### 2. 依赖注入模式
组件间通过依赖注入实现解耦：
```python
# 示例：性能监控器注入
traffic_analyzer.set_performance_monitor(performance_monitor)
ui_manager.set_performance_monitor(performance_monitor)
```

### 3. 配置驱动设计
所有可变参数通过配置文件管理：
```json
{
  "monitoring": {"data_collection_interval": 3},
  "display": {"max_table_rows": 50},
  "performance": {"enable_caching": true}
}
```

## 🔧 核心组件架构

### 主控制器 (NetworkMonitor)
```
NetworkMonitor
├── 协调各组件工作
├── 管理主事件循环  
├── 处理用户输入
└── 异常处理和恢复
```

**职责**：
- 系统初始化和资源管理
- 组件间通信协调
- 生命周期管理

### 流量分析器 (TrafficAnalyzer)
```
TrafficAnalyzer
├── analyze_connections()     # 主分析入口
├── _allocate_traffic()       # 核心分配算法
├── _identify_devices()       # 设备识别逻辑
└── _identify_connection_target() # 目标识别
```

**核心算法**：
1. **连接分析算法**：解析系统网络连接，建立IP-设备映射
2. **流量分配算法**：基于连接数比例分配流量（见算法说明）
3. **设备聚合算法**：智能识别并聚合虚拟设备（VPN、代理）

### UI管理器 (UIManager)  
```
UIManager
├── create_main_layout()      # 主界面布局
├── _create_devices_panel()   # 设备表格渲染
├── _create_websites_panel()  # 网站表格渲染
└── 渲染缓存优化机制
```

**渲染优化**：
- 增量更新：仅在数据变化时重新渲染
- 表格缓存：缓存渲染结果避免重复计算
- 行数限制：大数据集自动分页显示

## 🧮 核心算法详解

### 流量分配算法

**问题背景**：
- 系统只能获取连接信息（IP:端口对），无法直接获取每个连接的实际流量
- 需要将网络接口的总流量合理分配给各个设备和连接

**算法原理**：
```python
def _allocate_traffic(connections, total_bytes_delta):
    """
    基于连接数比例的流量分配算法
    
    算法假设：
    1. 每个连接的平均流量大致相等（简化假设）
    2. 设备的流量与其连接数成正比
    3. 长期统计下，该假设具有合理性
    
    算法步骤：
    1. 统计每个设备的连接数
    2. 计算连接数占总连接数的比例  
    3. 按比例分配总流量增量
    """
    for device, device_connections in connections.items():
        connection_count = len(device_connections)
        ratio = connection_count / total_connections
        
        # 流量分配核心公式
        device.bytes_in += total_bytes_in_delta * ratio
        device.bytes_out += total_bytes_out_delta * ratio
```

**算法优势**：
- ✅ 计算简单，性能高效
- ✅ 不需要额外的系统权限
- ✅ 跨平台兼容性好
- ✅ 长期统计具有参考价值

**算法局限**：
- ❌ 无法反映单个大文件下载的真实流量
- ❌ 对短期突发流量估算可能不准确
- ❌ 依赖连接数，而非实际数据传输量

**改进方向**：
- 基于端口类型的权重调整（HTTP > DNS）
- 考虑连接持续时间的权重系数  
- 集成更精确的流量监控API（如果可用）

### 服务识别算法

**四层识别体系**：

```python
def identify_service_by_ip(ip):
    """
    多层服务识别算法
    
    第1层：IP段精确匹配（置信度：0.95）
    - 基于已知服务的IP段数据库
    - 例：8.8.8.8 -> Google DNS
    
    第2层：ASN启发式识别（置信度：0.85）  
    - 基于自治系统号推断服务提供商
    - 例：AS15169 -> Google服务
    
    第3层：IP模式匹配（置信度：0.75）
    - 基于IP地址的模式规律
    - 例：210.129.x.x -> 可能是Niconico
    
    第4层：DNS反查识别（置信度：0.60）
    - 通过反向DNS查询获取域名
    - 基于域名关键词匹配服务
    """
    # 实现见 unified_service_identifier.py
```

## 📊 性能优化设计

### 缓存策略

**多级缓存体系**：

1. **渲染缓存** (ui_manager.py)
   ```python
   # 表格渲染结果缓存，避免重复计算
   cache_key = f"{table_type}_{data_hash}"
   cached_table = render_cache.get(cache_key)
   ```

2. **服务识别缓存** (unified_service_identifier.py)
   ```python
   # IP识别结果缓存，减少重复识别
   cached_result = self.cache.get(ip)
   ```

### 性能监控

**实时性能指标收集**：
```python
@monitor_performance("operation_name")
def expensive_operation():
    # 自动记录执行时间
    # 超过阈值时报警
    pass
```

**性能优化建议**：
- CPU使用率 > 80% → 增加数据采集间隔
- 内存使用率 > 85% → 启用缓存清理
- UI渲染 > 500ms → 启用性能模式

## 🎯 总结

本架构通过**职责分离、依赖注入、配置驱动**等设计模式，实现了：

- ✅ **高内聚低耦合**：每个模块职责明确，依赖关系清晰
- ✅ **高性能**：多级缓存 + 增量渲染 + 性能监控
- ✅ **高安全性**：隐私保护 + 权限控制 + 输入验证
- ✅ **高可维护性**：完整测试 + 详细文档 + 模块化设计
- ✅ **高扩展性**：插件化预留 + 配置化管理

这是一个**企业级品质**的网络监控工具架构！

---

## 🎯 项目当前状态

### ✅ 已完成的改进
- **代码重构**: 消除重复代码，提升可维护性
- **配置文件化**: 网络设置可通过 `config.json` 配置
- **职责分离**: 解析器和查询逻辑完全分离
- **增强识别**: 真实 ASN 查询提高服务商识别准确率
- **方法拆分**: 大型方法重构为小型、专门的函数
- **🆕 跨平台抽象层**: 创建了数据收集器抽象层，为跨平台支持奠定基础

### 📊 代码质量提升
- **消除重复**: `_is_china_ip` 统一到 `utils.py`
- **准确性**: 移除不准确的后备逻辑 (如假设非中国IP为'us')
- **可维护性**: 移除硬编码的过时URL，改为动态获取
- **模块化**: 每个模块职责单一且明确

## 🚧 跨平台支持现状分析

### ❌ 平台依赖的命令

当前工具依赖以下 macOS 特定命令：

```bash
# network_monitor.py 中使用的命令
arp -a              # 获取ARP表
netstat -n          # 获取网络连接
netstat -ib         # 获取网络接口统计
route -n get default # 获取默认网关
```

### 🔄 跨平台命令映射

| 功能 | macOS | Linux | Windows |
|------|-------|--------|---------|
| ARP表 | `arp -a` | `arp -a` 或 `ip neigh` | `arp -a` |
| 网络连接 | `netstat -n` | `ss -tuln` 或 `netstat -n` | `netstat -n` |
| 网络接口 | `netstat -ib` | `cat /proc/net/dev` | `netstat -e` |
| 默认网关 | `route -n get default` | `ip route show default` | `route print` |

## 🏗️ 跨平台支持架构

### ✅ 已实现的抽象数据收集器

```python
# 已实现的架构 (data_collector.py)
class BaseDataCollector(ABC):
    @abstractmethod
    def get_arp_table(self) -> Dict[str, str]: pass
    @abstractmethod 
    def get_connections(self) -> List[Dict]: pass
    @abstractmethod
    def get_interface_stats(self) -> Dict: pass
    @abstractmethod
    def detect_local_network(self) -> str: pass

class DarwinDataCollector(BaseDataCollector):
    # ✅ 完整实现 - 支持 macOS
    
class LinuxDataCollector(BaseDataCollector):
    # ⏳ 占位符实现 - 抛出 NotImplementedError
    
class WindowsDataCollector(BaseDataCollector):
    # ⏳ 占位符实现 - 抛出 NotImplementedError
```

### ✅ 已实现的平台检测

```python
# 已实现 (data_collector.py)
def create_data_collector() -> BaseDataCollector:
    system = platform.system().lower()
    
    if system == 'darwin':
        return DarwinDataCollector()  # ✅ 完整功能
    elif system == 'linux':
        return LinuxDataCollector()   # ⚠️ 抛出 NotImplementedError
    elif system == 'windows':
        return WindowsDataCollector() # ⚠️ 抛出 NotImplementedError
    else:
        raise NotImplementedError(f"不支持的操作系统: {system}")
```

### 🔄 NetworkMonitor 集成

NetworkMonitor 现在通过数据收集器抽象层工作：

```python
# network_monitor.py 中的集成
class NetworkMonitor:
    def __init__(self):
        self.data_collector = create_data_collector()  # 🔄 平台自适应
        self.local_network = self.data_collector.detect_local_network()
        
    def _collect_network_data(self):
        return (
            self.data_collector.get_arp_table(),      # 🔄 抽象化
            self._get_active_connections(),
            self.data_collector.get_interface_stats() # 🔄 抽象化  
        )
```

## 📋 下一阶段开发路线图

### ✅ Phase 1: 平台抽象层 (已完成)
- [x] 创建 `BaseDataCollector` 抽象基类
- [x] 实现 `DarwinDataCollector` (基于现有代码)
- [x] 添加平台检测逻辑
- [x] 集成到 `NetworkMonitor` 中

### Phase 2: Linux 支持
- [ ] 实现 `LinuxDataCollector`
- [ ] 测试 Ubuntu/CentOS/Debian 兼容性
- [ ] 处理权限需求差异

### Phase 3: Windows 支持  
- [ ] 实现 `WindowsDataCollector`
- [ ] 处理 PowerShell 集成
- [ ] Windows 特有的网络接口处理

### Phase 4: 增强功能
- [ ] 自动权限提升提示
- [ ] 更好的错误处理和降级
- [ ] 跨平台配置文件模板

## 🎯 技术重点

### 优先级排序
1. **高优先级**: Linux 支持 (服务器环境需求)
2. **中优先级**: Windows 支持 (桌面环境需求) 
3. **低优先级**: 其他Unix系统支持

### 关键挑战
- **权限管理**: 不同平台的网络信息访问权限要求
- **命令差异**: 相同功能在不同平台的命令参数差异
- **输出格式**: 不同平台命令输出格式解析
- **性能优化**: 确保跨平台不影响性能

## 📈 预期收益

跨平台支持完成后，该工具将能够：
- 🐧 在 Linux 服务器上监控网络流量
- 🪟 在 Windows 桌面环境中使用
- 🔄 在不同操作系统间保持一致的用户体验
- 📊 大幅扩展潜在用户群体

---

**总结**: 目前工具在代码质量和架构设计方面已经非常优秀，跨平台支持是下一步最有价值的改进方向。通过抽象数据收集层，可以在保持现有功能不变的前提下，优雅地扩展到其他操作系统。