#!/bin/bash

# 网络流量监控工具安装脚本

echo "🚀 安装网络流量监控工具"
echo "=========================="

# 检查Python版本
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 未安装，请先安装Python3"
    exit 1
fi

echo "✅ 检测到 Python: $(python3 --version)"

# 创建虚拟环境
if [ ! -d "venv" ]; then
    echo "🔧 创建Python虚拟环境..."
    python3 -m venv venv
fi

# 激活虚拟环境并安装依赖
echo "📦 激活虚拟环境并安装依赖包..."
source venv/bin/activate
pip install --upgrade pip
pip install rich

# 设置执行权限
chmod +x network_monitor.py

echo "✅ 安装完成！"
echo ""
echo "使用方法："
echo "  source venv/bin/activate && python3 network_monitor.py"
echo "  或者使用运行脚本: ./run.sh"
echo ""
echo "注意："
echo "  • 某些功能需要管理员权限"
echo "  • 按 Ctrl+C 退出监控"
echo "  • 工具会自动检测网络接口和本地网段"