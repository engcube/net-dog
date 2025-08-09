#!/bin/bash

# 网络流量监控工具运行脚本

# 检查虚拟环境是否存在
if [ ! -d "venv" ]; then
    echo "❌ 虚拟环境不存在，请先运行 ./install.sh"
    exit 1
fi

# 激活虚拟环境并运行程序
echo "🚀 启动网络流量监控工具..."
source venv/bin/activate
python3 network_monitor.py