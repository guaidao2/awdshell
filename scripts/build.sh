#!/usr/bin/env bash
# awdshell 单文件构建（Wails 原生窗口，Linux / macOS）
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== awdshell 单文件构建 ==="
echo "前端为免构建的静态资源（frontend/dist），会随 Go 一起打进单个可执行文件。"
echo "前置依赖：Go 1.24+ 与 Wails CLI（go install github.com/wailsapp/wails/v2/cmd/wails@latest）"
echo

wails build -clean -trimpath -ldflags "-s -w"

echo
echo "完成: build/bin/awdshell"
ls -lh build/bin/ 2>/dev/null || true
