# =============================================================================
# docker/down.ps1 —— 拆掉 CED 真实链路演示栈。
#
# 这个脚本做什么
#   docker compose --profile gunicorn down -v --remove-orphans
#     · 带上 --profile gunicorn：第二档的 gateway / backend 容器也要一起删
#     · -v：连匿名卷一起删（探针/nginx 都没挂卷，保险起见）
#     · --remove-orphans：清掉改过服务名之后留下的孤儿容器
#   **不会**删镜像：下次 up 不用重新构建。要连镜像一起清就手动
#   docker rmi nginx:1.25-alpine ced/probe:dev ced/backend:dev
#
# 前置条件
#   · Docker daemon 在运行（找不到 docker 会直接报错退出）
#   · 当前目录无所谓：脚本自己切到 docker/ 目录再执行 compose
#
# 用法
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/down.ps1
#
# 注意：本机已装 Docker Desktop（`F:\docker`），本脚本**已实机运行过**（2026-10-02）。
#       跑法必须带 `-ExecutionPolicy Bypass`：默认 Restricted 策略会直接拒绝加载脚本
#       （实测：`powershell -NoProfile -ExecutionPolicy Bypass -File docker/up.ps1` 报 running scripts is disabled）。
# =============================================================================

[CmdletBinding()]
param(
    # 只停容器不删网络/卷（默认 down -v 全清）
    [switch]$StopOnly
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[X] 找不到 docker 命令：本脚本需要 Docker Desktop / docker CLI + compose v2。" -ForegroundColor Red
    exit 1
}

if ($StopOnly) {
    $composeArgs = @("compose", "--profile", "gunicorn", "stop")
} else {
    $composeArgs = @("compose", "--profile", "gunicorn", "down", "-v", "--remove-orphans")
}

Write-Host "docker $($composeArgs -join ' ')" -ForegroundColor Cyan
& docker @composeArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "[X] compose 命令失败，先看上面的报错。" -ForegroundColor Red
    exit 1
}

Write-Host "已清理。镜像仍保留（下次 up 无需重新构建）。" -ForegroundColor Green
