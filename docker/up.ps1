# =============================================================================
# docker/up.ps1 —— 起 CED 真实链路演示栈，并等到探针控制口真的 ready 才返回。
#
# 这个脚本做什么
#   1) docker compose up -d --build（默认只起 probe + front 两个服务）
#   2) 轮询 http://127.0.0.1:8801/health，直到探针 ready（带超时，失败给排查线索）
#   3) 冒烟：从宿主 8080 发一条原始请求穿过 nginx，把探针的观测 JSON 打出来
#
# 前置条件
#   · 装了 Docker Desktop / docker CLI + compose v2（`docker compose version` 能用）
#   · Docker daemon 正在运行
#   · 宿主端口 8080、8801 空闲（加 -Gunicorn 时还要 8081、8090 空闲）
#   · 仓库根目录里有 ced/ 与 main.py —— 探针镜像的构建上下文就是仓库根
#   · 首次构建 nginx/probe 镜像需要能拉取基础镜像（现场断网见 docker/README.md 的离线快照）
#
# 用法
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/up.ps1                  # 第一档：probe + front
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/up.ps1 -Gunicorn        # 第二档：加 gateway + backend
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/up.ps1 -TimeoutSec 180
#
# 注意：本机已装 Docker Desktop（`F:\docker`），本脚本**已实机运行过**（2026-10-02）。
#       跑法必须带 `-ExecutionPolicy Bypass`：默认 Restricted 策略会直接拒绝加载脚本
#       （实测：`powershell -NoProfile -ExecutionPolicy Bypass -File docker/up.ps1` 报 running scripts is disabled）。
# =============================================================================

[CmdletBinding()]
param(
    # 同时启动第二档演示：nginx(gateway) → gunicorn(backend) → 探针
    [switch]$Gunicorn,
    # 等探针控制口 ready 的超时（秒）
    [int]$TimeoutSec = 90
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

function Stop-WithMessage([string]$message) {
    Write-Host "[X] $message" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------- 前置检查
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Stop-WithMessage "找不到 docker 命令：本脚本需要 Docker Desktop / docker CLI + compose v2。"
}

# 说明：`docker info` 失败时会往 stderr 写东西，而 Windows PowerShell 5.1 里
# 把原生命令的 stderr 重定向后会被当成错误记录（$ErrorActionPreference=Stop 会直接终止）。
# 所以这里临时把偏好设回 Continue，用退出码判断。
$pref = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& docker info *> $null
$daemonOk = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $pref

if (-not $daemonOk) {
    Stop-WithMessage "Docker daemon 不可用（Docker Desktop 没启动？）。"
}

# 宿主端口预检：早报比 compose 报"port is already allocated"清楚得多。
# 本开发机上 8080 就被 Steam 的 steamwebhelper 占着（不是 Windows 保留）。
$needPorts = @(8080, 8801)
if ($Gunicorn) { $needPorts += @(8081, 8090) }
$busy = @()
foreach ($p in $needPorts) {
    $holder = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue
    if ($holder) {
        $names = ($holder | ForEach-Object {
            (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        } | Where-Object { $_ } | Select-Object -Unique) -join ", "
        $busy += ("{0} (pid {1} {2})" -f $p, ($holder[0].OwningProcess), $names)
    }
}
if ($busy.Count -gt 0) {
    Write-Host "[!] 这些宿主端口已被占用：$($busy -join '; ')" -ForegroundColor Yellow
    Write-Host "    要么关掉占用者，要么改 docker/docker-compose.yml 的 ports 并**同步改**" -ForegroundColor Yellow
    Write-Host "    ced/topologies/real-*.yaml 里的 endpoint（端口是对应的）。" -ForegroundColor Yellow
    Stop-WithMessage "宿主端口不空闲，先处理再重跑。"
}

# ---------------------------------------------------------------- 1) up
$composeArgs = @("compose")
if ($Gunicorn) { $composeArgs += @("--profile", "gunicorn") }
$composeArgs += @("up", "-d", "--build")

Write-Host "[1/3] docker $($composeArgs -join ' ')" -ForegroundColor Cyan
& docker @composeArgs
if ($LASTEXITCODE -ne 0) {
    Stop-WithMessage "compose up 失败，先看上面的报错（构建镜像需要网络拉基础镜像）。"
}

# ---------------------------------------------------------------- 2) 等探针 ready
Write-Host "[2/3] 等探针控制口 ready（最多 $TimeoutSec 秒）" -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$health = $null
while ((Get-Date) -lt $deadline) {
    try {
        $resp = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 `
            -Uri "http://127.0.0.1:8801/health"
        if ($resp.StatusCode -eq 200) { $health = $resp.Content; break }
    } catch {
        # 端口还没通是正常的，继续轮询
    }
    Start-Sleep -Milliseconds 500
}

if ($null -eq $health) {
    Write-Host "[!] 超时：探针控制口 8801 未就绪。以下现场信息用于排查：" -ForegroundColor Yellow
    & docker compose ps
    & docker compose logs --tail 40 probe
    Stop-WithMessage "探针未就绪。栈保持原状（不自动 down），方便你进去看。"
}
Write-Host "     探针 ready -> $health"

# ---------------------------------------------------------------- 3) 冒烟
# 从宿主发一条最普通的 POST 穿过 nginx，直接看探针记录到的观测 JSON。
# 说明：nginx 不会对上游半关闭，探针要等到自己的空闲超时（5 秒）才处理这条请求，
#       所以这里最多等 15 秒 —— 这是探针的设计（见 ced/probe/server.py IDLE_TIMEOUT）。
Write-Host "[3/3] 冒烟：POST /ced-smoke 经 nginx 转发，看探针记录了哪些字段" -ForegroundColor Cyan
$raw = "POST /ced-smoke HTTP/1.1`r`nHost: 127.0.0.1:8080`r`nContent-Length: 5`r`nConnection: close`r`n`r`nHELLO"
$client = New-Object System.Net.Sockets.TcpClient
try {
    $client.Connect("127.0.0.1", 8080)
    $stream = $client.GetStream()
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($raw)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    # 半关闭写端：告诉 nginx"我发完了"
    $client.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)

    $stream.ReadTimeout = 15000
    $buffer = New-Object byte[] 65536
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
        $n = $stream.Read($buffer, 0, $buffer.Length)
        if ($n -le 0) { break }
        [void]$sb.Append([System.Text.Encoding]::UTF8.GetString($buffer, 0, $n))
    }
    Write-Host $sb.ToString()
} catch {
    Write-Host "[!] 冒烟请求失败：$($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    先看 docker compose logs front 与 docker compose logs probe。" -ForegroundColor Yellow
} finally {
    $client.Close()
}

Write-Host ""
Write-Host "栈已就绪。下一步：" -ForegroundColor Green
Write-Host "  python -m ced scan --topology ced/topologies/real-nginx-probe.yaml --limit 12 --out results/real.md"
Write-Host "  （--limit 12 是必须的：前置不会半关闭，探针每条请求要等 5 秒，见 docker/README.md）"
Write-Host "  收工：powershell -NoProfile -ExecutionPolicy Bypass -File docker/down.ps1"
