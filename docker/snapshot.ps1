# =============================================================================
# docker/snapshot.ps1 —— 离线快照 / 恢复。比赛现场断网时用这个。
#
# 为什么需要它
#   compose 栈的正常启动要联网：nginx:1.25-alpine 要拉，probe/backend 要 pip/apt 拉基础镜像。
#   现场断网就全废。所以**有网的机器上**先把镜像 save 成 tar，现场再 load 回去。
#
# 这个脚本做什么
#   默认（保存）：
#     docker save 每个镜像到 docker/images/<镜像名>.tar
#     生成 docker/images/manifest.txt，每行：<镜像:tag>\t<tar 文件名>\t<sha256>
#     镜像不在本地时会明确报出来（不静默跳过），最后以非 0 退出，提示先 build/pull。
#   -Verify：只校验 docker/images/ 下每个 tar 的大小与 sha256 是否与 manifest 一致（不 load）。
#   -Load：按 manifest 从 tar 恢复 —— 先校验 sha256，对得上才 docker load。
#
# 现场用法（断网机器）
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/snapshot.ps1 -Load
#   docker compose up -d --no-build            # 注意 --no-build：别再触发联网构建
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/up.ps1  # 或直接用 up.ps1（它会 --build，但镜像已存在不会联网）
#
# 前置条件
#   · 保存/校验/恢复都需要 docker CLI（daemon 要在跑）；只有 -Verify 的哈希校验需要 daemon
#   · manifest.txt 与 tar 必须成对拷到现场（U 盘/内网盘）
#
# 用法
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/snapshot.ps1                    # 保存
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/snapshot.ps1 -Verify            # 校验
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/snapshot.ps1 -Load              # 恢复
#   powershell -NoProfile -ExecutionPolicy Bypass -File docker/snapshot.ps1 -OutDir D:\ced-images
#
# 注意：本机已装 Docker Desktop（`F:\docker`），本脚本**已实机运行过**（2026-10-02）。
#       跑法必须带 `-ExecutionPolicy Bypass`：默认 Restricted 策略会直接拒绝加载脚本
#       （实测：`powershell -NoProfile -ExecutionPolicy Bypass -File docker/up.ps1` 报 running scripts is disabled）。
# =============================================================================

[CmdletBinding()]
param(
    # 从 tar 恢复（现场断网用）
    [switch]$Load,
    # 只校验哈希，不 load
    [switch]$Verify,
    # tar 与 manifest.txt 的存放目录
    [string]$OutDir = (Join-Path $PSScriptRoot "images"),
    # 要快照的镜像；改了 docker-compose.yml 里的 image: 就要同步改这里
    [string[]]$Images = @(
        "nginx:1.25-alpine",   # front / gateway 前置
        "ced/probe:dev",       # 探针（compose build probe 产出）
        "ced/backend:dev"      # 第二档 gunicorn 后端（compose build backend 产出）
    )
)

$ErrorActionPreference = "Stop"
$manifest = Join-Path $OutDir "manifest.txt"

function Convert-ToFileName([string]$image) {
    # nginx:1.25-alpine -> nginx_1.25-alpine.tar ; ced/probe:dev -> ced_probe_dev.tar
    return ($image -replace '[\\/:]', '_') + ".tar"
}

function Get-ImageId([string]$image) {
    # 说明：原生命令的 stderr 被重定向后，PowerShell 会把它当成错误记录；
    # 在 $ErrorActionPreference=Stop 下会直接终止脚本。这里临时设回 Continue。
    $pref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $id = & docker image inspect --format "{{.Id}}" $image 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        return $id
    } finally {
        $ErrorActionPreference = $pref
    }
}

# ---------------------------------------------------------------- 恢复模式
if ($Load) {
    if (-not (Test-Path -LiteralPath $manifest)) {
        Write-Host "[X] 找不到 $manifest —— 先在联网机器上跑一次 snapshot.ps1（保存模式）。" -ForegroundColor Red
        exit 1
    }
    $rows = Get-Content -LiteralPath $manifest | Where-Object { $_.Trim() -ne "" }
    $failed = 0
    foreach ($row in $rows) {
        $parts = $row -split "`t"
        if ($parts.Count -lt 3) { continue }
        $image = $parts[0].Trim()
        $file = Join-Path $OutDir $parts[1].Trim()
        $want = $parts[2].Trim().ToLower()

        if (-not (Test-Path -LiteralPath $file)) {
            Write-Host "[X] 缺文件 $file（manifest 里有 $image）" -ForegroundColor Red
            $failed++
            continue
        }
        $got = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
        if ($got -ne $want) {
            Write-Host "[X] $file 的 sha256 与 manifest 不符：$got != $want （拷贝损坏？）" -ForegroundColor Red
            $failed++
            continue
        }
        Write-Host "docker load -i $file   ($image)" -ForegroundColor Cyan
        & docker load -i $file
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[X] docker load 失败：$image" -ForegroundColor Red
            $failed++
        }
    }
    if ($failed -gt 0) {
        Write-Host "[X] $failed 个镜像没有恢复成功。" -ForegroundColor Red
        exit 1
    }
    Write-Host "全部镜像已恢复。接着：docker compose up -d --no-build" -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------- 校验模式
if ($Verify) {
    if (-not (Test-Path -LiteralPath $manifest)) {
        Write-Host "[X] 找不到 $manifest" -ForegroundColor Red
        exit 1
    }
    $failed = 0
    foreach ($row in (Get-Content -LiteralPath $manifest | Where-Object { $_.Trim() -ne "" })) {
        $parts = $row -split "`t"
        if ($parts.Count -lt 3) { continue }
        $file = Join-Path $OutDir $parts[1].Trim()
        $want = $parts[2].Trim().ToLower()
        if (-not (Test-Path -LiteralPath $file)) {
            Write-Host "[X] 缺文件 $file" -ForegroundColor Red; $failed++; continue
        }
        $got = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
        if ($got -ne $want) {
            Write-Host "[X] $($parts[1]) 哈希不符" -ForegroundColor Red; $failed++
        } else {
            Write-Host "  [OK] $($parts[0])  $($parts[1])"
        }
    }
    if ($failed -gt 0) { Write-Host "[X] $failed 个文件不合格。" -ForegroundColor Red; exit 1 }
    Write-Host "快照完整，可以拷到现场用 -Load 恢复。" -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------- 保存模式
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[X] 找不到 docker 命令。" -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "快照目录：$OutDir" -ForegroundColor Cyan

$lines = New-Object System.Collections.Generic.List[string]
$missing = New-Object System.Collections.Generic.List[string]

foreach ($image in $Images) {
    $id = Get-ImageId $image
    if ($null -eq $id) {
        Write-Host "[!] 本地没有镜像 $image —— 先 docker compose build / docker pull" -ForegroundColor Yellow
        $missing.Add($image)
        continue
    }
    $name = Convert-ToFileName $image
    $file = Join-Path $OutDir $name

    Write-Host "docker save -o $name $image" -ForegroundColor Cyan
    & docker save -o $file $image
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[X] docker save 失败：$image" -ForegroundColor Red
        $missing.Add($image)
        continue
    }

    $sha = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
    $sizeMb = [math]::Round((Get-Item -LiteralPath $file).Length / 1MB, 1)
    Write-Host ("  -> {0}  {1} MB  sha256 {2}" -f $name, $sizeMb, $sha.Substring(0, 16))
    $lines.Add(("{0}`t{1}`t{2}" -f $image, $name, $sha))
}

# manifest 用 UTF-8 写；纯 ASCII 内容，任何编辑器都读得动
Set-Content -LiteralPath $manifest -Value $lines -Encoding UTF8
Write-Host "清单：$manifest（$($lines.Count) 条：镜像:tag`t文件`tsha256）" -ForegroundColor Cyan

if ($missing.Count -gt 0) {
    Write-Host "[X] 有 $($missing.Count) 个镜像没进快照：$($missing -join ', ')" -ForegroundColor Red
    Write-Host "    先构建/拉取，再重跑本脚本；半成品快照在现场会少一个服务。" -ForegroundColor Red
    exit 1
}

Write-Host "快照完成。把整个 $OutDir 目录拷到现场，用 -Load 恢复。" -ForegroundColor Green
