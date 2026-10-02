# CED 探针镜像 —— 扮演"真实后端"。
#
# 为什么这么小：探针是纯标准库实现（零第三方依赖），只需要 ced/ 与 main.py。
# 构建上下文是**仓库根目录**（见 docker-compose.yml 的 build.context: ..），
# 根目录的 .dockerignore 已经把 refs/、results/、docs/、docker/images/ 等排除掉，
# 所以送进 daemon 的上下文很小。
#
# 构建与运行：
#   docker compose build probe
#   docker compose up -d probe
#
# 端口：8800 数据口（只在 compose 内部网络暴露给 front/backend）；
#       8801 控制口（compose 里映射到宿主 127.0.0.1:8801）。
#
# 注意：本机没有 Docker，本文件**未实机验证**（见 docker/README.md）。

FROM python:3.11-slim

WORKDIR /app

# 可复现与可观测：不写 .pyc、日志不缓冲（compose logs 能实时看到 "probe ready:" 行）
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 只拷贝运行探针所需的最小内容
COPY ced/ /app/ced/
COPY main.py /app/main.py

# 数据口 / 控制口（仅为文档作用，实际暴露由 compose 决定）
EXPOSE 8800 8801

# --policy ref-cl-first：探针扮演的后端基线策略。
# 想换成别的参照策略（ref-te-first 等，见 ced/impls/reference.py）改这里即可，
# 但改了之后拓扑文件里的说明也要同步改 —— 报告的"后端"口径会跟着变。
CMD ["python", "-m", "ced.probe.server", "--host", "0.0.0.0", "--data-port", "8800", "--api-port", "8801", "--policy", "ref-cl-first"]
