# CED 第二档演示的后端：真正的 gunicorn 进程管理器 + 一个最小 WSGI 应用。
#
#   链路：client → nginx(gateway, 8081) → **本容器 gunicorn(8090)** → probe:8800
#
# 应用自身零第三方依赖（docker/backend/app.py 只用标准库）；
# 这里只装 gunicorn —— 我们需要的是一个**真实的 WSGI 服务器**来解析 HTTP，
# 而不是自己写一个玩具解析器。
#
# 构建上下文是 docker/backend/（见 docker-compose.yml 的 build.context）。
#
# 构建需要联网装 gunicorn。现场断网时用 docker/snapshot.ps1 预先 save 好的镜像：
#   docker load -i ../images/ced_backend_dev.tar
#   docker compose --profile gunicorn up -d --no-build
#
# 本机没有 Docker，本文件**未实机验证**（见 docker/README.md）。

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN pip install --no-cache-dir "gunicorn>=21,<24"

COPY app.py /app/app.py

EXPOSE 8090

# --forwarded-allow-ips 是本档演示的关键开关，默认值故意写成 127.0.0.1：
#   gunicorn 默认**不采信**来自非受信对端的 X-Forwarded-*；而 nginx 是另一个容器，
#   它的 IP 不是 127.0.0.1 —— 也就是说默认配置下 nginx 发的 X-Forwarded-For 被丢弃，
#   environ 里的 REMOTE_ADDR 会是 nginx 的容器地址。
#   compose 里把 CED_FORWARDED_ALLOW_IPS 设成 nginx(gateway) 的固定 IP 172.28.0.3，
#   于是 X-Forwarded-* 被采信 —— 用 /environ 的 REMOTE_ADDR 前后对比就能看到差别。
#   **不要写 "*"**：那等于采信任何客户端伪造的 X-Forwarded-For，
#   日志里的"攻击者地址"就成了攻击者自己填的。
#
# --access-logfile - ：把 gunicorn 解析出的请求行（它自己的定帧结论）打到容器日志，
#   是排查"到底谁把这条请求读成了什么"的第一手证据：docker compose logs backend
#
# --workers 1 --worker-class sync ：单人复现用，行为确定、日志不交错。
ENV CED_FORWARDED_ALLOW_IPS=127.0.0.1

CMD exec gunicorn --bind 0.0.0.0:8090 --workers 1 --worker-class sync --access-logfile - --log-level info --forwarded-allow-ips=${CED_FORWARDED_ALLOW_IPS} app:application
