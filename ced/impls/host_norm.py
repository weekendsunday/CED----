"""可配置的 Host / 路由归一化读取器 —— 第三领域的参照实现内核。

与 ``path_norm.py`` 同构、只建模一件事：**同一段 Host 头字节，两个实现认为
它指向哪个虚拟主机（路由 / 缓存键）**。

耦合误差出在归一化上：前置按自己的归一化结果选路由或算缓存键、后端按自己的
归一化结果选站；两者不一致就是**虚拟主机绕过**（访问到本不该路由到的站）或
**缓存投毒**（一条响应被缓存到另一个键下喂给别人）。

归一化顺序（**刻意固定**：先解码、再做结构归一化）——
反过来的话 ``exa%6Dple.com`` 就永远不会被当成 ``example.com``，百分号类分歧也就
消失了。顺序本身不是策略开关，是这份内核的口径。

每个 :class:`HostPolicy` 对应一组真实世界中出现过的 Host 归一化策略组合。
参照实现用于**内部基准**（自证平台有效）；真实产品通过 probe 协议接入。
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

#: `%XX` 转义
_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
#: IPv4 字面量
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass(frozen=True)
class HostPolicy:
    """一组 Host 归一化策略开关。每一项都是一个真实存在的实现差异点。"""

    name: str = "host-literal"

    # 尾随点：DNS 里 `example.com.` 是 FQDN 的根，浏览器/curl 会剥掉；
    # nginx `server_name example.com` 却匹配不上带点的写法 → 路由/缓存键分叉。
    trailing_dot: str = "keep"          # keep | strip | reject

    # 主机名大小写：DNS 大小写不敏感，但基于原始字符串的 vhost 表/缓存键是敏感的。
    case_fold: str = "sensitive"        # sensitive | insensitive

    # 默认端口：RFC 7230 说 Host 只在非默认端口时带端口，但很多缓存/路由
    # 把 `example.com:80` 与 `example.com` 当成两个键（或反之归一为同一个）。
    default_port: str = "keep"          # keep | strip

    # userinfo：RFC 3986 authority 允许 `user@host`，HTTP Host 不该有；
    # WHATWG URL 解析器会剥掉 userinfo，朴素 Host 处理器则把整串当主机名
    # → 经典的 `evil.com@victim.com` 缓存投毒 / 虚拟主机绕过。
    userinfo: str = "keep"              # keep | strip | reject

    # 重复点（空标签）：`example..com` 在 DNS 里无效，但有的归一化会折叠它，
    # 于是与 `example.com` 的缓存键 / vhost 判定分叉。
    duplicate_dot: str = "keep"         # keep | collapse

    # IDN / 非 ASCII 主机名：浏览器按 IDNA 转成 A-label（punycode），
    # 只看原始字节的服务器却拿 Unicode 字节去比对 vhost。
    idn: str = "raw"                    # raw | idna | reject

    # IPv6 字面量：WHATWG URL 归一化为 RFC 5952 规范（压缩、小写）形式，
    # 朴素解析器逐字节保留 → `[0:...:1]` 与 `[::1]` 落在不同 ACL / 缓存键上。
    ipv6: str = "keep"                  # keep | canonical

    # 百分号编码主机名：RFC 3986 reg-name 允许 `%XX`，有的反向代理会解码 Host，
    # 有的原样保留 → `exa%6Dple.com` 与 `example.com` 分叉。
    percent_host: str = "keep"          # keep | decode | reject

    #: 前置实际转发出去的形式。**只影响链路模型**，不影响单侧归一化。
    forward_form: str = "raw"           # raw | normalized


@dataclass
class HostResult:
    """一次 Host 归一化的完整结果 —— 就是"这个实现认为这段字节属于哪个站"。"""

    ok: bool = True
    status: int = 200
    reason: str = "OK"
    #: 归一化后的主机名（不含端口；userinfo=keep 时含 userinfo）
    norm_host: str = ""
    #: 解析出的端口；无 / 被剥离时为 None
    port: int | None = None
    #: 主机字面量是否是 IP（IPv4 / IPv6）
    is_ip: bool = False
    #: 归一化结果里是否仍保留 userinfo（keep 且输入带 `@` 时为真）
    has_userinfo: bool = False
    notes: list[str] = field(default_factory=list)

    def to_fields(self) -> dict:
        return {
            "accepted": self.ok,
            "status": self.status,
            "norm_host": self.norm_host,
            "port": self.port,
            "is_ip": self.is_ip,
            "has_userinfo": self.has_userinfo,
        }


# --------------------------------------------------------------------------- 工具

def _percent_decode(text: str) -> tuple[str, bool]:
    """解一层百分号编码（大小写都认）。不合法/残缺的 `%` 原样保留。"""
    out: list[str] = []
    changed = False
    i, n = 0, len(text)
    while i < n:
        if (text[i] == "%" and i + 3 <= n
                and _is_hex(text[i + 1]) and _is_hex(text[i + 2])):
            out.append(chr(int(text[i + 1:i + 3], 16)))
            i += 3
            changed = True
        else:
            out.append(text[i])
            i += 1
    return "".join(out), changed


def _is_hex(ch: str) -> bool:
    return ch in "0123456789abcdefABCDEF"


def _split_port(text: str) -> tuple[str, int | None]:
    """把 authority 拆成 (主机部分, 端口)。IPv6 的 `[...]` 特殊处理。"""
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return text, None
        rest = text[end + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            return text[:end + 1], int(rest[1:])
        return text, None
    idx = text.rfind(":")
    if idx != -1 and text[idx + 1:].isdigit():
        return text[:idx], int(text[idx + 1:])
    return text, None


def _collapse_dots(host: str) -> str:
    """把连续的点折叠成一个（合并空标签）。"""
    return re.sub(r"\.{2,}", ".", host)


def _to_alabel(host: str) -> str | None:
    """把含非 ASCII 的主机名转成 IDNA A-label（punycode）。失败返回 None。"""
    try:
        text = host.encode("latin-1").decode("utf-8")
    except UnicodeError:
        return None
    try:
        return text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None


def _ipv6_canonical(inner: str) -> str | None:
    """把方括号里的 IPv6 归一化为 RFC 5952 规范形式。失败返回 None。"""
    try:
        return str(ipaddress.IPv6Address(inner))
    except ValueError:
        return None


# --------------------------------------------------------------------------- 主入口

def normalize_host(payload: bytes, policy: HostPolicy) -> HostResult:
    """按 ``policy`` 归一化一段 Host 头字节。

    ``payload`` 是 Host 头的**值**（authority 部分）的原样字节，
    例如 ``b"example.com."`` / ``b"user@example.com:80"`` / ``b"[0:0:0:0:0:0:0:1]"``。
    """
    text = payload.decode("latin-1")
    notes: list[str] = []

    # ① 先解码（顺序刻意固定，见模块 docstring）
    if policy.percent_host == "reject" and _ESCAPE.search(text):
        return HostResult(ok=False, status=400, reason="percent_encoded_host",
                          notes=["Host 含百分号编码，按策略拒绝"])
    if policy.percent_host == "decode":
        text, changed = _percent_decode(text)
        if changed:
            notes.append("百分号编码已解一层")

    # ② userinfo
    has_userinfo = False
    if "@" in text:
        if policy.userinfo == "reject":
            return HostResult(ok=False, status=400, reason="userinfo",
                              notes=["Host 含 userinfo，按策略拒绝"])
        if policy.userinfo == "strip":
            text = text.split("@", 1)[1]
            notes.append("userinfo 已剥离")
        else:
            has_userinfo = True
            notes.append("userinfo 原样保留（被当作主机名的一部分）")

    # ③ 端口
    host_text, port = _split_port(text)
    if port is not None and policy.default_port == "strip" and port in (80, 443):
        notes.append(f"默认端口 {port} 已剥离")
        port = None

    # ④ 主机部分结构归一化
    is_ip = False
    if host_text.startswith("[") and host_text.endswith("]"):
        is_ip = True
        inner = host_text[1:-1]
        if policy.ipv6 == "canonical":
            canon = _ipv6_canonical(inner)
            if canon is not None:
                host_text = f"[{canon}]"
                notes.append("IPv6 已归一化为 RFC 5952 规范形式")
            else:
                notes.append("IPv6 解析失败，原样保留")
    else:
        if any(ord(ch) > 127 for ch in host_text):
            if policy.idn == "reject":
                return HostResult(ok=False, status=400, reason="non_ascii_host",
                                  notes=["主机名含非 ASCII 字节，按策略拒绝"])
            if policy.idn == "idna":
                alabel = _to_alabel(host_text)
                if alabel is not None:
                    host_text = alabel
                    notes.append("非 ASCII 主机名已转 A-label（punycode）")
                else:
                    notes.append("IDNA 转换失败，原样保留")
        if policy.duplicate_dot == "collapse":
            collapsed = _collapse_dots(host_text)
            if collapsed != host_text:
                host_text = collapsed
                notes.append("重复点（空标签）已折叠")
        if host_text.endswith("."):
            if policy.trailing_dot == "reject":
                return HostResult(ok=False, status=400, reason="trailing_dot",
                                  notes=["主机名以点结尾，按策略拒绝"])
            if policy.trailing_dot == "strip":
                host_text = host_text.rstrip(".")
                notes.append("尾随点已剥离")
        is_ip = bool(_IPV4.match(host_text))

    # ⑤ 大小写
    if policy.case_fold == "insensitive":
        lowered = host_text.lower()
        if lowered != host_text:
            host_text = lowered
            notes.append("主机名已小写化")

    return HostResult(ok=True, status=200, reason="OK", norm_host=host_text,
                      port=port, is_ip=is_ip, has_userinfo=has_userinfo,
                      notes=notes)


__all__ = ["HostPolicy", "HostResult", "normalize_host"]
