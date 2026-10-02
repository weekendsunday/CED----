"""可配置的「字节 → 文本」解释内核 —— 编码 / Unicode 归一化领域的参照实现内核。

与 ``path_norm.py`` / ``http_reader.py`` 同构，只建模一件事：
**同一段字节，两个实现把它解释成了什么文本**。

不碰路径结构（那是 url-norm 的地盘）：本内核只回答"这段字节是什么字符"——
百分号转义、过长 UTF-8、UTF-8 还是 Latin-1、Unicode 规范化形式、全角折叠、
Unicode 大小写折叠、`%uXXXX` 遗留转义、孤立代理项、`%00` 截断。
其中的每一种都对应过真实的**过滤器绕过**（WAF 关键字黑名单、路径前缀、扩展名白名单）。

每个 :class:`EncPolicy` 对应一组真实世界中出现过的解释策略组合。参照实现用于
**内部基准**（自证平台有效）；真实产品通过 probe 协议接入。

解释顺序（**刻意固定**，写在这里以免被误当成实现细节）：
    ① `%uXXXX` 解码（若开启）→ ② `%XX` 解码 → ③ 字节按 utf-8 / latin-1 解码
    → ④ Unicode 规范化 → ⑤ 全角折叠 → ⑥ 大小写折叠 → ⑦ NUL 截断
顺序反过来的话，`%u002f` 就不会被先解成 `/`，遗留转义类分歧也就消失了。
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

@dataclass(frozen=True)
class EncPolicy:
    """一组「字节 → 文本」解释策略开关。每一项都是一个真实存在的实现差异点。"""

    name: str = "default"

    # 过长 UTF-8 序列是否接受（`%c0%af` → `/`）。
    # 先例：IIS 4.0/5.0 的 Unicode 编码漏洞（`%c0%af` 绕过路径检查，CVE-2000-0884）；
    # 现代严格 UTF-8 解码器一律拒绝过长序列（RFC 3629）。
    overlong_utf8: str = "reject"        # reject | accept

    # Unicode 规范化形式。先例：macOS 文件系统用 NFD、浏览器/多数 WAF 用 NFC；
    # 同一串"看起来一样"的文本在两种形式下码点不同（é = U+00E9 vs e+U+0301）。
    unicode_form: str = "none"           # none | nfc | nfd

    # 全角字符是否折叠成 ASCII。先例：全角斜杠 `／`（U+FF0F）、全角点号 `．`
    # 常被路径过滤器漏看，而 NFKC / ICU 折叠的栈会把它变回 `/` / `.`。
    fullwidth_fold: str = "keep"         # keep | fold

    # `%uXXXX` 风格的百分号转义（IIS 遗留）。先例：IIS 的 `%u002e%u002e`
    # 目录穿越；Apache/PHP 只认 `%XX`，于是检查侧与执行侧看到不同的字符串。
    percent_u: str = "reject"            # reject | decode

    # Unicode 大小写折叠。先例：Kelvin 符号 `K`（U+212A）、长 s `ſ`（U+017F）、
    # 连字 `ﬀ`（U+FB00）在 casefold 后变成 `k` / `s` / `ff`，
    # 能骗过只做 ASCII 小写的关键字黑名单。
    case_fold_unicode: str = "sensitive"  # sensitive | fold

    # 解码后的字节按 UTF-8 还是 Latin-1 解释。先例：经典 UTF-8 / Latin-1
    # 混淆（`%C3%A9` 是 é 还是 Ã©），网关与后端口径不一致即绕过。
    byte_encoding: str = "utf-8"         # utf-8 | latin-1

    # 孤立代理项（如 CESU-8 编码的 `%ED%A0%80` = U+D800）怎么处理。
    # 先例：JSON / WAF 拒绝孤立代理项，而某些后端把它解出来当普通码点。
    lone_surrogate: str = "reject"       # reject | keep | replace

    # `%00`（NUL）是否截断字符串。先例：C 字符串截断 / PHP 的 `%00` 注入
    # （`safe.php%00.jpg` 骗过扩展名白名单）。
    nul_truncate: str = "keep"           # keep | truncate


@dataclass
class EncResult:
    """一次解释的完整结果 —— 就是"这个实现把这段字节读成了什么文本"。"""

    ok: bool = True
    status: int = 200
    reason: str = "OK"
    #: 解释结果的可读且**唯一**的渲染形式（ASCII 原样、其余写成 `\uXXXX`）
    norm_text: str = ""
    #: 解释结果的码点序列（`U+XXXX` 空格分隔），与 norm_text 同源
    codepoints: str = ""
    #: 真正改变过字节序列的解码层数（`%uXXXX` + `%XX`）
    decoded_layers: int = 0
    notes: list[str] = field(default_factory=list)

    def to_fields(self) -> dict:
        return {
            "accepted": self.ok,
            "status": self.status,
            "norm_text": self.norm_text,
            "codepoints": self.codepoints,
            "decoded_layers": self.decoded_layers,
        }


# --------------------------------------------------------------------------- 工具

def _is_hex(ch: int) -> bool:
    return 0x30 <= ch <= 0x39 or 0x41 <= ch <= 0x46 or 0x61 <= ch <= 0x66


def _render(text: str) -> str:
    """把文本渲染成可读且唯一的形式：ASCII 原样，其余写成转义。

    刻意**保留空格与可见 ASCII**（读起来像人话），把控制字符 / 非 ASCII /
    孤立代理项写成 `\\uXXXX`（大于 BMP 用 `\\UXXXXXXXX`）。
    同一次解释只要 norm_text 不同，文本必不相同 —— 判定与比对都靠这一点。
    """
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if 0x20 <= o <= 0x7E and ch != "\\":
            out.append(ch)
        elif ch == "\\":
            out.append("\\\\")
        elif o <= 0xFFFF:
            out.append("\\u%04x" % o)
        else:
            out.append("\\U%08x" % o)
    return "".join(out)


def _codepoints(text: str) -> str:
    return " ".join("U+%04X" % ord(ch) for ch in text)


_PERCENT_U = re.compile(rb"%u([0-9A-Fa-f]{4})")


def _decode_percent_u_bytes(data: bytes) -> tuple[bytes, bool]:
    """解一层 `%uXXXX`（IIS 遗留）：把码点按 UTF-8 编码写回字节流。

    畸形（代理项码点等编不出 UTF-8）的原样保留，绝不静默丢弃。
    """
    def repl(match: re.Match) -> bytes:
        cp = int(match.group(1), 16)
        try:
            return chr(cp).encode("utf-8")
        except Exception:                       # 孤立代理项无法编码 → 原样保留
            return match.group(0)

    out, count = _PERCENT_U.subn(repl, data)
    return out, count > 0


def _decode_percent_bytes(data: bytes) -> tuple[bytes, bool]:
    """解一层 `%XX`。不合法 / 残缺的 `%` 原样保留。"""
    out = bytearray()
    i, n = 0, len(data)
    changed = False
    while i < n:
        if (data[i] == 0x25 and i + 3 <= n
                and _is_hex(data[i + 1]) and _is_hex(data[i + 2])):
            out.append(int(data[i + 1:i + 3], 16))
            i += 3
            changed = True
        else:
            out.append(data[i])
            i += 1
    return bytes(out), changed


#: 每种序列长度对应的"最短合法码点"——低于它即为过长编码
_LEN_MIN = {2: 0x80, 3: 0x800, 4: 0x10000}


def _decode_utf8(data: bytes, policy: EncPolicy) -> tuple[str | None, str]:
    """按策略解码 UTF-8。成功返回 (文本, "")，失败返回 (None, 原因)。

    过长序列与孤立代理项按策略决定接受 / 拒绝 / 替换 —— 这正是现实中
    严格解码器与宽容解码器的分水岭。
    """
    out: list[str] = []
    i, n = 0, len(data)
    while i < n:
        lead = data[i]
        if lead < 0x80:
            out.append(chr(lead))
            i += 1
            continue
        if 0xC0 <= lead <= 0xDF:
            need, cp = 1, lead & 0x1F
        elif 0xE0 <= lead <= 0xEF:
            need, cp = 2, lead & 0x0F
        elif 0xF0 <= lead <= 0xF7:
            need, cp = 3, lead & 0x07
        else:
            return None, "invalid_lead"
        if i + need >= n:
            return None, "truncated"
        for k in range(1, need + 1):
            cont = data[i + k]
            if not (0x80 <= cont <= 0xBF):
                return None, "invalid_continue"
            cp = (cp << 6) | (cont & 0x3F)
        total = need + 1
        if cp < _LEN_MIN[total] and policy.overlong_utf8 != "accept":
            return None, "overlong"
        if cp > 0x10FFFF:
            return None, "out_of_range"
        if 0xD800 <= cp <= 0xDFFF:
            if policy.lone_surrogate == "reject":
                return None, "surrogate"
            if policy.lone_surrogate == "replace":
                cp = 0xFFFD
        out.append(chr(cp))
        i += total
    return "".join(out), ""


def _normalize(text: str, form: str) -> str:
    """Unicode 规范化。含孤立代理项时某些形式无法处理 → 原样返回（不静默改字）。"""
    if form not in ("nfc", "nfd"):
        return text
    try:
        return unicodedata.normalize(form.upper(), text)
    except Exception:                            # noqa: BLE001
        return text


def _fold_fullwidth(text: str) -> str:
    """全角 ASCII 变体（U+FF01–U+FF5E）与表意空格（U+3000）折叠成 ASCII。

    只做**全角折叠**这一件事，刻意不用 NFKC —— NFKC 会顺带折叠连字 / 上标，
    把两个策略开关（宽度折叠、Unicode 大小写）搅在一起，分歧就不可归因了。
    """
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if 0xFF01 <= o <= 0xFF5E:
            out.append(chr(o - 0xFEE0))
        elif o == 0x3000:
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------- 公共工具（供语料 / 消融实验复用）

def unescape(data: bytes) -> bytes:
    """把 payload 里的 `%uXXXX` 与 `%XX` 转义解成字节（单层、顺序同内核）。"""
    data, _ = _decode_percent_u_bytes(data)
    data, _ = _decode_percent_bytes(data)
    return data


# --------------------------------------------------------------------------- 主入口

def interpret(raw: bytes, policy: EncPolicy) -> EncResult:
    """按 ``policy`` 解释一段字节，返回"这个实现读到的文本"。"""
    data = bytes(raw)
    notes: list[str] = []
    layers = 0

    # ① `%uXXXX`（IIS 遗留）
    if policy.percent_u == "decode":
        data, changed = _decode_percent_u_bytes(data)
        if changed:
            layers += 1
            notes.append("解了 %uXXXX 遗留转义")

    # ② `%XX`（所有实现都认，大小写不敏感）
    data, changed = _decode_percent_bytes(data)
    if changed:
        layers += 1

    # ③ 字节 → 文本
    if policy.byte_encoding == "latin-1":
        text = data.decode("latin-1")
    else:
        text, error = _decode_utf8(data, policy)
        if text is None:
            diag = data.decode("latin-1")
            return EncResult(ok=False, status=400, reason=error,
                             norm_text=_render(diag), codepoints=_codepoints(diag),
                             decoded_layers=layers,
                             notes=notes + [f"UTF-8 解码失败：{error}"])

    # ④ Unicode 规范化
    text = _normalize(text, policy.unicode_form)
    # ⑤ 全角折叠
    if policy.fullwidth_fold == "fold":
        text = _fold_fullwidth(text)
    # ⑥ Unicode 大小写折叠
    if policy.case_fold_unicode == "fold":
        try:
            text = text.casefold()
        except Exception:                        # noqa: BLE001 —— 畸形文本不改变行为
            pass
    # ⑦ NUL 截断
    if policy.nul_truncate == "truncate":
        cut = text.find("\x00")
        if cut != -1:
            text = text[:cut]
            notes.append("在 NUL 处截断")

    return EncResult(ok=True, status=200, reason="OK",
                     norm_text=_render(text), codepoints=_codepoints(text),
                     decoded_layers=layers, notes=notes)


__all__ = ["EncPolicy", "EncResult", "interpret", "unescape"]
