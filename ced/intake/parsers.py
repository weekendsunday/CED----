"""外部发现格式解析 —— 把各扫描器的输出统一成「待验证的假设」。

只依赖标准库（``json`` / ``xml.etree`` / ``shlex``），不追任何第三方解析器：

    nuclei  JSON / JSONL，取 ``matched-at`` / ``host``
    burp    XML sitemap，取 ``<item><url>``
    har     JSON，取 ``log.entries[].request.url``（含 ``postData`` 一并进 raw）
    curl    以 ``curl `` 开头的命令行，取出 URL（``-X`` / ``-H`` / ``--data`` 进 raw）
    list    每行一条 URL 或裸目标
    manual  显式指定：整段文本当成一条假设

**格式识别失败必须报人话错误，绝不静默返回空清单** —— 一个把 500 条 nuclei
结果解析成 0 条却悄无声息的 intake，比没有 intake 更危险。
"""
from __future__ import annotations

import json
import shlex
from pathlib import Path
from xml.etree import ElementTree

from .model import Hypothesis

#: 支持的格式；``auto`` 表示按内容 / 扩展名嗅探
FORMATS: tuple[str, ...] = ("auto", "nuclei", "burp", "har", "curl", "list", "manual")

#: 扩展名 → 格式提示
_EXT_HINT: dict[str, str] = {
    ".har": "har",
    ".xml": "burp",
    ".sh": "curl",
    ".txt": "list",
    ".lst": "list",
    ".list": "list",
    ".json": "json",
    ".jsonl": "json",
    ".ndjson": "json",
}

#: nuclei 结果里能用来定位目标的字段（按优先级）
_NUCLEI_TARGET_KEYS: tuple[str, ...] = ("matched-at", "matched", "host", "url")
#: 判定一份 JSON 是不是 nuclei 结果的标志字段
_NUCLEI_MARKERS: tuple[str, ...] = ("matched-at", "matched", "template-id", "template")


# --------------------------------------------------------------------------- 读入

def _read_source(src: str) -> tuple[str, str]:
    """返回 (文本, 扩展名提示)。

    只有当整串是一个**已存在的文件**时才当路径读；否则一律当内联文本。
    这样 ``load("http://x/a?b")`` 不会被误当成文件名。
    """
    if not isinstance(src, str):
        raise TypeError(f"load() 只接受 str（路径或文本），收到 {type(src).__name__}")
    if "\n" not in src and len(src) < 4096:
        candidate = Path(src)
        try:
            exists = candidate.is_file()
        except OSError:
            exists = False
        if exists:
            text = candidate.read_text(encoding="utf-8", errors="replace")
            return text, _EXT_HINT.get(candidate.suffix.lower(), "")
    return src, ""


# --------------------------------------------------------------------------- 嗅探

def _sniff(text: str, hint: str) -> str:
    """按内容 + 扩展名提示决定格式；识别不了就报人话错误。"""
    stripped = text.strip()
    if not stripped:
        raise ValueError("输入为空：没有任何可解析的内容")
    if stripped.startswith("<"):
        return "burp"
    if hint in ("har", "burp", "curl", "list"):
        return hint
    if stripped[0] in "{[":
        return _sniff_json(stripped)
    for line in stripped.splitlines():
        if line.strip().startswith("curl "):
            return "curl"
    return "list"


def _sniff_json(text: str) -> str:
    """在 JSON 家族里分辨 HAR 与 nuclei。"""
    data = _try_loads(text)
    if data is not None:
        return _classify_json(data, text)
    # 整段不是单个 JSON —— 可能是 JSONL
    objects = _jsonl_objects(text)
    if objects and any(_looks_like_nuclei(o) for o in objects):
        return "nuclei"
    raise ValueError(
        "看起来像 JSON，但既不是 HAR（缺 log.entries），也不是 nuclei 结果"
        "（缺 matched-at / template-id），也不是合法的 JSONL")


def _classify_json(data, text: str) -> str:
    if isinstance(data, dict):
        if isinstance(data.get("log"), dict) and "entries" in data["log"]:
            return "har"
        if _looks_like_nuclei(data):
            return "nuclei"
    if isinstance(data, list) and data and all(isinstance(o, dict) for o in data):
        if any(_looks_like_nuclei(o) for o in data):
            return "nuclei"
    raise ValueError(
        "JSON 内容无法识别：HAR 需要 log.entries，nuclei 需要 matched-at / template-id 等字段")


def _looks_like_nuclei(obj: dict) -> bool:
    return any(key in obj for key in _NUCLEI_MARKERS)


def _try_loads(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _jsonl_objects(text: str) -> list:
    """逐行 JSON（JSONL / NDJSON）；任一行不合法则整体判定失败。"""
    out: list = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"JSONL 第 {len(out) + 1} 行不是合法 JSON：{exc}") from exc
    return out


def _json_objects(text: str) -> list:
    """既能吃整段 JSON，也能吃 JSONL —— nuclei 两种输出都存在。"""
    data = _try_loads(text)
    if data is not None:
        if isinstance(data, list):
            return data
        return [data]
    return _jsonl_objects(text)


# --------------------------------------------------------------------------- 各格式

def _parse_nuclei(text: str) -> list[Hypothesis]:
    objects = _json_objects(text)
    hyps: list[Hypothesis] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        target = next((obj[k] for k in _NUCLEI_TARGET_KEYS
                       if obj.get(k)), None)
        if not target:
            continue
        note = obj.get("template-id") or obj.get("template") or ""
        hyps.append(Hypothesis(
            source="nuclei",
            target=str(target),
            raw=json.dumps(obj, ensure_ascii=False),
            note=str(note),
        ))
    if not hyps:
        raise ValueError(
            "nuclei 结果里找不到 matched-at / host 字段："
            "确认这是 nuclei 的 -json / -jsonl 输出")
    return hyps


def _parse_burp(text: str) -> list[Hypothesis]:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ValueError(f"Burp XML 解析失败：{exc}") from exc
    hyps: list[Hypothesis] = []
    for item in root.iter("item"):
        url_el = item.find("url")
        if url_el is None or not (url_el.text or "").strip():
            continue
        host_el = item.find("host")
        note = (host_el.text or "").strip() if host_el is not None else ""
        hyps.append(Hypothesis(
            source="burp",
            target=url_el.text.strip(),
            raw=ElementTree.tostring(item, encoding="unicode").strip(),
            note=note,
        ))
    if not hyps:
        raise ValueError("Burp sitemap 里没有可用的 <item><url>")
    return hyps


def _parse_har(text: str) -> list[Hypothesis]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"HAR 不是合法 JSON：{exc}") from exc
    log = data.get("log") if isinstance(data, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("HAR 缺少 log.entries 数组")
    hyps: list[Hypothesis] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            continue
        url = request.get("url")
        if not url:
            continue
        raw = str(url)
        post = request.get("postData")
        if isinstance(post, dict) and post.get("text"):
            raw = f"{raw}\n\n{post['text']}"
        hyps.append(Hypothesis(
            source="har",
            target=str(url),
            raw=raw,
            note=str(request.get("method", "")),
        ))
    if not hyps:
        raise ValueError("HAR 的 log.entries 里没有任何 request.url")
    return hyps


#: curl 选项里**需要跟一个值**的那些（值不能当成 URL）
_CURL_ARG_OPTS = frozenset({
    "-X", "--request", "-H", "--header", "-d", "--data", "--data-raw",
    "--data-binary", "--data-urlencode", "-o", "--output", "-u", "--user",
    "-A", "--user-agent", "-b", "--cookie", "-e", "--referer", "--url",
    "-F", "--form", "-x", "--proxy", "--connect-to", "--resolve",
    "--max-time", "--connect-timeout", "-w", "--write-out", "-T", "--upload-file",
})


def _curl_url(line: str) -> str:
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    tokens = tokens[1:]           # 去掉开头的 ``curl``
    positional: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("-"):
            if "=" not in token and token in _CURL_ARG_OPTS:
                i += 2            # 跳过选项及其值
            else:
                i += 1
            continue
        positional.append(token)
        i += 1
    for token in positional:
        if token.startswith(("http://", "https://")):
            return token
    for token in positional:
        if token.startswith("/") or "://" in token:
            return token
    return positional[0] if positional else ""


def _parse_curl(text: str) -> list[Hypothesis]:
    hyps: list[Hypothesis] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("curl "):
            continue
        url = _curl_url(stripped)
        if url:
            hyps.append(Hypothesis(source="curl", target=url, raw=stripped))
    if not hyps:
        raise ValueError("没有以 `curl ` 开头的命令行")
    return hyps


def _parse_list(text: str) -> list[Hypothesis]:
    hyps: list[Hypothesis] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        hyps.append(Hypothesis(source="list", target=stripped))
    if not hyps:
        raise ValueError("清单里没有任何非空、非注释行")
    return hyps


def _parse_manual(text: str) -> list[Hypothesis]:
    body = text.strip()
    if not body:
        raise ValueError("manual 输入为空")
    return [Hypothesis(source="manual", target=body, raw=text)]


_PARSERS = {
    "nuclei": _parse_nuclei,
    "burp": _parse_burp,
    "har": _parse_har,
    "curl": _parse_curl,
    "list": _parse_list,
    "manual": _parse_manual,
}


# --------------------------------------------------------------------------- 入口

def load(path_or_text: str, fmt: str = "auto") -> list[Hypothesis]:
    """把一份外部发现素材解析成假设清单。

    ``fmt="auto"`` 时按内容与扩展名嗅探；显式指定格式时即为最终格式。
    识别失败或解析不出任何条目都会抛 ``ValueError``（人话消息），
    **不返回空清单**。
    """
    if fmt not in FORMATS:
        raise ValueError(f"未知格式 {fmt!r}（可选：{', '.join(FORMATS)}）")
    text, hint = _read_source(path_or_text)
    chosen = _sniff(text, hint) if fmt == "auto" else fmt
    return _PARSERS[chosen](text)


__all__ = ["FORMATS", "load"]
