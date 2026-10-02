"""定向变异引擎：把种子扩成一批"仍在同一轴附近"的变体。

与通用 fuzz 的区别：每个算子都瞄准分帧语法点，而不是随机翻字节。
确定性 —— 由外部传入 random.Random(seed)，同 seed 同输出。
"""
from __future__ import annotations

import random
import re

CRLF = b"\r\n"

CL_VARIANTS = [b"03", b"+3", b" 3", b"3 ", b"abc", b"0x3", b"0000003"]
TE_VARIANTS = [b"chunked", b"Chunked", b"CHUNKED", b"xchunked",
               b"identity, chunked", b"chunked, identity", b"gzip, chunked"]
HEADER_CASE_FLIPS = [(b"Content-Length", b"CONTENT-LENGTH"),
                     (b"Transfer-Encoding", b"transfer-encoding"),
                     (b"Host", b"hOsT")]


def _split_head(seed: bytes) -> tuple[list[bytes], bytes]:
    """拆出头部行与尾部（含分隔与 body）。找不到分隔则原样返回。"""
    idx = seed.find(CRLF + CRLF)
    if idx == -1:
        return [], seed
    return seed[:idx].split(CRLF), seed[idx + 4:]


def _join(lines: list[bytes], tail: bytes) -> bytes:
    return CRLF.join(lines) + CRLF + CRLF + tail


# --------------------------------------------------------------------------- 算子

def op_cl_variant(seed: bytes, rng: random.Random) -> bytes | None:
    m = re.search(rb"(?i)content-length:[ \t]*([^\r\n]*)", seed)
    if not m:
        return None
    return seed[:m.start(1)] + rng.choice(CL_VARIANTS) + seed[m.end(1):]


def op_te_variant(seed: bytes, rng: random.Random) -> bytes | None:
    m = re.search(rb"(?i)transfer-encoding:[ \t]*([^\r\n]*)", seed)
    if not m:
        return None
    return seed[:m.start(1)] + rng.choice(TE_VARIANTS) + seed[m.end(1):]


def op_dup_header(seed: bytes, rng: random.Random) -> bytes | None:
    lines, tail = _split_head(seed)
    if len(lines) < 2:
        return None
    i = rng.randrange(1, len(lines))
    lines.insert(i, lines[i])
    return _join(lines, tail)


def op_header_case(seed: bytes, rng: random.Random) -> bytes | None:
    pairs = [(a, b) for a, b in HEADER_CASE_FLIPS if a in seed]
    if not pairs:
        return None
    a, b = rng.choice(pairs)
    return seed.replace(a, b, 1)


def op_bare_lf(seed: bytes, rng: random.Random) -> bytes | None:
    return seed.replace(CRLF, b"\n") if CRLF in seed else None


def op_obs_fold(seed: bytes, rng: random.Random) -> bytes | None:
    lines, tail = _split_head(seed)
    if len(lines) < 2:
        return None
    lines.insert(rng.randrange(1, len(lines)) + 1, b" injected: fold")
    return _join(lines, tail)


def op_swap_cl_te(seed: bytes, rng: random.Random) -> bytes | None:
    lines, tail = _split_head(seed)
    cl = next((i for i, l in enumerate(lines)
               if l.lower().startswith(b"content-length:")), None)
    te = next((i for i, l in enumerate(lines)
               if l.lower().startswith(b"transfer-encoding:")), None)
    if cl is None or te is None:
        return None
    lines[cl], lines[te] = lines[te], lines[cl]
    return _join(lines, tail)


def op_trailing_bytes(seed: bytes, rng: random.Random) -> bytes | None:
    """在完整请求后再接一段字节 —— 分帧分歧最直接的放大器。"""
    return seed + b"GET /smuggled HTTP/1.1" + CRLF + b"Host: localhost" + CRLF + CRLF


def op_method_lower(seed: bytes, rng: random.Random) -> bytes | None:
    return re.sub(rb"^([A-Z]+) ", lambda m: m.group(1).lower() + b" ", seed, count=1)


def op_absolute_uri(seed: bytes, rng: random.Random) -> bytes | None:
    return re.sub(rb"^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) /",
                  lambda m: m.group(0)[:-1] + b" http://localhost/", seed, count=1)


OPS = (op_cl_variant, op_te_variant, op_dup_header, op_header_case, op_bare_lf,
       op_obs_fold, op_swap_cl_te, op_trailing_bytes, op_method_lower,
       op_absolute_uri)


class Mutator:
    """对每个种子随机叠加 1~3 个算子，产出确定性变体。"""

    def __init__(self, variants_per_case: int = 6) -> None:
        self.variants_per_case = variants_per_case

    def expand(self, cases: list[tuple[str, bytes]],
               rng: random.Random) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        seen: set[bytes] = set()
        for axis, seed in cases:
            if seed not in seen:
                seen.add(seed)
                out.append((axis, seed))
            for _ in range(self.variants_per_case):
                cur = seed
                for op in rng.sample(OPS, k=rng.randint(1, 3)):
                    try:
                        nxt = op(cur, rng)
                    except Exception:      # 算子对畸形输入失败即跳过
                        nxt = None
                    if nxt:
                        cur = nxt
                if cur not in seen:
                    seen.add(cur)
                    out.append((axis, cur))
        return out
