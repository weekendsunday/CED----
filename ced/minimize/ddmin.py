"""ddmin 最小化：把判别样本压到最小，同时保持"分歧依然存在"。

最小化的价值：给出的 PoC 越小，客户越容易看明白是哪一处语法在起作用，
也越容易判断"这到底算不算漏洞"。
"""
from __future__ import annotations

from typing import Callable, Sequence, TypeVar

from .. import httpmsg

T = TypeVar("T")


def ddmin(units: Sequence[T], predicate: Callable[[list[T]], bool]) -> list[T]:
    """经典 ddmin：不断尝试删掉一半的子集，直到无法再删。

    前提：``predicate`` 对原始集合为真，且对空集为假。
    """
    current = list(units)
    if not predicate(current):
        return current

    n = 2
    while len(current) >= 2:
        chunk = max(1, len(current) // n)
        reduced = False
        for start in range(0, len(current), chunk):
            candidate = current[:start] + current[start + chunk:]
            if candidate and predicate(candidate):
                current = candidate
                n = max(2, n - 1)
                reduced = True
                break
        if not reduced:
            if n >= len(current):
                break
            n = min(len(current), n * 2)
    return current


def minimize_headers(payload: bytes,
                     predicate: Callable[[bytes], bool]) -> bytes:
    """在"请求头"这一粒度上最小化，保持请求行与头/体分隔不变。

    ``predicate(payload) -> bool``：该样本是否仍然构成分歧。

    **分帧领域**的最小化单元（``Http1FramingAdapter.minimize`` 调用它）。
    """
    msg = httpmsg.split(payload)
    if msg is None or not predicate(payload):
        return payload

    header_indices = [i for i, _ in msg.header_lines()]
    if not header_indices:
        return payload

    def build(keep: list[int]) -> bytes:
        keep_set = set(keep) | {0}          # 请求行始终保留
        return httpmsg.Message(
            lines=[ln for i, ln in enumerate(msg.lines) if i in keep_set],
            eol=msg.eol, sep=msg.sep, tail=msg.tail).build()

    kept = ddmin(header_indices, lambda ks: bool(ks) and predicate(build(ks)))
    return build(list(kept))


def minimize_segments(payload: bytes,
                      predicate: Callable[[bytes], bool]) -> bytes:
    """在"路径段"这一粒度上最小化，保持开头的斜杠与查询串不变。

    对 ``/a/%2E%2E/admin`` 这类 target，要压掉的正是"多余的段"。

    **路径归一化领域**的最小化单元（``UrlNormAdapter.minimize`` 调用它）。
    """
    if not predicate(payload):
        return payload
    text = payload.decode("latin-1")
    path, sep, query = text.partition("?")
    if not path.startswith("/"):
        return payload
    segments = path.split("/")[1:]          # 丢掉开头的空段（它就是那个根斜杠）
    if not segments:
        return payload

    def build(keep: list[int]) -> bytes:
        body = "/" + "/".join(segments[i] for i in keep)
        return (body + (sep + query if sep else "")).encode("latin-1")

    everything = list(range(len(segments)))
    if not predicate(build(everything)):
        # 重建本身就会改变语义（例如原路径带连续斜杠）—— 宁可不最小化，
        # 也不能返回一个"分歧还在不在都不确定"的样本。
        return payload

    kept = ddmin(everything, lambda ks: bool(ks) and predicate(build(ks)))
    return build(list(kept))
