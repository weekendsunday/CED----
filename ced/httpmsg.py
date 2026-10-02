"""HTTP 消息的结构化拆解/重组工具（保持原始行尾，不擅自规范化）。"""
from __future__ import annotations

from dataclasses import dataclass

CRLF = b"\r\n"


@dataclass
class Message:
    lines: list[bytes]   # 请求行 + 头行
    eol: bytes           # 行分隔符（原样保留）
    sep: bytes           # 头部结束分隔符
    tail: bytes          # 后续字节（body 等，原样）

    def build(self) -> bytes:
        return self.eol.join(self.lines) + self.sep + self.tail

    def header_lines(self) -> list[tuple[int, bytes]]:
        """(行号, 内容)，跳过请求行。"""
        return [(i, ln) for i, ln in enumerate(self.lines) if i > 0]


def split(payload: bytes) -> Message | None:
    """拆解一条消息；找不到头部终止符返回 None。"""
    idx = payload.find(CRLF + CRLF)
    sep = CRLF + CRLF
    if idx == -1:
        idx = payload.find(b"\n\n")
        sep = b"\n\n"
        if idx == -1:
            return None
    head = payload[:idx]
    eol = CRLF if CRLF in head else b"\n"
    lines = head.split(eol)
    return Message(lines=lines, eol=eol, sep=sep, tail=payload[idx + len(sep):])


def drop_line(msg: Message, index: int) -> Message:
    """去掉某一行，返回新消息。"""
    return Message(lines=[ln for i, ln in enumerate(msg.lines) if i != index],
                   eol=msg.eol, sep=msg.sep, tail=msg.tail)


def replace_line(msg: Message, index: int, line: bytes) -> Message:
    lines = list(msg.lines)
    lines[index] = line
    return Message(lines=lines, eol=msg.eol, sep=msg.sep, tail=msg.tail)


def header_name(line: bytes) -> bytes | None:
    """取头名（小写）；不是头行返回 None。"""
    idx = line.find(b":")
    if idx <= 0:
        return None
    return line[:idx].strip().lower()
