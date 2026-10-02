"""参照实现层：HTTP/1.1 消息分帧解析内核 + 一组策略。"""

from .http_reader import FramingPolicy, ParseResult, parse_request

__all__ = ["FramingPolicy", "ParseResult", "parse_request"]
