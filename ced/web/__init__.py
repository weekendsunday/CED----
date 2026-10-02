"""本地网页界面（零依赖，只用标准库）。"""

from .server import DEFAULT_PORT, main, serve

__all__ = ["DEFAULT_PORT", "main", "serve"]
