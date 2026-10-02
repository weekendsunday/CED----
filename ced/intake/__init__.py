"""验证层 —— 把外部扫描器的发现当成「待验证的假设」重新裁判。

    parsers.load(...)  →  统一格式（nuclei / Burp / HAR / curl / list / manual）
    verify.verify(...) →  喂进同一条差分 oracle 链，输出 confirmed / refuted / unverifiable

扫描器说"这里有问题"只是线索；是否有问题由确定性差分决定。
"""

from .model import Hypothesis, Verification
from .parsers import FORMATS, load
from .verify import CONFIRMED, REFUTED, UNVERIFIABLE, verify

__all__ = [
    "Hypothesis", "Verification",
    "FORMATS", "load",
    "CONFIRMED", "REFUTED", "UNVERIFIABLE", "verify",
]
