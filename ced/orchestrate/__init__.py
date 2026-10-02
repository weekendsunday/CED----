"""拓扑：客户给出的"产品 + 串联方式"。"""

from .chain import ChainEvidence, chain_evidence
from .topology import Topology, load

__all__ = ["Topology", "load", "ChainEvidence", "chain_evidence"]
