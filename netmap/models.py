from __future__ import annotations

import collections
from dataclasses import dataclass, field


@dataclass
class Packet:
    ts: float
    src: str
    dst: str
    sport: str = ""
    dport: str = ""
    protocol: str = "OTHER"
    length: int = 0
    payload: str = ""
    info: str = ""
    ip_version: int = 0
    src_mac: str = ""
    dst_mac: str = ""

@dataclass
class Node:
    key: str
    ip: str
    name: str
    x: float
    y: float
    vx: float = 0.0
    vy: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0


@dataclass
class Edge:
    key: tuple
    src: str
    dst: str
    sport: str
    dport: str
    protocol: str
    packets: collections.deque = field(default_factory=collections.deque)
    bytes: int = 0
    last_seen: float = 0.0
