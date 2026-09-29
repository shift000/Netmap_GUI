from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess


DEFAULT_CONFIG = {
    "tshark_path": "/usr/bin/tshark",
    "interface": "",
    "window": {"width": 1500, "height": 950, "fps": 60},
    "retention_seconds": 15,
    "max_packets_per_edge": 80,
    "payload_max_chars": 300,
    "node_radius": 42,

    "ip_filter": "IPv4", # ALL/IPv4/IPv6

    # IPv4/IPv6 anhand dieser Merkmale zusammenführen.
    "map_ip_versions": True,

    "layout": {
        "repulsion": 65000.0,
        "spring": 0.0022,
        "spring_length": 260.0,
        "damping": 0.84,
    },
    "protocol_colors": {
        "TCP": [70, 160, 255],
        "UDP": [90, 220, 120],
        "ICMP": [255, 190, 70],
        "DNS": [190, 110, 255],
        "HTTP": [255, 90, 90],
        "TLS": [80, 220, 220],
        "ARP": [255, 140, 210],
        "DHCP": [240, 240, 100],
    },
}


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path.exists():
        user = json.loads(path.read_text())
        deep_merge(cfg, user)
    return cfg


def deep_merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            deep_merge(a[k], v)
        else:
            a[k] = v


def interfaces(tshark):
    p = subprocess.run([tshark, "-D"], text=True, capture_output=True, check=False)
    result = []
    for line in p.stdout.splitlines():
        if ". " in line:
            num, name = line.split(". ", 1)
            result.append((num.strip(), name.strip()))
    return result


def reverse_dns(ip, cache):
    if ip in cache:
        return cache[ip]
    # Keep capture processing independent from DNS latency.
    try:
        import socket
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = ip
    cache[ip] = name
    return name
