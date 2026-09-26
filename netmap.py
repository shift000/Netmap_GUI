#!/usr/bin/env python3
"""
Live TShark/Pygame network map for Linux.

Requirements:
  sudo apt install tshark
  python3 -m pip install pygame

Run:
  python3 netmap.py
  python3 netmap.py --config config.json
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import queue
import random
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import pygame


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

class Capture:
    def __init__(self, tshark, interface, out_queue):
        self.tshark = tshark
        self.interface = interface
        self.q = out_queue
        self.proc = None
        self.stop_event = threading.Event()

    def start(self):
        # -T fields ist für einen Live-Stream mit explizit angegebenen
        # -e Feldern wesentlich zuverlässiger als -T ek.
        cmd = [
            self.tshark,
            "-l",
            "-n",
            "-i", self.interface,

            "-T", "fields",

            "-E", "separator=\t",
            "-E", "occurrence=f",
            "-E", "aggregator=,",
            "-E", "quote=n",

            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
            
            "-e", "eth.src",
            "-e", "eth.dst",

            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",

            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",

            "-e", "data.data",
            "-e", "tcp.payload",
            "-e", "udp.payload",

            "-e", "icmp.type",

            "-e", "arp.src.proto_ipv4",
            "-e", "arp.dst.proto_ipv4",
        ]

        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            self.q.put(("error", f"TShark konnte nicht gestartet werden: {exc}"))
            return

        threading.Thread(
            target=self._read,
            daemon=True,
            name="tshark-reader",
        ).start()

        threading.Thread(
            target=self._stderr,
            daemon=True,
            name="tshark-stderr",
        ).start()

    def _stderr(self):
        if not self.proc or not self.proc.stderr:
            return

        for line in self.proc.stderr:
            if self.stop_event.is_set():
                break

            line = line.strip()
            if line:
                self.q.put(("error", line))

    @staticmethod
    def _first(v):
        if isinstance(v, list):
            return v[0] if v else ""
        return v or ""

    def _read(self):
        if not self.proc or not self.proc.stdout:
            return

        for line in self.proc.stdout:
            if self.stop_event.is_set():
                break

            line = line.rstrip("\r\n")

            if not line:
                continue

            # Die Felder werden exakt in der Reihenfolge gelesen,
            # in der sie oben mit -e angegeben wurden.
            fields = line.split("\t")

            # TShark sollte immer 20 Felder liefern. Falls eine
            # Version weniger liefert, wird der Rest aufgefüllt.
            fields += [""] * (20 - len(fields))

            try:
                p = self._parse_fields(fields)
                if p:
                    self.q.put(("packet", p))
            except Exception as exc:
                self.q.put(("error", f"Packet parse error: {exc}"))

    def _parse_fields(self, f):
        f += [""] * (22 - len(f))

        (
            ts,
            frame_len,
            protocol,
            info,

            src_mac,
            dst_mac,
 
            ip_src,
            ip_dst,
            ipv6_src,
            ipv6_dst,

            tcp_src,
            tcp_dst,
            udp_src,
            udp_dst,

            data_data,
            tcp_payload,
            udp_payload,

            icmp_type,

            arp_src,
            arp_dst,

            _unused1,
            _unused2,
        ) = f[:22]

        if ip_src or ip_dst:
            ip_version = 4
            src = ip_src
            dst = ip_dst

        elif ipv6_src or ipv6_dst:
            ip_version = 6
            src = ipv6_src
            dst = ipv6_dst

        elif arp_src or arp_dst:
            ip_version = 4
            src = arp_src
            dst = arp_dst

        else:
            return None

        if not src or not dst or not ts:
            return None

        protocol = protocol.upper().strip() if protocol else "OTHER"

        sport = tcp_src or udp_src or ""
        dport = tcp_dst or udp_dst or ""

        payload = tcp_payload or udp_payload or data_data or ""

        try:
            timestamp = float(ts)
        except ValueError:
 
            return None

        try:
            length = int(float(frame_len)) if frame_len else 0
        except ValueError:
            length = 0

        return Packet(
            ts=timestamp,
            src=str(src),
            dst=str(dst),
            sport=str(sport),
            dport=str(dport),
            protocol=protocol,
            length=length,
            payload=self._payload_to_text(payload),
            info=str(info or ""),
            ip_version=ip_version,
            src_mac=str(src_mac or "").lower(),
            dst_mac=str(dst_mac or "").lower(),
        )

    @staticmethod
    def _payload_to_text(payload):
        if not payload:
            return ""

        try:
            # TShark liefert data.data/tcp.payload/udp.payload
            # normalerweise als Hex-String, z.B.:
            # 474554202f20485454502f312e310d0a
            hex_string = str(payload).replace(":", "").replace(",", "")

            raw = bytes.fromhex(hex_string)

            return "".join(
                chr(b)
                if 32 <= b <= 126 or b in (9, 10, 13)
                else "."
                for b in raw
            ).strip()

        except (ValueError, TypeError):
            return str(payload)

    def stop(self):
        self.stop_event.set()

        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


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


class App:
    def __init__(self, cfg, interface):
        self.cfg = cfg
        self.interface = interface
        self.w, self.h = cfg["window"]["width"], cfg["window"]["height"]
        self.fps = cfg["window"]["fps"]
        self.screen = pygame.display.set_mode((self.w, self.h), pygame.RESIZABLE)
        pygame.display.set_caption(f"TShark Network Map — {interface}")
        self.clock = pygame.time.Clock()
        self.font = pygame.font.SysFont("DejaVu Sans", 14)
        self.small = pygame.font.SysFont("DejaVu Sans", 11)
        self.bold = pygame.font.SysFont("DejaVu Sans", 16, bold=True)

        self.nodes = {}
        self.edges = {}
        self.node_ports = collections.defaultdict(set)
        self.q = queue.Queue()
        self.dns_cache = {}
        self.capture = Capture(cfg["tshark_path"], interface, self.q)
        self.running = True
        self.paused = False
        self.hover_edge = None
        self.payload_scroll = 0
        self.dns_enabled = False
        self.save_feedback = ""
        self.show_stats = False
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_timestamps = collections.deque()  # für packets/s
        self.byte_timestamps = collections.deque()  # für bytes/s
        self.node_packet_count = {}  # IP -> packet count
        self.protocol_counts = collections.Counter()  # protokoll -> anzahl
        self.show_help = False
        self.filter_text = ""
        self.filter_proto = ""
        self.port_filter = ""  # leer = alle Ports
        self.ip_filter = cfg.get("ip_filter", "ALL").upper()
        self.ip_alias = {}
        self.last_layout = time.monotonic()
        self.status = ""
        self.drawn_curves = []  # [(points, edge), ...] für Hover-Erkennung
        self._rng = random.Random()  # Thread-sicheres RNG für Node-Positionen
        self.mac_to_ip = {}  # MAC -> kanonische IP (erste bekannte)
        self.ip_aliases = collections.defaultdict(set)  # IP -> weitere bekannte IPs dieses Hosts
        self.capture.start()
        
    def grouped_edges(self):
        """
        Gruppiert alle Edge-Objekte nach:
            Quelle -> Ziel -> Protokoll

        Mehrere Ports/Verbindungen desselben Protokolls
        werden dadurch zu einer visuellen Linie zusammengefasst.

        Gegenrichtungen (A->B und B->A) bleiben separat,
        damit draw_grouped_edges() sie auseinanderlegen kann.
        """
        groups = {}

        for e in self.edges.values():
            if e.src not in self.nodes or e.dst not in self.nodes:
                continue

            if not e.packets:
                continue

            # Richtung bleibt im Key, damit draw_grouped_edges()
            # gegenläufige Verbindungen erkennen und trennen kann.
            key = (e.src, e.dst, e.protocol)

            if key not in groups:
                groups[key] = {
                    "src": e.src,
                    "dst": e.dst,
                    "protocol": e.protocol,
                    "edges": [],
                    "packets": [],
                    "bytes": 0,
                    "last_seen": 0,
                }

            g = groups[key]
            g["edges"].append(e)
            g["packets"].extend(e.packets)
            g["bytes"] += e.bytes
            g["last_seen"] = max(g["last_seen"], e.last_seen)

        return list(groups.values())

    def add_packet(self, p):
        if self.ip_filter == "IPV4" and p.ip_version != 4:
            return

        if self.ip_filter == "IPV6" and p.ip_version != 6:
            return

        now = p.ts

        if self.filter_proto and p.protocol != self.filter_proto:
            return

        if self.filter_text and self.filter_text.lower() not in (
            f"{p.src} {p.dst} {p.protocol} {p.sport} {p.dport} {p.info}"
        ).lower():
            return

        if self.port_filter:
            port_match = (self.port_filter in str(p.sport)) or (self.port_filter in str(p.dport))
            if not port_match:
                return

        # MAC-basierte kanonische IP ermitteln.
        def canonical_ip(ip, mac):
            if not mac:
                return ip
            if mac in self.mac_to_ip:
                return self.mac_to_ip[mac]
            # Neue MAC → erste bekannte IP als kanonisch merken.
            self.mac_to_ip[mac] = ip
            return ip

        c_src = canonical_ip(p.src, p.src_mac)
        c_dst = canonical_ip(p.dst, p.dst_mac)

        if c_src != p.src:
            self.ip_aliases[c_src].add(p.src)
        if c_dst != p.dst:
            self.ip_aliases[c_dst].add(p.dst)

        for ip, cip in ((p.src, c_src), (p.dst, c_dst)):
            if cip not in self.nodes:
                name = reverse_dns(cip, self.dns_cache) if self.dns_enabled else cip
                self.nodes[cip] = Node(
                    cip, cip, name,
                    self._rng.uniform(150, self.w - 150),
                    self._rng.uniform(130, self.h - 120),
                )
            self.nodes[cip].last_seen = now
            self.nodes[cip].packet_count += 1

        # Direction + ports are part of the edge identity.
        key = (c_src, c_dst, p.sport, p.dport, p.protocol)
        if key not in self.edges:
            self.edges[key] = Edge(
                key, c_src, c_dst, p.sport, p.dport, p.protocol
            )
        e = self.edges[key]
        e.packets.append(p)
        e.bytes += p.length
        e.last_seen = now
        maxp = self.cfg["max_packets_per_edge"]
        while len(e.packets) > maxp:
            e.packets.popleft()

        if p.sport:
            self.node_ports[p.src].add(p.sport)
        if p.dport:
            self.node_ports[p.dst].add(p.dport)

        # Statistiken aktualisieren.
        self.total_packets += 1
        self.total_bytes += p.length
        self.packet_timestamps.append(now)
        self.byte_timestamps.append((now, p.length))
        self.protocol_counts[p.protocol] += 1
        self.node_packet_count[p.src] = self.node_packet_count.get(p.src, 0) + 1
        self.node_packet_count[p.dst] = self.node_packet_count.get(p.dst, 0) + 1

    def prune(self):
        retention = max(1, float(self.cfg["retention_seconds"]))
        cutoff = time.time() - retention
        for key in list(self.edges):
            e = self.edges[key]
            while e.packets and e.packets[0].ts < cutoff:
                e.packets.popleft()
            if not e.packets and e.last_seen < cutoff:
                del self.edges[key]
        active_ips = set()
        for e in self.edges.values():
            active_ips.add(e.src)
            active_ips.add(e.dst)
        for ip in list(self.nodes):
            if ip not in active_ips and self.nodes[ip].last_seen < cutoff:
                del self.nodes[ip]
                self.node_ports.pop(ip, None)
                # Aliases und MAC-Mappings dieses Knotens entfernen.
                for alias in self.ip_aliases.pop(ip, []):
                    self.mac_to_ip.pop(alias, None)
                # Auch das MAC-Mapping der kanonischen IP selbst entfernen.
                self.mac_to_ip.pop(ip, None)

    def force_layout(self, dt):
        nodes = list(self.nodes.values())
        rep = self.cfg["layout"]["repulsion"]
        spring = self.cfg["layout"]["spring"]
        target = self.cfg["layout"]["spring_length"]
        damp = self.cfg["layout"]["damping"]

        for i, a in enumerate(nodes):
            fx = fy = 0.0
            for b in nodes[i + 1:]:
                dx, dy = a.x - b.x, a.y - b.y
                d2 = max(dx * dx + dy * dy, 900.0)
                d = math.sqrt(d2)
                f = rep / d2
                fx += dx / d * f
                fy += dy / d * f
                b.vx -= dx / d * f * dt
                b.vy -= dy / d * f * dt
            a.vx += fx * dt
            a.vy += fy * dt

        for e in self.edges.values():
            a, b = self.nodes.get(e.src), self.nodes.get(e.dst)
            if not a or not b:
                continue
            dx, dy = b.x - a.x, b.y - a.y
            d = max(1.0, math.hypot(dx, dy))
            f = spring * (d - target)
            a.vx += dx / d * f * dt
            a.vy += dy / d * f * dt
            b.vx -= dx / d * f * dt
            b.vy -= dy / d * f * dt

        margin = 90
        for n in nodes:
            n.vx *= damp
            n.vy *= damp
            n.x += n.vx
            n.y += n.vy
            n.x = max(margin, min(self.w - margin, n.x))
            n.y = max(margin, min(self.h - margin, n.y))

    def node_position(self, ip):
        n = self.nodes[ip]
        return n.x, n.y

    def node_radius(self, ip):
        n = self.nodes[ip]
        base = self.cfg["node_radius"]
        return base * min(2.0, 1.0 + math.log1p(n.packet_count) / 10)

    def port_point(self, ip, other_ip, port, is_source):
        n = self.nodes[ip]
        dx = self.nodes[other_ip].x - n.x
        dy = self.nodes[other_ip].y - n.y
        ang = math.atan2(dy, dx)
        # Slightly rotate endpoints so several simultaneous ports are visually separable.
        ports = sorted(self.node_ports[ip], key=lambda x: (int(x) if x.isdigit() else 99999, x))
        idx = ports.index(port) if port in ports else 0
        spread = min(math.radians(48), math.radians(8) * max(0, len(ports) - 1))
        offset = (idx - (len(ports) - 1) / 2) * (spread / max(1, len(ports) - 1)) if len(ports) > 1 else 0
        ang += offset
        r = self.node_radius(ip)
        return n.x + math.cos(ang) * r, n.y + math.sin(ang) * r, ang

    def edge_endpoints(self, e):
        a = self.port_point(e.src, e.dst, e.sport, True) if e.sport else (
            *self.node_position(e.src), 0
        )
        b = self.port_point(e.dst, e.src, e.dport, False) if e.dport else (
            *self.node_position(e.dst), 0
        )
        return a[0], a[1], b[0], b[1]

    @staticmethod
    def dist_segment(px, py, ax, ay, bx, by):
        dx, dy = bx - ax, by - ay
        if dx == dy == 0:
            return math.hypot(px - ax, py - ay)
        t = max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
        x, y = ax + t * dx, ay + t * dy
        return math.hypot(px - x, py - y)

    def draw_edge_curve(
        self,
        x1, y1,
        x2, y2,
        offset,
        color,
        width,
        active=False,
    ):
        dx = x2 - x1
        dy = y2 - y1
        length = max(1.0, math.hypot(dx, dy))

        # Senkrechter Vektor zur eigentlichen Verbindung.
        nx = -dy / length
        ny = dx / length

        # Kontrollpunkt seitlich verschieben.
        bend = offset

        cx = (x1 + x2) / 2 + nx * bend
        cy = (y1 + y2) / 2 + ny * bend

        points = []

        steps = 24

        for i in range(steps + 1):
            t = i / steps
            u = 1.0 - t

            x = (
                u * u * x1
                + 2 * u * t * cx
                + t * t * x2
            )

            y = (
                u * u * y1
                + 2 * u * t * cy
                + t * t * y2
            )

            points.append((int(x), int(y)))

        if len(points) >= 2:
            pygame.draw.lines(
                self.screen,
                color,
                False,
                points,
                width,
            )

        return points

    def draw_grouped_edges(self):
        self.drawn_curves = []
        groups = self.grouped_edges()

        # Normalisierte Paare für gegenläufige Verbindungen.
        pairs = collections.defaultdict(list)

        for g in groups:
            # Normalisierte Form als geometrisches Paar (Richtung = 0/1).
            norm_src, norm_dst = (
                (g["src"], g["dst"])
                if g["src"] < g["dst"]
                else (g["dst"], g["src"])
            )
            # Richtung: 0 = normal, 1 = umgekehrt
            direction = 0 if g["src"] < g["dst"] else 1
            pairs[(norm_src, norm_dst)].append((direction, g))

        now = time.time()

        for pair, group_list in pairs.items():
            # Stabil sortieren: erst Richtung, dann Protokoll
            group_list.sort(key=lambda x: (x[0], x[1]["protocol"]))

            count = len(group_list)

            # Abstand zwischen parallelen Linien.
            spacing = 40.0

            for index, (direction, g) in enumerate(group_list):
                src = self.nodes.get(g["src"])
                dst = self.nodes.get(g["dst"])

                if not src or not dst:
                    continue

                dx = dst.x - src.x
                dy = dst.y - src.y
                length = max(1.0, math.hypot(dx, dy))
    
                nx = -dy / length
                ny = dx / length

                r_src = self.node_radius(g["src"])
                r_dst = self.node_radius(g["dst"])

                x1 = src.x + dx / length * r_src
                y1 = src.y + dy / length * r_src

                x2 = dst.x - dx / length * r_dst
                y2 = dst.y - dy / length * r_dst

                # Mittig um die direkte Verbindung verteilen.
                # Richtung 1 (umgekehrt) → in die entgegengesetzte
                # geometrische Richtung verschieben.
                dir_sign = 1 if direction == 0 else -1
                offset = (
                    index - (count - 1) / 2
                ) * spacing * dir_sign

                # Anzahl der einzelnen Verbindungen dieses Protokolls.
                edge_count = len(g["edges"])

                # Nicht linear unendlich dick werden lassen.
                width = min(
                    2 + int(math.sqrt(edge_count)),
                    12,
                )

                active = now - g["last_seen"] < 0.75

                if active:
                    width += 1

                ## new width
                total_packets = len(g["packets"])
                total_bytes = g["bytes"]

                width = 2

                if total_packets > 20:
                    width += 1

                if total_packets > 100:
                    width += 2

                if total_packets > 500:
                    width += 2

                if total_bytes > 100_000:
                    width += 1

                if total_bytes > 1_000_000:
                    width += 2

                width = min(width, 12)

                ## new width end

                color = self.color(g["protocol"])

                points = self.draw_edge_curve(
                    x1,
                    y1,
                    x2,
                    y2,
                    offset,
                    color,
                    width,
                    active,
                )

                # Kurve für Hover-Erkennung speichern.
                if points:
                    self.drawn_curves.append((points, g["edges"][0] if g["edges"] else None))

                # Pfeilspitze am Ende der Kurve.
                # Richtung 1 (umgekehrt) → Pfeil am Startpunkt,
                # zeigt in Richtung des eigentlichen Ziels.
                if len(points) >= 3:
                    if direction == 0:
                        px, py = points[-1]
                        px2, py2 = points[-4]
                    else:
                        px, py = points[0]
                        px2, py2 = points[3]

                    angle = math.atan2(
                        py - py2,
                        px - px2,
                    )

                    size = 9

                    p1 = (px, py)

                    p2 = (
                        px - math.cos(angle - 0.45) * size,
                        py - math.sin(angle - 0.45) * size,
                    )

                    p3 = (
                        px - math.cos(angle + 0.45) * size,
                        py - math.sin(angle + 0.45) * size,
                    )

                    pygame.draw.polygon(
                        self.screen,
                        color,
                        [p1, p2, p3],
                    )

                # Protokollname nur bei mehreren Protokollen
                # oder ausreichend großer Verbindung anzeigen.
                if count > 1:
                    mx = sum(p[0] for p in points) / len(points)
                    my = sum(p[1] for p in points) / len(points)

                    label = self.small.render(
                        f"{g['protocol']} × {edge_count}",
                        True,
                        color,
                    )

                    self.screen.blit(
                        label,
                        label.get_rect(
                            center=(mx + nx * offset, my + ny * offset)
                        ),
                    )

    def draw(self):
        self.screen.fill((11, 14, 19))
        now = time.time()

        self.draw_grouped_edges()

        # Edges.
#        for e in self.edges.values():
#           if e.src not in self.nodes or e.dst not in self.nodes or not e.packets:
 #               continue
  #          color = self.color(e.protocol)
   #         x1, y1, x2, y2 = self.edge_endpoints(e)
    #        active = now - e.last_seen < 0.75
     #       width = 3 if active else 1
      #      pygame.draw.line(self.screen, color, (x1, y1), (x2, y2), width)
#
            # Direction arrow.
 #           ang = math.atan2(y2 - y1, x2 - x1)
  #          ax, ay = x2, y2
      #      size = 9
   #         p1 = (ax, ay)
    #        p2 = (ax - math.cos(ang - 0.45) * size, ay - math.sin(ang - 0.45) * size)
     #       p3 = (ax - math.cos(ang + 0.45) * size, ay - math.sin(ang + 0.45) * size)
      #      pygame.draw.polygon(self.screen, color, [p1, p2, p3])
#
 #           # Port labels next to circular opening.
  #          if e.sport:
   #             self.draw_port(e.src, e.dst, e.sport)
    #        if e.dport:
     #           self.draw_port(e.dst, e.src, e.dport)

        # Nodes.
        for n in self.nodes.values():
            active = now - n.last_seen < 1.0
            col = (235, 240, 245) if active else (125, 132, 142)
            # Radius steigt mit Traffic, aber max 2x.
            base = self.cfg["node_radius"]
            traffic_scale = min(2.0, 1.0 + math.log1p(n.packet_count) / 10)
            radius = int(base * traffic_scale)
            pygame.draw.circle(self.screen, (23, 28, 36), (int(n.x), int(n.y)), radius)
            pygame.draw.circle(self.screen, col, (int(n.x), int(n.y)), radius, 2)
            # Hostname nur anzeigen wenn DNS aktiviert und tatsächlich aufgelöst.
            label = n.ip
            name = n.name if self.dns_enabled and n.name != n.ip else ""
            s = self.bold.render(label, True, (235, 240, 245))
            self.screen.blit(s, s.get_rect(center=(n.x, n.y - 7)))
            if name:
                s2 = self.small.render(name[:28], True, (165, 175, 188))
                self.screen.blit(s2, s2.get_rect(center=(n.x, n.y + 12)))

        self.draw_hud()
        self.draw_stats()

        if self.hover_edge:
            self.draw_payload_popup(self.hover_edge)

        if self.show_help:
            self.draw_help()

        self.draw_legend()

        pygame.display.flip()

    def draw_port(self, ip, other, port):
        if ip not in self.nodes or other not in self.nodes:
            return
        x, y, ang = self.port_point(ip, other, port, False)
        x += math.cos(ang) * 12
        y += math.sin(ang) * 12
        s = self.small.render(f":{port}", True, (225, 225, 225))
        self.screen.blit(s, s.get_rect(center=(x, y)))

    def draw_payload_popup(self, e):
        mx, my = pygame.mouse.get_pos()
        packets = list(e.packets)
        if not packets:
            return
        lines = []
        for p in packets[max(0, len(packets) - 16 + self.payload_scroll):]:
            text = p.payload or p.info or "(kein lesbarer Payload)"
            text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
            lines.append(f"{time.strftime('%H:%M:%S', time.localtime(p.ts))}  {text[:110]}")
        header = f"{e.protocol}  {e.src}:{e.sport or '-'} → {e.dst}:{e.dport or '-'}"
        widths = [self.font.size(header)[0]] + [self.small.size(x)[0] for x in lines]
        w = min(max(widths + [360]) + 20, 720)
        h = 42 + len(lines) * 17
        x = min(mx + 18, self.w - w - 10)
        y = min(my + 18, self.h - h - 10)
        surf = pygame.Surface((w, h), pygame.SRCALPHA)
        surf.fill((8, 10, 14, 235))
        pygame.draw.rect(surf, self.color(e.protocol), surf.get_rect(), 2)
        surf.blit(self.font.render(header, True, (245, 245, 245)), (10, 8))
        for i, line in enumerate(lines):
            surf.blit(self.small.render(line, True, (205, 212, 220)), (10, 34 + i * 17))
        self.screen.blit(surf, (x, y))


    def draw_hud(self):
        left = [
            f"Interface: {self.interface}",
            f"Nodes: {len(self.nodes)}  Connections: {len(self.edges)}",
            f"Retention: {self.cfg['retention_seconds']} s",
            f"Filter: {self.filter_text or '*'}"
            + (f"  proto={self.filter_proto}" if self.filter_proto else "")
            + (f"  port={self.port_filter}" if self.port_filter else ""),
            f"DNS: {'ON' if self.dns_enabled else 'OFF'}   IP: {self.ip_filter}   SPACE Pause   F Filter   P Proto   O Port   I IP   D DNS   S Stats   E Save   C Clear   H Help   ESC Quit",
        ]

        if self.paused:
            left.append("PAUSED")

        for i, text in enumerate(left):
            self.screen.blit(
                self.small.render(text, True, (175, 185, 198)),
                (12, 10 + i * 17),
            )

        # TShark-Fehler deutlich anzeigen.
        if self.status:
            error_text = self.status[:180]
            self.screen.blit(
                self.small.render(
                    f"TShark: {error_text}",
                    True,
                    (255, 100, 100),
                ),
                (12, 10 + len(left) * 17),
            )

        # Screenshot-Speicher-Bestätigung.
        if self.save_feedback:
            self.screen.blit(
                self.small.render(
                    f"Saved: {self.save_feedback}",
                    True,
                    (100, 255, 100),
                ),
                (12, 10 + (len(left) + 1) * 17),
            )
            self.save_feedback = ""

    def draw_legend(self):
        # Zeigt alle definierten Protokoll-Farben aus DEFAULT_CONFIG.
        colors = self.cfg.get("protocol_colors", {})
        protos = sorted(colors.keys())

        x = self.w - 12
        y = self.h - 25

        # Von rechts nach links zeichnen.
        for p in reversed(protos):
            col = tuple(colors[p])
            s = self.small.render(p, True, (195, 200, 210))
            sw = s.get_width()

            pygame.draw.rect(
                self.screen,
                col,
                (x - sw - 18, y, 10, 14),
            )
            self.screen.blit(s, (x - sw - 4, y))
            x -= sw + 22

    def draw_help(self):
        lines = [
            "F = Textfilter setzen, ENTER anwenden, BACKSPACE löschen",
            "P = Protokollfilter (z.B. TCP, DNS, TLS), ENTER anwenden",
            "O = Port-Filter (z.B. 443, 80), ENTER anwenden",
            "I = IP-Filter umschalten (ALL → IPv4 → IPv6 → ALL)",
            "D = DNS-Namensauflösung ein/aus",
            "S = Statistik-Panel ein/aus",
            "E = Screenshot speichern",
            "Maus über Verbindung = Paket-/Payload-Verlauf",
            "Mausrad über Payload = Verlauf scrollen",
            "SPACE = Capture pausieren, C = Ansicht leeren",
        ]
        w, h = 570, 300
        x, y = (self.w - w) // 2, (self.h - h) // 2
        s = pygame.Surface((w, h), pygame.SRCALPHA)
        s.fill((8, 10, 14, 245))
        pygame.draw.rect(s, (100, 110, 125), s.get_rect(), 2)
        for i, line in enumerate(lines):
            s.blit(self.font.render(line, True, (230, 235, 240)), (18, 18 + i * 27))
        self.screen.blit(s, (x, y))

    def draw_stats(self):
        if not self.show_stats:
            return

        # Packets/s und Bytes/s berechnen (letzte Sekunde).
        now = time.time()
        cutoff = now - 1.0
        while self.packet_timestamps and self.packet_timestamps[0] < cutoff:
            self.packet_timestamps.popleft()
        while self.byte_timestamps and self.byte_timestamps[0][0] < cutoff:
            self.byte_timestamps.popleft()
        pps = len(self.packet_timestamps)
        bps = sum(b for _, b in self.byte_timestamps)

        # Top 5 Talker.
        top = sorted(self.node_packet_count.items(), key=lambda x: -x[1])[:5]

        # Protokoll-Verteilung (Top 6).
        proto_top = self.protocol_counts.most_common(6)

        lines = [
            f"Packets/s: {pps}",
            f"Bytes/s: {bps:,}",
            f"Total: {self.total_packets} / {self.total_bytes:,}",
            "",
        ]
        if proto_top:
            lines.append("Protokolle:")
            for proto, cnt in proto_top:
                bar_len = int(cnt / max(1, self.total_packets) * 20)
                bar = "█" * bar_len
                lines.append(f"  {proto:<6} {bar} {cnt}")

        lines.append("")
        lines.append("Top Talkers:")
        for ip, cnt in top:
            lines.append(f"  {ip}: {cnt}")

        w, h = 260, 42 + len(lines) * 16
        x, y = self.w - w - 12, 10

        surf = pygame.Surface((w, h), pygame.SRCALPHA)
        surf.fill((8, 10, 14, 220))
        pygame.draw.rect(surf, (80, 90, 110), surf.get_rect(), 1)

        for i, line in enumerate(lines):
            col = (140, 200, 255) if i == 0 or i == 3 or i == (3 + 2 + len(proto_top) + 1) else (205, 212, 220)
            surf.blit(
                self.small.render(line, True, col),
                (10, 8 + i * 16),
            )

        self.screen.blit(surf, (x, y))

    def color(self, protocol):
        if protocol in self.cfg["protocol_colors"]:
            return tuple(self.cfg["protocol_colors"][protocol])
        # Stable color for protocols not explicitly configured.
        h = abs(hash(protocol)) % 360
        c = pygame.Color(0)
        c.hsva = (h, 70, 95, 100)
        return c[:3]

    def update_hover(self):
        mx, my = pygame.mouse.get_pos()
        best, best_d = None, 16
        for points, edge in self.drawn_curves:
            if edge is None or edge.src not in self.nodes or edge.dst not in self.nodes:
                continue
            # Entlang der Kurve prüfen: Abstand zu jedem Segment.
            for i in range(len(points) - 1):
                d = self.dist_segment(
                    mx, my,
                    points[i][0], points[i][1],
                    points[i + 1][0], points[i + 1][1],
                )
                if d < best_d:
                    best, best_d = edge, d
        self.hover_edge = best

    def events(self):
        for ev in pygame.event.get():
            if ev.type == pygame.QUIT:
                self.running = False
            elif ev.type == pygame.VIDEORESIZE:
                self.w, self.h = ev.w, ev.h
                self.screen = pygame.display.set_mode((self.w, self.h), pygame.RESIZABLE)
            elif ev.type == pygame.KEYDOWN:
                if ev.key == pygame.K_ESCAPE:
                    self.running = False
                elif ev.key == pygame.K_SPACE:
                    self.paused = not self.paused
                elif ev.key == pygame.K_h:
                    self.show_help = not self.show_help
                elif ev.key == pygame.K_s:
                    self.show_stats = not self.show_stats
                elif ev.key == pygame.K_c:
                    self.nodes.clear()
                    self.edges.clear()
                    self.node_ports.clear()
                    self.total_packets = 0
                    self.total_bytes = 0
                    self.packet_timestamps.clear()
                    self.port_filter = ""
                    self.byte_timestamps.clear()
                    self.node_packet_count.clear()
                    self.protocol_counts.clear()
                    self.mac_to_ip.clear()
                    self.ip_aliases.clear()
                elif ev.key == pygame.K_f:
                    self.filter_text = self.text_input("Filter")
                elif ev.key == pygame.K_p:
                    self.filter_proto = self.text_input("Protokoll").upper()
                elif ev.key == pygame.K_o:
                    self.port_filter = self.text_input("Port")
                elif ev.key == pygame.K_i:
                    opts = ["ALL", "IPV4", "IPV6"]
                    self.ip_filter = opts[(opts.index(self.ip_filter) + 1) % len(opts)]
                elif ev.key == pygame.K_d:
                    self.dns_enabled = not self.dns_enabled
                elif ev.key == pygame.K_e:
                    import datetime
                    fname = f"netmap_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                    pygame.image.save(self.screen, fname)
                    self.save_feedback = fname
            elif ev.type == pygame.MOUSEWHEEL and self.hover_edge:
                self.payload_scroll = max(
                    -len(self.hover_edge.packets) + 1,
                    min(0, self.payload_scroll + ev.y)
                )

    def text_input(self, title):
        value = ""
        old = self.show_help
        self.show_help = False
        while True:
            for ev in pygame.event.get():
                if ev.type == pygame.KEYDOWN:
                    if ev.key == pygame.K_RETURN:
                        self.show_help = old
                        return value
                    if ev.key == pygame.K_ESCAPE:
                        self.show_help = old
                        return ""
                    if ev.key == pygame.K_BACKSPACE:
                        value = value[:-1]
                    elif ev.unicode and ev.unicode.isprintable():
                        value += ev.unicode
            self.screen.fill((11, 14, 19))
            txt = self.font.render(f"{title}: {value}_", True, (235, 240, 245))
            self.screen.blit(txt, (30, 30))
            pygame.display.flip()
            self.clock.tick(30)

    def run(self):
        while self.running:
            self.events()

            while not self.q.empty():
                kind, obj = self.q.get_nowait()
                if kind == "packet" and not self.paused:
                    self.add_packet(obj)
                elif kind == "error":
                    self.status = obj

            if not self.paused:
                self.prune()
                self.force_layout(1.0 / max(1, self.fps))

            self.update_hover()
            if self.hover_edge:
                self.payload_scroll = 0

            self.draw()
            self.clock.tick(self.fps)

        self.capture.stop()


def choose_interface(tshark):
    items = interfaces(tshark)
    if not items:
        raise RuntimeError("TShark meldet keine Interfaces. TShark-Berechtigungen prüfen.")

    print("\nVerfügbare Interfaces:")
    for num, name in items:
        print(f"  {num}: {name}")

    while True:
        choice = input("\nInterface auswählen (Nummer oder Name): ").strip()
        for num, name in items:
            if choice == num or choice == name:
                # tshark accepts either its numeric interface id or its name.
                return num if choice == num else name
        print("Ungültige Auswahl.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    config_path = Path(args.config)
    cfg = load_config(config_path)

    tshark = cfg["tshark_path"]
    if not Path(tshark).exists():
        tshark = shutil.which("tshark") or tshark
    if not shutil.which(tshark) and not Path(tshark).exists():
        raise SystemExit("TShark nicht gefunden. tshark_path in config.json setzen.")

    interface = cfg.get("interface") or choose_interface(tshark)

    pygame.init()
    try:
        App(cfg, interface).run()
    finally:
        pygame.quit()


if __name__ == "__main__":
    main()
