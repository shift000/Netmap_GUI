from __future__ import annotations

import collections
import math
import queue
import random
import socket
import subprocess
import time

import pygame

from .capture import Capture
from .detail_view import DetailView
from .layout import ForceLayout
from .models import Edge, Node
from .renderer import Renderer


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
        self.dns_enabled = False
        self.promiscuous = True
        self.save_feedback = ""
        self.capture = Capture(cfg["tshark_path"], interface, self.q, promiscuous=self.promiscuous)
        self.running = True
        self.paused = False
        self.hover_edge = None
        self.payload_scroll = 0
        self.show_stats = False
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_timestamps = collections.deque()  # für packets/s
        self.byte_timestamps = collections.deque()  # für bytes/s
        self.node_packet_count = {}  # IP -> packet count
        self.protocol_counts = collections.Counter()  # protokoll -> anzahl
        self.show_help = False
        self.show_wiki = False  # W toggle
        self.filter_text = ""
        self.filter_proto = ""
        self.port_filter = ""  # leer = alle Ports
        self.ip_filter = cfg.get("ip_filter", "ALL").upper()
        self.status = ""
        self.drawn_curves = []  # [(points, edge), ...] für Hover-Erkennung
        self._rng = random.Random()  # Thread-sicheres RNG für Node-Positionen
        self.mac_to_ip = {}  # MAC -> kanonische IP (erste bekannte)
        self.ip_aliases = collections.defaultdict(set)  # IP -> other known IPs of this host
        self.selected_node = None  # Für Node-Klick-Detailansicht
        self.detail_node = None  # second node in detail view
        self.detail_view = False  # True when detail view is active
        self.fullscreen = False  # F11 toggle
        self._popup_rect = None  # rect of last payload popup (x, y, w, h)
        self._popup_protocol = None  # protocol name shown in popup

        # Lokale IP(s) ermitteln für Node-Hervorhebung
        self.local_ips = set()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
        # Auch 127.0.0.1 als lokal
        self.local_ips.add("127.0.0.1")

        # Performance caches
        self._sorted_ports = {}  # IP -> sorted port list (cached)
        self._grouped_edges_cache = None  # cached grouped_edges result
        self._edge_count = 0  # edge count to detect changes

        # Initialize layout and renderer
        self.force_layout = ForceLayout(cfg, self.w, self.h)
        self.force_layout.nodes = self.nodes
        self.force_layout.node_ports = self.node_ports
        self.force_layout.small = self.small
        self.force_layout.screen = self.screen

        self.renderer = Renderer(self.screen, cfg, self.small, self.bold, self.font)

        # Detail view renderer (created here but used via detail_view attribute)
        self.detail_view_renderer = DetailView(self.screen, cfg, self.small, self.bold, self.font)

        # Wiki renderer
        from .wiki_view import WikiView
        self.wiki_view = WikiView(self.screen, cfg, self.small, self.bold, self.font)

        self.capture.start()

    def grouped_edges(self):
        """
        Groups all Edge objects by:
            Source -> Destination -> Protocol

        Multiple ports/connections of the same protocol
        are merged into a single visual line.

        Opposite directions (A->B and B->A) stay separate,
        so draw_grouped_edges() can spread them apart.
        """
        if self._grouped_edges_cache is not None:
            return self._grouped_edges_cache

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

        self._grouped_edges_cache = list(groups.values())
        return self._grouped_edges_cache

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
                name = cip
                if self.dns_enabled:
                    import socket as _socket
                    try:
                        name = _socket.gethostbyaddr(cip)[0]
                        self.dns_cache[cip] = name
                    except Exception:
                        name = cip
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
            self._sorted_ports.pop(p.src, None)  # invalidate port cache
        if p.dport:
            self.node_ports[p.dst].add(p.dport)
            self._sorted_ports.pop(p.dport, None)  # invalidate port cache

        # Invalidate grouped_edges cache
        self._grouped_edges_cache = None

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
        edge_count_before = len(self.edges)
        for key in list(self.edges):
            e = self.edges[key]
            while e.packets and e.packets[0].ts < cutoff:
                e.packets.popleft()
            if not e.packets and e.last_seen < cutoff:
                del self.edges[key]
        # Invalidate cache if edges changed
        if len(self.edges) != edge_count_before:
            self._grouped_edges_cache = None
        active_ips = set()
        for e in self.edges.values():
            active_ips.add(e.src)
            active_ips.add(e.dst)
        for ip in list(self.nodes):
            if ip not in active_ips and self.nodes[ip].last_seen < cutoff:
                del self.nodes[ip]
                self.node_ports.pop(ip, None)
                self._sorted_ports.pop(ip, None)
                # Aliases und MAC-Mappings dieses Knotens entfernen.
                for alias in self.ip_aliases.pop(ip, []):
                    self.mac_to_ip.pop(alias, None)
                # Auch das MAC-Mapping der kanonischen IP selbst entfernen.
                self.mac_to_ip.pop(ip, None)

    def force_layout_step(self, dt):
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

    def node_at(self, mx, my):
        """Return node IP at mouse position, or None."""
        for ip, n in self.nodes.items():
            r = self.force_layout.node_radius(ip)
            dx, dy = mx - n.x, my - n.y
            if dx * dx + dy * dy <= r * r:
                return ip
        return None

    def color(self, protocol):
        if protocol in self.cfg["protocol_colors"]:
            return tuple(self.cfg["protocol_colors"][protocol])
        # Stable color for protocols not explicitly configured.
        h = abs(hash(protocol)) % 360
        c = pygame.Color(0)
        c.hsva = (h, 70, 95, 100)
        return c[:3]

    def events(self):
        for ev in pygame.event.get():
            # Wiki gets first chance at input
            if self.wiki_view.handle_event(self, ev):
                continue
            if ev.type == pygame.QUIT:
                self.running = False
            elif ev.type == pygame.VIDEORESIZE:
                if self.fullscreen:
                    # Ignoriere Resize-Events im Fullscreen-Modus (verursachen Flackern)
                    continue
                self.w, self.h = ev.w, ev.h
                self.screen = pygame.display.set_mode((self.w, self.h), pygame.RESIZABLE)
                self.force_layout.w = self.w
                self.force_layout.h = self.h
            elif ev.type == pygame.KEYDOWN:
                if ev.key == pygame.K_ESCAPE:
                    self.running = False
                elif ev.key == pygame.K_SPACE:
                    self.paused = not self.paused
                elif ev.key == pygame.K_h:
                    self.show_help = not self.show_help
                elif ev.key == pygame.K_w:
                    self.show_wiki = not self.show_wiki
                elif ev.key == pygame.K_F11:
                    self.fullscreen = not self.fullscreen
                    if self.fullscreen:
                        desktop = pygame.display.Info()
                        self.w, self.h = desktop.current_w, desktop.current_h
                        self.screen = pygame.display.set_mode((self.w, self.h), pygame.FULLSCREEN)
                    else:
                        self.screen = pygame.display.set_mode((self.w, self.h), pygame.RESIZABLE)
                    self.force_layout.w = self.w
                    self.force_layout.h = self.h
                elif ev.key == pygame.K_p:
                    self.filter_proto = self.text_input("Protocol").upper()
                elif ev.key == pygame.K_F5:
                    self.promiscuous = not self.promiscuous
                    self.capture.set_promiscuous(self.promiscuous)
                elif ev.key == pygame.K_s:
                    self.show_stats = not self.show_stats
                elif ev.key == pygame.K_c:
                    self.nodes.clear()
                    self.edges.clear()
                    self.node_ports.clear()
                    self._sorted_ports.clear()
                    self._grouped_edges_cache = None
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
                elif ev.key == pygame.K_q and self.detail_view:
                    self.detail_view = False
                    self.selected_node = None
                    self.detail_node = None
                elif self.detail_view:
                    # Arrow key scrolling for info text
                    src = self.detail_hover_packet or getattr(self, '_last_detail_packet', None)
                    if src:
                        info = src.payload or src.info or ""
                        info = " ".join(info.replace("\r", " ").replace("\n", " ").split())
                        max_offset = max(0, len(info) - 1000)
                        if ev.key == pygame.K_DOWN:
                            self.detail_info_offset = min(max_offset, self.detail_info_offset + 500)
                        elif ev.key == pygame.K_UP:
                            self.detail_info_offset = max(0, self.detail_info_offset - 500)
            elif ev.type == pygame.MOUSEBUTTONDOWN and ev.button == 1:
                if self.detail_view:
                    # Q exits; click on protocol badge → wiki
                    mx, my = ev.pos
                    proto = self.detail_view_renderer.protocol_at(mx, my)
                    if proto:
                        from .wiki import PROTOCOLS
                        if proto in PROTOCOLS:
                            self.show_wiki = True
                            self.wiki_view.open_with(proto)
                        else:
                            self._copy_to_clipboard(proto)
                            self.status = f"'{proto}' not in wiki — copied to clipboard"
                else:
                    clicked = self.node_at(*ev.pos)
                    if clicked:
                        if self.selected_node is None:
                            self.selected_node = clicked
                        elif self.selected_node == clicked:
                            self.selected_node = None
                        else:
                            self.detail_node = clicked
                            self.detail_view = True
                    else:
                        self.selected_node = None
            elif ev.type == pygame.MOUSEWHEEL and self.hover_edge:
                self.payload_scroll = max(
                    -len(self.hover_edge.packets) + 1,
                    min(0, self.payload_scroll + ev.y)
                )
            elif ev.type == pygame.MOUSEWHEEL and self.detail_view:
                self.detail_scroll = max(0, self.detail_scroll + ev.y * 30)

    def _copy_to_clipboard(self, text):
        """Copy text to system clipboard."""
        try:
            subprocess.run(["xclip", "-selection", "clipboard", "-i"],
                         input=text.encode(), check=False)
        except Exception:
            try:
                subprocess.run(["xsel", "--clipboard", "--input"],
                             input=text.encode(), check=False)
            except Exception:
                pass

    def text_input(self, title):
        value = ""
        old = self.show_help
        self.show_help = False
        while True:
            ev = pygame.event.wait()
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
            elif ev.type == pygame.QUIT:
                self.show_help = old
                return ""
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
                self.force_layout_step(1.0 / max(1, self.fps))

            self.renderer.draw(self)
            self.clock.tick(self.fps)

        self.capture.stop()
