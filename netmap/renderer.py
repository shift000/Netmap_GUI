from __future__ import annotations

import collections
import math
import time

import pygame


class Renderer:
    def __init__(self, screen, cfg, small, bold, font):
        self.screen = screen
        self.cfg = cfg
        self.small = small
        self.bold = bold
        self.font = font
        self.drawn_curves = []

    def draw(self, app):
        screen = self.screen
        cfg = self.cfg

        screen.fill((11, 14, 19))
        now = time.time()

        # Draw grouped edges
        app.force_layout.draw_grouped_edges(
            screen,
            app.nodes,
            app.node_ports,
            app.grouped_edges,
            app.color,
            app._sorted_ports,
        )
        app.drawn_curves = app.force_layout.drawn_curves
        # Update hover AFTER curves are drawn
        mx, my = pygame.mouse.get_pos()
        app.hover_edge = app.force_layout.update_hover(
            mx, my, app.drawn_curves, app.nodes, app.force_layout.node_radius
        )
        if app.hover_edge:
            app.payload_scroll = 0

        # Nodes.
        for n in app.nodes.values():
            active = now - n.last_seen < 1.0
            col = (235, 240, 245) if active else (125, 132, 142)
            # Radius steigt mit Traffic, aber max 2x.
            base = cfg["node_radius"]
            traffic_scale = min(2.0, 1.0 + math.log1p(n.packet_count) / 10)
            radius = int(base * traffic_scale)
            pygame.draw.circle(screen, (23, 28, 36), (int(n.x), int(n.y)), radius)
            pygame.draw.circle(screen, col, (int(n.x), int(n.y)), radius, 2)
            # Hostname nur anzeigen wenn DNS aktiviert und tatsächlich aufgelöst.
            label = n.ip
            name = n.name if app.dns_enabled and n.name != n.ip else ""
            s = self.bold.render(label, True, (235, 240, 245))
            screen.blit(s, s.get_rect(center=(n.x, n.y - 7)))
            if name:
                s2 = self.small.render(name[:28], True, (165, 175, 188))
                screen.blit(s2, s2.get_rect(center=(n.x, n.y + 12)))

        # Selection highlight.
        if app.selected_node and app.selected_node in app.nodes:
            n = app.nodes[app.selected_node]
            r = app.force_layout.node_radius(app.selected_node)
            pygame.draw.circle(screen, (80, 200, 255), (int(n.x), int(n.y)), r + 6, 2)

        # Lokale Node hervorheben — nur exakte IP, keine Aliases
        for lip in app.local_ips:
            if lip in app.nodes:
                n = app.nodes[lip]
                r = app.force_layout.node_radius(lip)
                pygame.draw.circle(screen, (80, 255, 140), (int(n.x), int(n.y)), r + 10, 2)
                pygame.draw.circle(screen, (40, 200, 90), (int(n.x), int(n.y)), r + 6, 1)

        self.draw_hud(app)
        self.draw_stats(app)

        if app.hover_edge:
            self.draw_payload_popup(app, app.hover_edge)

        if app.show_help:
            self.draw_help()

        self.draw_legend(app)

        if app.detail_view:
            app.detail_view_renderer.draw(app)
            pygame.display.flip()
            return

        # Wiki panel
        if app.show_wiki:
            app.wiki_view.draw(app)
            pygame.display.flip()
            return

        # Activity indicator: radar sweep bottom-left.
        cx, cy = 18, app.h - 18
        t = time.time()
        # Static center dot
        pygame.draw.circle(screen, (80, 255, 120), (cx, cy), 4)
        # Rotating sweep arm
        angle = t * 2.5  # revolutions per second
        sweep_len = 14
        end_x = cx + math.cos(angle) * sweep_len
        end_y = cy - math.sin(angle) * sweep_len
        # Draw sweep trail (fading arc effect via multiple segments)
        for i in range(1, 9):
            frac = i / 9.0
            a = angle - frac * 0.5
            alpha = int(200 * (1 - frac))
            ex = cx + math.cos(a) * sweep_len
            ey = cy - math.sin(a) * sweep_len
            col = (80, 255, 120, alpha) if hasattr(pygame, 'Color') else (80, 255, 120)
            pygame.draw.line(screen, col, (cx, cy), (ex, ey), 1)
        pygame.draw.line(screen, (80, 255, 120), (cx, cy), (end_x, end_y), 2)

        pygame.display.flip()

    def draw_hud(self, app):
        screen = self.screen
        left = [
            f"Interface: {app.interface}",
            f"Nodes: {len(app.nodes)}  Connections: {len(app.edges)}",
            f"Retention: {app.cfg['retention_seconds']} s",
            f"Filter: {app.filter_text or '*'}"
            + (f"  proto={app.filter_proto}" if app.filter_proto else "")
            + (f"  port={app.port_filter}" if app.port_filter else ""),
            f"Mode: {'PROMISC' if app.promiscuous else 'NORMAL'}   DNS: {'ON' if app.dns_enabled else 'OFF'}   IP: {app.ip_filter}   F11 Fullscreen   SPACE Pause   F Filter   P Proto   O Port   I IP   D DNS   S Stats   E Save   C Clear   H Help   ESC Quit",
        ]

        if app.paused:
            left.append("PAUSED")

        for i, text in enumerate(left):
            screen.blit(
                self.small.render(text, True, (175, 185, 198)),
                (12, 10 + i * 17),
            )

        # TShark-Fehler deutlich anzeigen.
        if app.status:
            error_text = app.status[:180]
            screen.blit(
                self.small.render(
                    f"TShark: {error_text}",
                    True,
                    (255, 100, 100),
                ),
                (12, 10 + len(left) * 17),
            )

        # Screenshot-Speicher-Bestätigung.
        if app.save_feedback:
            screen.blit(
                self.small.render(
                    f"Saved: {app.save_feedback}",
                    True,
                    (100, 255, 100),
                ),
                (12, 10 + (len(left) + 1) * 17),
            )
            app.save_feedback = ""

    def draw_legend(self, app):
        screen = self.screen
        # Shows all defined protocol colors from DEFAULT_CONFIG.
        colors = self.cfg.get("protocol_colors", {})
        protos = sorted(colors.keys())

        x = app.w - 12
        y = app.h - 25

        # Draw right to left.
        for p in reversed(protos):
            col = tuple(colors[p])
            s = self.small.render(p, True, (195, 200, 210))
            sw = s.get_width()

            pygame.draw.rect(
                screen,
                col,
                (x - sw - 18, y, 10, 14),
            )
            screen.blit(s, (x - sw - 4, y))
            x -= sw + 22

    def draw_help(self):
        screen = self.screen
        lines = [
            "F11 = Toggle fullscreen",
            "F = Set text filter, ENTER to apply, BACKSPACE to delete",
            "P = Protocol filter (e.g. TCP, DNS, TLS), ENTER to apply",
            "O = Port filter (e.g. 443, 80), ENTER to apply",
            "I = Toggle IP filter (ALL → IPv4 → IPv6 → ALL)",
            "D = DNS name resolution on/off",
            "S = Statistics panel on/off",
            "E = Save screenshot",
            "Click node = Select, Click second node = Detail view",
            "Q = Exit detail view, Click empty = Deselect",
            "Mouse over connection = Packet/Payload history",
            "Scroll wheel on payload = Scroll history",
            "SPACE = Pause capture, C = Clear view",
        ]
        w, h = 570, 340
        x, y = (self.screen.get_width() - w) // 2, (self.screen.get_height() - h) // 2
        s = pygame.Surface((w, h), pygame.SRCALPHA)
        s.fill((8, 10, 14, 245))
        pygame.draw.rect(s, (100, 110, 125), s.get_rect(), 2)
        for i, line in enumerate(lines):
            s.blit(self.font.render(line, True, (230, 235, 240)), (18, 18 + i * 27))
        screen.blit(s, (x, y))

    def draw_stats(self, app):
        screen = self.screen
        if not app.show_stats:
            return

        # Packets/s und Bytes/s berechnen (letzte Sekunde).
        now = time.time()
        cutoff = now - 1.0
        while app.packet_timestamps and app.packet_timestamps[0] < cutoff:
            app.packet_timestamps.popleft()
        while app.byte_timestamps and app.byte_timestamps[0][0] < cutoff:
            app.byte_timestamps.popleft()
        pps = len(app.packet_timestamps)
        bps = sum(b for _, b in app.byte_timestamps)

        # Top 5 Talker.
        top = sorted(app.node_packet_count.items(), key=lambda x: -x[1])[:5]

        # Protokoll-Verteilung (Top 6).
        proto_top = app.protocol_counts.most_common(6)

        lines = [
            f"Packets/s: {pps}",
            f"Bytes/s: {bps:,}",
            f"Total: {app.total_packets} / {app.total_bytes:,}",
            "",
        ]
        if proto_top:
            lines.append("Protokolle:")
            for proto, cnt in proto_top:
                bar_len = int(cnt / max(1, app.total_packets) * 20)
                bar = "█" * bar_len
                lines.append(f"  {proto:<6} {bar} {cnt}")

        lines.append("")
        lines.append("Top Talkers:")
        for ip, cnt in top:
            lines.append(f"  {ip}: {cnt}")

        w, h = 260, 42 + len(lines) * 16
        x, y = app.w - w - 12, 10

        surf = pygame.Surface((w, h), pygame.SRCALPHA)
        surf.fill((8, 10, 14, 220))
        pygame.draw.rect(surf, (80, 90, 110), surf.get_rect(), 1)

        for i, line in enumerate(lines):
            col = (140, 200, 255) if i == 0 or i == 3 or i == (3 + 2 + len(proto_top) + 1) else (205, 212, 220)
            surf.blit(
                self.small.render(line, True, col),
                (10, 8 + i * 16),
            )

        screen.blit(surf, (x, y))

    def draw_payload_popup(self, app, e):
        screen = self.screen
        mx, my = pygame.mouse.get_pos()
        if e is None or not hasattr(e, 'packets') or not isinstance(e.packets, (list, tuple, collections.deque)):
            app._popup_rect = None
            app._popup_protocol = None
            return
        packets = list(e.packets)
        if not packets:
            app._popup_rect = None
            app._popup_protocol = None
            return
        lines = []
        for p in packets[max(0, len(packets) - 16 + app.payload_scroll):]:
            text = p.payload or p.info or "(kein lesbarer Payload)"
            text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
            lines.append(f"{time.strftime('%H:%M:%S', time.localtime(p.ts))}  {text[:110]}")
        header = f"{e.protocol}  {e.src}:{e.sport or '-'} → {e.dst}:{e.dport or '-'}"
        widths = [self.font.size(header)[0]] + [self.small.size(x)[0] for x in lines]
        w = min(max(widths + [360]) + 20, 720)
        h = 42 + len(lines) * 17
        x = min(mx + 18, self.screen.get_width() - w - 10)
        y = min(my + 18, self.screen.get_height() - h - 10)
        # Speichere Popup-Position für Klick-Erkennung
        app._popup_rect = pygame.Rect(x, y, w, h)
        app._popup_protocol = e.protocol
        surf = pygame.Surface((w, h), pygame.SRCALPHA)
        surf.fill((8, 10, 14, 235))
        pygame.draw.rect(surf, self.color(e.protocol), surf.get_rect(), 2)
        surf.blit(self.font.render(header, True, (245, 245, 245)), (10, 8))
        for i, line in enumerate(lines):
            surf.blit(self.small.render(line, True, (205, 212, 220)), (10, 34 + i * 17))
        screen.blit(surf, (x, y))

    def color(self, protocol):
        if protocol in self.cfg["protocol_colors"]:
            return tuple(self.cfg["protocol_colors"][protocol])
        # Stable color for protocols not explicitly configured.
        h = abs(hash(protocol)) % 360
        c = pygame.Color(0)
        c.hsva = (h, 70, 95, 100)
        return c[:3]
