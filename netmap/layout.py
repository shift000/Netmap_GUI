from __future__ import annotations

import math
import time

import pygame


class ForceLayout:
    def __init__(self, cfg, w, h):
        self.cfg = cfg
        self.w = w
        self.h = h
        self.nodes = {}  # updated by App
        self.drawn_curves = []

    def node_radius(self, ip):
        n = self.nodes[ip]
        base = self.cfg["node_radius"]
        return base * min(2.0, 1.0 + math.log1p(n.packet_count) / 10)

    def port_point(self, ip, other_ip, port, is_source, sorted_ports):
        n = self.nodes[ip]
        dx = self.nodes[other_ip].x - n.x
        dy = self.nodes[other_ip].y - n.y
        ang = math.atan2(dy, dx)
        # Use cached sorted port list, populate cache if missing
        ports = sorted_ports.get(ip)
        if ports is None:
            ports = sorted(self.node_ports[ip], key=lambda x: (int(x) if x.isdigit() else 99999, x))
            sorted_ports[ip] = ports
        idx = ports.index(port) if port in ports else 0
        spread = min(math.radians(48), math.radians(8) * max(0, len(ports) - 1))
        offset = (idx - (len(ports) - 1) / 2) * (spread / max(1, len(ports) - 1)) if len(ports) > 1 else 0
        ang += offset
        r = self.node_radius(ip)
        return n.x + math.cos(ang) * r, n.y + math.sin(ang) * r, ang

    def edge_endpoints(self, e, sorted_ports):
        a = self.port_point(e.src, e.dst, e.sport, True, sorted_ports) if e.sport else (
            *self.node_position(e.src), 0
        )
        b = self.port_point(e.dst, e.src, e.dport, False, sorted_ports) if e.dport else (
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
        screen,
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
                screen,
                color,
                False,
                points,
                width,
            )

        return points

    def draw_grouped_edges(self, screen, nodes, node_ports, grouped_edges_func, color_func, sorted_ports):
        self.drawn_curves = []
        self.node_ports = node_ports  # ensure it's set
        groups = grouped_edges_func()

        # Normalisierte Paare für gegenläufige Verbindungen.
        import collections
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
                src = nodes.get(g["src"])
                dst = nodes.get(g["dst"])

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

                color = color_func(g["protocol"])

                points = self.draw_edge_curve(
                    screen,
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
                        screen,
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

                    screen.blit(
                        label,
                        label.get_rect(
                            center=(mx + nx * offset, my + ny * offset)
                        ),
                    )

    def update_hover(self, mx, my, drawn_curves, nodes, node_radius_func):
        best, best_d = None, 16
        for points, edge in drawn_curves:
            if edge is None or edge.src not in nodes or edge.dst not in nodes:
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
        return best
