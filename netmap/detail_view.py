from __future__ import annotations

import time

import pygame


class DetailView:
    def __init__(self, screen, cfg, small, bold, font):
        self.screen = screen
        self.cfg = cfg
        self.small = small
        self.bold = bold
        self.font = font
        self._proto_rects = []  # [(rect, protocol_name), ...] for click detection

    def protocol_at(self, mx, my):
        """Return protocol name if mx,my is over a protocol badge, else None."""
        for rect, proto in self._proto_rects:
            if rect.collidepoint(mx, my):
                return proto
        return None

    def draw(self, app):
        """Detail view: sequence diagram style showing individual packets between two nodes."""
        if not app.detail_view or not app.selected_node or not app.detail_node:
            return

        screen = self.screen
        w = app.w
        h = app.h

        n1, n2 = app.selected_node, app.detail_node

        # Full-screen dark overlay
        overlay = pygame.Surface((w, h), pygame.SRCALPHA)
        overlay.fill((8, 10, 14, 245))
        screen.blit(overlay, (0, 0))

        # Title
        title = f"{n1}  ↔  {n2}"
        ts = self.font.render(title, True, (235, 240, 245))
        screen.blit(ts, ts.get_rect(center=(w // 2, 30)))

        sub = self.small.render("Q = Back   |   Scroll with mouse wheel   |   Click protocol badge → wiki", True, (140, 155, 170))
        screen.blit(sub, sub.get_rect(center=(w // 2, 55)))

        # Collect all packets between these two nodes (both directions).
        all_packets = []
        for e in app.edges.values():
            if e.src == n1 and e.dst == n2:
                for p in e.packets:
                    all_packets.append((p, n1, n2))  # forward
            elif e.src == n2 and e.dst == n1:
                for p in e.packets:
                    all_packets.append((p, n2, n1))  # reversed for display

        # Sort chronologically
        all_packets.sort(key=lambda x: x[0].ts)

        # Column positions for nodes
        margin = 100
        col1 = margin
        col2 = w - margin
        header_y = 90
        row_h = 18
        spacing = 2

        # Draw vertical lines (lifelines)
        pygame.draw.line(screen, (60, 70, 90), (col1, header_y), (col1, h - 40), 2)
        pygame.draw.line(screen, (60, 70, 90), (col2, header_y), (col2, h - 40), 2)

        # Node labels at top
        l1 = self.bold.render(n1[:20], True, (200, 220, 255))
        l2 = self.bold.render(n2[:20], True, (200, 220, 255))
        screen.blit(l1, l1.get_rect(center=(col1, header_y - 20)))
        screen.blit(l2, l2.get_rect(center=(col2, header_y - 20)))

        if not all_packets:
            empty = self.small.render("No traffic recorded between these nodes yet", True, (120, 130, 150))
            screen.blit(empty, empty.get_rect(center=(w // 2, h // 2)))
            return

        # Scroll offset (stored per-instance)
        if not hasattr(app, 'detail_scroll'):
            app.detail_scroll = 0
            app.detail_last_count = 0
        max_scroll = max(0, len(all_packets) * (row_h + spacing) - (h - header_y - 80))
        # Auto-scroll to bottom if new packets arrived and we're already at bottom
        if len(all_packets) > app.detail_last_count:
            if app.detail_scroll >= max_scroll - 10 or app.detail_last_count == 0:
                app.detail_scroll = max_scroll
            app.detail_last_count = len(all_packets)
        app.detail_scroll = max(0, min(max_scroll, app.detail_scroll))

        # Draw column headers
        screen.blit(self.small.render("TIME", True, (140, 155, 170)), (col1, header_y + 5))
        screen.blit(self.small.render("→", True, (140, 155, 170)), (col1 + 70, header_y + 5))
        mid = w // 2 - 30
        screen.blit(self.small.render("INFO", True, (140, 155, 170)), (mid, header_y + 5))
        screen.blit(self.small.render("←", True, (140, 155, 170)), (col2 - 70, header_y + 5))
        screen.blit(self.small.render("PORT", True, (140, 155, 170)), (col2 + 5, header_y + 5))

        # Clear protocol rects for click detection
        self._proto_rects.clear()

        y_base = header_y + 30
        visible_start = max(0, app.detail_scroll // (row_h + spacing))
        app.detail_hover_packet = None  # Reset each frame

        for idx, (p, src, dst) in enumerate(all_packets):
            # Advance y even for skipped items so visible items align correctly
            y = y_base - app.detail_scroll + idx * (row_h + spacing)
            if y < header_y + 30:
                continue
            if y > h - 50:
                break

            is_fwd = (src == n1)
            col = app.color(p.protocol)

            # Background row (alternating) - MUST be drawn FIRST
            if idx % 2 == 0:
                pygame.draw.rect(screen, (15, 18, 25), (col1 + 3, y, col2 - col1 - 6, row_h))

            # Direction arrow
            arrow = "→" if is_fwd else "←"
            arrow_col = (100, 220, 120) if is_fwd else (220, 100, 100)
            arr_surf = self.small.render(arrow, True, arrow_col)
            screen.blit(arr_surf, (col1 + 70, y))

            # Timestamp
            ts_str = time.strftime("%H:%M:%S", time.localtime(p.ts))
            ms = int((p.ts % 1) * 1000)
            ts_full = f"{ts_str}.{ms:03d}"
            screen.blit(self.small.render(ts_full, True, (180, 185, 200)), (col1 + 5, y))

            # Info/payload (truncated to fixed length)
            info = p.payload or p.info or ""
            info = " ".join(info.replace("\r", " ").replace("\n", " ").split())
            max_info_len = 50
            if len(info) > max_info_len:
                info = info[:max_info_len - 3] + "..."
            info_col = (210, 215, 225)
            info_surf = self.small.render(info, True, info_col)
            # Place info centered between the two columns
            info_x = col1 + (col2 - col1) // 2 - info_surf.get_width() // 2
            screen.blit(info_surf, (info_x, y))

            # Port on left side: n1's port in this direction
            # fwd=True: n1 sends → sport (source)
            # fwd=False: n1 receives ← dport (destination)
            port_left = f":{p.sport}" if is_fwd else f":{p.dport}"
            screen.blit(self.small.render(port_left, True, (160, 165, 180)), (col1 - 60, y))

            # Port on right side: n2's port in this direction
            # fwd=True: n2 receives → dport (destination)
            # fwd=False: n2 sends → sport (source)
            port_right = f":{p.dport}" if is_fwd else f":{p.sport}"
            screen.blit(self.small.render(port_right, True, (160, 165, 180)), (col2 + 5, y))

            # Small protocol indicator (symmetric on both sides)
            proto_surf = self.small.render(p.protocol[:4], True, (10, 10, 10))
            if is_fwd:
                # Left side: after arrow
                bg_x = col1 + 95
                txt_x = col1 + 97
            else:
                # Right side: before port, symmetric with left
                bg_x = col2 - proto_surf.get_width() - 9
                txt_x = col2 - proto_surf.get_width() - 7
            pygame.draw.rect(screen, col, (bg_x, y + 2, proto_surf.get_width() + 4, row_h - 4))
            screen.blit(proto_surf, (txt_x, y + 4))
            # Record for click detection
            self._proto_rects.append((pygame.Rect(bg_x, y + 2, proto_surf.get_width() + 4, row_h - 4), p.protocol))

            # Hover detection: store packet for popup
            mx, my = pygame.mouse.get_pos()
            row_top = y
            row_bottom = y + row_h
            if col1 + 3 <= mx <= col2 - 3 and row_top <= my <= row_bottom:
                app.detail_hover_packet = p
                app._last_detail_packet = p  # Remember for arrow key scrolling

        # Draw hover popup for detail view only if hovering over a row
        if hasattr(app, 'detail_hover_packet') and app.detail_hover_packet:
            p = app.detail_hover_packet
            mx, my = pygame.mouse.get_pos()
            info = p.payload or p.info or ""
            info = " ".join(info.replace("\r", " ").replace("\n", " ").split())
            info_len = len(info)
            lines = [
                f"Time: {time.strftime('%H:%M:%S', time.localtime(p.ts))}.{int((p.ts % 1) * 1000):03d}",
                f"Protocol: {p.protocol}",
                f"Source: {p.src}:{p.sport}",
                f"Dest: {p.dst}:{p.dport}",
                f"Length: {p.length} bytes",
            ]
            info_offset = getattr(app, 'detail_info_offset', 0)
            # Show 1000-char window from full info
            if info_len > 1000:
                lines.append("Info: " + info[info_offset:info_offset + 1000])
            elif info:
                lines.append("Info: " + info)
            # Scroll indicator
            if info_len > 1000:
                lines.append(f"↑↓ Scroll ({info_offset}-{info_offset + 1000}/{info_len})")
            # Max size: 50% of screen
            max_w = max(200, w // 2)
            max_h = max(150, h // 2)
            line_h = 16
            popup_w = min(400, max_w)
            # Wrap lines to fit width (chunk-based, not char-by-char)
            wrapped_lines = []
            for line in lines:
                while len(line) > 0:
                    # Binary search for max chars that fit
                    lo, hi = 0, min(len(line), 200)
                    while lo < hi:
                        mid = (lo + hi + 1) // 2
                        if self.small.size(line[:mid])[0] <= popup_w - 20:
                            lo = mid
                        else:
                            hi = mid - 1
                    if lo == 0:
                        lo = 1
                    wrapped_lines.append(line[:lo])
                    line = line[lo:]
            popup_h = min(30 + len(wrapped_lines) * line_h, max_h)
            x = min(mx + 15, w - popup_w - 10)
            y = min(my + 15, h - popup_h - 10)
            surf = pygame.Surface((popup_w, popup_h), pygame.SRCALPHA)
            surf.fill((8, 10, 14, 240))
            pygame.draw.rect(surf, app.color(p.protocol), surf.get_rect(), 2)
            for i, line in enumerate(wrapped_lines):
                surf.blit(self.small.render(line, True, (205, 212, 220)), (10, 10 + i * 16))
            screen.blit(surf, (x, y))
        else:
            app.detail_hover_packet = None
            app.detail_info_offset = 0

        # Scrollbar
        if max_scroll > 0:
            bar_h_total = h - header_y - 80
            thumb_h = max(30, int(bar_h_total * (1 - max_scroll / max(1, len(all_packets) * (row_h + spacing)))))
            thumb_y = header_y + 30 + int(bar_h_total * app.detail_scroll / max_scroll)
            pygame.draw.rect(screen, (40, 45, 55), (w - 15, header_y + 30, 8, bar_h_total))
            pygame.draw.rect(screen, (80, 90, 110), (w - 15, thumb_y, 8, thumb_h))
