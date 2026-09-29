from __future__ import annotations

import pygame
import math

from .wiki import PROTOCOLS


class WikiView:
    """Scrollable protocol reference panel."""

    def __init__(self, screen, cfg, small, bold, font):
        self.screen = screen
        self.cfg = cfg
        self.small = small
        self.bold = bold
        self.font = font
        self._search = ""
        self._scroll = 0
        self._list_scroll = 0
        self._selected_proto = None
        self._detail_scroll = 0
        self._info_offset = 0
        self._jump_to = None

    def open_with(self, proto_name):
        """Set a protocol to be auto-selected when wiki is next opened."""
        self._jump_to = proto_name

    def draw(self, app):
        """Draw the wiki panel."""
        if not getattr(app, 'show_wiki', False):
            return False

        # Auto-jump to protocol if requested
        if self._jump_to:
            self._selected_proto = self._jump_to
            self._jump_to = None
            self._search = ""
            self._list_scroll = 0

        screen = self.screen
        w, h = screen.get_width(), screen.get_height()

        # Full-screen overlay
        overlay = pygame.Surface((w, h), pygame.SRCALPHA)
        overlay.fill((8, 10, 14, 245))
        screen.blit(overlay, (0, 0))

        # Header
        header_h = 46
        header_bg = pygame.Surface((w, header_h), pygame.SRCALPHA)
        header_bg.fill((10, 14, 22, 252))
        screen.blit(header_bg, (0, 0))
        pygame.draw.line(screen, (45, 55, 75), (0, header_h - 1), (w, header_h - 1))

        title = self.bold.render("Protocol Reference", True, (195, 210, 230))
        screen.blit(title, (16, 14))
        hint = self.small.render("[Q] Close   [F] Search   [↑↓] Navigate", True, (100, 110, 130))
        screen.blit(hint, (title.get_width() + 28, 17))

        # Search bar
        sy = header_h + 10
        sbg = pygame.Surface((w - 32, 30), pygame.SRCALPHA)
        sbg.fill((14, 19, 30, 220))
        pygame.draw.rect(sbg, (55, 65, 85), sbg.get_rect(), 1)
        screen.blit(sbg, (16, sy))
        if self._search:
            label = f"Search: {self._search}_"
        else:
            label = "Search protocols..."
        txt = self.small.render(label, True, (160, 170, 190))
        screen.blit(txt, (22, sy + 7))

        # Left column: protocol list with sections
        col_w = min(270, w // 4)
        col_x = 16
        list_y = sy + 46
        list_h = h - list_y - 16

        # Build sections: section_name -> [(name, entry), ...]
        sections = {}
        for proto in sorted(PROTOCOLS.keys()):
            sec = PROTOCOLS[proto].get("_section", "Protocols")
            if sec not in sections:
                sections[sec] = []
            sections[sec].append(proto)

        # Build flat visible list with section headers
        visible_items = []  # (type, data)  type='section' or 'item'
        for sec_name, protos in sections.items():
            visible_items.append(('section', sec_name))
            for p in protos:
                visible_items.append(('item', p))

        # Filter
        if self._search:
            filtered_items = [
                item for item in visible_items
                if item[0] == 'section' or
                   self._search.lower() in item[1].lower() or
                   self._search.lower() in PROTOCOLS[item[1]].get("description", "").lower()
            ]
        else:
            filtered_items = visible_items

        if not filtered_items:
            empty = self.small.render("No protocols match your search.", True, (120, 130, 150))
            screen.blit(empty, (col_x + 8, list_y + 10))

        # Scrollbar for list
        row_h = 30
        section_h = 22
        visible_count = int(list_h / row_h)
        max_scroll = max(0, len(filtered_items) - visible_count)
        self._list_scroll = max(0, min(max_scroll, self._list_scroll))

        if max_scroll > 0:
            thumb = max(20, int(list_h * visible_count / len(filtered_items)))
            thumb_y = list_y + int(list_h * self._list_scroll / max_scroll)
            pygame.draw.rect(screen, (35, 40, 60), (col_x + col_w - 10, list_y, 7, list_h))
            pygame.draw.rect(screen, (70, 80, 110), (col_x + col_w - 10, thumb_y, 7, thumb))

        # Protocol list with sections
        for i in range(visible_count):
            idx = i + self._list_scroll
            if idx >= len(filtered_items):
                break
            item = filtered_items[idx]
            ry = list_y + i * row_h

            if item[0] == 'section':
                # Section header
                sec_bg = pygame.Surface((col_w - 12, section_h), pygame.SRCALPHA)
                sec_bg.fill((10, 14, 25, 200))
                screen.blit(sec_bg, (col_x, ry))
                pygame.draw.rect(screen, (45, 55, 80), (col_x, ry, col_w - 12, section_h), border_radius=4)
                st = self.small.render(item[1].upper(), True, (100, 115, 155))
                screen.blit(st, (col_x + 8, ry + 5))
            else:
                proto = item[1]
                sel = proto == self._selected_proto
                bg = (28, 40, 65) if sel else (11, 15, 24)
                pygame.draw.rect(screen, bg, (col_x, ry, col_w - 12, row_h - 2), border_radius=4)
                if sel:
                    pygame.draw.rect(screen, (80, 130, 200), (col_x, ry, 3, row_h - 2), border_radius=1)

                color = self._proto_color(proto)
                pygame.draw.circle(screen, color, (col_x + 16, ry + row_h // 2), 5)

                nm = self.small.render(proto, True, (215, 225, 240))
                screen.blit(nm, (col_x + 28, ry + 4))

                desc = PROTOCOLS[proto].get("description", "")[:45]
                ds = self.small.render(desc, True, (100, 110, 125))
                screen.blit(ds, (col_x + 28, ry + 16))

        # Divider
        div_x = col_x + col_w
        pygame.draw.line(screen, (40, 48, 70), (div_x, list_y), (div_x, h - 16), 1)

        # Right column: detail
        dx = div_x + 16
        dw = w - dx - 16
        dy = list_y
        dh = h - list_y - 16

        if self._selected_proto and self._selected_proto in PROTOCOLS:
            info = PROTOCOLS[self._selected_proto]
            self._draw_detail(screen, self._selected_proto, info, dx, dy, dw, dh)

        pygame.display.flip()
        return True

    def _draw_detail(self, screen, name, info, x, y, w, h):
        """Draw the detail view for one protocol."""
        line_h = 17
        gap = 18
        cy = y

        # Title + color bar
        title = self.bold.render(name, True, (210, 225, 245))
        screen.blit(title, (x, cy))
        cy += title.get_height() + 4
        color = self._proto_color(name)
        pygame.draw.rect(screen, color, (x, cy, w, 3))
        cy += 12

        # Description
        cy = self._wrap_text(screen, info.get("description", ""), x, cy, w, (180, 190, 210), self.small)
        cy += gap

        # Reference
        ref = info.get("reference", "")
        if ref:
            cy = self._wrap_text(screen, f"RFC: {ref}", x, cy, w, (120, 145, 190), self.small)
            cy += gap

        # Ports
        ports = info.get("ports", [])
        if ports:
            port_str = "Ports: " + ", ".join(str(p) for p in ports)
            cy = self._wrap_text(screen, port_str, x, cy, w, (140, 200, 160), self.small)
            cy += gap

        # Flags
        flags = info.get("flags", {})
        if flags:
            section_title = self.small.render("Flags / Status Codes", True, (130, 160, 215))
            screen.blit(section_title, (x, cy))
            cy += section_title.get_height() + 4

            for key, val in flags.items():
                flag_label = f"  {key}"
                lsurf = self.small.render(flag_label, True, (160, 200, 165))
                screen.blit(lsurf, (x, cy))
                lx = x + lsurf.get_width() + 4
                avail = w - lsurf.get_width() - 4
                cy = self._wrap_text(screen, val, lx, cy, avail, (185, 195, 210), self.small)
            cy += gap

        # Header Fields / Bit Layout
        header_fields = info.get("header_fields", [])
        if header_fields:
            section_title = self.small.render("Header Layout", True, (130, 160, 215))
            screen.blit(section_title, (x, cy))
            cy += section_title.get_height() + 6

            for field in header_fields:
                if len(field) == 3:
                    field_name, field_bits, field_desc = field
                    if field_name == "" and field_bits == "" and field_desc == "":
                        cy += 4
                        continue
                    if field_name == "":
                        stitle = self.small.render(f"  {field_desc}", True, (130, 150, 190))
                        screen.blit(stitle, (x, cy))
                        cy += stitle.get_height() + 3
                        continue
                else:
                    field_name = field[0]
                    field_bits = field[1] if len(field) > 1 else ""
                    field_desc = field[2] if len(field) > 2 else ""

                nm_surf = self.small.render(f"  {field_name}", True, (150, 210, 155))
                screen.blit(nm_surf, (x, cy))
                name_end_x = x + nm_surf.get_width()

                badge_bottom = 0
                desc_x = x

                if field_bits:
                    bits_surf = self.small.render(field_bits, True, (90, 110, 145))
                    if name_end_x + 8 + bits_surf.get_width() + 8 < x + w:
                        bx = name_end_x + 8
                        pygame.draw.rect(screen, (20, 28, 45), (bx, cy + 2, bits_surf.get_width() + 8, 16), border_radius=3)
                        screen.blit(bits_surf, (bx + 4, cy + 5))
                        desc_x = bx + bits_surf.get_width() + 12
                        avail_w = w - (desc_x - x) - 4
                        badge_bottom = cy + 2 + 16
                    else:
                        pygame.draw.rect(screen, (20, 28, 45), (x + 4, cy + 18, bits_surf.get_width() + 8, 16), border_radius=3)
                        screen.blit(bits_surf, (x + 8, cy + 21))
                        desc_x = x + 4
                        avail_w = w - 8
                        badge_bottom = cy + 18 + 16
                else:
                    avail_w = w

                cy2 = self._wrap_text(screen, field_desc, desc_x, cy, avail_w, (175, 182, 198), self.small)
                cy = max(cy2, badge_bottom) if field_bits else max(cy2, cy + line_h + 4)

            cy += gap

        # Manual Examples
        nc_example = info.get("nc_example", "")
        if nc_example:
            section_title = self.small.render("Manual Examples (nc / tool)", True, (130, 160, 215))
            screen.blit(section_title, (x, cy))
            cy += section_title.get_height() + 6
            cy = self._wrap_text(screen, nc_example, x, cy, w, (175, 220, 160), self.small, mono=True)
            cy += gap

        # Notes
        notes = info.get("notes", "")
        if notes:
            section_title = self.small.render("Notes", True, (130, 160, 215))
            screen.blit(section_title, (x, cy))
            cy += section_title.get_height() + 4
            cy = self._wrap_text(screen, notes, x, cy, w, (140, 148, 160), self.small)
            cy += gap

    def _wrap_text(self, screen, text, x, y, max_w, color, surf, mono=False, indent=0):
        """Wrap text to fit max_w pixels, return new y position."""
        if not text:
            return y
        cy = y
        paragraphs = text.split('\n')
        for para in paragraphs:
            if not para:
                cy += surf.get_height() // 2
                continue
            words = para.split()
            line = ""
            first_line = True
            for word in words:
                test = (line + " " + word).strip()
                tw = surf.size(test)[0]
                if tw > max_w - (indent if first_line else 0) and line:
                    display = line
                    s = surf.render(display, True, color)
                    screen.blit(s, (x + (indent if first_line else 0), cy))
                    cy += s.get_height()
                    line = word
                    first_line = False
                else:
                    line = test
            if line:
                s = surf.render(line, True, color)
                screen.blit(s, (x + (indent if first_line else 0), cy))
                cy += s.get_height()
        return cy

    def _proto_color(self, proto):
        """Get color for a protocol."""
        cfg_colors = self.cfg.get("protocol_colors", {})
        if proto in cfg_colors:
            return tuple(cfg_colors[proto])
        h = abs(hash(proto)) % 360
        c = pygame.Color(0)
        c.hsva = (h, 70, 95, 100)
        return c[:3]

    def handle_event(self, app, event):
        """Handle a pygame event. Returns True if consumed."""
        if not getattr(app, 'show_wiki', False):
            return False

        if event.type == pygame.KEYDOWN:
            if event.key in (pygame.K_q, pygame.K_ESCAPE):
                app.show_wiki = False
                return True
            elif event.key == pygame.K_f:
                old = app.show_help
                app.show_help = False
                val = app.text_input("Search")
                app.show_help = old
                self._search = val
                self._list_scroll = 0
                return True
            elif event.key in (pygame.K_DOWN, pygame.K_UP):
                # Build filtered items with sections
                sections = {}
                for proto in sorted(PROTOCOLS.keys()):
                    sec = PROTOCOLS[proto].get("_section", "Protocols")
                    if sec not in sections:
                        sections[sec] = []
                    sections[sec].append(proto)
                visible_items = []
                for sec_name, protos in sections.items():
                    visible_items.append(('section', sec_name))
                    for p in protos:
                        visible_items.append(('item', p))
                if self._search:
                    filtered = [item for item in visible_items
                              if item[0] == 'section' or
                                 self._search.lower() in item[1].lower() or
                                 self._search.lower() in PROTOCOLS[item[1]].get("description", "").lower()]
                else:
                    filtered = visible_items

                cur_idx = -1
                for i, item in enumerate(filtered):
                    if item[0] == 'item' and item[1] == self._selected_proto:
                        cur_idx = i
                        break

                direction = 1 if event.key == pygame.K_DOWN else -1
                next_idx = cur_idx + direction
                while 0 <= next_idx < len(filtered) and filtered[next_idx][0] != 'item':
                    next_idx += direction
                if 0 <= next_idx < len(filtered) and filtered[next_idx][0] == 'item':
                    self._selected_proto = filtered[next_idx][1]
                return True
        elif event.type == pygame.MOUSEBUTTONDOWN:
            w, h = self.screen.get_width(), self.screen.get_height()
            col_w = min(270, w // 4)
            col_x = 16
            list_y = 102
            row_h = 30
            section_h = 22

            mx, my = event.pos
            if col_x <= mx <= col_x + col_w - 12 and list_y <= my <= h - 16:
                sections = {}
                for proto in sorted(PROTOCOLS.keys()):
                    sec = PROTOCOLS[proto].get("_section", "Protocols")
                    if sec not in sections:
                        sections[sec] = []
                    sections[sec].append(proto)
                visible_items = []
                for sec_name, protos in sections.items():
                    visible_items.append(('section', sec_name))
                    for p in protos:
                        visible_items.append(('item', p))
                if self._search:
                    filtered = [item for item in visible_items
                              if item[0] == 'section' or
                                 self._search.lower() in item[1].lower() or
                                 self._search.lower() in PROTOCOLS[item[1]].get("description", "").lower()]
                else:
                    filtered = visible_items
                y = list_y
                for item in filtered[self._list_scroll:]:
                    ih = section_h if item[0] == 'section' else row_h
                    if list_y <= my < y + ih:
                        if item[0] == 'item':
                            self._selected_proto = item[1]
                        return True
                    y += ih
                    if y > h:
                        break
        elif event.type == pygame.MOUSEWHEEL:
            w, h = self.screen.get_width(), self.screen.get_height()
            list_y = 102
            list_h = h - list_y - 16
            row_h = 30
            section_h = 22
            sections = {}
            for proto in sorted(PROTOCOLS.keys()):
                sec = PROTOCOLS[proto].get("_section", "Protocols")
                if sec not in sections:
                    sections[sec] = []
                sections[sec].append(proto)
            visible_items = []
            for sec_name, protos in sections.items():
                visible_items.append(('section', sec_name))
                for p in protos:
                    visible_items.append(('item', p))
            if self._search:
                filtered = [item for item in visible_items
                          if item[0] == 'section' or
                             self._search.lower() in item[1].lower() or
                             self._search.lower() in PROTOCOLS[item[1]].get("description", "").lower()]
            else:
                filtered = visible_items
            visible_count = int(list_h / row_h)
            max_scroll = max(0, len(filtered) - visible_count)
            self._list_scroll = max(0, min(max_scroll, self._list_scroll + event.y))
            return True

        return False
