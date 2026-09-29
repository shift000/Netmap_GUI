from __future__ import annotations

import subprocess
import threading
import time
from queue import Empty, Queue

from .models import Packet


class Capture:
    def __init__(self, tshark, interface, out_queue, promiscuous=True):
        self.tshark = tshark
        self.interface = interface
        self.q = out_queue
        self.proc = None
        self.stop_event = threading.Event()
        self.promiscuous = promiscuous

    def start(self):
        # -T fields ist für einen Live-Stream mit explizit angegebenen
        # -e Feldern wesentlich zuverlässiger als -T ek.
        cmd = [
            self.tshark,
            "-l",
            "-n",
            "-i", self.interface,
        ]

        if not self.promiscuous:
            cmd += ["-p"]

        cmd += [
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
            self.q.put(("error", f"TShark could not be started: {exc}"))
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

    def set_promiscuous(self, enabled):
        """Restart TShark with new promiscuous setting."""
        if self.promiscuous == enabled:
            return
        self.promiscuous = enabled
        self.stop()
        # Wait for threads to finish
        time.sleep(0.3)
        self.stop_event = threading.Event()
        self.start()
