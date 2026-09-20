#!/usr/bin/env python3
"""Python DPI packet analyzer (functional replacement for the C++ version)."""

from __future__ import annotations

import argparse
import fnmatch
import queue
import struct
import threading
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


class AppType(Enum):
    UNKNOWN = "Unknown"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    QUIC = "QUIC"
    GOOGLE = "Google"
    FACEBOOK = "Facebook"
    YOUTUBE = "YouTube"
    TWITTER = "Twitter/X"
    INSTAGRAM = "Instagram"
    NETFLIX = "Netflix"
    AMAZON = "Amazon"
    MICROSOFT = "Microsoft"
    APPLE = "Apple"
    WHATSAPP = "WhatsApp"
    TELEGRAM = "Telegram"
    TIKTOK = "TikTok"
    SPOTIFY = "Spotify"
    ZOOM = "Zoom"
    DISCORD = "Discord"
    GITHUB = "GitHub"
    CLOUDFLARE = "Cloudflare"


SNI_PATTERNS: List[Tuple[AppType, Tuple[str, ...]]] = [
    (AppType.GOOGLE, ("google", "gstatic", "googleapis", "ggpht", "gvt1")),
    (AppType.YOUTUBE, ("youtube", "ytimg", "youtu.be", "yt3.ggpht")),
    (AppType.FACEBOOK, ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")),
    (AppType.INSTAGRAM, ("instagram", "cdninstagram")),
    (AppType.WHATSAPP, ("whatsapp", "wa.me")),
    (AppType.TWITTER, ("twitter", "twimg", "x.com", "t.co")),
    (AppType.NETFLIX, ("netflix", "nflxvideo", "nflximg")),
    (AppType.AMAZON, ("amazon", "amazonaws", "cloudfront", "aws")),
    (AppType.MICROSOFT, ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")),
    (AppType.APPLE, ("apple", "icloud", "mzstatic", "itunes")),
    (AppType.TELEGRAM, ("telegram", "t.me")),
    (AppType.TIKTOK, ("tiktok", "tiktokcdn", "musical.ly", "bytedance")),
    (AppType.SPOTIFY, ("spotify", "scdn.co")),
    (AppType.ZOOM, ("zoom",)),
    (AppType.DISCORD, ("discord", "discordapp")),
    (AppType.GITHUB, ("github", "githubusercontent")),
    (AppType.CLOUDFLARE, ("cloudflare", "cf-")),
]


@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int


@dataclass
class Flow:
    app_type: AppType = AppType.UNKNOWN
    host: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


@dataclass
class ParsedPacket:
    raw_data: bytes
    ts_sec: int
    ts_usec: int
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    has_ip: bool = False
    has_tcp: bool = False
    has_udp: bool = False
    payload_offset: int = 0
    payload: bytes = b""


@dataclass
class Stats:
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    forwarded: int = 0
    dropped: int = 0
    app_counts: Counter = field(default_factory=Counter)
    detected_hosts: Dict[str, AppType] = field(default_factory=dict)


class BlockingRules:
    def __init__(self) -> None:
        self.blocked_ips: set[int] = set()
        self.blocked_apps: set[AppType] = set()
        self.blocked_domains_exact: set[str] = set()
        self.blocked_domains_patterns: List[str] = []

    @staticmethod
    def parse_ip(ip: str) -> int:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            raise ValueError(f"Invalid IPv4 address: {ip}")
        return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(self.parse_ip(ip))

    def block_app(self, app_name: str) -> None:
        for app in AppType:
            if app.value == app_name:
                self.blocked_apps.add(app)
                return
        raise ValueError(f"Unknown app: {app_name}")

    def block_domain(self, domain: str) -> None:
        d = domain.lower()
        if "*" in d:
            self.blocked_domains_patterns.append(d)
        else:
            self.blocked_domains_exact.add(d)

    def is_domain_blocked(self, host: str) -> bool:
        if not host:
            return False
        host_lower = host.lower()
        if host_lower in self.blocked_domains_exact:
            return True
        return any(fnmatch.fnmatch(host_lower, pattern) for pattern in self.blocked_domains_patterns)

    def should_block(self, src_ip: int, app: AppType, host: str) -> bool:
        return src_ip in self.blocked_ips or app in self.blocked_apps or self.is_domain_blocked(host)

    def load_rules(self, filename: str) -> None:
        section = ""
        for line in Path(filename).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line
                continue
            if section == "[BLOCKED_IPS]":
                self.block_ip(line)
            elif section == "[BLOCKED_APPS]":
                self.block_app(line)
            elif section == "[BLOCKED_DOMAINS]":
                self.block_domain(line)


class PcapReader:
    def __init__(self, filename: str) -> None:
        self.fh = open(filename, "rb")
        self.global_header_raw = self.fh.read(24)
        if len(self.global_header_raw) != 24:
            raise ValueError("Invalid PCAP global header")
        magic_le = struct.unpack("<I", self.global_header_raw[:4])[0]
        magic_be = struct.unpack(">I", self.global_header_raw[:4])[0]
        if magic_le == 0xA1B2C3D4:
            self.endian = "<"
        elif magic_be == 0xA1B2C3D4:
            self.endian = ">"
        else:
            raise ValueError("Unsupported PCAP format")

    def packets(self) -> Iterable[Tuple[int, int, bytes]]:
        hdr_fmt = self.endian + "IIII"
        while True:
            hdr = self.fh.read(16)
            if not hdr:
                break
            if len(hdr) != 16:
                raise ValueError("Truncated PCAP packet header")
            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(hdr_fmt, hdr)
            data = self.fh.read(incl_len)
            if len(data) != incl_len:
                raise ValueError("Truncated PCAP packet payload")
            yield ts_sec, ts_usec, data

    def close(self) -> None:
        self.fh.close()


class PcapWriter:
    def __init__(self, filename: str, global_header_raw: bytes, endian: str = "<") -> None:
        self.fh = open(filename, "wb")
        self.endian = endian
        self.fh.write(global_header_raw)

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes) -> None:
        self.fh.write(struct.pack(self.endian + "IIII", ts_sec, ts_usec, len(data), len(data)))
        self.fh.write(data)

    def close(self) -> None:
        self.fh.close()


def ip_to_text(raw: bytes) -> str:
    return f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}"


def parse_packet(ts_sec: int, ts_usec: int, data: bytes) -> Optional[ParsedPacket]:
    if len(data) < 14:
        return None
    ethertype = struct.unpack("!H", data[12:14])[0]
    parsed = ParsedPacket(raw_data=data, ts_sec=ts_sec, ts_usec=ts_usec)
    if ethertype != 0x0800:
        return parsed
    if len(data) < 34:
        return None
    ip_offset = 14
    ver_ihl = data[ip_offset]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ip_offset + ihl:
        return None
    parsed.has_ip = True
    parsed.protocol = data[ip_offset + 9]
    parsed.src_ip = ip_to_text(data[ip_offset + 12 : ip_offset + 16])
    parsed.dst_ip = ip_to_text(data[ip_offset + 16 : ip_offset + 20])
    l4_offset = ip_offset + ihl

    if parsed.protocol == 6:
        if len(data) < l4_offset + 20:
            return None
        parsed.has_tcp = True
        parsed.src_port, parsed.dst_port = struct.unpack("!HH", data[l4_offset : l4_offset + 4])
        tcp_hlen = ((data[l4_offset + 12] >> 4) & 0x0F) * 4
        if tcp_hlen < 20 or len(data) < l4_offset + tcp_hlen:
            return None
        parsed.payload_offset = l4_offset + tcp_hlen
    elif parsed.protocol == 17:
        if len(data) < l4_offset + 8:
            return None
        parsed.has_udp = True
        parsed.src_port, parsed.dst_port = struct.unpack("!HH", data[l4_offset : l4_offset + 4])
        parsed.payload_offset = l4_offset + 8
    else:
        parsed.payload_offset = l4_offset

    parsed.payload = data[parsed.payload_offset :] if parsed.payload_offset < len(data) else b""
    return parsed


def extract_sni(payload: bytes) -> Optional[str]:
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    version = int.from_bytes(payload[1:3], "big")
    if version < 0x0300 or version > 0x0304:
        return None
    record_len = int.from_bytes(payload[3:5], "big")
    if record_len > len(payload) - 5 or payload[5] != 0x01:
        return None
    off = 5 + 4 + 2 + 32
    if off >= len(payload):
        return None
    sid_len = payload[off]
    off += 1 + sid_len
    if off + 2 > len(payload):
        return None
    cs_len = int.from_bytes(payload[off : off + 2], "big")
    off += 2 + cs_len
    if off >= len(payload):
        return None
    comp_len = payload[off]
    off += 1 + comp_len
    if off + 2 > len(payload):
        return None
    ext_len = int.from_bytes(payload[off : off + 2], "big")
    off += 2
    end = min(off + ext_len, len(payload))
    while off + 4 <= end:
        ext_type = int.from_bytes(payload[off : off + 2], "big")
        ext_size = int.from_bytes(payload[off + 2 : off + 4], "big")
        off += 4
        if off + ext_size > end:
            break
        if ext_type == 0x0000 and ext_size >= 5:
            host_len = int.from_bytes(payload[off + 3 : off + 5], "big")
            start = off + 5
            stop = start + host_len
            if stop <= off + ext_size:
                try:
                    return payload[start:stop].decode("ascii")
                except UnicodeDecodeError:
                    return None
        off += ext_size
    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    if len(payload) < 4:
        return None
    if payload[:4] not in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"):
        return None
    text = payload.decode("latin1", errors="ignore")
    for line in text.splitlines():
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            return host.split(":", 1)[0]
    return None


def classify_host(host: str) -> AppType:
    if not host:
        return AppType.UNKNOWN
    lowered = host.lower()
    for app, patterns in SNI_PATTERNS:
        if any(p in lowered for p in patterns):
            return app
    return AppType.HTTPS


class Worker:
    def __init__(self, rules: BlockingRules, stats: Stats, stats_lock: threading.Lock, out_q: "queue.Queue[Tuple[bool, Tuple[int, int, bytes]]]"):
        self.rules = rules
        self.stats = stats
        self.stats_lock = stats_lock
        self.out_q = out_q
        self.flows: Dict[FiveTuple, Flow] = {}

    def process(self, parsed: ParsedPacket) -> None:
        key = FiveTuple(
            BlockingRules.parse_ip(parsed.src_ip),
            BlockingRules.parse_ip(parsed.dst_ip),
            parsed.src_port,
            parsed.dst_port,
            parsed.protocol,
        )
        flow = self.flows.setdefault(key, Flow())
        flow.packets += 1
        flow.bytes += len(parsed.raw_data)

        if not flow.host:
            if parsed.has_tcp and parsed.dst_port == 443 and len(parsed.payload) > 5:
                sni = extract_sni(parsed.payload)
                if sni:
                    flow.host = sni
                    flow.app_type = classify_host(sni)
            if parsed.has_tcp and parsed.dst_port == 80 and not flow.host:
                host = extract_http_host(parsed.payload)
                if host:
                    flow.host = host
                    flow.app_type = classify_host(host)

        if flow.app_type == AppType.UNKNOWN and (parsed.src_port == 53 or parsed.dst_port == 53):
            flow.app_type = AppType.DNS
        elif flow.app_type == AppType.UNKNOWN and parsed.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif flow.app_type == AppType.UNKNOWN and parsed.dst_port == 80:
            flow.app_type = AppType.HTTP

        if not flow.blocked:
            flow.blocked = self.rules.should_block(key.src_ip, flow.app_type, flow.host)

        with self.stats_lock:
            self.stats.app_counts[flow.app_type] += 1
            if flow.host:
                self.stats.detected_hosts[flow.host] = flow.app_type
            if flow.blocked:
                self.stats.dropped += 1
            else:
                self.stats.forwarded += 1

        if not flow.blocked:
            self.out_q.put((True, (parsed.ts_sec, parsed.ts_usec, parsed.raw_data)))


def run_engine(
    input_file: str,
    output_file: str,
    rules: BlockingRules,
    lbs: int = 2,
    fps: int = 2,
) -> Stats:
    reader = PcapReader(input_file)
    writer = PcapWriter(output_file, reader.global_header_raw, reader.endian)

    stats = Stats()
    stats_lock = threading.Lock()
    total_workers = max(1, lbs * fps)
    out_q: "queue.Queue[Tuple[bool, Tuple[int, int, bytes]]]" = queue.Queue()
    workers = [Worker(rules, stats, stats_lock, out_q) for _ in range(total_workers)]
    in_queues: List["queue.Queue[Optional[ParsedPacket]]"] = [queue.Queue(maxsize=10000) for _ in range(total_workers)]

    def worker_loop(i: int) -> None:
        while True:
            pkt = in_queues[i].get()
            if pkt is None:
                break
            workers[i].process(pkt)

    threads = [threading.Thread(target=worker_loop, args=(i,), daemon=True) for i in range(total_workers)]
    for t in threads:
        t.start()

    for ts_sec, ts_usec, data in reader.packets():
        parsed = parse_packet(ts_sec, ts_usec, data)
        if parsed is None:
            continue
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue
        with stats_lock:
            stats.total_packets += 1
            stats.total_bytes += len(data)
            if parsed.has_tcp:
                stats.tcp_packets += 1
            elif parsed.has_udp:
                stats.udp_packets += 1
        idx = hash((parsed.src_ip, parsed.dst_ip, parsed.src_port, parsed.dst_port, parsed.protocol)) % total_workers
        in_queues[idx].put(parsed)

    for q in in_queues:
        q.put(None)
    for t in threads:
        t.join()

    while not out_q.empty():
        _ok, packet = out_q.get()
        writer.write_packet(*packet)

    reader.close()
    writer.close()
    return stats


def print_report(stats: Stats) -> None:
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {stats.total_packets:>10}                             ║")
    print(f"║ Total Bytes:        {stats.total_bytes:>10}                             ║")
    print(f"║ TCP Packets:        {stats.tcp_packets:>10}                             ║")
    print(f"║ UDP Packets:        {stats.udp_packets:>10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Forwarded:          {stats.forwarded:>10}                             ║")
    print(f"║ Dropped:            {stats.dropped:>10}                             ║")
    print("╚══════════════════════════════════════════════════════════════╝")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DPI Engine v2.0 (Python)")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("--block-ip", action="append", default=[], dest="block_ips")
    parser.add_argument("--block-app", action="append", default=[], dest="block_apps")
    parser.add_argument("--block-domain", action="append", default=[], dest="block_domains")
    parser.add_argument("--rules", help="Rule file in [BLOCKED_*] format")
    parser.add_argument("--lbs", type=int, default=2)
    parser.add_argument("--fps", type=int, default=2)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    rules = BlockingRules()
    if args.rules:
        rules.load_rules(args.rules)
    for ip in args.block_ips:
        rules.block_ip(ip)
    for app in args.block_apps:
        rules.block_app(app)
    for domain in args.block_domains:
        rules.block_domain(domain)

    stats = run_engine(args.input, args.output, rules, args.lbs, args.fps)
    print_report(stats)
    print(f"\nOutput written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
