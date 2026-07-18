from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet, Raw

from packet_sniffer.models import PacketEvent, utc_now_iso


CLEARTEXT_SECRET_RE = re.compile(
    rb"(?i)\b(user(name)?|login|password|passwd|pwd|token|api[_-]?key)\s*[:=]\s*[^&\s]{3,}"
)

COMMON_PORTS = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    80,
    110,
    123,
    143,
    161,
    389,
    443,
    445,
    465,
    587,
    993,
    995,
    3389,
}


@dataclass
class AnalyzerState:
    syn_window_seconds: int = 10
    syn_scan_threshold: int = 20
    high_volume_threshold: int = 200
    syn_targets: dict[str, deque[tuple[float, str]]] = field(default_factory=lambda: defaultdict(deque))
    flow_counts: dict[tuple[str, str], deque[float]] = field(default_factory=lambda: defaultdict(deque))


class PacketAnalyzer:
    """Converts Scapy packets into events and applies simple defensive heuristics."""

    def __init__(self, state: AnalyzerState | None = None) -> None:
        self.state = state or AnalyzerState()

    def analyze(self, packet: Packet) -> PacketEvent:
        event = self._base_event(packet)
        event.suspicious.extend(self._suspicious_patterns(packet, event))
        return event

    def _base_event(self, packet: Packet) -> PacketEvent:
        event = PacketEvent(
            timestamp=utc_now_iso(),
            protocol="OTHER",
            length=len(packet),
            summary=packet.summary(),
        )

        if IP in packet:
            event.src_ip = packet[IP].src
            event.dst_ip = packet[IP].dst
        elif IPv6 in packet:
            event.src_ip = packet[IPv6].src
            event.dst_ip = packet[IPv6].dst

        if TCP in packet:
            tcp = packet[TCP]
            event.protocol = "TCP"
            event.src_port = int(tcp.sport)
            event.dst_port = int(tcp.dport)
            event.flags = [str(tcp.flags)]
        elif UDP in packet:
            udp = packet[UDP]
            event.protocol = "UDP"
            event.src_port = int(udp.sport)
            event.dst_port = int(udp.dport)
        elif ICMP in packet:
            event.protocol = "ICMP"
            event.metadata["icmp_type"] = int(packet[ICMP].type)
            event.metadata["icmp_code"] = int(packet[ICMP].code)
        elif ARP in packet:
            event.protocol = "ARP"
            event.src_ip = packet[ARP].psrc
            event.dst_ip = packet[ARP].pdst
            event.metadata["operation"] = int(packet[ARP].op)

        if DNS in packet and packet[DNS].qd:
            event.protocol = "DNS"
            query = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
            event.metadata["query"] = query

        return event

    def _suspicious_patterns(self, packet: Packet, event: PacketEvent) -> list[str]:
        findings: list[str] = []

        if TCP in packet and event.src_ip and event.dst_ip:
            findings.extend(self._tcp_findings(packet, event))

        if Raw in packet:
            payload = bytes(packet[Raw].load)
            if CLEARTEXT_SECRET_RE.search(payload):
                findings.append("possible_cleartext_secret")

        if event.dst_port and event.dst_port not in COMMON_PORTS and event.dst_port > 1024:
            findings.append("uncommon_destination_port")

        if DNS in packet and "query" in event.metadata:
            query = str(event.metadata["query"])
            if len(query) > 80:
                findings.append("long_dns_query")
            if query.count(".") >= 5:
                findings.append("deeply_nested_dns_query")

        if event.src_ip and event.dst_ip:
            findings.extend(self._volume_findings(event.src_ip, event.dst_ip))

        return sorted(set(findings))

    def _tcp_findings(self, packet: Packet, event: PacketEvent) -> Iterable[str]:
        tcp = packet[TCP]
        flags = str(tcp.flags)

        if flags == "S":
            now = time.monotonic()
            targets = self.state.syn_targets[event.src_ip]
            targets.append((now, f"{event.dst_ip}:{event.dst_port}"))
            self._trim_targets(targets, now)
            unique_targets = {target for _, target in targets}
            if len(unique_targets) >= self.state.syn_scan_threshold:
                yield "possible_syn_scan"

        if flags == "FPU":
            yield "possible_xmas_scan"
        if flags == "F":
            yield "possible_fin_scan"
        if int(tcp.window) == 0 and flags == "S":
            yield "zero_window_syn"

    def _volume_findings(self, src_ip: str, dst_ip: str) -> Iterable[str]:
        now = time.monotonic()
        key = (src_ip, dst_ip)
        entries = self.state.flow_counts[key]
        entries.append(now)
        while entries and now - entries[0] > self.state.syn_window_seconds:
            entries.popleft()

        if len(entries) >= self.state.high_volume_threshold:
            yield "high_packet_rate_between_hosts"

    def _trim_targets(self, targets: deque[tuple[float, str]], now: float) -> None:
        while targets and now - targets[0][0] > self.state.syn_window_seconds:
            targets.popleft()
