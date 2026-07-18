from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table
from scapy.all import sniff, wrpcap
from scapy.packet import Packet

from packet_sniffer.analyzer import PacketAnalyzer
from packet_sniffer.logging import EventLogger


class PacketSniffer:
    def __init__(
        self,
        interface: str | None,
        bpf_filter: str | None,
        jsonl_path: Path,
        csv_path: Path | None = None,
        pcap_path: Path | None = None,
        packet_count: int = 0,
        timeout: int | None = None,
        quiet: bool = False,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self.timeout = timeout
        self.pcap_path = pcap_path
        self.quiet = quiet
        self.console = Console()
        self.analyzer = PacketAnalyzer()
        self.logger = EventLogger(jsonl_path=jsonl_path, csv_path=csv_path)
        self.captured_packets: list[Packet] = []

    def run(self) -> None:
        self._print_startup()
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
                count=self.packet_count,
                timeout=self.timeout,
            )
        finally:
            self.logger.close()
            if self.pcap_path and self.captured_packets:
                self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
                wrpcap(str(self.pcap_path), self.captured_packets)

    def _handle_packet(self, packet: Packet) -> None:
        if self.pcap_path:
            self.captured_packets.append(packet)

        event = self.analyzer.analyze(packet)
        self.logger.write(event)

        if not self.quiet:
            self._print_event(event.protocol, event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.suspicious)

    def _print_startup(self) -> None:
        if self.quiet:
            return
        self.console.print("[bold green]Packet sniffer started[/bold green]")
        self.console.print(f"Interface: {self.interface or 'default'}")
        self.console.print(f"Filter: {self.bpf_filter or 'none'}")
        if self.packet_count:
            self.console.print(f"Packet limit: {self.packet_count}")
        if self.timeout:
            self.console.print(f"Timeout: {self.timeout}s")

    def _print_event(
        self,
        protocol: str,
        src_ip: str | None,
        dst_ip: str | None,
        src_port: int | None,
        dst_port: int | None,
        suspicious: list[str],
    ) -> None:
        table = Table.grid(padding=(0, 1))
        table.add_column(style="cyan")
        table.add_column()
        table.add_row("proto", protocol)
        table.add_row("src", f"{src_ip or '-'}:{src_port or '-'}")
        table.add_row("dst", f"{dst_ip or '-'}:{dst_port or '-'}")
        if suspicious:
            table.add_row("alert", ", ".join(suspicious))
        self.console.print(table)
