from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from scapy.all import get_if_list

from packet_sniffer.sniffer import PacketSniffer

app = typer.Typer(help="Capture and analyze live network traffic for defensive monitoring.")
console = Console()


@app.command()
def capture(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to capture on."),
    protocol: Optional[str] = typer.Option(
        None,
        "--protocol",
        "-p",
        help="Protocol shortcut: tcp, udp, icmp, arp, dns, http, https.",
    ),
    bpf_filter: Optional[str] = typer.Option(None, "--filter", "-f", help="Raw BPF filter, overrides --protocol."),
    count: int = typer.Option(0, "--count", "-c", min=0, help="Stop after this many packets. 0 means unlimited."),
    timeout: Optional[int] = typer.Option(None, "--timeout", "-t", min=1, help="Stop after this many seconds."),
    jsonl: Path = typer.Option(Path("logs/packets.jsonl"), "--jsonl", help="JSON Lines log path."),
    csv: Optional[Path] = typer.Option(Path("logs/packets.csv"), "--csv", help="Optional CSV log path."),
    pcap: Optional[Path] = typer.Option(None, "--pcap", help="Optional PCAP file for Wireshark validation."),
    quiet: bool = typer.Option(False, "--quiet", help="Do not print each packet to the terminal."),
) -> None:
    selected_filter = bpf_filter or protocol_to_bpf(protocol)
    sniffer = PacketSniffer(
        interface=interface,
        bpf_filter=selected_filter,
        jsonl_path=jsonl,
        csv_path=csv,
        pcap_path=pcap,
        packet_count=count,
        timeout=timeout,
        quiet=quiet,
    )
    sniffer.run()


@app.command("interfaces")
def interfaces() -> None:
    """List capture interfaces visible to Scapy."""
    for iface in get_if_list():
        console.print(iface)


def protocol_to_bpf(protocol: str | None) -> str | None:
    if protocol is None:
        return None

    filters = {
        "tcp": "tcp",
        "udp": "udp",
        "icmp": "icmp",
        "arp": "arp",
        "dns": "udp port 53 or tcp port 53",
        "http": "tcp port 80",
        "https": "tcp port 443",
    }
    normalized = protocol.lower()
    if normalized not in filters:
        valid = ", ".join(sorted(filters))
        raise typer.BadParameter(f"Unknown protocol '{protocol}'. Choose one of: {valid}")
    return filters[normalized]


if __name__ == "__main__":
    app()
