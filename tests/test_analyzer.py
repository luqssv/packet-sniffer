from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from packet_sniffer.analyzer import AnalyzerState, PacketAnalyzer


def test_extracts_tcp_event_fields() -> None:
    packet = IP(src="10.0.0.2", dst="93.184.216.34") / TCP(sport=50500, dport=443, flags="S")

    event = PacketAnalyzer().analyze(packet)

    assert event.protocol == "TCP"
    assert event.src_ip == "10.0.0.2"
    assert event.dst_ip == "93.184.216.34"
    assert event.src_port == 50500
    assert event.dst_port == 443
    assert event.flags == ["S"]


def test_flags_cleartext_secret_in_payload() -> None:
    packet = (
        IP(src="10.0.0.2", dst="93.184.216.34")
        / TCP(sport=50500, dport=80, flags="PA")
        / Raw(load=b"POST /login username=alice&password=hunter2")
    )

    event = PacketAnalyzer().analyze(packet)

    assert "possible_cleartext_secret" in event.suspicious


def test_flags_long_dns_query() -> None:
    packet = (
        IP(src="10.0.0.2", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="a" * 90 + ".example.com"))
    )

    event = PacketAnalyzer().analyze(packet)

    assert event.protocol == "DNS"
    assert "long_dns_query" in event.suspicious


def test_flags_syn_scan_after_threshold() -> None:
    analyzer = PacketAnalyzer(AnalyzerState(syn_scan_threshold=3))

    findings = []
    for port in [10001, 10002, 10003]:
        packet = IP(src="10.0.0.9", dst="10.0.0.10") / TCP(sport=40000, dport=port, flags="S")
        findings = analyzer.analyze(packet).suspicious

    assert "possible_syn_scan" in findings
