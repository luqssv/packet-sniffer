# Packet Sniffer

A defensive Python packet sniffer for capturing and analyzing live traffic. It supports protocol filters, suspicious-pattern alerts, JSON/CSV logs, optional PCAP export, and a Wireshark validation workflow.

> Use this only on networks and devices you own or are authorized to monitor.

## What It Does

- Captures live packets with Scapy/libpcap.
- Filters by protocol shortcut or raw BPF filter.
- Logs every packet event to `logs/packets.jsonl` and `logs/packets.csv`.
- Optionally saves raw packets to a `.pcap` file for Wireshark.
- Flags defensive indicators:
  - possible SYN scans
  - possible FIN or XMAS scans
  - cleartext credentials or API tokens in payloads
  - uncommon destination ports
  - unusually long or deeply nested DNS queries
  - high packet rate between the same hosts

## Requirements

- Python 3.10+
- Windows: install [Npcap](https://npcap.com/) so Scapy can capture packets.
- macOS/Linux: libpcap is usually built in or available through your package manager.
- Admin/root privileges for live capture.
- Wireshark for validation.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .[dev]
```

List available interfaces:

```powershell
packet-sniffer interfaces
```

Run a short capture:

```powershell
packet-sniffer capture --interface "YOUR_INTERFACE" --protocol dns --count 25 --pcap captures/dns-test.pcap
```

If you are not sure which interface to use, run without `--interface` first:

```powershell
packet-sniffer capture --protocol tcp --count 10
```

## Filtering

Protocol shortcuts:

```powershell
packet-sniffer capture --protocol tcp
packet-sniffer capture --protocol udp
packet-sniffer capture --protocol dns
packet-sniffer capture --protocol http
packet-sniffer capture --protocol https
packet-sniffer capture --protocol icmp
packet-sniffer capture --protocol arp
```

Raw BPF filters override protocol shortcuts:

```powershell
packet-sniffer capture --filter "host 8.8.8.8 and udp port 53"
packet-sniffer capture --filter "tcp port 443" --timeout 30
packet-sniffer capture --filter "net 192.168.1.0/24"
```

## Logs

Default output:

- `logs/packets.jsonl`: one JSON object per packet event.
- `logs/packets.csv`: spreadsheet-friendly event log.

Example event:

```json
{
  "protocol": "DNS",
  "src_ip": "192.168.1.10",
  "dst_ip": "8.8.8.8",
  "src_port": 53000,
  "dst_port": 53,
  "suspicious": ["long_dns_query"],
  "metadata": {"query": "very-long-name.example.com"}
}
```

## Wireshark Validation

1. Run this sniffer and save a PCAP:

   ```powershell
   packet-sniffer capture --protocol dns --count 50 --pcap captures/validation.pcap
   ```

2. Generate traffic in another terminal:

   ```powershell
   nslookup example.com
   ping 8.8.8.8
   curl http://example.com
   ```

3. Open `captures/validation.pcap` in Wireshark.

4. Compare Wireshark display filters to this tool's logs:

   ```text
   dns
   tcp
   icmp
   tcp.flags.syn == 1 && tcp.flags.ack == 0
   ```

5. Confirm that packet counts, source/destination addresses, ports, DNS queries, and suspicious flags match the JSON/CSV logs.

## Complete Test Plan

Run unit tests:

```powershell
pytest
```

Manual live-capture tests:

1. DNS filter:

   ```powershell
   packet-sniffer capture --protocol dns --count 10 --pcap captures/dns.pcap
   nslookup example.com
   ```

2. ICMP filter:

   ```powershell
   packet-sniffer capture --protocol icmp --count 4 --pcap captures/icmp.pcap
   ping 8.8.8.8
   ```

3. HTTP cleartext alert against a local test server:

   ```powershell
   python -m http.server 8080
   packet-sniffer capture --filter "tcp port 8080" --count 20 --pcap captures/http.pcap
   curl "http://127.0.0.1:8080/?username=alice&password=hunter2"
   ```

4. Wireshark comparison:
   - Open each `.pcap`.
   - Apply the matching Wireshark display filter.
   - Compare rows with `logs/packets.jsonl` or `logs/packets.csv`.

## How It Works

`src/packet_sniffer/cli.py` defines the command-line interface. It maps friendly protocol names like `dns` or `https` to BPF capture filters.

`src/packet_sniffer/sniffer.py` starts Scapy's live capture. For each packet, it calls the analyzer, writes logs, prints a concise terminal event, and optionally stores raw packets for PCAP export.

`src/packet_sniffer/analyzer.py` converts packets into normalized `PacketEvent` records. It inspects layers such as IP, TCP, UDP, ICMP, ARP, DNS, and Raw payloads, then applies suspicious-pattern heuristics.

`src/packet_sniffer/logging.py` writes every event to JSON Lines and CSV so you can use the logs in scripts, SIEM pipelines, or spreadsheets.

## Create a New GitHub Repo

This workspace can be initialized as a local git repo:

```powershell
git init
git add .
git commit -m "Initial packet sniffer"
```

Then create an empty GitHub repo and push:

```powershell
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/packet-sniffer.git
git push -u origin main
```

If you have GitHub CLI installed:

```powershell
gh repo create packet-sniffer --private --source . --remote origin --push
```
