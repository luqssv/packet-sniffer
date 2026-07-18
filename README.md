# Packet Sniffer

A simple defensive packet sniffer for capturing and reviewing live network traffic.

It can:

- Capture live packets from a network interface
- Filter traffic by protocol
- Flag suspicious activity
- Save logs as JSONL and CSV
- Save PCAP files for Wireshark

> Only use this on networks and devices you own or have permission to monitor.

## Requirements

- Python 3.10+
- Admin/root permissions for live packet capture
- Windows users: install [Npcap](https://npcap.com/)
- Optional: Wireshark for opening `.pcap` files

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .[dev]
```

## List Interfaces

```powershell
packet-sniffer interfaces
```

## Run

Capture DNS traffic:

```powershell
packet-sniffer capture --protocol dns --count 25 --pcap captures/dns-test.pcap
```

Capture TCP traffic:

```powershell
packet-sniffer capture --protocol tcp --count 50
```

Use a custom filter:

```powershell
packet-sniffer capture --filter "tcp port 443" --timeout 30
```

## Protocol Filters

Supported shortcuts:

- `tcp`
- `udp`
- `dns`
- `http`
- `https`
- `icmp`
- `arp`

## Output

By default, logs are saved to:

- `logs/packets.jsonl`
- `logs/packets.csv`

If you use `--pcap`, packets are also saved for Wireshark.

## Test

```powershell
pytest
```

## Push To GitHub

Create an empty GitHub repository, then run:

```powershell
git remote add origin https://github.com/YOUR_USERNAME/packet-sniffer.git
git push -u origin main
```

Or with GitHub CLI:

```powershell
gh repo create packet-sniffer --private --source . --remote origin --push
```
