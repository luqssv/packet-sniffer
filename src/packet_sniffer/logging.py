from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import TextIO

from packet_sniffer.models import PacketEvent


class EventLogger:
    def __init__(self, jsonl_path: Path, csv_path: Path | None = None) -> None:
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self.jsonl_file: TextIO = jsonl_path.open("a", encoding="utf-8")
        self.csv_file: TextIO | None = None
        self.csv_writer: csv.DictWriter[str] | None = None

        if csv_path:
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            should_write_header = not csv_path.exists() or csv_path.stat().st_size == 0
            self.csv_file = csv_path.open("a", encoding="utf-8", newline="")
            self.csv_writer = csv.DictWriter(
                self.csv_file,
                fieldnames=[
                    "timestamp",
                    "protocol",
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "length",
                    "summary",
                    "flags",
                    "suspicious",
                    "metadata",
                ],
            )
            if should_write_header:
                self.csv_writer.writeheader()

    def write(self, event: PacketEvent) -> None:
        data = event.to_dict()
        self.jsonl_file.write(json.dumps(data, sort_keys=True) + "\n")
        self.jsonl_file.flush()

        if self.csv_writer:
            row = data.copy()
            row["flags"] = ",".join(row["flags"])
            row["suspicious"] = ",".join(row["suspicious"])
            row["metadata"] = json.dumps(row["metadata"], sort_keys=True)
            self.csv_writer.writerow(row)
            assert self.csv_file is not None
            self.csv_file.flush()

    def close(self) -> None:
        self.jsonl_file.close()
        if self.csv_file:
            self.csv_file.close()

    def __enter__(self) -> "EventLogger":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
