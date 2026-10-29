#!/usr/bin/env python3
"""Decode a SIP pcap into the text the trace boards read (capture/<take>.messages.txt).

    .venv/bin/python projects/voip-school-sip/tools/pcap_messages.py <take.pcap> [out.txt]

Needs tshark on the machine (the lab has it). One block per SIP packet, with frame number, relative time and the
source/destination; the payload is the UDP payload decoded as text, CRLF folded to LF.
"""
import subprocess
import sys
from pathlib import Path

FIELDS = ["frame.number", "frame.time_relative", "ip.src", "ip.dst", "udp.payload"]


def main() -> None:
    pcap = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else pcap.with_suffix(".messages.txt")
    cmd = ["tshark", "-r", str(pcap), "-Y", "sip", "-T", "fields"]
    for f in FIELDS:
        cmd += ["-e", f]
    text = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    blocks = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        n, t, src, dst, payload = parts[:5]
        if not payload:
            continue
        try:
            raw = bytes.fromhex(payload.replace(":", ""))
        except ValueError:
            continue
        msg = raw.decode("utf-8", "replace").replace("\r\n", "\n").strip()
        blocks.append(f"===== frame {n}  t={float(t):.3f}s  {src} -> {dst}\n{msg}\n")
    out.write_text("\n".join(blocks))
    print(f"{out}: {len(blocks)} SIP messages")


if __name__ == "__main__":
    main()
