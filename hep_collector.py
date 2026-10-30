#!/usr/bin/env python3
"""A minimal HEP collector: receive HEPv3 packets over UDP and print what each one carries.

    hep_collector.py [--listen 192.0.2.10:9060] [--keys file]

OpenSIPS (proto_hep + tracer) mirrors every SIP message it receives and sends to a HEP collector, as it saw it: a call
over TLS arrives here as plain SIP text, because OpenSIPS decrypted it before tracing it. proto_tls can also report each
TLS connection (certificates, a key, the result of the handshake) as a HEP event. Homer is the usual collector; this one
only decodes the packets, one block per packet, in the same layout as the lab's .messages.txt files:

    ===== hep 3  t=0.012s  192.0.2.21:40312 -> 192.0.2.10:5061  TLS  SIP
    REGISTER sip:lab.sip SIP/2.0
    ...

HEPv3 (the HEP3 header, then chunks of vendor id, type id, length and value) is decoded here because tshark 4.4 has no
HEP dissector. --keys writes one line per TLS event: client address, server address and the key the event carries (for
a TLS 1.2 connection, the master secret; see take-security.sh's tlsdebug12 case).
"""
import argparse
import re
import socket
import struct
import sys
import time

TRANSPORT = {6: "TCP", 17: "UDP", 22: "TLS"}   # the IP protocol chunk (2); OpenSIPS 4.0 writes 22 for SIP over TLS
PAYLOAD_TYPE = {1: "SIP", 5: "RTCP", 100: "LOG"}


def chunks(data: bytes) -> dict:
    """The chunks of one HEPv3 packet, keyed by chunk type (vendor 0 only)."""
    if data[:4] != b"HEP3":
        raise ValueError("not a HEPv3 packet")
    total = struct.unpack("!H", data[4:6])[0]
    pos, out = 6, {}
    while pos + 6 <= min(total, len(data)):
        vendor, ctype, length = struct.unpack("!HHH", data[pos:pos + 6])
        if length < 6:
            break
        if vendor == 0:
            out[ctype] = data[pos + 6:pos + length]
        pos += length
    return out


def num(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0


def address(c: dict, ip: int, port: int) -> str:
    raw = c.get(ip, b"")
    if len(raw) == 4:
        host = socket.inet_ntop(socket.AF_INET, raw)
    elif len(raw) == 16:
        host = "[" + socket.inet_ntop(socket.AF_INET6, raw) + "]"
    else:
        host = "?"
    return f"{host}:{num(c.get(port, b''))}"


TLS_TAIL = re.compile(rb":([A-Z_]+):([A-Z_]+):([\x20-\x7e]*)$")


def tls_event(payload: bytes) -> tuple[str, str]:
    """proto_tls's event: TLS:<subject>:<issuer>:<key bytes>:<event>:<status>:<message> when a connection is accepted
    or made, TLS:<event>:<status>:<message> when it closes. Returns (text, key hex)."""
    tail = TLS_TAIL.search(payload)
    if not tail:
        return payload.hex(), ""
    text = f"TLS event: {tail.group(1).decode()} {tail.group(2).decode()} ({tail.group(3).decode()})"
    head = payload[:tail.start()].split(b":", 3)
    if len(head) < 4:
        return text, ""
    key = head[3]
    text += (f"\ncertificate subject: {head[1].decode(errors='replace')}"
             f"\ncertificate issuer:  {head[2].decode(errors='replace')}"
             f"\nkey ({len(key)} bytes): {key.hex()}")
    return text, key.hex()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", default="192.0.2.10:9060")
    ap.add_argument("--keys", help="append client, server and key of every TLS event to this file")
    a = ap.parse_args()
    host, port = a.listen.rsplit(":", 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, int(port)))
    start, n = None, 0
    while True:
        data, _ = s.recvfrom(65535)
        try:
            c = chunks(data)
        except ValueError:
            continue
        n += 1
        t = num(c.get(9, b"")) + num(c.get(10, b"")) / 1e6
        start = start or t
        src = address(c, 3, 7) if 3 in c else address(c, 5, 7)
        dst = address(c, 4, 8) if 4 in c else address(c, 6, 8)
        proto = num(c.get(2, b""))
        ptype = num(c.get(11, b""))
        payload = c.get(15, b"")
        kind = PAYLOAD_TYPE.get(ptype, f"type {ptype}")
        if payload.startswith(b"TLS:"):
            body, key = tls_event(payload)
            kind = "TLS event"
            if a.keys and key:
                with open(a.keys, "a") as f:
                    f.write(f"{src} {dst} {key}\n")
        else:
            body = payload.decode("utf-8", "replace").replace("\r\n", "\n").strip()
        corr = c.get(17, b"").decode(errors="replace")
        print(f"===== hep {n}  t={t - start:.3f}s  {src} -> {dst}  {TRANSPORT.get(proto, f'proto {proto}')}  {kind}"
              + (f"  correlation {corr}" if corr else "") + f"\n{body}\n", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
