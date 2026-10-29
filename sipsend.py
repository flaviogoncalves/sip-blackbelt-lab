#!/usr/bin/env python3
"""Send hand-written SIP requests over UDP and print what comes back.

    sipsend.py [--src 192.0.2.21] [--wait 2] <host[:port]> <request-file>...

Each request file is one SIP request exactly as it goes on the wire, written with plain line ends (sipsend turns them into
CRLF). The file is sent as written, mistakes included: sipsend never fixes a header. These placeholders are filled in:

    {src}     the source address          {port}    the source port (a new one per request)
    {branch}  a new Via branch (z9hG4bK)  {tag}     a new From tag
    {callid}  a new Call-ID               {len}     the length in bytes of the body (after the blank line)

For each request it prints the request line, then the status line of every reply that arrives within --wait seconds
(a 100 Trying and the final response, for instance) with the headers that say why: Allow, Accept, Unsupported, Require,
Retry-After, Min-SE, Warning. "(no reply)" means the element dropped the request. For an INVITE it does what a phone
would: it ACKs a final error reply (RFC 3261 17.1.1.3), so the server stops resending it, and it CANCELs an INVITE that
is still ringing when --wait runs out (RFC 3261 9.1). Example (lab/requests/):

    ./sipsend.py 192.0.2.10 requests/no-call-id.sip
"""
import argparse
import secrets
import socket
from pathlib import Path

WHY = ("allow", "accept", "unsupported", "require", "retry-after", "min-se", "warning")


def build(text: str, src: str, port: int) -> bytes:
    head, _, body = text.replace("\r\n", "\n").partition("\n\n")
    token = secrets.token_hex(6)
    values = {"src": src, "port": str(port), "branch": "z9hG4bK" + token, "tag": token[:8], "callid": token,
              "len": str(len(body.replace("\n", "\r\n").encode()))}
    for key, value in values.items():
        head = head.replace("{" + key + "}", value)
    return (head.rstrip("\n").replace("\n", "\r\n") + "\r\n\r\n" + body.replace("\n", "\r\n")).encode()


def headers(msg: bytes) -> tuple[str, dict]:
    """The first line of a message and its first header of each name (lower-case name -> whole line)."""
    lines = msg.split(b"\r\n\r\n", 1)[0].decode(errors="replace").split("\r\n")
    found = {}
    for ln in lines[1:]:
        found.setdefault(ln.split(":", 1)[0].strip().lower(), ln)
    return lines[0], found


def summary(reply: bytes) -> str:
    lines = reply.decode(errors="replace").split("\r\n")
    why = [ln for ln in lines[1:] if ln.split(":", 1)[0].strip().lower() in WHY]
    return "  ".join([lines[0]] + why)


def in_transaction(request: bytes, method: str, to_line: str) -> bytes:
    """ACK (to a final error reply) or CANCEL for an INVITE: same Request-URI, Via branch, From, Call-ID and CSeq
    number as the INVITE; the ACK takes the To of the reply (with the tag), the CANCEL the To of the INVITE."""
    first, h = headers(request)
    cseq = h["cseq"].split(":", 1)[1].split()[0]
    lines = [f"{method} {first.split()[1]} SIP/2.0", h["via"], "Max-Forwards: 70", h["from"], to_line, h["call-id"],
             f"CSeq: {cseq} {method}", "Content-Length: 0"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def receive(s: socket.socket, request: bytes, dest: tuple) -> list:
    """Print every reply until the socket is quiet; ACK final error replies to an INVITE. Returns the status codes."""
    codes = []
    try:
        while True:
            reply = s.recv(65535)
            print("  < " + summary(reply))
            code = int(reply.split(b" ", 2)[1])
            codes.append(code)
            _, h = headers(reply)
            if request.startswith(b"INVITE ") and code >= 300 and h.get("cseq", "").endswith("INVITE"):
                s.sendto(in_transaction(request, "ACK", h["to"]), dest)
    except socket.timeout:
        pass
    return codes


def send(dest: tuple, path: Path, src: str, wait: float) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((src, 0))
        s.settimeout(wait)
        msg = build(path.read_text(), src, s.getsockname()[1])
        print(f"> {path.name}: {headers(msg)[0]}")
        s.sendto(msg, dest)
        codes = receive(s, msg, dest)
        if not codes:
            print("  < (no reply)")
        elif msg.startswith(b"INVITE ") and max(codes) < 200:
            print(f"> CANCEL (no final reply after {wait:g} s)")
            s.sendto(in_transaction(msg, "CANCEL", headers(msg)[1]["to"]), dest)
            receive(s, msg, dest)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("dest", help="host[:port] to send to (port 5060 if left out)")
    ap.add_argument("files", nargs="+", type=Path, help="request files")
    ap.add_argument("--src", default="192.0.2.21", help="source address (default 192.0.2.21, phone 2001)")
    ap.add_argument("--wait", type=float, default=2.0, help="seconds to wait for replies (default 2)")
    a = ap.parse_args()
    host, _, port = a.dest.partition(":")
    for path in a.files:
        send((host, int(port or 5060)), path, a.src, a.wait)


if __name__ == "__main__":
    main()
