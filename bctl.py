#!/usr/bin/env python3
"""Send one command to a baresip phone over ctrl_tcp (netstring JSON), e.g. bctl.py 4401 dial sip:2002@lab.sip"""
import json
import socket
import sys

port, cmd, params = int(sys.argv[1]), sys.argv[2], " ".join(sys.argv[3:])
body = json.dumps({"command": cmd, "params": params, "token": cmd}).encode()
with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
    s.sendall(str(len(body)).encode() + b":" + body + b",")
    try:
        print(s.recv(4096).decode(errors="replace"))
    except socket.timeout:
        pass
