#!/usr/bin/env python3
"""Turn the TLS keys OpenSIPS reported over HEP into a key log file that Wireshark and tshark read.

    hep_keylog.py <keys.txt> <capture.pcap> > keys.log

keys.txt is what hep_collector.py --keys wrote: one line per TLS connection OpenSIPS accepted (client address, server
address, key). For a TLS 1.2 connection that key is the master secret, and a key log line for it is
"CLIENT_RANDOM <client random> <master secret>" (the NSS key log format); the client random is in the connection's
Client Hello, which the capture has in clear. A TLS 1.3 connection is not decrypted by its master secret alone (it needs
the handshake and traffic secrets, which the HEP event does not carry), so this works only for TLS 1.2.
"""
import subprocess
import sys


def main() -> None:
    keys, pcap = sys.argv[1], sys.argv[2]
    hello = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "tls.handshake.type == 1", "-T", "fields", "-e", "ip.src", "-e", "tcp.srcport",
         "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tls.handshake.random"],
        capture_output=True, text=True, check=True).stdout
    randoms = {}
    for line in hello.splitlines():
        src, sport, dst, dport, rnd = line.split("\t")
        randoms[(f"{src}:{sport}", f"{dst}:{dport}")] = rnd.replace(":", "")
    found = 0
    for line in open(keys):
        client, server, key = line.split()
        rnd = randoms.get((client, server))
        if rnd and len(key) == 96:   # 48 bytes: a TLS 1.2 master secret
            print(f"CLIENT_RANDOM {rnd} {key}")
            found += 1
    print(f"{found} connection(s) matched", file=sys.stderr)


if __name__ == "__main__":
    main()
