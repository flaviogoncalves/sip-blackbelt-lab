#!/usr/bin/env python3
"""Write dtmf-inband.pcap for call-inband.xml: RTP PCMU (payload 0), 20 ms packets, the digits 1, 2, 3, # as audio
tones (200 ms tone, 200 ms gap) after 1 s of silence. SIPp's play_pcap_audio rewrites addresses and ports.
Tone pairs: 1 = 697+1209 Hz, 2 = 697+1336, 3 = 697+1477, # = 941+1477 (the DTMF keypad)."""
import math
import struct

RATE, PTIME = 8000, 160
DIGITS = {"1": (697, 1209), "2": (697, 1336), "3": (697, 1477), "#": (941, 1477)}


def ulaw(x):  # 16-bit linear sample -> G.711 mu-law byte
    sign = 0x80 if x < 0 else 0
    x = min(abs(x), 32635) + 0x84
    exp = 7
    while exp > 0 and not x & (0x4000 >> (7 - exp)):
        exp -= 1
    return ~(sign | exp << 4 | (x >> (exp + 3)) & 0x0F) & 0xFF


samples = [0] * RATE
for d in "123#":
    f1, f2 = DIGITS[d]
    samples += [int(8000 * (math.sin(2 * math.pi * f1 * n / RATE) + math.sin(2 * math.pi * f2 * n / RATE)))
                for n in range(RATE // 5)]
    samples += [0] * (RATE // 5)
samples += [0] * (RATE // 2)

out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
for i in range(len(samples) // PTIME):
    payload = bytes(ulaw(s) for s in samples[i * PTIME:(i + 1) * PTIME])
    rtp = struct.pack("!BBHII", 0x80, 0x80 if i == 0 else 0, i + 1, i * PTIME, 0x5EED0001) + payload
    udp = struct.pack("!HHHH", 30000, 40000, 8 + len(rtp), 0) + rtp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i, 0, 64, 17, 0,
                     bytes([192, 0, 2, 21]), bytes([192, 0, 2, 22])) + udp
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip
    t = i * 0.02
    out.append(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(eth), len(eth)) + eth)
open("dtmf-inband.pcap", "wb").write(b"".join(out))
print(len(out) - 1, "packets")
