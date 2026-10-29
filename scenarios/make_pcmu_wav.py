#!/usr/bin/env python3
"""Write voice-pcmu.wav for the load takes (take-wireshark.sh busy/ring): 4 s of G.711 mu-law (PCMU, 8 kHz, mono) in a
WAV file, a slow two-note tone pattern so the RTP Player has something to hear. SIPp's rtp_stream action plays it as
payload type 0 from its own RTP port per call (play_pcap_audio would send every call from one shared port)."""
import math
import struct

RATE = 8000


def ulaw(x):  # 16-bit linear sample -> G.711 mu-law byte
    sign = 0x80 if x < 0 else 0
    x = min(abs(x), 32635) + 0x84
    exp = 7
    while exp > 0 and not x & (0x4000 >> (7 - exp)):
        exp -= 1
    return ~(sign | exp << 4 | (x >> (exp + 3)) & 0x0F) & 0xFF


samples = []
for i, f in enumerate([440, 554, 440, 659, 440, 554, 440, 0]):   # 8 notes of 0.5 s, the last one silent
    for n in range(RATE // 2):
        env = min(1.0, n / 200, (RATE // 2 - n) / 200)              # 25 ms fade in and out: no clicks
        samples.append(int(6000 * env * math.sin(2 * math.pi * f * n / RATE)))
data = bytes(ulaw(s) for s in samples)
fmt = struct.pack("<HHIIHHHH", 7, 1, RATE, RATE, 1, 8, 2, 0)          # format 7 = mu-law, cbSize 0
riff = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"fact" + struct.pack("<II", 4, len(data)) \
    + b"data" + struct.pack("<I", len(data)) + data
open("voice-pcmu.wav", "wb").write(b"RIFF" + struct.pack("<I", len(riff)) + riff)
print(len(data), "samples")
