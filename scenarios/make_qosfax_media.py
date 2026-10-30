#!/usr/bin/env python3
"""Write the media files of take-qosfax.sh (lessons 6.10-6.13). Nothing here comes from a real fax machine or a real
phone: the files are generated so the takes have audio with known content.

  talk-silence.wav   8 kHz 16-bit mono WAV for pjsua (--play-file): 1 s of a 440 Hz tone ("talk"), then 3 s of digital
                     silence, four times (16 s). With VAD on, the phone should stop sending RTP in the silences.
  fax-cng.pcap       RTP PCMU (payload 0, 20 ms) for SIPp's play_pcap_audio: the calling fax's CNG tone, 1100 Hz for
                     0.5 s, then 3 s off (RFC 4733 table "CNG 1100 Hz, 0.5 s on, 3.0 s off"): one cycle, 3.5 s (the
                     answer's CED comes within it).
  fax-ced.pcap       RTP PCMU for SIPp: the answering fax's CED tone, 2100 Hz (ITU-T T.38 clause 7 lists "CED (2100 Hz)"),
                     3 s, then 1 s of silence.
  fax-silence.pcap   RTP PCMU for SIPp: 4 s of digital silence (the voice channel after a refused switch to T.38).
  fax-t38.pcap       UDPTL packets (ITU-T T.38 Annex A, the 2002 ASN.1, BASIC-ALIGNED PER) for SIPp's play_pcap_image:
                     what the receiving gateway sends once the call is in T.38 (T.38 D.2.2.4.2: "the ITU-T T.38 facsimile
                     call proceeds with an ITU-T T.38 V.21 flags indicator packet"): the t30-indicator v21-preamble
                     sent three times, 20 ms apart, each UDPTL packet carrying the earlier ones as secondary-ifp-packets
                     (T38FaxUdpEC:t38UDPRedundancy). No fax page data follows: there is no fax machine behind it.
SIPp's pcap play rewrites the addresses and ports to the negotiated ones. The v21-preamble indicator encodes the same
under the 1998 (A.2) and 2002 (A.1) ASN.1: both have the extension marker after the 16 root values.
"""
import math
import struct
import wave

RATE, PTIME = 8000, 160


def ulaw(x):  # 16-bit linear sample -> G.711 mu-law byte
    sign = 0x80 if x < 0 else 0
    x = min(abs(x), 32635) + 0x84
    exp = 7
    while exp > 0 and not x & (0x4000 >> (7 - exp)):
        exp -= 1
    return ~(sign | exp << 4 | (x >> (exp + 3)) & 0x0F) & 0xFF


def tone(f, secs, amp=8000):
    return [int(amp * math.sin(2 * math.pi * f * n / RATE)) for n in range(int(RATE * secs))]


def silence(secs):
    return [0] * int(RATE * secs)


def pcap(name, payloads, gap=0.02, sport=30000, dport=40000):
    """payloads: list of (time, udp payload); written as Ethernet/IPv4/UDP from 192.0.2.21 to 192.0.2.22."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for i, (t, data) in enumerate(payloads):
        udp = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i, 0, 64, 17, 0,
                         bytes([192, 0, 2, 21]), bytes([192, 0, 2, 22])) + udp
        eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip
        out.append(struct.pack("<IIII", int(t), int(round((t % 1) * 1e6)), len(eth), len(eth)) + eth)
    open(name, "wb").write(b"".join(out))
    print(name, len(payloads), "packets")


def rtp_pcap(name, samples, ssrc):
    frames = []
    for i in range(len(samples) // PTIME):
        payload = bytes(ulaw(s) for s in samples[i * PTIME:(i + 1) * PTIME])
        frames.append((i * 0.02, struct.pack("!BBHII", 0x80, 0x80 if i == 0 else 0, i + 1, i * PTIME, ssrc) + payload))
    pcap(name, frames)


# talk and silence for pjsua's VAD
w = wave.open("talk-silence.wav", "wb")
w.setnchannels(1); w.setsampwidth(2); w.setframerate(RATE)
s = []
for _ in range(4):
    s += tone(440, 1.0) + silence(3.0)
w.writeframes(struct.pack(f"<{len(s)}h", *s)); w.close()
print("talk-silence.wav", len(s) / RATE, "s")

# fax tones in G.711
rtp_pcap("fax-cng.pcap", tone(1100, 0.5) + silence(3.0), 0xFA0C0001)
rtp_pcap("fax-ced.pcap", tone(2100, 3.0) + silence(1.0), 0xFA0CED01)
rtp_pcap("fax-silence.pcap", silence(4.0), 0xFA0C5101)

# T.38 UDPTL (ITU-T T.38 Annex A.1, BASIC-ALIGNED PER)
#   IFPPacket: 1 bit data-field present, 1 bit CHOICE (0 t30-indicator, 1 t30-data), 1 extension bit of the ENUMERATED,
#   then the root value: 4 bits for t30-indicator (16 root values), 4 bits for t30-data (9 root values), padded to octet
V21_PREAMBLE = bytes([0b0_0_0_0011_0])          # t30-indicator v21-preamble (3) -> 0x06


def udptl(seq, primary, previous):
    """UDPTLPacket: seq-number (16 bits), primary-ifp-packet (open type: length octet + IFP), error-recovery CHOICE
    bit 0 = secondary-ifp-packets (padded to an octet), count, each previous IFP as an open type (newest first)."""
    out = struct.pack("!H", seq) + bytes([len(primary)]) + primary + b"\x00" + bytes([len(previous)])
    for p in previous:
        out += bytes([len(p)]) + p
    return out


ifps = [V21_PREAMBLE] * 3
packets = []
for seq, ifp in enumerate(ifps):
    prev = list(reversed(ifps[:seq]))   # every earlier IFP, newest first
    packets.append((0.5 + seq * 0.02, udptl(seq, ifp, prev)))
pcap("fax-t38.pcap", packets, sport=6000, dport=6000)
