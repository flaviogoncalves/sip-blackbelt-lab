#!/usr/bin/env python3
"""The level of the audio inside each G.711 RTP stream of a pcap, packet by packet, and where each sound starts.

    rtp_level.py <capture.pcap> [--silence -45]

Reads every RTP packet with payload type 0 (PCMU) or 8 (PCMA) (tshark, heuristic RTP on), decodes its 20 ms of audio
and takes its RMS level in dBFS. For each stream it prints the packets, the time span and the onsets: the packets where
sound starts after at least 100 ms of silence (a beep, a word). When two streams run in opposite directions between the
same two addresses, each onset of the first stream is paired with the first onset of the other stream after it: the
time between them is how late the sound came back (an echo, lesson 8.7), measured on the wire where the capture was
taken. Needs tshark.
"""
import argparse
import math
import subprocess


def ulaw(b: int) -> int:
    b = ~b & 0xFF
    t = ((b & 0x0F) << 3) + 0x84
    t <<= (b & 0x70) >> 4
    return (0x84 - t) if b & 0x80 else (t - 0x84)


def alaw(b: int) -> int:
    b ^= 0x55
    t = (b & 0x0F) << 4
    seg = (b & 0x70) >> 4
    t = t + 8 if seg == 0 else ((t + 0x108) << (seg - 1))
    return t if b & 0x80 else -t


DECODE = {"0": [ulaw(i) for i in range(256)], "8": [alaw(i) for i in range(256)]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--silence", type=float, default=-45.0)
    a = ap.parse_args()
    cmd = ["tshark", "-r", a.pcap, "-o", "rtp.heuristic_rtp:TRUE", "-Y", "rtp.p_type == 0 or rtp.p_type == 8",
           "-T", "fields", "-e", "frame.time_relative", "-e", "ip.src", "-e", "udp.srcport", "-e", "ip.dst",
           "-e", "udp.dstport", "-e", "rtp.p_type", "-e", "rtp.seq", "-e", "rtp.payload"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    streams = {}
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 8 or not f[7]:
            continue
        table = DECODE[f[5].split(",")[0]]
        pcm = [table[b] for b in bytes.fromhex(f[7].replace(":", ""))]
        rms = math.sqrt(sum(s * s for s in pcm) / len(pcm))
        level = 20 * math.log10(rms / 32768) if rms else -120.0
        streams.setdefault((f[1], f[2], f[3], f[4]), []).append((float(f[0]), int(f[6]), level))

    print(f"# G.711 RTP streams in {a.pcap}: level of each packet's audio (RMS dBFS), silence below {a.silence:.0f} dBFS")
    onsets = {}
    for key, pk in streams.items():
        src, sp, dst, dp = key
        loud = sum(1 for p in pk if p[2] >= a.silence)
        on, quiet_since = [], None
        for i, (t, seq, lv) in enumerate(pk):
            if lv < a.silence:
                quiet_since = t if quiet_since is None else quiet_since
            else:
                if i == 0 or (quiet_since is not None and t - quiet_since >= 0.1):
                    on.append(t)
                quiet_since = None
        onsets[key] = on
        print(f"\n{src}:{sp} -> {dst}:{dp}  {len(pk)} packets  {pk[0][0]:.3f}-{pk[-1][0]:.3f} s  "
              f"packets with sound {loud}, silent {len(pk) - loud}")
        print(f"  sound onsets ({len(on)}): " + "  ".join(f"{t:.3f}" for t in on))
    keys = list(streams)
    for k in keys:
        back = (k[2], k[3], k[0], k[1])
        if back in onsets and keys.index(k) < keys.index(back):
            print(f"\n# {k[0]}:{k[1]} -> {k[2]}:{k[3]}, then back: each onset and the first onset of the reverse "
                  "stream after it")
            for t in onsets[k]:
                later = [u for u in onsets[back] if u >= t]
                if later:
                    print(f"  {t:8.3f} s  back at {later[0]:8.3f} s  = {1000 * (later[0] - t):6.0f} ms later")


if __name__ == "__main__":
    main()
