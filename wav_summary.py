#!/usr/bin/env python3
"""Summarize a phone's recording (a 16-bit PCM WAV) so its numbers can be quoted: duration, level per second, gaps.

    wav_summary.py <recording.wav> [--silence -45] [--min-gap 10] [--onsets] [--tone 440]

Level = RMS of the samples in dBFS (0 dBFS = a full-scale square wave; a full-scale sine is -3 dBFS). The audio is cut
into 5 ms windows; a window below --silence dBFS is silent, and a run of silent windows of at least --min-gap ms
between two sounds is a gap (the phone played nothing there: a lost or late packet it could not hide). Leading and
trailing silence (before the call's audio starts, after it ends) is reported apart, not as gaps. --onsets also lists
where each sound starts after at least 100 ms of silence (the start of each beep or word), for echo and delay checks.
--tone HZ, for a recording of one steady tone of that frequency, also lists its breaks: samples that do not continue the
sine the two samples before them predict (x[n] = 2 cos(w) x[n-1] - x[n-2]), merged within 5 ms. A phone that plays the
next packet in place of a lost one leaves no silence, only such a break (a click: the tone jumps in phase).
"""
import argparse
import math
import struct
import wave

WIN_MS = 5


def db(rms: float) -> float:
    return 20 * math.log10(rms / 32768) if rms > 0 else -120.0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("wav")
    ap.add_argument("--silence", type=float, default=-45.0, help="dBFS below which a 5 ms window is silent")
    ap.add_argument("--min-gap", type=int, default=10, help="shortest gap reported, in ms")
    ap.add_argument("--onsets", action="store_true", help="list where each sound starts after >= 100 ms of silence")
    ap.add_argument("--tone", type=float, help="the recording is one steady tone of this frequency: list its breaks")
    a = ap.parse_args()

    with wave.open(a.wav) as w:
        rate, ch, width, n = w.getframerate(), w.getnchannels(), w.getsampwidth(), w.getnframes()
        raw = w.readframes(n)
    if width != 2:
        raise SystemExit(f"{a.wav}: {8 * width}-bit samples; only 16-bit PCM is read")
    samples = struct.unpack(f"<{len(raw) // 2}h", raw)[::ch]   # first channel only
    dur = len(samples) / rate
    print(f"# {a.wav}: {rate} Hz, {ch} channel(s), {len(samples)} samples = {dur:.3f} s")

    per = rate * WIN_MS // 1000
    wins = []
    for i in range(0, len(samples) - per + 1, per):
        chunk = samples[i:i + per]
        wins.append(db(math.sqrt(sum(s * s for s in chunk) / per)))
    loud = [i for i, v in enumerate(wins) if v >= a.silence]
    if not loud:
        print(f"# no sound at all: every {WIN_MS} ms window is below the silence threshold")
        return
    first, last = loud[0], loud[-1]
    print(f"# sound from {first * WIN_MS / 1000:.2f} s to {(last + 1) * WIN_MS / 1000:.2f} s "
          f"(silence before: {first * WIN_MS} ms, after: {(len(wins) - 1 - last) * WIN_MS} ms)")

    print(f"\n# level per second (RMS dBFS; 'silent' = {WIN_MS} ms windows below the threshold in that second)")
    sec = 1000 // WIN_MS
    for s in range(0, len(wins), sec):
        part = wins[s:s + sec]
        rms = math.sqrt(sum((32768 * 10 ** (v / 20)) ** 2 for v in part) / len(part))
        silent = sum(1 for v in part if v < a.silence)
        print(f"{s // sec:3d}-{s // sec + 1:<3d} s  {db(rms):6.1f} dBFS  silent windows {silent:3d}/{len(part)}")

    gaps, run = [], None
    for i in range(first, last + 1):
        if wins[i] < a.silence:
            run = i if run is None else run
        elif run is not None:
            if (i - run) * WIN_MS >= a.min_gap:
                gaps.append((run, i - run))
            run = None
    total = sum(g[1] for g in gaps) * WIN_MS
    span = (last + 1 - first) * WIN_MS
    print(f"\n# gaps inside the sound (silent runs >= {a.min_gap} ms, threshold {a.silence:.0f} dBFS): {len(gaps)}, "
          f"{total} ms in all = {100 * total / span:.1f}% of {span / 1000:.2f} s")
    for start, length in gaps:
        print(f"  at {start * WIN_MS / 1000:7.2f} s  {length * WIN_MS:5d} ms")

    if a.tone:
        c = 2 * math.cos(2 * math.pi * a.tone / rate)
        lo_i, hi_i = first * per + 2, (last + 1) * per
        amp = math.sqrt(2 * sum(x * x for x in samples[lo_i:hi_i]) / max(1, hi_i - lo_i))
        breaks, prev = [], -rate
        for n in range(lo_i, hi_i):
            if abs(samples[n] - c * samples[n - 1] + samples[n - 2]) > 0.25 * amp and n - prev > rate // 200:
                breaks.append(n)
            if abs(samples[n] - c * samples[n - 1] + samples[n - 2]) > 0.25 * amp:
                prev = n
        print(f"\n# breaks in the {a.tone:g} Hz tone (the sample does not continue the sine; tone amplitude {amp:.0f}): "
              f"{len(breaks)}")
        print("  " + "  ".join(f"{n / rate:.3f}" for n in breaks))
        spans = []   # breaks less than 30 ms apart belong to one damaged stretch (a 20 ms frame out of place has two)
        for n in breaks:
            if spans and n - spans[-1][1] <= rate * 30 // 1000:
                spans[-1][1] = n
            else:
                spans.append([n, n])
        print(f"# damaged stretches (breaks less than 30 ms apart joined): {len(spans)}, "
              f"{sum(1000 * (b - e0) / rate for e0, b in spans):.0f} ms between their first and last breaks in all")
        print("  " + "  ".join(f"{e0 / rate:.2f}({1000 * (b - e0) / rate:.0f})" for e0, b in spans))

    if a.onsets:
        quiet_needed = 100 // WIN_MS
        onsets, quiet = [], quiet_needed
        for i, v in enumerate(wins):
            if v < a.silence:
                quiet += 1
            else:
                if quiet >= quiet_needed:
                    onsets.append(i)
                quiet = 0
        print(f"\n# sound onsets (after >= 100 ms of silence): {len(onsets)}")
        print("  " + "  ".join(f"{o * WIN_MS / 1000:.2f}" for o in onsets))


if __name__ == "__main__":
    main()
