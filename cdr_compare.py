#!/usr/bin/env python3
"""Compare two sets of CDRs of the same calls: ours and the carrier's (SIP Black Belt, section 8).

    python3 cdr_compare.py <our CDR file> <carrier CDR file> [--unit SECONDS] [--min-diff MS] [--all]

Each file holds OpenSIPS acc records as db_flatstore writes them, one call per line, fields separated by '|':

    method|from_tag|to_tag|callid|sip_code|sip_reason|time|caller|callee|answered_at|ended_at|setuptime|created|
    duration|ms_duration

(the lab's column order: acc's own columns, the lab's extra fields, then the CDR columns). answered_at and ended_at
are when that side saw the 200 OK and the BYE (Unix seconds.microseconds, written by the lab's script; acc's own
time column has whole seconds); they may be empty. A call can have several lines on one side: a 183 when early media
is accounted, a failed attempt, the answered call.

The two sets are matched by Call-ID (both sides see the same Call-ID when no B2BUA sits between them). The report:
  1. the totals of each side: calls, answered, failed by reply code, minutes;
  2. the calls the two sides COUNT differently (answered on one side, failed or missing on the other);
  3. the answered calls whose DURATIONS differ by at least --min-diff milliseconds (default 500), with the start
     times and what each side bills for them;
  4. the gap in billed time and the calls that make it.
Billing: a call is billed in whole units of --unit seconds (default 60), every started unit counted (ceil). The
report also shows two per-second rules: every started second (ceil, which is what acc's own duration column holds)
and clock ticks, the whole seconds between the start and stop times each truncated to the second, as a switch that
stamps calls to the second bills them (so a 0.2 s call is 0 or 1 tick, a 1.8 s call 1 or 2, depending on where the
second boundaries fall on that side's clock).
"""
import argparse
import math
import sys
import time
from collections import Counter

COLUMNS = ["method", "from_tag", "to_tag", "callid", "sip_code", "sip_reason", "time", "caller", "callee",
           "answered_at", "ended_at", "setuptime", "created", "duration", "ms_duration"]


def read_cdrs(path):
    """Call-ID -> list of records (dicts) from one CDR file."""
    calls = {}
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("|")
            if len(fields) != len(COLUMNS):
                sys.exit(f"{path}:{n}: {len(fields)} fields, expected {len(COLUMNS)}")
            rec = dict(zip(COLUMNS, fields))
            for k in ("sip_code", "time", "setuptime", "created", "duration", "ms_duration"):
                rec[k] = int(rec[k] or 0)
            for k in ("answered_at", "ended_at"):
                rec[k] = float(rec[k]) if rec[k] else None
            calls.setdefault(rec["callid"], []).append(rec)
    return calls


def outcome(records):
    """The call's final record on one side: the answered one if any, else the last final reply."""
    answered = [r for r in records if r["sip_code"] == 200]
    if answered:
        return answered[-1]
    final = [r for r in records if r["sip_code"] >= 300]
    return final[-1] if final else None


def early_media(records):
    return any(100 < r["sip_code"] < 200 for r in records)


def early_seconds(records):
    """Whole seconds from the accounted 183 to the call's final reply (acc's created + setuptime), or None."""
    em = [r for r in records if 100 < r["sip_code"] < 200]
    final = outcome(records)
    if not em or final is None:
        return None
    return final["created"] + final["setuptime"] - em[0]["time"]


def units(ms, unit):
    return math.ceil(ms / (unit * 1000)) if ms > 0 else 0


def ticks(rec):
    """Clock ticks: whole seconds between the start and the stop, each truncated to the second (None if unknown)."""
    if rec["answered_at"] is None or rec["ended_at"] is None:
        return None
    return int(rec["ended_at"]) - int(rec["answered_at"])


def clock(t):
    """Unix time as HH:MM:SS (UTC), with milliseconds when the time has a fraction."""
    if not t:
        return "-"
    text = time.strftime("%H:%M:%S", time.gmtime(t))
    return text + f".{int(t * 1000) % 1000:03d}" if isinstance(t, float) else text


def status(rec):
    if rec is None:
        return "no CDR"
    if rec["sip_code"] == 200:
        return f"answered {rec['ms_duration'] / 1000:.3f} s"
    return f"failed {rec['sip_code']} {rec['sip_reason']}"


def side_totals(name, calls, unit):
    finals = [outcome(r) for r in calls.values()]
    answered = [r for r in finals if r and r["sip_code"] == 200]
    failed = Counter(f"{r['sip_code']} {r['sip_reason']}" for r in finals if r and r["sip_code"] != 200)
    ms = sum(r["ms_duration"] for r in answered)
    early = sum(1 for r in calls.values() if early_media(r))
    print(f"{name}: {sum(len(r) for r in calls.values())} CDR lines, {len(calls)} calls, {len(answered)} answered,"
          f" {sum(failed.values())} failed" + (f" ({', '.join(f'{v} x {k}' for k, v in sorted(failed.items()))})"
                                                if failed else ""))
    if early:
        secs = [early_seconds(r) for r in calls.values() if early_media(r)]
        print(f"  {early} calls with an early-media record (183 with SDP accounted), about"
              f" {sum(x for x in secs if x is not None)} s from the 183 to the final reply (whole seconds)")
    tick = [ticks(r) for r in answered]
    print(f"  talk time {ms / 1000:.3f} s = {ms / 60000:.2f} min; billed {sum(units(r['ms_duration'], unit) for r in answered)}"
          f" units of {unit} s; by the second: {sum(units(r['ms_duration'], 1) for r in answered)} s (every started"
          f" second), {sum(t for t in tick if t is not None)} s (clock ticks"
          + (f", {tick.count(None)} without both times)" if None in tick else ")"))
    return ms, sum(units(r["ms_duration"], unit) for r in answered)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("ours")
    ap.add_argument("carrier")
    ap.add_argument("--unit", type=int, default=60, help="billing unit in seconds (default 60)")
    ap.add_argument("--min-diff", type=int, default=500, help="smallest duration difference shown, ms (default 500)")
    ap.add_argument("--all", action="store_true", help="list every answered call, not only the mismatches")
    a = ap.parse_args()
    ours, theirs = read_cdrs(a.ours), read_cdrs(a.carrier)
    ids = sorted(set(ours) | set(theirs), key=lambda c: min(r["created"] for r in ours.get(c, []) + theirs.get(c, [])))

    print("== 1. totals")
    ms_o, u_o = side_totals("ours   ", ours, a.unit)
    ms_c, u_c = side_totals("carrier", theirs, a.unit)

    print("\n== 2. calls counted differently")
    n = 0
    for cid in ids:
        o, c = outcome(ours.get(cid, [])), outcome(theirs.get(cid, []))
        em_o, em_c = early_media(ours.get(cid, [])), early_media(theirs.get(cid, []))
        answered_o = o is not None and o["sip_code"] == 200
        answered_c = c is not None and c["sip_code"] == 200
        if answered_o != answered_c or (o is None) != (c is None) or em_o != em_c:
            n += 1
            note = ""
            if em_o != em_c:
                side = ours if em_o else theirs
                note = (f"  (early media accounted by {'us' if em_o else 'the carrier'}: 183 to final reply about"
                        f" {early_seconds(side[cid])} s)")
            print(f"{cid}: ours {status(o)}, carrier {status(c)}{note}")
    if not n:
        print("none")

    print(f"\n== 3. answered on both sides, durations {'(all)' if a.all else f'differing by >= {a.min_diff} ms'}")
    print(f"{'Call-ID':<24} {'answered (ours/carrier)':>25} {'ours s':>8} {'carrier':>8} {'diff s':>7}"
          f" {'ceil 1 s':>8} {'ticks':>6} {f'{a.unit} s':>6}")
    n = 0
    for cid in ids:
        o, c = outcome(ours.get(cid, [])), outcome(theirs.get(cid, []))
        if not (o and c and o["sip_code"] == 200 and c["sip_code"] == 200):
            continue
        diff = c["ms_duration"] - o["ms_duration"]
        if not a.all and abs(diff) < a.min_diff and o["duration"] == c["duration"] and ticks(o) == ticks(c):
            continue
        n += 1
        t_o, t_c = ticks(o), ticks(c)
        print(f"{cid[:24]:<24} {clock(o['answered_at'] or o['time']):>12}/{clock(c['answered_at'] or c['time']):<12}"
              f" {o['ms_duration'] / 1000:>8.3f} {c['ms_duration'] / 1000:>8.3f} {diff / 1000:>+7.3f}"
              f" {units(o['ms_duration'], 1):>4}/{units(c['ms_duration'], 1):<3}"
              f" {'-' if t_o is None else t_o:>3}/{'-' if t_c is None else t_c:<2}"
              f" {units(o['ms_duration'], a.unit):>3}/{units(c['ms_duration'], a.unit):<2}")
    if not n:
        print("none")
    print("(billing columns: ours/carrier; ceil 1 s = every started second, as acc's duration column; ticks = whole"
          " seconds between the start and stop, each truncated to the second on that side's clock)")

    print("\n== 4. the gap")
    gap = ms_c - ms_o
    pct = 100 * gap / ms_o if ms_o else float("inf")
    print(f"talk time: carrier {ms_c / 1000:.3f} s, ours {ms_o / 1000:.3f} s, gap {gap / 1000:+.3f} s ({pct:+.2f}% of ours)")
    print(f"billed in {a.unit} s units: carrier {u_c}, ours {u_o}, gap {u_c - u_o:+d}"
          + (f" ({100 * (u_c - u_o) / u_o:+.2f}%)" if u_o else ""))
    rows = []
    for cid in ids:
        o, c = outcome(ours.get(cid, [])), outcome(theirs.get(cid, []))
        mo = o["ms_duration"] if o and o["sip_code"] == 200 else 0
        mc = c["ms_duration"] if c and c["sip_code"] == 200 else 0
        if mc != mo:
            rows.append((mc - mo, cid, o, c))
    rows.sort(key=lambda r: -abs(r[0]))
    big = [r for r in rows if abs(r[0]) >= a.min_diff]
    if big:
        print(f"calls that make it (|difference| >= {a.min_diff} ms, largest first):")
        for d, cid, o, c in big:
            print(f"  {d / 1000:+9.3f} s  {cid}: ours {status(o)}, carrier {status(c)}")
    small = sum(r[0] for r in rows if abs(r[0]) < a.min_diff)
    print(f"the other {len(rows) - len(big)} calls with a difference add {small / 1000:+.3f} s")


if __name__ == "__main__":
    main()
