#!/usr/bin/env python3
"""HD100 regression run over PC/SC (pyscard). Read-only APDUs only: safe on any card.

For every HD100 reader slot with a card: print the ATR, then repeat a set of harmless APDUs
(SELECT PPSE / 1PAY / MF, GET CHALLENGE) and check the deterministic answers never change.

    python3 tools/regress.py              # all slots with a card, one after the other, 20 rounds
    python3 tools/regress.py -n 100 -p    # 100 rounds, all slots in parallel (contact + contactless at once)
    python3 tools/regress.py -r Contact   # only readers whose name contains "Contact" (case-sensitive)
"""
import argparse
import sys
import threading
import time

from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException, NoCardException

APDUS = [
    ("SELECT PPSE", "00A404000E325041592E5359532E444446303100", True),
    ("SELECT 1PAY", "00A404000E315041592E5359532E444446303100", True),
    ("SELECT MF", "00A40000023F00", True),
    ("GET CHALLENGE", "0084000008", False),  # random: only the SW is compared
]


def run(reader, rounds, out):
    name = str(reader)
    try:
        c = reader.createConnection()
        c.connect()
    except (NoCardException, CardConnectionException) as e:
        out[name] = f"no card ({e.__class__.__name__})"
        return
    atr = bytes(c.getATR()).hex().upper()
    ref = {}
    errors = []
    t0 = time.monotonic()
    count = 0
    for i in range(rounds):
        for label, hexapdu, deterministic in APDUS:
            try:
                d, s1, s2 = c.transmit(list(bytes.fromhex(hexapdu)))
            except CardConnectionException as e:
                errors.append(f"round {i} {label}: {e}")
                continue
            count += 1
            got = (bytes(d) if deterministic else b"", s1, s2)
            if label not in ref:
                ref[label] = got
            elif ref[label] != got:
                errors.append(f"round {i} {label}: {got[1]:02X}{got[2]:02X} {got[0].hex()} != first")
    dt = time.monotonic() - t0
    c.disconnect()
    lines = [f"ATR {atr}"]
    for label, (d, s1, s2) in ref.items():
        lines.append(f"  {label:14} {s1:02X}{s2:02X} {len(d):3} B")
    lines.append(f"  {count} APDUs in {dt:.2f}s ({1000 * dt / max(count, 1):.1f} ms each), {len(errors)} errors")
    lines += ["  ! " + e for e in errors[:10]]
    out[name] = "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=20, help="rounds")
    ap.add_argument("-p", action="store_true", help="all slots in parallel")
    ap.add_argument("-r", default="HD100", help="reader name filter")
    a = ap.parse_args()
    rs = [r for r in readers() if a.r in str(r) and "HD100" in str(r)]
    if not rs:
        sys.exit("no HD100 reader")
    out = {}
    if a.p:
        ts = [threading.Thread(target=run, args=(r, a.n, out)) for r in rs]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    else:
        for r in rs:
            run(r, a.n, out)
    bad = False
    for r in rs:
        print(f"== {r}\n{out.get(str(r))}")
        res = out.get(str(r), "")
        bad |= not res.startswith("no card") and " 0 errors" not in res
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
