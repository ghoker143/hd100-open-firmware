#!/usr/bin/env python3
"""Capture what the HD100's HID keyboard types (magstripe swipes, keypad), grabbing the device so the
text doesn't land in the focused window. Needs tools/70-hd100.rules (or root).

    python3 tools/kbd_capture.py            # print each line typed (Enter-terminated) until Ctrl-C
    python3 tools/kbd_capture.py -t 30      # stop after 30 s
    python3 tools/kbd_capture.py --keys     # print every key press / release as it happens
    python3 tools/kbd_capture.py --follow   # keep going across unplug / replug
"""
import argparse
import fcntl
import glob
import os
import select
import struct
import sys
import time

EVIOCGRAB = 0x40044590
EV_KEY = 1
FMT = "llHHi"  # struct input_event on 64-bit Linux
SIZE = struct.calcsize(FMT)

# Linux key codes -> (plain, shifted), US layout
KEYS = {2: "1!", 3: "2@", 4: "3#", 5: "4$", 6: "5%", 7: "6^", 8: "7&", 9: "8*", 10: "9(", 11: "0)",
        12: "-_", 13: "=+", 39: ";:", 51: ",<", 52: ".>", 53: "/?", 57: "  "}
for i, c in enumerate("qwertyuiop"):
    KEYS[16 + i] = c + c.upper()
for i, c in enumerate("asdfghjkl"):
    KEYS[30 + i] = c + c.upper()
for i, c in enumerate("zxcvbnm"):
    KEYS[44 + i] = c + c.upper()
NAMES = {28: "Enter", 14: "Backspace", 1: "Esc", 42: "LShift", 54: "RShift"}


def find(wait):
    """Event node of the HD100 keyboard; with `wait`, keep looking (the device may be re-plugging)."""
    while True:
        hits = glob.glob("/dev/input/by-id/*HD100*-event-kbd")
        if hits:
            return hits[0]
        if not wait:
            sys.exit("HD100 keyboard event node not found")
        time.sleep(0.2)


def open_grabbed(wait):
    while True:
        try:
            fd = os.open(find(wait), os.O_RDONLY)
            fcntl.ioctl(fd, EVIOCGRAB, 1)
            return fd
        except OSError:
            if not wait:
                raise
            time.sleep(0.2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", type=float, default=0, help="stop after this many seconds (0 = never)")
    ap.add_argument("--keys", action="store_true", help="print raw key events")
    ap.add_argument("--follow", action="store_true", help="survive unplug / replug")
    a = ap.parse_args()
    fd = open_grabbed(a.follow)
    end = time.monotonic() + a.t if a.t else None
    shift = False
    line = ""
    try:
        while True:
            left = None if end is None else end - time.monotonic()
            if left is not None and left <= 0:
                break
            r, _, _ = select.select([fd], [], [], left)
            if not r:
                continue
            try:
                data = os.read(fd, SIZE * 64)
            except OSError:
                if not a.follow:
                    raise
                os.close(fd)
                print("(device gone, waiting for it)", flush=True)
                fd = open_grabbed(True)
                continue
            for off in range(0, len(data), SIZE):
                _, _, typ, code, value = struct.unpack(FMT, data[off:off + SIZE])
                if typ != EV_KEY:
                    continue
                if a.keys and value in (0, 1):
                    name = NAMES.get(code) or KEYS.get(code, "?" + str(code))[0]
                    print(f"{time.monotonic():.3f} {'down' if value else 'up  '} {name}", flush=True)
                if code in (42, 54):
                    shift = value != 0
                elif value == 1:
                    if code == 28:
                        print(line, flush=True)
                        line = ""
                    elif code == 14:
                        line = line[:-1]
                    elif code in KEYS:
                        line += KEYS[code][1 if shift else 0]
    except KeyboardInterrupt:
        pass
    finally:
        if line:
            print(line + " (no Enter)")
        try:
            fcntl.ioctl(fd, EVIOCGRAB, 0)
        except OSError:
            pass


if __name__ == "__main__":
    main()
