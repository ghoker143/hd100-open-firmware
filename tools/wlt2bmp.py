#!/usr/bin/env python3
import argparse
import ctypes
import os
import sys

DEFAULT_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib", "libwlt2021.so")
SYMBOL = "_Z11Unpack_DataPhiS_Pi"  # Unpack_Data(unsigned char*, int, unsigned char*, int*)
WLT_LEN = 1024


class WltError(Exception):
    pass


def find_lib(path=None):
    for p in (path, os.environ.get("WLT_LIB"), DEFAULT_LIB):
        if p and os.path.isfile(p):
            return p
    raise WltError(f"libwlt2021.so not found (put it at {DEFAULT_LIB}, or use --lib / WLT_LIB)")


def decode(wlt: bytes, lib_path=None) -> bytes:
    """WLT bytes -> BMP file bytes."""
    if len(wlt) != WLT_LEN:
        raise WltError(f"WLT must be {WLT_LEN} bytes, got {len(wlt)}")
    lib = ctypes.CDLL(find_lib(lib_path))
    fn = getattr(lib, SYMBOL)
    fn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    fn.restype = ctypes.c_int
    src = ctypes.create_string_buffer(wlt, WLT_LEN)
    out = ctypes.create_string_buffer(64 * 1024)  # BMP is 38862 bytes; the SDK passes a ~40KB stack buffer
    n = ctypes.c_int(0)
    r = fn(src, WLT_LEN, out, ctypes.byref(n))
    if r != 1 or not 0 < n.value <= len(out):
        raise WltError(f"Unpack_Data failed: ret {r}, len {n.value}")
    bmp = out.raw[: n.value]
    if bmp[:2] != b"BM":
        raise WltError("decoder output is not a BMP")
    return bmp


def bmp_size(bmp: bytes):
    """(width, height, bits per pixel) from the BMP header"""
    w = int.from_bytes(bmp[18:22], "little", signed=True)
    h = int.from_bytes(bmp[22:26], "little", signed=True)
    bpp = int.from_bytes(bmp[28:30], "little")
    return w, abs(h), bpp


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("wlt")
    ap.add_argument("bmp", nargs="?")
    ap.add_argument("--lib")
    args = ap.parse_args()
    out = args.bmp or os.path.splitext(args.wlt)[0] + ".bmp"
    with open(args.wlt, "rb") as f:
        bmp = decode(f.read(), args.lib)
    with open(out, "wb") as f:
        f.write(bmp)
    w, h, bpp = bmp_size(bmp)
    print(f"{out}: {w}x{h} {bpp}-bit BMP, {len(bmp)} bytes")


if __name__ == "__main__":
    try:
        main()
    except WltError as e:
        sys.exit(f"error: {e}")
