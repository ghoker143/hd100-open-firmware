#!/usr/bin/env python3
import argparse
import sys
import time

from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException, NoCardException

HEADER = bytes([0xAA, 0xAA, 0xAA, 0x96, 0x69])

SW3 = {
    0x90: "OK", 0x9F: "card found", 0x80: "no card found", 0x81: "card select failed",
    0x41: "read failed", 0x10: "checksum error (to SAM)", 0x11: "length error (to SAM)",
    0x21: "bad command", 0x23: "not authorized", 0x24: "unknown command",
    0x31: "card authentication failed", 0x32: "SAM authentication failed", 0x33: "data verification failed",
    0x40: "unknown card type", 0x47: "card/SAM mismatch", 0x60: "SAM self-test failed",
    0x66: "SAM not authorized", 0x91: "no data",
}

NATIONS = [
    "汉", "蒙古", "回", "藏", "维吾尔", "苗", "彝", "壮", "布依", "朝鲜", "满", "侗", "瑶", "白", "土家",
    "哈尼", "哈萨克", "傣", "黎", "傈僳", "佤", "畲", "高山", "拉祜", "水", "东乡", "纳西", "景颇", "柯尔克孜",
    "土", "达斡尔", "仫佬", "羌", "布朗", "撒拉", "毛南", "仡佬", "锡伯", "阿昌", "普米", "塔吉克", "怒",
    "乌孜别克", "俄罗斯", "鄂温克", "德昂", "保安", "裕固", "京", "塔塔尔", "独龙", "鄂伦春", "赫哲", "门巴",
    "珞巴", "基诺",
]
SEX = {"0": "未知", "1": "男", "2": "女", "9": "未说明"}


class SamError(Exception):
    pass


def find_reader():
    for r in readers():
        if "Contactless" in str(r) and "HD100" in str(r):
            return r
    for r in readers():
        if "HD100" in str(r) and "Contact" not in str(r).replace("Contactless", ""):
            return r
    sys.exit("HD100 contactless reader not found: " + ", ".join(map(str, readers())))


def transmit(conn, apdu):
    data, sw1, sw2 = conn.transmit(list(apdu))
    return bytes(data), (sw1 << 8) | sw2


def sam(conn, cmd, para, data=b""):
    """One SAM command; returns the complete raw response frame."""
    body = bytes([cmd, para]) + bytes(data)
    resp, sw = transmit(conn, bytes([0xFF, 0x70, 0x00, 0x00, len(body)]) + body)
    frame = bytearray(resp)
    while sw >> 8 == 0x61:
        off = len(frame)
        resp, sw = transmit(conn, [0xFF, 0x72, off >> 8, off & 0xFF, 0x00])
        frame += resp
    if sw != 0x9000:
        raise SamError(f"reader SW {sw:04X}" + {0x6401: " (module timeout)", 0x6581: " (bad frame)",
                                                0x6A81: " (no module)", 0x6D00: " (firmware without SAM support)"}.get(sw, ""))
    frame = bytes(frame)
    if frame[:5] != HEADER or len(frame) < 11:
        raise SamError("bad frame: " + frame.hex(" "))
    n = int.from_bytes(frame[5:7], "big")
    if len(frame) != n + 7:
        raise SamError(f"length {len(frame)} != {n + 7}")
    chk = 0
    for b in frame[5:-1]:
        chk ^= b
    if chk != frame[-1]:
        raise SamError("checksum")
    return frame


def sw3(frame):
    return frame[9]


def describe(frame):
    s = frame[9]
    return f"{frame[7]:02X} {frame[8]:02X} {s:02X} ({SW3.get(s, '?')})"


def sam_id(frame):
    d = frame[10:-1]
    if len(d) < 16:
        return d.hex()
    le = lambda a, b: int.from_bytes(d[a:b], "little")
    return f"{le(0, 2):02d}.{le(2, 4):02d}-{le(4, 8):08d}-{le(8, 12):010d}-{le(12, 16):010d}"


def text_fields(t):
    """Standard 256-byte text record, UCS-2LE fixed-width fields:
    name 30 | sex 2 | nation 4 | birth 16 | address 70 | id 36 | authority 30 | valid from 16 | to 16 | reserved 36
    """
    def f(a, b):
        return t[a:b].decode("utf-16-le", "replace").rstrip(" \x00")
    kind = f(248, 250)
    if kind in ("I", "J", "Y"):
        return {"类型": {"I": "外国人永久居留身份证", "J": "港澳台居民居住证", "Y": "外国人永久居留身份证(2023)"}[kind],
                "原始文字(UCS-2)": f(0, 256)}
    nation = f(32, 36)
    try:
        nation_name = NATIONS[int(nation) - 1] + "族"
    except (ValueError, IndexError):
        nation_name = nation
    return {
        "姓名": f(0, 30),
        "性别": SEX.get(f(30, 32), f(30, 32)),
        "民族": nation_name,
        "出生": f(36, 52),
        "住址": f(52, 122),
        "公民身份号码": f(122, 158),
        "签发机关": f(158, 188),
        "有效期限": f"{f(188, 204)} - {f(204, 220)}",
    }


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--photo")
    ap.add_argument("--lib")
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--sam", nargs="+", metavar="HEX")
    ap.add_argument("--wait", action="store_true")
    args = ap.parse_args()

    reader = find_reader()
    print(f"reader: {reader}")
    conn = reader.createConnection()
    while True:
        try:
            conn.connect()
            break
        except (NoCardException, CardConnectionException):
            if not args.wait:
                sys.exit("no card on the reader (put the ID card on it, or use --wait)")
            time.sleep(0.3)
    print("ATR:", bytes(conn.getATR()).hex(" "))

    if args.sam:
        b = bytes.fromhex("".join(args.sam))
        fr = sam(conn, b[0], b[1], b[2:])
        print(f"SW {describe(fr)}")
        print(fr.hex(" "))
        return

    fr = sam(conn, 0x12, 0xFF)
    print(f"SAM ID: {sam_id(fr)}  [{describe(fr)}]")

    t0 = time.monotonic()
    fr = sam(conn, 0x20, 0x01)
    print(f"find card: {describe(fr)}")
    if args.raw:
        print(" ", fr.hex(" "))
    if sw3(fr) != 0x9F:
        sys.exit(1)
    fr = sam(conn, 0x20, 0x02)
    print(f"select card: {describe(fr)}")
    if args.raw:
        print(" ", fr.hex(" "))
    if sw3(fr) != 0x90:
        sys.exit(1)
    fr = sam(conn, 0x30, 0x01)
    dt = time.monotonic() - t0
    print(f"read: {describe(fr)}, {len(fr)} bytes, {dt:.2f}s total")
    if args.raw:
        print(" ", fr.hex(" "))
    if sw3(fr) != 0x90:
        sys.exit(1)
    d = fr[10:-1]
    tl, pl = int.from_bytes(d[0:2], "big"), int.from_bytes(d[2:4], "big")
    text, photo = d[4:4 + tl], d[4 + tl:4 + tl + pl]
    print(f"text {tl} bytes, photo {pl} bytes")
    for k, v in text_fields(text).items():
        print(f"  {k}: {v}")
    if args.photo:
        if args.photo.lower().endswith(".bmp"):
            import wlt2bmp
            try:
                bmp = wlt2bmp.decode(photo, args.lib)
            except wlt2bmp.WltError as e:
                sys.exit(f"photo decode: {e}")
            with open(args.photo, "wb") as f:
                f.write(bmp)
            w, h, bpp = wlt2bmp.bmp_size(bmp)
            print(f"photo saved to {args.photo} ({w}x{h} {bpp}-bit BMP)")
        else:
            with open(args.photo, "wb") as f:
                f.write(photo)
            print(f"photo saved to {args.photo} (WLT)")


if __name__ == "__main__":
    try:
        main()
    except SamError as e:
        sys.exit(f"SAM error: {e}")
