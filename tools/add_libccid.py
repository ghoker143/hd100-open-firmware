#!/usr/bin/env python3
# Add HD100 open firmware (1209:0003) to libccid's device list, so pcscd picks it up.
# Idempotent. Run with sudo, then restart pcscd:
#   sudo python3 tools/add_libccid.py && sudo systemctl restart pcscd
import re, sys, glob

VID, PID, NAME = "0x1209", "0x0003", "HD100 open firmware"
paths = glob.glob("/usr/lib*/readers/usb/ifd-ccid.bundle/Contents/Info.plist") + \
        glob.glob("/usr/lib*/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist")
if not paths:
    sys.exit("libccid Info.plist not found")
for path in paths:
    s = open(path).read()

    def arr(key):
        m = re.search(r"(<key>%s</key>\s*<array>)(.*?)(\n\s*</array>)" % key, s, re.S)
        return m

    ids = list(zip(re.findall(r"<string>(.*?)</string>", arr("ifdVendorID").group(2)),
                   re.findall(r"<string>(.*?)</string>", arr("ifdProductID").group(2))))
    if (VID, PID) in [(v.lower(), p.lower()) for v, p in ids]:
        print(path + ": already present")
        continue
    for key, val in (("ifdVendorID", VID), ("ifdProductID", PID), ("ifdFriendlyName", NAME)):
        m = arr(key)
        s = s[:m.end(2)] + "\n\t\t<string>%s</string>" % val + s[m.end(2):]
    open(path, "w").write(s)
    print(path + ": added %s:%s %s" % (VID, PID, NAME))
