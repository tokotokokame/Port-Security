#!/usr/bin/env python3
"""Pixel-art app icons (32x32 grid, scaled with nearest-neighbour).

Usage: python3 tools/make_icon.py <out_dir>   -> icon_{a,b,c}.png (512px)
"""
import sys
from pathlib import Path
from PIL import Image, ImageDraw

BG, BG2 = (13, 17, 23), (22, 27, 34)
TEAL, TEAL_D, TEAL_DD = (45, 212, 191), (17, 94, 89), (19, 78, 74)
GREEN, AMBER, WHITE, GREY = (74, 222, 128), (251, 191, 36), (230, 237, 243), (110, 118, 129)
RED = (248, 81, 73)

FONT = {  # 3x5 pixel glyphs
    "4": ["101", "101", "111", "001", "001"], "5": ["111", "100", "111", "001", "111"],
    "3": ["111", "001", "111", "001", "111"], ">": ["100", "010", "001", "010", "100"],
    "_": ["000", "000", "000", "000", "111"], ":": ["000", "010", "000", "010", "000"],
}


def base():
    im = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle([0, 0, 31, 31], radius=6, fill=BG)
    return im, d


def text(d, s, x, y, color):
    for ch in s:
        for r, row in enumerate(FONT[ch]):
            for c, bit in enumerate(row):
                if bit == "1": d.point((x + c, y + r), fill=color)
        x += 4


def jack(d, x, y, color, hole=BG):
    """RJ45-style socket, 10x8, top-left at (x, y)."""
    d.rectangle([x, y, x + 9, y + 7], fill=color)
    d.rectangle([x + 1, y + 1, x + 8, y + 5], fill=hole)
    d.rectangle([x + 3, y + 6, x + 6, y + 7], fill=hole)  # latch notch
    for i in range(4):
        d.point((x + 2 + i * 2, y + 1), fill=color)  # contacts


def icon_a(bg=True):  # shield + port socket (bg=False: adaptive-icon foreground)
    im, d = base() if bg else (lambda i: (i, ImageDraw.Draw(i)))(Image.new("RGBA", (32, 32), (0, 0, 0, 0)))
    shield = [(16, 4), (26, 7), (26, 16), (22, 23), (16, 28), (10, 23), (6, 16), (6, 7)]
    d.polygon(shield, fill=TEAL_DD, outline=TEAL)
    d.line([(16, 5), (16, 27)], fill=TEAL_D)
    jack(d, 11, 10, TEAL)
    text(d, "443", 11, 20, WHITE)
    d.point((24, 9), fill=WHITE)
    return im


def icon_b():  # terminal window with prompt and port number
    im, d = base()
    d.rectangle([3, 5, 28, 26], fill=BG2, outline=GREY)
    d.rectangle([4, 6, 27, 8], fill=(48, 54, 61))
    for i, c in enumerate([RED, AMBER, GREEN]):
        d.point((6 + i * 2, 7), fill=c)
    text(d, ">", 6, 11, GREEN)
    text(d, "445", 11, 11, TEAL)
    text(d, "_", 6, 18, GREEN)
    jack(d, 17, 17, TEAL_D, hole=BG2)
    return im


def icon_c():  # port socket under a magnifying glass, with network nodes
    im, d = base()
    for a, b in [((5, 6), (12, 6)), ((5, 6), (5, 13)), ((12, 6), (12, 9))]:
        d.line([a, b], fill=TEAL_D)
    for x, y in [(5, 6), (12, 6), (5, 13)]:
        d.rectangle([x - 1, y - 1, x + 1, y + 1], fill=TEAL_D)
    d.ellipse([9, 8, 25, 24], fill=BG2, outline=TEAL, width=2)
    jack(d, 12, 12, TEAL, hole=BG2)
    d.line([(23, 23), (28, 28)], fill=AMBER, width=3)
    d.point((13, 11), fill=WHITE)
    return im


ANDROID = {"mdpi": (48, 2), "hdpi": (72, 3), "xhdpi": (96, 4), "xxhdpi": (144, 6), "xxxhdpi": (192, 9)}


def android(res):
    """Launcher icons: legacy PNGs + adaptive icon (foreground on a 108dp canvas)."""
    res = Path(res)
    for dpi, (legacy, k) in ANDROID.items():
        d = res / f"mipmap-{dpi}"
        d.mkdir(parents=True, exist_ok=True)
        icon_a().resize((legacy, legacy), Image.NEAREST).save(d / "ic_launcher.png")
        size = legacy * 108 // 48
        fg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        art = icon_a(bg=False).resize((32 * k, 32 * k), Image.NEAREST)
        fg.paste(art, ((size - 32 * k) // 2, (size - 32 * k) // 2), art)
        fg.save(d / "ic_launcher_foreground.png")
    (res / "mipmap-anydpi-v26").mkdir(exist_ok=True)
    (res / "mipmap-anydpi-v26/ic_launcher.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <background android:drawable="@color/ic_launcher_background"/>\n'
        '    <foreground android:drawable="@mipmap/ic_launcher_foreground"/>\n</adaptive-icon>\n')
    (res / "values").mkdir(exist_ok=True)
    (res / "values/ic_launcher_background.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <color name="ic_launcher_background">#0D1117</color>\n</resources>\n')


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--android":
        android(sys.argv[2]); print("android icons written"); sys.exit()
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in [("a", icon_a), ("b", icon_b), ("c", icon_c)]:
        fn().resize((512, 512), Image.NEAREST).save(out / f"icon_{name}.png")
    print("written", out)
