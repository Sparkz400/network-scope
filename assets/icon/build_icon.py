# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Renders the application icon: icon.svg / icon-small.svg -> network-scope.ico (Windows),
network-scope.icns (the macOS app bundle, packaging/macos/), icon-256.png and icon-48.png.

The outputs are committed, so a normal build needs neither this script nor its tools. Run it
after changing either SVG (Windows, with Microsoft Edge or Google Chrome and Pillow installed):

    python assets/icon/build_icon.py

The browser renders each SVG at 1024 px with a transparent background; Pillow scales that down.
Sizes up to 32 px come from icon-small.svg (thicker lines, fewer details), the rest from icon.svg.
icon-48.png (icon-small.svg) is the window icon on Windows, which scales one image down to the
16 px title bar and 24 px taskbar; icon-256.png is the window icon elsewhere (macOS dock, Linux).
The .icns keeps the margin of Apple's icon grid (the mark is 824 of 1024 px), like other Dock icons.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
RENDER = 1024
SMALL = [16, 20, 24, 32]
LARGE = [40, 48, 64, 96, 128, 256]

BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
]


def browser() -> str:
    for path in BROWSERS:
        if os.path.exists(path):
            return path
    found = shutil.which("msedge") or shutil.which("chrome") or shutil.which("chromium")
    if not found:
        sys.exit("needs Microsoft Edge or Google Chrome to render the SVGs")
    return found


def render(svg: Path, work: Path) -> Image.Image:
    page = work / (svg.stem + ".html")
    page.write_text(
        "<!doctype html><html><body style='margin:0;background:transparent'>"
        f"<img src='{svg.as_uri()}' width='{RENDER}' height='{RENDER}' style='display:block'>"
        "</body></html>",
        encoding="utf-8",
    )
    out = work / (svg.stem + ".png")
    subprocess.run(
        [
            browser(),
            "--headless",
            "--disable-gpu",
            "--hide-scrollbars",
            "--force-device-scale-factor=1",
            "--default-background-color=00000000",
            f"--user-data-dir={work / 'profile'}",
            f"--window-size={RENDER},{RENDER}",
            f"--screenshot={out}",
            page.as_uri(),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    image = Image.open(out).convert("RGBA")
    if image.size != (RENDER, RENDER):
        sys.exit(f"{svg.name}: browser rendered {image.size}, expected {RENDER}x{RENDER}")
    if image.getpixel((0, 0))[3] != 0:
        sys.exit(f"{svg.name}: background is not transparent")
    return image


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        large = render(HERE / "icon.svg", work)
        small = render(HERE / "icon-small.svg", work)
    frames = [small.resize((s, s), Image.LANCZOS) for s in SMALL]
    frames += [large.resize((s, s), Image.LANCZOS) for s in LARGE]
    biggest = frames[-1]
    # Pillow picks, for each size, the appended image of exactly that size instead of resizing.
    biggest.save(
        HERE / "network-scope.ico",
        format="ICO",
        sizes=[(s, s) for s in SMALL + LARGE],
        append_images=frames[:-1],
    )
    biggest.save(HERE / "icon-256.png", optimize=True)
    small.resize((48, 48), Image.LANCZOS).save(HERE / "icon-48.png", optimize=True)
    write_icns(large, small)
    print("wrote network-scope.ico, network-scope.icns, icon-256.png and icon-48.png to", HERE)


def write_icns(large: Image.Image, small: Image.Image) -> None:
    """The macOS icon: 16 to 1024 px, the mark at 824/1024 of the canvas (Apple's icon grid)."""

    def padded(source: Image.Image, size: int) -> Image.Image:
        inner = round(size * 824 / 1024)
        canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        offset = (size - inner) // 2
        canvas.alpha_composite(source.resize((inner, inner), Image.LANCZOS), (offset, offset))
        return canvas

    # Pillow takes, for each size of the format, the appended image of that size if there is one.
    frames = [padded(small, s) for s in (16, 32)]
    frames += [padded(large, s) for s in (64, 128, 256, 512)]
    padded(large, 1024).save(HERE / "network-scope.icns", format="ICNS", append_images=frames)


if __name__ == "__main__":
    main()
