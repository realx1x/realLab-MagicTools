from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
ICONS = ROOT / "apps" / "desktop" / "src-tauri" / "icons"
SIZE = 512


def render_icon() -> Image.Image:
    image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle(
        (24, 24, SIZE - 24, SIZE - 24),
        radius=72,
        fill="#141414",
        outline="#2B2B2B",
        width=8,
    )

    accent = "#22C7E8"
    running = "#39D98A"
    warning = "#F6C453"
    line_width = 24

    draw.line((156, 132, 156, 380), fill=accent, width=line_width)
    draw.line((156, 180, 350, 132), fill=accent, width=line_width)
    draw.line((156, 256, 350, 256), fill=accent, width=line_width)
    draw.line((156, 332, 350, 380), fill=accent, width=line_width)

    for x, y, color, radius in (
        (156, 132, accent, 42),
        (156, 256, accent, 52),
        (156, 380, accent, 42),
        (362, 128, running, 46),
        (362, 256, accent, 46),
        (362, 384, warning, 46),
    ):
        draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=color)
        inner = max(radius - 18, 8)
        draw.ellipse((x - inner, y - inner, x + inner, y + inner), fill="#141414")

    return image


def main() -> None:
    ICONS.mkdir(parents=True, exist_ok=True)
    icon = render_icon()
    icon.save(ICONS / "icon.png", optimize=True)
    icon.resize((32, 32), Image.Resampling.LANCZOS).save(ICONS / "32x32.png", optimize=True)
    icon.resize((128, 128), Image.Resampling.LANCZOS).save(ICONS / "128x128.png", optimize=True)
    icon.resize((256, 256), Image.Resampling.LANCZOS).save(
        ICONS / "128x128@2x.png", optimize=True
    )
    icon.save(ICONS / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    icon.save(ICONS / "icon.icns", sizes=[(16, 16), (32, 32), (64, 64), (128, 128), (256, 256), (512, 512)])


if __name__ == "__main__":
    main()
