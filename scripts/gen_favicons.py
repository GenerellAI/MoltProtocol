"""Generate favicons for moltprotocol.org from the coral emoji 🪸."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont  # type: ignore


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SITE_ROOT = PROJECT_ROOT / "sites" / "moltprotocol.org"
PUBLIC_ROOT = SITE_ROOT / "public"
OUTPUT_DIR = PUBLIC_ROOT / "favicons"
SOURCE = OUTPUT_DIR / "source-emoji.png"

EMOJI = "🪸"
EMOJI_FONT_PATH = Path("/System/Library/Fonts/Apple Color Emoji.ttc")
EMOJI_FONT_SIZES = [512, 320, 256, 192, 160, 128, 96, 64, 48, 40, 32, 20]
EMOJI_CANVAS_SIDE = 1024

PADDING_RATIO = 0.03
ALPHA_CROP_THRESHOLD = 20

SIZES = [16, 32, 48, 64, 96, 128, 180, 192, 256, 512]
ICO_SIZES = [16, 32, 48]


def load_emoji_font() -> ImageFont.FreeTypeFont:
    if not EMOJI_FONT_PATH.exists():
        raise FileNotFoundError(f"Missing emoji font at {EMOJI_FONT_PATH}")
    for size in EMOJI_FONT_SIZES:
        try:
            return ImageFont.truetype(str(EMOJI_FONT_PATH), size)
        except OSError:
            continue
    raise RuntimeError(f"Could not load {EMOJI_FONT_PATH} at a supported size")


def draw_emoji_source() -> Image.Image:
    image = Image.new("RGBA", (EMOJI_CANVAS_SIDE, EMOJI_CANVAS_SIDE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    font = load_emoji_font()
    kwargs = {"font": font}
    try:
        bbox = draw.textbbox((0, 0), EMOJI, embedded_color=True, **kwargs)
        x = (EMOJI_CANVAS_SIDE - (bbox[2] - bbox[0])) // 2 - bbox[0]
        y = (EMOJI_CANVAS_SIDE - (bbox[3] - bbox[1])) // 2 - bbox[1]
        draw.text((x, y), EMOJI, embedded_color=True, **kwargs)
    except TypeError:
        bbox = draw.textbbox((0, 0), EMOJI, **kwargs)
        x = (EMOJI_CANVAS_SIDE - (bbox[2] - bbox[0])) // 2 - bbox[0]
        y = (EMOJI_CANVAS_SIDE - (bbox[3] - bbox[1])) // 2 - bbox[1]
        draw.text((x, y), EMOJI, **kwargs)
    return image


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    source = draw_emoji_source()
    source.save(SOURCE)

    alpha = source.getchannel("A")
    thresholded = alpha.point(lambda px: 255 if px > ALPHA_CROP_THRESHOLD else 0)
    alpha_box = thresholded.getbbox()
    if alpha_box is None:
        raise ValueError("Rendered emoji has no visible pixels")

    trimmed = source.crop(alpha_box)
    base_side = max(trimmed.size)
    square = Image.new("RGBA", (base_side, base_side), (0, 0, 0, 0))
    square.paste(trimmed, ((base_side - trimmed.width) // 2, (base_side - trimmed.height) // 2))

    padded_side = int(round(base_side * (1 + 2 * PADDING_RATIO)))
    processed = Image.new("RGBA", (padded_side, padded_side), (0, 0, 0, 0))
    processed.paste(square, ((padded_side - base_side) // 2, (padded_side - base_side) // 2))

    for size in SIZES:
        out = OUTPUT_DIR / f"icon-{size}.png"
        resized = processed.resize((size, size), Image.LANCZOS)
        resized.save(out)

    # Standard browser/app names in /public root
    Image.open(OUTPUT_DIR / "icon-16.png").save(PUBLIC_ROOT / "favicon-16x16.png")
    Image.open(OUTPUT_DIR / "icon-32.png").save(PUBLIC_ROOT / "favicon-32x32.png")
    Image.open(OUTPUT_DIR / "icon-180.png").save(PUBLIC_ROOT / "apple-touch-icon.png")
    Image.open(OUTPUT_DIR / "icon-192.png").save(PUBLIC_ROOT / "android-chrome-192x192.png")
    Image.open(OUTPUT_DIR / "icon-512.png").save(PUBLIC_ROOT / "android-chrome-512x512.png")

    processed.save(OUTPUT_DIR / "favicon.ico", format="ICO", sizes=[(s, s) for s in ICO_SIZES])
    processed.save(PUBLIC_ROOT / "favicon.ico", format="ICO", sizes=[(s, s) for s in ICO_SIZES])

    Image.open(OUTPUT_DIR / "icon-256.png").save(OUTPUT_DIR / "favicon.png")
    Image.open(OUTPUT_DIR / "icon-256.png").save(PUBLIC_ROOT / "favicon.png")

    print(f"Generated favicon set from emoji {EMOJI}")
    print(f"Output directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
