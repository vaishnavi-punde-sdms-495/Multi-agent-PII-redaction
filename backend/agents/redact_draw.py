import os
import logging
from PIL import Image, ImageDraw

logger = logging.getLogger(__name__)


def draw_redactions(image_path, final_redactions, preview_path, redacted_path):
    """
    Draw boxes for a single page/image. Pure function, no DB writes —
    used directly by both the single-image audit step and the per-page
    PDF pipeline, so PDF pages don't each create their own Job/AuditLog row.

    Returns: (redacted_count, pii_types_set)
    """
    image = Image.open(image_path).convert('RGB')
    img_w, img_h = image.size

    preview_image = image.copy()
    preview_draw = ImageDraw.Draw(preview_image, 'RGBA')

    redacted_image = image.copy()
    redacted_draw = ImageDraw.Draw(redacted_image)

    redacted_count = 0
    pii_types = set()

    for item in final_redactions:
        if not item.get('approved', False):
            continue

        bbox = item.get('bbox')
        pii_type = item.get('pii_type', 'unknown')

        if not bbox or len(bbox) != 4:
            logger.warning(f"⚠️ Invalid bbox format for {pii_type}: {bbox}")
            continue

        x1 = max(0, int(bbox[0]))
        y1 = max(0, int(bbox[1]))
        x2 = min(img_w, int(bbox[2]))
        y2 = min(img_h, int(bbox[3]))

        if x2 <= x1 or y2 <= y1:
            logger.warning(f"⚠️ Invalid bbox for {pii_type}: {bbox}")
            continue

        preview_draw.rectangle([x1, y1, x2, y2], fill=(255, 0, 0, 80))
        preview_draw.rectangle([x1, y1, x2, y2], outline=(255, 0, 0), width=2)
        redacted_draw.rectangle([x1, y1, x2, y2], fill=(0, 0, 0))

        redacted_count += 1
        pii_types.add(pii_type)
        logger.info(f"🔴 Redacted {pii_type} at [{x1},{y1},{x2},{y2}]")

    os.makedirs(os.path.dirname(preview_path), exist_ok=True)
    preview_rgb = Image.new('RGB', preview_image.size, (255, 255, 255))
    preview_rgb.paste(preview_image, mask=preview_image.split()[3] if preview_image.mode == 'RGBA' else None)
    preview_rgb.save(preview_path, quality=95, optimize=True)

    os.makedirs(os.path.dirname(redacted_path), exist_ok=True)
    redacted_image.save(redacted_path, quality=95, optimize=True)

    logger.info(f"✅ Saved {redacted_count} redactions -> {redacted_path}")
    return redacted_count, pii_types