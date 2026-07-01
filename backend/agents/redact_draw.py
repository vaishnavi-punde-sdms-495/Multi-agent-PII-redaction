import os
import logging
from PIL import Image, ImageDraw

logger = logging.getLogger(__name__)


def draw_redactions(image_path, final_redactions, preview_path, redacted_path):
    """
    Draw boxes for a single page/image.

    Each redaction item may carry either:
      - 'bboxes': list of per-line boxes (new — preferred, gives tight
                  line-by-line boxes for addresses and avoids giant merged
                  envelopes when items are close together)
      - 'bbox':   single box (legacy fallback)

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

        pii_type = item.get('pii_type', 'unknown')

        # Resolve the list of boxes to draw for this item
        bboxes_to_draw = item.get('bboxes') or []
        if not bboxes_to_draw:
            # Fallback: single legacy bbox
            single = item.get('bbox')
            if single:
                bboxes_to_draw = [single]

        if not bboxes_to_draw:
            logger.warning(f"No bbox(es) for {pii_type} — skipping")
            continue

        drew_any = False
        for bbox in bboxes_to_draw:
            if not bbox or len(bbox) != 4:
                continue

            x1 = max(0, int(bbox[0]))
            y1 = max(0, int(bbox[1]))
            x2 = min(img_w, int(bbox[2]))
            y2 = min(img_h, int(bbox[3]))

            if x2 <= x1 or y2 <= y1:
                logger.warning(f"Degenerate bbox for {pii_type}: {bbox}")
                continue

            # Preview: semi-transparent red highlight
            preview_draw.rectangle([x1, y1, x2, y2], fill=(255, 0, 0, 80))
            preview_draw.rectangle([x1, y1, x2, y2], outline=(255, 0, 0), width=2)

            # Redacted: solid black box
            redacted_draw.rectangle([x1, y1, x2, y2], fill=(0, 0, 0))

            drew_any = True
            logger.info(f"Redacted {pii_type} line-box at [{x1},{y1},{x2},{y2}]")

        if drew_any:
            redacted_count += 1
            pii_types.add(pii_type)

    os.makedirs(os.path.dirname(preview_path), exist_ok=True)
    preview_rgb = Image.new('RGB', preview_image.size, (255, 255, 255))
    preview_rgb.paste(preview_image, mask=preview_image.split()[3] if preview_image.mode == 'RGBA' else None)
    preview_rgb.save(preview_path, quality=95, optimize=True)

    os.makedirs(os.path.dirname(redacted_path), exist_ok=True)
    redacted_image.save(redacted_path, quality=95, optimize=True)

    logger.info(f"Saved {redacted_count} redactions -> {redacted_path}")
    return redacted_count, pii_types