"""
Unified word extraction - used purely as a local bbox-locator now.
Detection logic (what is PII) lives in llm_detection.py via Llama 4 Scout;
this module's job is only to map a piece of text to exact pixel coordinates.
"""
import re
import cv2
import pytesseract
import numpy as np
from PIL import Image
from difflib import SequenceMatcher
import logging

logger = logging.getLogger(__name__)

# Words whose top-edges are within this many pixels are considered the same line
LINE_TOLERANCE_PX = 12

# Standalone punctuation tokens that Tesseract emits as separate words but
# carry no useful bbox signal on their own — skipping them prevents phantom
# black boxes appearing where only a '&' or '-' sits between real words.
_PUNCT_ONLY = re.compile(r'^[\-\&\|\.\,\:\;\!\?\(\)\[\]\{\}\/\\\'\"\_\+\=\*\#\@\%]+$')


class WordExtractor:
    """Extract text with exact pixel positions (like fitz.get_text('words'))."""

    @staticmethod
    def extract_words(image_path):
        img = cv2.imread(image_path)
        if img is None:
            logger.error(f"Failed to load image: {image_path}")
            return [], 0, 0

        h, w = img.shape[:2]
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        ocr_data = pytesseract.image_to_data(thresh, output_type=pytesseract.Output.DICT)

        words = []
        for i in range(len(ocr_data['text'])):
            word = ocr_data['text'][i].strip()
            if word:
                x = ocr_data['left'][i]
                y = ocr_data['top'][i]
                width = ocr_data['width'][i]
                height = ocr_data['height'][i]
                conf = int(ocr_data['conf'][i])
                if conf > 0:
                    words.append({
                        'text': word,
                        'bbox': (x, y, x + width, y + height),
                        'confidence': conf,
                        'page': 0
                    })

        logger.info(f"Extracted {len(words)} words from image")
        return words, w, h

    @staticmethod
    def get_full_text(words):
        return " ".join(w['text'] for w in words)

    @staticmethod
    def find_word_bboxes(matched_text, words, fuzzy_threshold=0.82):
        """Return a flat list of individual word bboxes for matched_text tokens."""
        result = []
        tokens = [t for t in matched_text.lower().split() if t]
        if not tokens:
            return result

        word_index = {}
        for w in words:
            word_index.setdefault(w['text'].lower(), []).append(w)

        for token in tokens:
            # Skip standalone punctuation tokens (&, -, |, etc.).
            # They are valid in the matched text but Tesseract often emits
            # them as zero-width or misaligned bboxes that cause phantom
            # black boxes. The surrounding real-word bboxes already define
            # the correct line extent, so skipping these is safe.
            if _PUNCT_ONLY.match(token):
                logger.debug(f"Skipping punctuation token '{token}' in bbox lookup")
                continue

            if token in word_index:
                result.extend(w['bbox'] for w in word_index[token])
                continue

            # fuzzy fallback
            best_ratio = 0.0
            best_word = None
            for w in words:
                wt = w['text'].lower()
                if abs(len(wt) - len(token)) > 3:
                    continue
                ratio = SequenceMatcher(None, token, wt).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_word = w
            if best_word and best_ratio >= fuzzy_threshold:
                result.append(best_word['bbox'])
                logger.info(f"Fuzzy matched '{token}' -> '{best_word['text']}' ({best_ratio:.2f})")

        return result

    @staticmethod
    def find_line_bboxes(matched_text, words, fuzzy_threshold=0.82, padding=4):
        """
        Core bbox method used by the detection pipeline.

        Groups matched word bboxes by line (words within LINE_TOLERANCE_PX
        vertically = same line) and returns ONE tight bbox per line.

        This means:
        - A name on one line -> one tight box
        - An address spanning 3 lines -> 3 separate line-width boxes
        - Two items that happen to be vertically close but on different
          lines -> separate boxes, no giant merged envelope

        Returns: list of [x0, y0, x1, y1] with padding applied, one per line.
                 Empty list if nothing matched.
        """
        raw_bboxes = WordExtractor.find_word_bboxes(matched_text, words, fuzzy_threshold)
        if not raw_bboxes:
            return []

        # Sort by top-edge (y0) so we group top-to-bottom
        raw_bboxes = sorted(raw_bboxes, key=lambda b: b[1])

        lines = []   # list of lists of bboxes on the same line
        for bbox in raw_bboxes:
            placed = False
            for line in lines:
                # compare against the average top-edge of existing line members
                avg_top = sum(b[1] for b in line) / len(line)
                if abs(bbox[1] - avg_top) <= LINE_TOLERANCE_PX:
                    line.append(bbox)
                    placed = True
                    break
            if not placed:
                lines.append([bbox])

        result = []
        for line in lines:
            x0 = min(b[0] for b in line)
            y0 = min(b[1] for b in line)
            x1 = max(b[2] for b in line)
            y1 = max(b[3] for b in line)
            result.append([x0 - padding, y0 - padding, x1 + padding, y1 + padding])

        return result

    @staticmethod
    def find_phrase_bbox(matched_text, words, fuzzy_threshold=0.82):
        """
        Legacy single-bbox helper kept for callers that still need one envelope.
        Returns (x0,y0,x1,y1) merging ALL lines, or None if nothing matched.
        Use find_line_bboxes instead wherever per-line boxes are wanted.
        """
        bboxes = WordExtractor.find_word_bboxes(matched_text, words, fuzzy_threshold)
        if not bboxes:
            return None
        x0 = min(b[0] for b in bboxes)
        y0 = min(b[1] for b in bboxes)
        x1 = max(b[2] for b in bboxes)
        y1 = max(b[3] for b in bboxes)
        return (x0, y0, x1, y1)