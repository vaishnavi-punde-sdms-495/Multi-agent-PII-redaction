"""
Unified word extraction - used purely as a local bbox-locator now.
Detection logic (what is PII) lives in llm_detection.py via Llama 4 Scout;
this module's job is only to map a piece of text to exact pixel coordinates.
"""
import cv2
import pytesseract
import numpy as np
from PIL import Image
from difflib import SequenceMatcher
import logging

logger = logging.getLogger(__name__)


class WordExtractor:
    """Extract text with exact pixel positions (like fitz.get_text('words'))."""

    @staticmethod
    def extract_words(image_path):
        """
        Extract words with exact bounding box positions.
        Returns: (words, width, height)
        """
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
        """
        Find bounding boxes for matched text.
        1) Exact token match (fast path).
        2) If a token isn't found exactly (common when Scout's reading differs
           slightly from Tesseract's, e.g. due to scan noise), fall back to
           fuzzy matching against OCR tokens so we don't silently drop a box.
        """
        result = []
        tokens = [t for t in matched_text.lower().split() if t]
        if not tokens:
            return result

        word_index = {}
        for w in words:
            word_index.setdefault(w['text'].lower(), []).append(w)

        for token in tokens:
            if token in word_index:
                result.extend(w['bbox'] for w in word_index[token])
                continue

            # fuzzy fallback
            best_ratio = 0.0
            best_word = None
            for w in words:
                wt = w['text'].lower()
                # cheap length pre-filter before doing the expensive comparison
                if abs(len(wt) - len(token)) > 3:
                    continue
                ratio = SequenceMatcher(None, token, wt).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_word = w
            if best_word and best_ratio >= fuzzy_threshold:
                result.append(best_word['bbox'])
                logger.info(f"🔎 Fuzzy matched '{token}' -> '{best_word['text']}' ({best_ratio:.2f})")

        return result

    @staticmethod
    def find_phrase_bbox(matched_text, words, fuzzy_threshold=0.82):
        """
        Convenience helper: returns a single merged bbox (x0,y0,x1,y1) for a
        whole phrase, or None if nothing matched.
        """
        bboxes = WordExtractor.find_word_bboxes(matched_text, words, fuzzy_threshold)
        if not bboxes:
            return None
        x0 = min(b[0] for b in bboxes)
        y0 = min(b[1] for b in bboxes)
        x1 = max(b[2] for b in bboxes)
        y1 = max(b[3] for b in bboxes)
        return (x0, y0, x1, y1)
