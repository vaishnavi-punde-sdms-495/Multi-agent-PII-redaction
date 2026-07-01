#regex_detection.py
import re
from agents.word_extractor import WordExtractor
from utils.regex_patterns import PATTERNS
import logging

logger = logging.getLogger(__name__)

class RegexDetectionAgent:
    def process(self, data):
        job_id = data['job_id']
        enhanced_path = data['enhanced_image_path']
        img_w = data['original_w']
        img_h = data['original_h']
        custom_words = data.get('custom_words', [])  # list of lowercase strings from frontend

        logger.info(f"Extracting words for job {job_id}")

        words, actual_w, actual_h = WordExtractor.extract_words(enhanced_path)
        full_text = WordExtractor.get_full_text(words)
        logger.info(f"Extracted {len(words)} words")

        mandatory_redactions = []
        ocr_results = []

        for word in words:
            ocr_results.append({
                'text': word['text'],
                'bbox_xyxy': list(word['bbox']),
                'confidence': word['confidence']
            })

        # --- Standard regex patterns ---
        for pii_type, pattern in PATTERNS.items():
            matches = re.finditer(pattern, full_text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group()
                logger.info(f"Found {pii_type}: {matched_text}")

                line_bboxes = WordExtractor.find_line_bboxes(matched_text, words, padding=4)

                if line_bboxes:
                    clamped = []
                    for b in line_bboxes:
                        clamped.append([
                            max(0, b[0]),
                            max(0, b[1]),
                            min(img_w, b[2]),
                            min(img_h, b[3])
                        ])

                    mandatory_redactions.append({
                        'pii_type': pii_type,
                        'text': matched_text,
                        'text_value': matched_text,
                        'bbox': clamped[0],
                        'bboxes': clamped,
                        'confidence': 1.0,
                        'source': 'regex'
                    })
                    logger.info(f"Bbox for {pii_type}: {len(clamped)} line(s)")

        # --- Custom keyword matching ---
        # Each custom word is matched as a whole word (case-insensitive) against OCR text.
        # We then locate its bbox via WordExtractor just like regex matches.
        already_matched = {r['text_value'].lower() for r in mandatory_redactions}

        for keyword in custom_words:
            keyword = keyword.strip()
            if not keyword:
                continue

            # whole-word, case-insensitive search in the full OCR text
            pattern = r'(?<!\w)' + re.escape(keyword) + r'(?!\w)'
            for match in re.finditer(pattern, full_text, re.IGNORECASE):
                matched_text = match.group()
                if matched_text.lower() in already_matched:
                    continue  # avoid duplicating something already caught by standard regex

                line_bboxes = WordExtractor.find_line_bboxes(matched_text, words, padding=4)

                if line_bboxes:
                    clamped = []
                    for b in line_bboxes:
                        clamped.append([
                            max(0, b[0]),
                            max(0, b[1]),
                            min(img_w, b[2]),
                            min(img_h, b[3])
                        ])

                    mandatory_redactions.append({
                        'pii_type': 'custom',
                        'text': matched_text,
                        'text_value': matched_text,
                        'bbox': clamped[0],
                        'bboxes': clamped,
                        'confidence': 1.0,
                        'source': 'custom_keyword'
                    })
                    already_matched.add(matched_text.lower())
                    logger.info(f"Custom keyword '{keyword}' matched '{matched_text}' -> {len(clamped)} bbox(es)")
                else:
                    logger.warning(f"Custom keyword '{keyword}' found in text but no bbox located")

        logger.info(f"Found {len(mandatory_redactions)} PII items with bboxes")

        return {
            'job_id': job_id,
            'enhanced_image_path': enhanced_path,
            'original_w': img_w,
            'original_h': img_h,
            'mandatory_redactions': mandatory_redactions,
            'ocr_results': ocr_results,
            'custom_words': custom_words  # pass through so later agents can see them
        }