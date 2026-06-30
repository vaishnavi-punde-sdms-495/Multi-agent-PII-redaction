import logging
from agents.word_extractor import WordExtractor
from agents.context_rules import ContextRules
from agents.llm_client import call_groq_vision_json

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a PII detection agent for Indian identity and personal documents
(Aadhaar, PAN, voter ID, passport, driving license, bank passbooks, utility bills, etc).

You are given the document IMAGE directly. Read it visually and identify every piece of PII:
- full names of actual people only (including relative names: father/mother/spouse/guardian).
  A name is the proper name of a specific human being, typically 2-4 words, written as it
  would appear on an ID (e.g. "Soham Nigam", "Ramesh Kumar Sharma"). Do NOT tag as "name":
  section headers or field labels (e.g. "Education", "Experience", "Skills", "Objective",
  "References", "Father's Name" as a label by itself), company/organization names, job
  titles or designations, project names, skill names, technology/tool names, or any single
  standalone word. Only tag the actual person-name VALUE written after a label like "Name:".
- complete addresses
- phone numbers, email addresses
- date of birth / other dates tied to identity
- Aadhaar, PAN, passport, voter ID, driving license, GST, bank account numbers
- signatures (label them as pii_type "signature")
- photographs of the person (label as pii_type "photo", give the visible region)

For every item, return the EXACT text as it appears in the image, character for character,
including any OCR-visible noise — do not correct typos, do not normalize formatting/spacing,
do not translate. If a value is split across multiple lines, return it as it visually reads,
space separated.

Do not flag printed form labels themselves (e.g. do not flag "Name:" alone, only the value
written after it). Do not invent text that is not visibly present in the image.

Return strict JSON only, in this shape:
{"detections": [
  {"pii_type": "name|address|phone|email|dob|aadhaar|pan|passport|voter_id|driving_license|gst|account_number|signature|photo",
   "text_value": "<exact text as seen, or short description for signature/photo>",
   "confidence": 0.0-1.0,
   "reasoning": "<why this is PII>"}
]}"""

USER_PROMPT = "Find all PII in this document image and return the JSON described in the system prompt."


class LLMVisionDetectionAgent:
    """
    Detection brain = Llama 4 Scout reading the image directly.
    Bbox locator = local Tesseract OCR (word_extractor), used only to map
    Scout's returned text back to exact pixel coordinates.
    """

    def process(self, data):
        job_id = data['job_id']
        enhanced_path = data.get('enhanced_image_path')
        img_w = data.get('original_w', 1200)
        img_h = data.get('original_h', 800)

        # Local OCR — used ONLY for bbox lookup, not for detection logic
        words, actual_w, actual_h = WordExtractor.extract_words(enhanced_path)
        logger.info(f"📝 Local OCR (bbox locator): {len(words)} words")

        vision_detections = []
        detected_values = []

        result = call_groq_vision_json(SYSTEM_PROMPT, USER_PROMPT, enhanced_path)

        if not result:
            logger.warning("⚠️ Scout vision call failed/empty — falling back to empty detection set "
                            "for this stage (regex_detect stage still covers mandatory patterns)")
        else:
            for d in result.get('detections', []):
                pii_type = d.get('pii_type', 'unknown')
                text_value = (d.get('text_value') or '').strip()
                if not text_value:
                    continue

                dedupe_key = text_value.lower()
                if dedupe_key in detected_values:
                    continue

                # Lightweight format sanity-check using your existing rules, where applicable
                valid = True
                if pii_type == 'aadhaar':
                    valid = ContextRules.is_valid_aadhaar(text_value)
                elif pii_type == 'pan':
                    valid = ContextRules.is_valid_pan(text_value)
                elif pii_type == 'phone':
                    valid = ContextRules.is_valid_phone(text_value)
                elif pii_type == 'email':
                    valid = ContextRules.is_valid_email(text_value)
                elif pii_type == 'dob':
                    valid = ContextRules.is_valid_dob(text_value)
                elif pii_type == 'name':
                    valid = not ContextRules.is_false_positive_name(text_value)
                # signature/address/photo/voter_id/passport/driving_license/gst/account_number:
                # no strict local validator exists yet — trust Scout, validation agent double-checks later

                if not valid:
                    logger.info(f"⏭️ Rejected by ContextRules: {pii_type} = {text_value}")
                    continue

                bbox = self._locate_bbox(text_value, words, img_w, img_h)
                if bbox is None:
                    # No reliable local bbox found — do NOT guess a fallback box.
                    # Drawing a black box in the wrong place is worse than missing one;
                    # this gets logged so it can be surfaced for manual review instead.
                    logger.warning(f"⚠️ No bbox located for Scout detection '{text_value}' "
                                    f"({pii_type}) — skipping auto-redaction, flagging for review")
                    vision_detections.append({
                        'pii_type': pii_type,
                        'text_value': text_value,
                        'bbox': None,
                        'confidence': d.get('confidence', 0.7),
                        'reasoning': d.get('reasoning', 'Llama 4 Scout visual detection'),
                        'needs_manual_review': True
                    })
                    continue

                detected_values.append(dedupe_key)
                vision_detections.append({
                    'pii_type': pii_type,
                    'text_value': text_value,
                    'bbox': bbox,
                    'confidence': d.get('confidence', 0.85),
                    'reasoning': d.get('reasoning', 'Llama 4 Scout visual detection')
                })
                logger.info(f"✅ Scout {pii_type}: {text_value} -> bbox {bbox}")

        logger.info(f"📊 Scout found {len(vision_detections)} PII items")

        return {
            'job_id': job_id,
            'enhanced_image_path': enhanced_path,
            'original_w': img_w,
            'original_h': img_h,
            'mandatory_redactions': data.get('mandatory_redactions', []),
            'vision_detections': vision_detections,
            'ocr_results': data.get('ocr_results', [])
        }

    @staticmethod
    def _locate_bbox(text_value, words, img_w, img_h, padding=4):
        merged = WordExtractor.find_phrase_bbox(text_value, words)
        if merged is None:
            return None
        x0, y0, x1, y1 = merged
        return [
            max(0, x0 - padding),
            max(0, y0 - padding),
            min(img_w, x1 + padding),
            min(img_h, y1 + padding)
        ]
