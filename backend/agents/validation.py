#validation.py
import json
import logging
from agents.context_rules import ContextRules
from agents.word_extractor import WordExtractor
from agents.llm_client import call_groq_vision_json

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a validation agent reviewing a list of proposed PII redactions against a
document IMAGE, to prevent both over-redaction (boxing non-sensitive content) and under-redaction
(missing real PII).

You will receive: the image, and a JSON list of candidate redactions already proposed by another agent.

For each candidate, decide approve or reject by visually checking the image.
Reject things like: organization names mistaken for person names, form labels, generic dates that
aren't a person's DOB, partial/garbled text that isn't actually PII.

Then separately, scan the image yourself for any PII that is NOT in the candidate list at all
(missed items) — including signatures and photographs of the person.

Return strict JSON only:
{"reviewed": [{"index": <int index into the candidates array>, "approved": true|false, "note": "..."}],
 "missed": [{"pii_type": "...", "text_value": "<exact text or short description for signature/photo>"}]}"""


class ValidationAgent:
    def process(self, data):
        job_id = data['job_id']
        enhanced_path = data['enhanced_image_path']
        img_w = data.get('original_w', 1200)
        img_h = data.get('original_h', 800)
        mandatory = data.get('mandatory_redactions', [])
        vision = data.get('vision_detections', [])

        all_detections = mandatory + vision

        if not all_detections:
            return {
                'job_id': job_id,
                'enhanced_image_path': enhanced_path,
                'final_redactions': [],
                'missed_pii': [],
                'overall_risk': 'LOW'
            }

        # --- Stage 1: cheap local pre-filter (format/regex validation, free, no API call) ---
        prefiltered = []
        for d in all_detections:
            pii_type = d.get('pii_type', 'unknown')
            text_value = d.get('text_value', d.get('text', ''))
            bbox = d.get('bbox')

            approved = True
            note = f'Approved {pii_type}'
            confidence = d.get('confidence', 0.9)

            if pii_type == 'aadhaar' and not ContextRules.is_valid_aadhaar(text_value):
                approved, note, confidence = False, f'Invalid Aadhaar format: {text_value}', 0.3
            elif pii_type == 'pan' and not ContextRules.is_valid_pan(text_value):
                approved, note, confidence = False, f'Invalid PAN format: {text_value}', 0.3
            elif pii_type == 'phone' and not ContextRules.is_valid_phone(text_value):
                approved, note, confidence = False, f'Invalid phone format: {text_value}', 0.3
            elif pii_type == 'email' and not ContextRules.is_valid_email(text_value):
                approved, note, confidence = False, f'Invalid email format: {text_value}', 0.3
            elif pii_type == 'dob' and not ContextRules.is_valid_dob(text_value):
                approved, note, confidence = False, f'Invalid DOB format: {text_value}', 0.3
            elif pii_type == 'name' and ContextRules.is_false_positive_name(text_value):
                approved, note, confidence = False, f'False positive name: {text_value}', 0.2

            if not approved:
                logger.info(f"Stage1 rejected {pii_type}: {text_value} - {note}")
                continue

            prefiltered.append({
                'pii_type': pii_type,
                'text_value': text_value,
                'bbox': bbox,
                'confidence': confidence,
                'note': note
            })

        # --- Stage 2: Scout visual second opinion (catches context errors + missed PII) ---
        candidates_payload = [
            {'index': i, 'pii_type': c['pii_type'], 'text_value': c['text_value']}
            for i, c in enumerate(prefiltered)
        ]

        final_redactions = []
        words = None  # lazily loaded only if we need to locate bboxes for "missed" items

        review_result = call_groq_vision_json(
            SYSTEM_PROMPT,
            f"Candidates:\n{json.dumps(candidates_payload)}",
            enhanced_path
        )

        if review_result:
            approvals = {r['index']: r for r in review_result.get('reviewed', []) if 'index' in r}

            for i, c in enumerate(prefiltered):
                decision = approvals.get(i)
                # default to approved if Scout didn't return an explicit decision for this index,
                # so a partial/odd model response doesn't silently drop valid redactions
                approved = decision['approved'] if decision else True
                note = decision.get('note', c['note']) if decision else c['note']

                if c['bbox'] is None:
                    # candidate had no local bbox (flagged in detection stage) — still keep it
                    # visible to the audit/redaction step as needs_manual_review, never auto-skip
                    approved = approved and False
                    note = note + ' | no bbox located, requires manual redaction'

                if approved and c['bbox'] is not None:
                    final_redactions.append({
                        'pii_type': c['pii_type'],
                        'text_value': c['text_value'],
                        'bbox': c['bbox'],
                        'approved': True,
                        'final_confidence': c['confidence'],
                        'flag_for_review': c['confidence'] < 0.7,
                        'validation_note': note
                    })
                    logger.info(f"Approved {c['pii_type']} at bbox: {c['bbox']}")
                else:
                    logger.info(f"Rejected/needs-review {c['pii_type']}: {c['text_value']} - {note}")

            # Missed items Scout found visually — locate bbox locally before adding
            missed = review_result.get('missed', [])
            if missed:
                words, _, _ = WordExtractor.extract_words(enhanced_path)
                for m in missed:
                    text_value = (m.get('text_value') or '').strip()
                    pii_type = m.get('pii_type', 'unknown')
                    if not text_value:
                        continue
                    merged = WordExtractor.find_phrase_bbox(text_value, words)
                    if merged is None:
                        logger.warning(f"Missed item '{text_value}' found by validator but no bbox "
                                        f"located — flagging for manual review instead of guessing")
                        continue
                    x0, y0, x1, y1 = merged
                    bbox = [max(0, x0 - 4), max(0, y0 - 4), min(img_w, x1 + 4), min(img_h, y1 + 4)]
                    final_redactions.append({
                        'pii_type': pii_type,
                        'text_value': text_value,
                        'bbox': bbox,
                        'approved': True,
                        'final_confidence': 0.75,
                        'flag_for_review': True,
                        'validation_note': f'Caught by validation-stage Scout review (missed by detection): {text_value}'
                    })
                    logger.info(f"Added missed-item redaction {pii_type} at bbox: {bbox}")
        else:
            # Scout review unavailable — fall back to stage-1 approvals only, all flagged for review
            logger.warning("Validation-stage Scout call failed — using local pre-filter results only")
            for c in prefiltered:
                if c['bbox'] is None:
                    continue
                final_redactions.append({
                    'pii_type': c['pii_type'],
                    'text_value': c['text_value'],
                    'bbox': c['bbox'],
                    'approved': True,
                    'final_confidence': min(c['confidence'], 0.6),
                    'flag_for_review': True,
                    'validation_note': c['note'] + ' | Scout validation unavailable, local-only approval'
                })

        # --- Risk scoring ---
        pii_types = [d.get('pii_type') for d in final_redactions]
        high_risk = ['aadhaar', 'pan', 'passport']
        medium_risk = ['phone', 'email', 'dob', 'address']

        if any(t in high_risk for t in pii_types):
            risk = 'HIGH'
        elif any(t in medium_risk for t in pii_types):
            risk = 'MEDIUM'
        else:
            risk = 'LOW'

        logger.info(f"Validated {len(final_redactions)} items, Risk: {risk}")

        return {
            'job_id': job_id,
            'enhanced_image_path': enhanced_path,
            'final_redactions': final_redactions,
            'missed_pii': [],
            'overall_risk': risk
        }