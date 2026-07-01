import json
import logging
from agents.context_rules import ContextRules
from agents.word_extractor import WordExtractor
from agents.llm_client import call_groq_vision_json, call_groq_text_json

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

NAME_CHECK_SYSTEM_PROMPT = """You are a strict classifier. You will be given a JSON list of text strings
that another system flagged as possibly being a person's full name (as it would appear on an ID, resume,
or form).

For each one, decide: is this ACTUALLY a real human personal name (first name + last name, or similar,
the way a person's name is written on official documents)?

Answer NO for: resume/document section headers, job titles, project titles, skill names, technology/tool
names, company/organization names, dates, addresses, generic phrases, or any text that is not literally
a person's name. Answer NO even if the text is capitalized and grammatically looks like a noun phrase —
only the literal name of a human being counts as YES.

If a candidate contains a real name merged with extra non-name words (e.g. a name accidentally joined
with a city, date, or job title by an upstream OCR/extraction step), answer NO — only answer YES when the
ENTIRE string is just the name itself, nothing else.

Return strict JSON only:
{"results": [{"index": <int>, "is_person_name": true|false}]}"""


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

        # --- Stage 1: cheap local pre-filter ---
        prefiltered = []
        seen = set()
        for d in all_detections:
            pii_type = d.get('pii_type', 'unknown')
            text_value = d.get('text_value', d.get('text', ''))
            bbox = d.get('bbox')
            # carry bboxes list through — if not present, build from single bbox
            bboxes = d.get('bboxes', [bbox] if bbox else [])

            dedupe_key = (pii_type, text_value.strip().lower())
            if dedupe_key in seen:
                continue

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

            seen.add(dedupe_key)
            prefiltered.append({
                'pii_type': pii_type,
                'text_value': text_value,
                'bbox': bbox,
                'bboxes': bboxes,
                'confidence': confidence,
                'note': note
            })

        # --- Stage 2: Scout visual second opinion ---
        candidates_payload = [
            {'index': i, 'pii_type': c['pii_type'], 'text_value': c['text_value']}
            for i, c in enumerate(prefiltered)
        ]

        final_redactions = []
        words = None

        review_result = call_groq_vision_json(
            SYSTEM_PROMPT,
            f"Candidates:\n{json.dumps(candidates_payload)}",
            enhanced_path
        )

        if review_result:
            approvals = {r['index']: r for r in review_result.get('reviewed', []) if 'index' in r}

            for i, c in enumerate(prefiltered):
                decision = approvals.get(i)
                approved = decision['approved'] if decision else True
                note = decision.get('note', c['note']) if decision else c['note']

                if c['bbox'] is None:
                    approved = False
                    note = note + ' | no bbox located, requires manual redaction'

                if approved and c['bbox'] is not None:
                    final_redactions.append({
                        'pii_type': c['pii_type'],
                        'text_value': c['text_value'],
                        'bbox': c['bbox'],
                        'bboxes': c['bboxes'],
                        'approved': True,
                        'final_confidence': c['confidence'],
                        'flag_for_review': c['confidence'] < 0.7,
                        'validation_note': note
                    })
                    logger.info(f"Approved {c['pii_type']} — {len(c['bboxes'])} line box(es)")
                else:
                    logger.info(f"Rejected {c['pii_type']}: {c['text_value']} - {note}")

            # Missed items Scout found visually — locate per-line bboxes locally
            missed = review_result.get('missed', [])
            if missed:
                words, _, _ = WordExtractor.extract_words(enhanced_path)
                for m in missed:
                    text_value = (m.get('text_value') or '').strip()
                    pii_type = m.get('pii_type', 'unknown')
                    if not text_value:
                        continue
                    line_bboxes = WordExtractor.find_line_bboxes(text_value, words)
                    if not line_bboxes:
                        logger.warning(f"Missed item '{text_value}' — no bbox located, skipping")
                        continue
                    primary_bbox = line_bboxes[0]
                    final_redactions.append({
                        'pii_type': pii_type,
                        'text_value': text_value,
                        'bbox': primary_bbox,
                        'bboxes': line_bboxes,
                        'approved': True,
                        'final_confidence': 0.75,
                        'flag_for_review': True,
                        'validation_note': f'Caught by validation Scout review (missed by detection): {text_value}'
                    })
                    logger.info(f"Added missed {pii_type} — {len(line_bboxes)} line box(es)")
        else:
            # Scout unavailable — fall back to stage-1 approvals
            logger.warning("Validation Scout call failed — using local pre-filter only")
            for c in prefiltered:
                if c['bbox'] is None:
                    continue
                final_redactions.append({
                    'pii_type': c['pii_type'],
                    'text_value': c['text_value'],
                    'bbox': c['bbox'],
                    'bboxes': c['bboxes'],
                    'approved': True,
                    'final_confidence': min(c['confidence'], 0.6),
                    'flag_for_review': True,
                    'validation_note': c['note'] + ' | Scout unavailable, local-only approval'
                })

        # --- Stage 3: dedicated LLM name classifier ---
        final_redactions = self._filter_names_with_llm(final_redactions)

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

    @staticmethod
    def _filter_names_with_llm(final_redactions):
        name_items = [(i, r) for i, r in enumerate(final_redactions) if r.get('pii_type') == 'name']
        if not name_items:
            return final_redactions

        payload = [{'index': i, 'text_value': r['text_value']} for i, r in name_items]
        result = call_groq_text_json(NAME_CHECK_SYSTEM_PROMPT, json.dumps(payload))

        if not result:
            logger.warning("LLM name-check failed — keeping name candidates as-is")
            return final_redactions

        verdicts = {
            r['index']: r.get('is_person_name', True)
            for r in result.get('results', []) if 'index' in r
        }

        filtered = []
        for i, r in enumerate(final_redactions):
            if r.get('pii_type') != 'name':
                filtered.append(r)
                continue
            is_name = verdicts.get(i, True)
            if is_name:
                filtered.append(r)
            else:
                logger.info(f"LLM name-check rejected: {r['text_value']}")

        return filtered