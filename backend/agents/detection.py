import logging
import re
from agents.presidio_fast import get_presidio
from agents.context_rules import ContextRules
from agents.word_extractor import WordExtractor

logger = logging.getLogger(__name__)

presidio = get_presidio()

class VisionDetectionAgent:
    def process(self, data):
        job_id = data['job_id']
        enhanced_path = data.get('enhanced_image_path')
        img_w = data.get('original_w', 1200)
        img_h = data.get('original_h', 800)
        
        # Get words with exact positions
        words, actual_w, actual_h = WordExtractor.extract_words(enhanced_path)
        ocr_text = WordExtractor.get_full_text(words)
        logger.info(f"📝 OCR: {len(words)} words")
        
        vision_detections = []
        detected_values = []
        
        # 1. Presidio detection
        if ocr_text and presidio.analyzer:
            try:
                results = presidio.detect(ocr_text)
                for r in results:
                    matched_text = ocr_text[r.start:r.end]
                    pii_type = ContextRules.get_entity_type(r.entity_type)
                    
                    # Skip if not valid Indian PII
                    if pii_type not in ['name', 'email', 'phone', 'dob', 'aadhaar', 'pan']:
                        continue
                    
                    # Skip false positive names
                    if pii_type == 'name' and ContextRules.is_false_positive_name(matched_text):
                        continue
                    
                    # Skip duplicates
                    if matched_text.lower() in detected_values:
                        continue
                    
                    # Validate using context rules
                    valid = True
                    if pii_type == 'aadhaar':
                        valid = ContextRules.is_valid_aadhaar(matched_text)
                    elif pii_type == 'pan':
                        valid = ContextRules.is_valid_pan(matched_text)
                    elif pii_type == 'phone':
                        valid = ContextRules.is_valid_phone(matched_text)
                    elif pii_type == 'email':
                        valid = ContextRules.is_valid_email(matched_text)
                    elif pii_type == 'dob':
                        valid = ContextRules.is_valid_dob(matched_text)
                    
                    if valid:
                        detected_values.append(matched_text.lower())
                        
                        # Find bboxes
                        bboxes = WordExtractor.find_word_bboxes(matched_text, words)
                        
                        if bboxes:
                            x0 = min(b[0] for b in bboxes)
                            y0 = min(b[1] for b in bboxes)
                            x1 = max(b[2] for b in bboxes)
                            y1 = max(b[3] for b in bboxes)
                            padding = 4
                            bbox = [
                                max(0, x0 - padding),
                                max(0, y0 - padding),
                                min(img_w, x1 + padding),
                                min(img_h, y1 + padding)
                            ]
                        else:
                            bbox = [50, 100 + len(vision_detections) * 35, 350, 130 + len(vision_detections) * 35]
                        
                        vision_detections.append({
                            'pii_type': pii_type,
                            'text_value': matched_text,
                            'bbox': bbox,
                            'confidence': r.score,
                            'reasoning': f'Presidio detected {r.entity_type}'
                        })
                        logger.info(f"✅ Presidio {pii_type}: {matched_text}")
            except Exception as e:
                logger.error(f"❌ Presidio error: {e}")
        
        # 2. Regex fallback for all PII types
        patterns = {
            'aadhaar': r'\b\d{12}\b|\b\d{4}\s?\d{4}\s?\d{4}\b',
            'pan': r'\b[A-Z]{5}\d{4}[A-Z]\b',
            'phone': r'\b[6-9]\d{9}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            'dob': r'\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b',
            'name': r'\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)+\b'
        }
        
        for pii_type, pattern in patterns.items():
            matches = re.finditer(pattern, ocr_text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group()
                if matched_text.lower() in detected_values:
                    continue
                
                # Validate
                valid = True
                if pii_type == 'aadhaar':
                    valid = ContextRules.is_valid_aadhaar(matched_text)
                elif pii_type == 'pan':
                    valid = ContextRules.is_valid_pan(matched_text)
                elif pii_type == 'phone':
                    valid = ContextRules.is_valid_phone(matched_text)
                elif pii_type == 'email':
                    valid = ContextRules.is_valid_email(matched_text)
                elif pii_type == 'dob':
                    valid = ContextRules.is_valid_dob(matched_text)
                elif pii_type == 'name':
                    valid = not ContextRules.is_false_positive_name(matched_text)
                
                if valid:
                    detected_values.append(matched_text.lower())
                    
                    # Find bboxes
                    bboxes = WordExtractor.find_word_bboxes(matched_text, words)
                    
                    if bboxes:
                        x0 = min(b[0] for b in bboxes)
                        y0 = min(b[1] for b in bboxes)
                        x1 = max(b[2] for b in bboxes)
                        y1 = max(b[3] for b in bboxes)
                        padding = 4
                        bbox = [
                            max(0, x0 - padding),
                            max(0, y0 - padding),
                            min(img_w, x1 + padding),
                            min(img_h, y1 + padding)
                        ]
                    else:
                        bbox = [50, 100 + len(vision_detections) * 35, 350, 130 + len(vision_detections) * 35]
                    
                    vision_detections.append({
                        'pii_type': pii_type,
                        'text_value': matched_text,
                        'bbox': bbox,
                        'confidence': 0.9,
                        'reasoning': f'Regex fallback'
                    })
                    logger.info(f"✅ Regex {pii_type}: {matched_text}")
        
        # 3. Special: Detect Indian IDs using context rules
        if ocr_text:
            # Look for patterns that match Indian IDs
            indian_id_patterns = [
                (r'\b[A-Z]{3}[0-9]{7}\b', 'voter_id'),
                (r'\b[A-Z][0-9]{7}\b', 'passport'),
                (r'\b[A-Z]{2}[0-9]{2}\s?[0-9]{11}\b', 'driving_license'),
                (r'\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[0-9]{1}[A-Z]{1}[0-9]{1}\b', 'gst')
            ]
            
            for pattern, id_type in indian_id_patterns:
                matches = re.finditer(pattern, ocr_text, re.IGNORECASE)
                for match in matches:
                    matched_text = match.group()
                    if matched_text.lower() in detected_values:
                        continue
                    
                    # Check if it's a fake ID
                    if ContextRules.is_fake_id(matched_text):
                        continue
                    
                    detected_values.append(matched_text.lower())
                    
                    # Find bboxes
                    bboxes = WordExtractor.find_word_bboxes(matched_text, words)
                    
                    if bboxes:
                        x0 = min(b[0] for b in bboxes)
                        y0 = min(b[1] for b in bboxes)
                        x1 = max(b[2] for b in bboxes)
                        y1 = max(b[3] for b in bboxes)
                        padding = 4
                        bbox = [
                            max(0, x0 - padding),
                            max(0, y0 - padding),
                            min(img_w, x1 + padding),
                            min(img_h, y1 + padding)
                        ]
                    else:
                        bbox = [50, 100 + len(vision_detections) * 35, 350, 130 + len(vision_detections) * 35]
                    
                    vision_detections.append({
                        'pii_type': id_type,
                        'text_value': matched_text,
                        'bbox': bbox,
                        'confidence': 0.85,
                        'reasoning': f'Indian ID detected: {id_type}'
                    })
                    logger.info(f"✅ Indian ID {id_type}: {matched_text}")
        
        logger.info(f"📊 Found {len(vision_detections)} PII items")
        
        return {
            'job_id': job_id,
            'enhanced_image_path': enhanced_path,
            'original_w': img_w,
            'original_h': img_h,
            'mandatory_redactions': data.get('mandatory_redactions', []),
            'vision_detections': vision_detections,
            'ocr_results': []
        }
