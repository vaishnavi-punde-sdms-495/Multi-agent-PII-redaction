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
        
        logger.info(f"🔍 Extracting words for job {job_id}")
        
        # Extract words with exact positions (like fitz.get_text("words"))
        words, actual_w, actual_h = WordExtractor.extract_words(enhanced_path)
        
        # Get full text
        full_text = WordExtractor.get_full_text(words)
        logger.info(f"📝 Extracted {len(words)} words")
        
        mandatory_redactions = []
        ocr_results = []
        
        # Store OCR results with their bboxes
        for word in words:
            ocr_results.append({
                'text': word['text'],
                'bbox_xyxy': list(word['bbox']),
                'confidence': word['confidence']
            })
        
        # Check each pattern
        for pii_type, pattern in PATTERNS.items():
            matches = re.finditer(pattern, full_text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group()
                logger.info(f"✅ Found {pii_type}: {matched_text}")
                
                # Find bboxes for this matched text (SAME as PDF project!)
                bboxes = WordExtractor.find_word_bboxes(matched_text, words)
                
                if bboxes:
                    # Merge all bboxes (SAME logic as PDF project)
                    x0 = min(b[0] for b in bboxes)
                    y0 = min(b[1] for b in bboxes)
                    x1 = max(b[2] for b in bboxes)
                    y1 = max(b[3] for b in bboxes)
                    
                    # Add small padding (4px)
                    padding = 4
                    bbox = [
                        max(0, x0 - padding),
                        max(0, y0 - padding),
                        min(img_w, x1 + padding),
                        min(img_h, y1 + padding)
                    ]
                    
                    mandatory_redactions.append({
                        'pii_type': pii_type,
                        'text': matched_text,
                        'bbox': bbox,  # EXACT bbox from word positions
                        'confidence': 1.0,
                        'source': 'regex'
                    })
                    logger.info(f"📦 Bbox for {pii_type}: {bbox}")
        
        logger.info(f"📊 Found {len(mandatory_redactions)} PII items with bboxes")
        
        return {
            'job_id': job_id,
            'enhanced_image_path': enhanced_path,
            'original_w': img_w,
            'original_h': img_h,
            'mandatory_redactions': mandatory_redactions,
            'ocr_results': ocr_results
        }
