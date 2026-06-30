#preprocessing.py
import cv2
import numpy as np
from PIL import Image
import os
from config import settings
import logging

logger = logging.getLogger(__name__)

class PreprocessingAgent:
    def process(self, job_id, image_path):
        try:
            logger.info(f"🔄 Preprocessing job {job_id}")
            
            # Load image
            image = Image.open(image_path).convert('RGB')
            original_w, original_h = image.size
            
            # Convert to OpenCV
            img = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            
            # Only resize if too large (max 2000px)
            max_dim = 2000
            h, w = img.shape[:2]
            if max(h, w) > max_dim:
                scale = max_dim / max(h, w)
                new_w = int(w * scale)
                new_h = int(h * scale)
                img = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)
            
            # Save enhanced image (keep as BGR for OCR)
            enhanced_path = os.path.join(settings.STORAGE_PATH, 'enhanced', f'{job_id}.jpg')
            cv2.imwrite(enhanced_path, img)
            
            logger.info(f"✅ Preprocessing complete for job {job_id}")
            
            return {
                'job_id': str(job_id),
                'enhanced_image_path': enhanced_path,
                'original_w': original_w,
                'original_h': original_h,
                'metadata': {'enhanced': True}
            }
        except Exception as e:
            logger.error(f"❌ Preprocessing failed: {e}")
            raise
