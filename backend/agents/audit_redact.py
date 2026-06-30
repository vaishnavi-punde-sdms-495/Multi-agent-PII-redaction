#audit_redact.py
import os
import json
import uuid
from datetime import datetime
import logging

from config import settings
from database import SessionLocal
from models.job import Job
from models.audit_log import AuditLog
from agents.redact_draw import draw_redactions

logger = logging.getLogger(__name__)


class AuditRedactAgent:
    """Single-image jobs: draw boxes AND write the Job/AuditLog rows.
    (PDF jobs use draw_redactions directly per page via pdf_pipeline in
    tasks/pipeline.py, then write one aggregated Job/AuditLog row at the end —
    see process_pdf_task.)"""

    def process(self, data):
        job_id = data['job_id']
        enhanced_path = data['enhanced_image_path']
        final_redactions = data.get('final_redactions', [])

        logger.info(f"🖼️ Redacting {len(final_redactions)} items")

        preview_path = os.path.join(settings.STORAGE_PATH, 'preview', f'{job_id}_preview.jpg')
        redacted_path = os.path.join(settings.STORAGE_PATH, 'redacted', f'{job_id}.jpg')

        redacted_count, pii_types = draw_redactions(
            enhanced_path, final_redactions, preview_path, redacted_path
        )

        db = SessionLocal()
        try:
            job = db.query(Job).filter(Job.id == job_id).first()
            if job:
                job.status = 'completed'
                job.redacted_image_path = redacted_path
                job.completed_at = datetime.utcnow()
                db.commit()

            audit = AuditLog(
                id=uuid.uuid4(),
                job_id=job_id,
                pii_types_found=list(pii_types),
                pii_count=redacted_count,
                confidence_scores={t: 1.0 for t in pii_types},
                risk_score=data.get('overall_risk', 'MEDIUM'),
                requires_review=False,
                agent_decisions=json.dumps(data),
                items_redacted=redacted_count,
                items_flagged=0,
                processing_time_ms=0
            )
            db.add(audit)
            db.commit()
            logger.info(f"✅ Audit log created with {redacted_count} redactions")
        except Exception as e:
            logger.error(f"❌ DB error: {e}")
            db.rollback()
        finally:
            db.close()

        return {
            'job_id': job_id,
            'redacted_image_path': redacted_path,
            'preview_image_path': preview_path,
            'items_redacted': redacted_count,
            'items_flagged': 0,
            'risk_score': data.get('overall_risk', 'MEDIUM')
        }