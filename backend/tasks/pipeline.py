import os
import json
import uuid
import logging
from datetime import datetime

from celery import chain
from tasks.celery_app import celery_app
from config import settings

logger = logging.getLogger(__name__)


@celery_app.task(name='preprocess')
def preprocess_task(job_id, image_path, custom_words=None):
    from agents.preprocessing import PreprocessingAgent
    agent = PreprocessingAgent()
    data = agent.process(job_id, image_path)
    data['custom_words'] = custom_words or []  # inject so regex_detect can read it
    return data


@celery_app.task(name='regex_detect')
def regex_detect_task(data):
    from agents.regex_detection import RegexDetectionAgent
    agent = RegexDetectionAgent()
    return agent.process(data)


@celery_app.task(name='vision_detect', bind=True, max_retries=2, default_retry_delay=5)
def vision_detect_task(self, data):
    from agents.llm_detection import LLMVisionDetectionAgent
    agent = LLMVisionDetectionAgent()
    try:
        return agent.process(data)
    except Exception as e:
        logger.error(f"vision_detect_task failed: {e}")
        try:
            raise self.retry(exc=e)
        except self.MaxRetriesExceededError:
            logger.error("vision_detect exhausted retries — continuing with regex-only detections")
            data.setdefault('vision_detections', [])
            return data


@celery_app.task(name='validate', bind=True, max_retries=2, default_retry_delay=5)
def validate_task(self, data):
    from agents.validation import ValidationAgent
    agent = ValidationAgent()
    try:
        return agent.process(data)
    except Exception as e:
        logger.error(f"validate_task failed: {e}")
        try:
            raise self.retry(exc=e)
        except self.MaxRetriesExceededError:
            logger.error("validate exhausted retries — failing job rather than auto-approving unreviewed PII")
            raise


@celery_app.task(name='audit_redact')
def audit_redact_task(data):
    from agents.audit_redact import AuditRedactAgent
    agent = AuditRedactAgent()
    return agent.process(data)


def process_image_chain(job_id, image_path, custom_words=None):
    logger.info(f"Starting image pipeline for job {job_id}")
    pipeline = chain(
        preprocess_task.s(job_id, image_path, custom_words or []),
        regex_detect_task.s(),
        vision_detect_task.s(),
        validate_task.s(),
        audit_redact_task.s()
    )
    return pipeline.apply_async()


@celery_app.task(name='process_pdf', bind=True, max_retries=1)
def process_pdf_task(self, job_id, pdf_path, custom_words=None):
    from database import SessionLocal
    from models.job import Job
    from models.audit_log import AuditLog
    from agents.pdf_utils import pdf_to_images, images_to_pdf
    from agents.preprocessing import PreprocessingAgent
    from agents.regex_detection import RegexDetectionAgent
    from agents.llm_detection import LLMVisionDetectionAgent
    from agents.validation import ValidationAgent
    from agents.redact_draw import draw_redactions

    custom_words = custom_words or []
    logger.info(f"Starting PDF pipeline for job {job_id}, custom_words: {custom_words}")
    db = SessionLocal()

    def set_status(status, **fields):
        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = status
            for k, v in fields.items():
                setattr(job, k, v)
            db.commit()

    try:
        set_status('preprocessing')

        pages_dir = os.path.join(settings.STORAGE_PATH, 'enhanced', f'{job_id}_pages')
        pages = pdf_to_images(pdf_path, pages_dir, job_id)
        set_status('preprocessing', page_count=len(pages), pages_done=0)

        redacted_page_paths = []
        all_pii_types = set()
        total_redacted = 0
        total_flagged = 0
        page_agent_decisions = []
        all_final_redactions = []
        overall_risk_rank = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
        overall_risk = 'LOW'

        regex_agent = RegexDetectionAgent()
        vision_agent = LLMVisionDetectionAgent()
        validation_agent = ValidationAgent()

        for page_index, page_path, page_w, page_h in pages:
            page_job_id = f"{job_id}_p{page_index}"
            logger.info(f"Processing page {page_index + 1}/{len(pages)}")

            set_status('detecting', pages_done=page_index)

            data = PreprocessingAgent().process(page_job_id, page_path)
            data['custom_words'] = custom_words  # inject into every page
            data = regex_agent.process(data)
            data = vision_agent.process(data)

            set_status('validating', pages_done=page_index)
            data = validation_agent.process(data)

            final_redactions = data.get('final_redactions', [])
            for r in final_redactions:
                r['page'] = page_index  # tag each item with its page number

            preview_path = os.path.join(settings.STORAGE_PATH, 'preview', f'{job_id}_page{page_index}_preview.jpg')
            redacted_path = os.path.join(settings.STORAGE_PATH, 'redacted', f'{job_id}_page{page_index}.jpg')

            redacted_count, pii_types = draw_redactions(
                data['enhanced_image_path'], final_redactions,
                preview_path, redacted_path
            )

            redacted_page_paths.append((page_index, redacted_path))
            all_pii_types.update(pii_types)
            total_redacted += redacted_count
            total_flagged += sum(1 for r in final_redactions if r.get('flag_for_review'))
            page_agent_decisions.append({'page': page_index, 'final_redactions': final_redactions})
            all_final_redactions.extend(final_redactions)  # flat list for /result endpoint

            page_risk = data.get('overall_risk', 'LOW')
            if overall_risk_rank.get(page_risk, 0) > overall_risk_rank.get(overall_risk, 0):
                overall_risk = page_risk

            set_status('redacting', pages_done=page_index + 1)

        redacted_page_paths.sort(key=lambda t: t[0])
        ordered_paths = [p for _, p in redacted_page_paths]

        redacted_pdf_path = os.path.join(settings.STORAGE_PATH, 'redacted', f'{job_id}.pdf')
        images_to_pdf(ordered_paths, redacted_pdf_path)

        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = 'completed'
            job.redacted_pdf_path = redacted_pdf_path
            job.completed_at = datetime.utcnow()
            db.commit()

        # Store both flat list (for /result endpoint) and per-page list (for debugging)
        agent_decisions = {
            'final_redactions': all_final_redactions,
            'pages': page_agent_decisions,
        }

        audit = AuditLog(
            id=uuid.uuid4(),
            job_id=job_id,
            pii_types_found=list(all_pii_types),
            pii_count=total_redacted,
            confidence_scores={t: 1.0 for t in all_pii_types},
            risk_score=overall_risk,
            requires_review=total_flagged > 0,
            agent_decisions=json.dumps(agent_decisions),
            items_redacted=total_redacted,
            items_flagged=total_flagged,
            processing_time_ms=0
        )
        db.add(audit)
        db.commit()

        logger.info(f"PDF job {job_id} complete: {len(pages)} pages, {total_redacted} redactions")
        return {
            'job_id': job_id,
            'redacted_pdf_path': redacted_pdf_path,
            'page_count': len(pages),
            'items_redacted': total_redacted,
            'risk_score': overall_risk
        }

    except Exception as e:
        logger.error(f"PDF pipeline failed for job {job_id}: {e}")
        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = 'failed'
            job.error_message = str(e)
            db.commit()
        raise
    finally:
        db.close()


def process_document_chain(job_id, file_path, custom_words=None):
    from agents.pdf_utils import is_pdf
    if is_pdf(file_path):
        return process_pdf_task.apply_async(
            args=[job_id, file_path],
            kwargs={'custom_words': custom_words or []}
        )
    return process_image_chain(job_id, file_path, custom_words=custom_words)