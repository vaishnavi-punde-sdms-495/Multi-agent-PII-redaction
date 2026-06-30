from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uuid
import os
import sys
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import settings
from database import init_db, engine
from tasks.pipeline import process_document_chain
from agents.pdf_utils import is_pdf
from models.job import Job
from database import SessionLocal
from sqlalchemy import text

app = FastAPI(title="PII Redaction Service", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.pdf'}


@app.on_event("startup")
async def startup():
    print("Starting PII Redaction Service...")
    init_db()
    print("Database initialized")
    for sub in ('preview', 'redacted', 'uploads', 'enhanced'):
        os.makedirs(os.path.join(settings.STORAGE_PATH, sub), exist_ok=True)


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        print(f"Received file: {file.filename}")

        if file.size > settings.MAX_UPLOAD_SIZE:
            raise HTTPException(400, "File too large")

        ext = os.path.splitext(file.filename or '')[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(400, f"Unsupported file type '{ext}'. Allowed: jpg, jpeg, png, pdf")

        file_type = 'pdf' if ext == '.pdf' else 'image'
        job_id = str(uuid.uuid4())

        upload_dir = os.path.join(settings.STORAGE_PATH, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        stored_ext = ext if file_type == 'pdf' else '.jpg'
        file_path = os.path.join(upload_dir, f'{job_id}{stored_ext}')

        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)

        db = SessionLocal()
        job = Job(
            id=job_id,
            original_filename=file.filename,
            original_image_path=file_path,
            status="pending",
            file_type=file_type
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        db.close()

        print(f"Job created: {job_id} ({file_type})")

        result = process_document_chain(job_id, file_path)
        print(f"Task started: {result.id}")

        return {"job_id": job_id, "status": "pending", "file_type": file_type, "message": "Job queued"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in upload: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/jobs/{job_id}/status")
async def get_status(job_id: str):
    db = SessionLocal()
    job = db.query(Job).filter(Job.id == job_id).first()
    db.close()
    if not job:
        raise HTTPException(404, "Job not found")

    progress_map = {
        "pending": 0, "preprocessing": 15, "regex_detection": 25,
        "detecting": 50, "validating": 75, "redacting": 90,
        "completed": 100, "failed": 100
    }

    progress = progress_map.get(job.status, 0)
    if job.file_type == 'pdf' and job.page_count and job.status in ('detecting', 'validating', 'redacting'):
        page_fraction = job.pages_done / job.page_count
        progress = 25 + int(page_fraction * 65)

    return {
        "job_id": str(job.id),
        "status": job.status,
        "progress": progress,
        "current_agent": job.status,
        "file_type": job.file_type,
        "page_count": job.page_count,
        "pages_done": job.pages_done,
        "error_message": job.error_message,
        "created_at": job.created_at.isoformat()
    }


@app.get("/api/jobs/{job_id}/result")
async def get_result(job_id: str):
    db = SessionLocal()
    job = db.query(Job).filter(Job.id == job_id).first()
    db.close()
    if not job:
        raise HTTPException(404, "Job not found")

    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM audit_logs WHERE job_id = :job_id ORDER BY created_at DESC LIMIT 1"),
            {"job_id": job_id}
        )
        audit = result.fetchone()

    redacted_url = None
    preview_url = None

    if job.file_type == 'pdf':
        if job.redacted_pdf_path and os.path.exists(job.redacted_pdf_path):
            redacted_url = f"/api/files/redacted-pdf/{job_id}.pdf"
        
        # Check multiple preview path patterns
        preview_patterns = [
            os.path.join(settings.STORAGE_PATH, 'preview', f'{job_id}_page0_preview.jpg'),
            os.path.join(settings.STORAGE_PATH, 'preview', f'{job_id}_page_0_preview.jpg'),
            os.path.join(settings.STORAGE_PATH, 'preview', f'{job_id}_preview.jpg'),
        ]
        for candidate in preview_patterns:
            if os.path.exists(candidate):
                preview_url = f"/api/images/preview/{os.path.basename(candidate)}"
                break
    else:
        if job.redacted_image_path and os.path.exists(job.redacted_image_path):
            redacted_url = f"/api/images/redacted/{job_id}.jpg"
        preview_path = os.path.join(settings.STORAGE_PATH, 'preview', f'{job_id}_preview.jpg')
        if os.path.exists(preview_path):
            preview_url = f"/api/images/preview/{job_id}_preview.jpg"

    pii_types = audit.pii_types_found if audit else []
    pii_count = audit.pii_count if audit else 0
    risk_score = audit.risk_score if audit else "UNKNOWN"
    requires_review = audit.requires_review if audit else False

    # Parse per-item data from agent_decisions
    detected_items = []
    if audit and audit.agent_decisions:
        try:
            raw = audit.agent_decisions
            decisions = json.loads(raw) if isinstance(raw, str) else raw
            
            # Try to get final_redactions from the flattened list first (new PDF structure)
            redactions = decisions.get('final_redactions', [])
            
            # If flattened list is empty, try pages structure (old PDF structure)
            if not redactions and 'pages' in decisions:
                for page in decisions.get('pages', []):
                    page_num = page.get('page', 0)
                    for r in page.get('final_redactions', []):
                        r['page'] = page_num
                        redactions.append(r)
            
            # Build detected_items from redactions
            for r in redactions:
                if not r.get('approved', False):
                    continue
                detected_items.append({
                    'pii_type': r.get('pii_type', 'unknown'),
                    'text_value': r.get('text_value', ''),
                    'confidence': r.get('final_confidence', r.get('confidence', 0.9)),
                    'bbox': r.get('bbox'),
                    'page': r.get('page'),
                    'flag_for_review': r.get('flag_for_review', False),
                    'validation_note': r.get('validation_note', ''),
                })
        except Exception as e:
            print(f"Warning: could not parse agent_decisions for job {job_id}: {e}")

    return {
        "job_id": str(job.id),
        "status": job.status,
        "file_type": job.file_type,
        "page_count": job.page_count,
        "detected_items": detected_items,
        "redacted_image_url": redacted_url if job.file_type == 'image' else None,
        "redacted_pdf_url": redacted_url if job.file_type == 'pdf' else None,
        "preview_image_url": preview_url,
        "pii_summary": {
            "count": pii_count,
            "types": pii_types,
            "risk_score": risk_score,
            "requires_review": requires_review
        }
    }


@app.get("/api/images/preview/{filename}")
async def get_preview_image(filename: str):
    path = os.path.join(settings.STORAGE_PATH, 'preview', filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Preview image not found")
    return FileResponse(path, media_type="image/jpeg")


@app.get("/api/images/redacted/{filename}")
async def get_redacted_image(filename: str):
    path = os.path.join(settings.STORAGE_PATH, 'redacted', filename)
    if os.path.exists(path):
        return FileResponse(
            path, media_type="image/jpeg", filename=f"redacted_{filename}",
            headers={"Content-Disposition": f"attachment; filename=redacted_{filename}"}
        )
    raise HTTPException(404, f"Redacted image not found: {filename}")


@app.get("/api/files/redacted-pdf/{filename}")
async def get_redacted_pdf(filename: str):
    path = os.path.join(settings.STORAGE_PATH, 'redacted', filename)
    if os.path.exists(path):
        return FileResponse(
            path, media_type="application/pdf", filename=f"redacted_{filename}",
            headers={"Content-Disposition": f"attachment; filename=redacted_{filename}"}
        )
    raise HTTPException(404, f"Redacted PDF not found: {filename}")


@app.get("/api/health")
async def health():
    return {"status": "ok", "redis": "connected"}


@app.get("/api/audit")
async def get_audit():
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 20"))
        logs = result.fetchall()

    return [{
        "id": str(log[0]),
        "job_id": str(log[1]),
        "pii_types": log[2],
        "risk_score": log[5],
        "requires_review": log[6],
        "created_at": log[10].isoformat() if log[10] else None
    } for log in logs]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)