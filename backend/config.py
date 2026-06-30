import os
from dotenv import load_dotenv

# Load .env from the backend/ directory regardless of cwd the process was
# started from (e.g. celery worker started from repo root vs backend/).
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_THIS_DIR, '.env'))
load_dotenv(os.path.join(_THIS_DIR, '..', '.env'))  # fallback: repo-root .env


class Settings:
    DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://pii_user:pii_secure_pass@localhost/pii_redaction')
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    STORAGE_PATH = os.getenv('STORAGE_PATH', './storage')

    # Groq (Llama 4 Scout for vision detection + validation, Llama 3.3 available for text-only use)
    GROQ_API_KEY = os.getenv('GROQ_API_KEY', '')
    GROQ_VISION_MODEL = os.getenv('GROQ_VISION_MODEL', 'meta-llama/llama-4-scout-17b-16e-instruct')
    GROQ_TEXT_MODEL = os.getenv('GROQ_TEXT_MODEL', 'llama-3.3-70b-versatile')
    GROQ_TIMEOUT = int(os.getenv('GROQ_TIMEOUT', '30'))

    MAX_UPLOAD_SIZE = 10485760


settings = Settings()

if not settings.GROQ_API_KEY:
    import logging
    logging.getLogger(__name__).warning(
        "⚠️ GROQ_API_KEY is not set — Scout-based detection/validation will fail. "
        "Check that backend/.env exists and contains GROQ_API_KEY=..."
    )