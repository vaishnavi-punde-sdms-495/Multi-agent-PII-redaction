import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from celery import Celery

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

celery_app = Celery(
    'pii_redaction',
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=['tasks.pipeline']
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=700,
    task_soft_time_limit=600,
    broker_connection_retry_on_startup=True,
)

if __name__ == '__main__':
    celery_app.start()
