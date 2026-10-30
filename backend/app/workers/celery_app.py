"""
Celery application factory.
Workers consume tasks from the 'scans' and 'default' queues.
"""
from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "devsecops",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,         # re-queue on worker crash
    worker_prefetch_multiplier=1,  # one task per worker at a time (heavy scans)
    task_routes={
        "app.workers.scan_tasks.run_scan": {"queue": "scans"},
    },
    result_expires=60 * 60 * 24,  # keep results for 24 hours
)
