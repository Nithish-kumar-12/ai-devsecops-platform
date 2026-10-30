"""
Celery task definitions for scan execution.
Full implementation added in Phase 5 (scan infrastructure).
"""
import structlog

from app.workers.celery_app import celery_app

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="app.workers.scan_tasks.run_scan",
    bind=True,
    max_retries=0,
    queue="scans",
)
def run_scan(self, scan_id: str) -> dict:
    """
    Orchestrate a full security scan pipeline for the given scan_id.

    Phase 5 will implement:
    - Load scan config from DB
    - Route to appropriate scanner adapters based on scan_type
    - Invoke normalizer → deduplicator → correlator → severity classifier
    - Persist findings and update scan status
    - Trigger AI analysis (Phase 10)
    - Evaluate CI/CD gate (Phase 11)
    """
    logger.info("run_scan task received", scan_id=scan_id)
    # Placeholder — will be replaced in Phase 5
    raise NotImplementedError(
        f"Scan task not yet implemented (scan_id={scan_id}). "
        "Full implementation arrives in Phase 5."
    )
