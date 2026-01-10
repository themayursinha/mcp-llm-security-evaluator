import os
import asyncio
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks
from sqlmodel import Session, select, col
from datetime import datetime

from .database import engine, create_db_and_tables, save_report_to_db
from .models import EvaluationReport
from evaluator.runner import SecurityEvaluator
from app.config import Config
from app.logging_config import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="MCP LLM Security Evaluator API",
    description="REST API for running and managing LLM security evaluations.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


def get_db_session():
    with Session(engine) as session:
        yield session


async def run_evaluation_task(profile: str, provider: str, model: Optional[str] = None):
    """Background task to run evaluation and save to DB."""
    try:
        llm_kwargs = {}
        if model:
            llm_kwargs["model"] = model

        evaluator = SecurityEvaluator(
            llm_provider=provider, profile=profile, **llm_kwargs
        )

        report = await evaluator.run_evaluation_suite()
        save_report_to_db(report)
        logger.info(f"Evaluation completed and saved for profile: {profile}")
    except Exception as e:
        logger.error(f"Background evaluation failed: {e}")


@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}


@app.post("/evaluate")
async def trigger_evaluation(
    background_tasks: BackgroundTasks,
    profile: str = "default",
    provider: str = "auto",
    model: Optional[str] = None,
):
    """Trigger a new security evaluation."""
    background_tasks.add_task(run_evaluation_task, profile, provider, model)
    return {
        "message": "Evaluation started in background",
        "profile": profile,
        "provider": provider,
        "model": model or "default",
    }


@app.get("/reports", response_model=List[dict])
def list_reports(
    offset: int = 0, limit: int = 100, session: Session = Depends(get_db_session)
):
    """List all historical evaluation reports (summary only)."""
    statement = (
        select(  # type: ignore
            col(EvaluationReport.id),
            col(EvaluationReport.timestamp),
            col(EvaluationReport.overall_security_score),
            col(EvaluationReport.mcp_security_score),
            col(EvaluationReport.leakage_detected),
            col(EvaluationReport.provider),
            col(EvaluationReport.status),
        )
        .order_by(col(EvaluationReport.timestamp).desc())
        .offset(offset)
        .limit(limit)
    )

    results = session.exec(statement).all()
    # Convert Row objects to dicts
    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "overall_security_score": r[2],
            "mcp_security_score": r[3],
            "leakage_detected": r[4],
            "provider": r[5],
            "status": r[6],
        }
        for r in results
    ]


@app.get("/reports/{report_id}")
def get_report(report_id: int, session: Session = Depends(get_db_session)):
    """Get the full JSON report for a specific evaluation."""
    report = session.get(EvaluationReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.report_json


@app.get("/trends")
def get_trends(limit: int = 10, session: Session = Depends(get_db_session)):
    """Get historical security score trends."""
    statement = (
        select(  # type: ignore
            col(EvaluationReport.timestamp),
            col(EvaluationReport.overall_security_score),
            col(EvaluationReport.mcp_security_score),
        )
        .order_by(col(EvaluationReport.timestamp).asc())
        .limit(limit)
    )

    results = session.exec(statement).all()
    return [
        {"timestamp": r[0], "overall_score": r[1], "mcp_score": r[2]} for r in results
    ]
