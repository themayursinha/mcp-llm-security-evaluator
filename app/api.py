import os
import asyncio
from typing import List, Optional
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Query,
    BackgroundTasks,
    WebSocket,
    WebSocketDisconnect,
    Request,
)
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select, col
from datetime import datetime
from pathlib import Path

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

# Setup templates
template_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Serve the live monitor as the home page."""
    return templates.TemplateResponse("monitor.html", {"request": request})


@app.get("/monitor", response_class=HTMLResponse)
async def monitor_page(request: Request):
    """Serve the live monitor page."""
    return templates.TemplateResponse("monitor.html", {"request": request})


@app.get("/ui/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Serve a historical reports browser (TBD)."""
    # For now, redirect or serve a simple list
    return templates.TemplateResponse(
        "monitor.html", {"request": request}
    )  # Fallback to monitor


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


def get_db_session():
    with Session(engine) as session:
        yield session


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # Connection might be closed
                continue


manager = ConnectionManager()


@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def run_evaluation_task(profile: str, provider: str, model: Optional[str] = None):
    """Background task to run evaluation and save to DB."""

    async def progress_callback(update: dict):
        await manager.broadcast({"type": "progress", "payload": update})

    try:
        llm_kwargs = {}
        if model:
            llm_kwargs["model"] = model

        evaluator = SecurityEvaluator(
            llm_provider=provider,
            profile=profile,
            progress_callback=progress_callback,
            **llm_kwargs,
        )

        report = await evaluator.run_evaluation_suite()
        db_report = save_report_to_db(report)

        # Send completion event and alert check
        summary = report.get("summary", {})
        score = summary.get("overall_security_score", 0.0)
        threshold = Config.SECURITY_THRESHOLD

        alert = None
        if score < threshold:
            alert = f"SECURITY ALERT: Overall score {score}% is below threshold {threshold}%!"
            logger.warning(alert)

        await manager.broadcast(
            {
                "type": "complete",
                "payload": {
                    "summary": summary,
                    "alert": alert,
                    "report_id": db_report.id,
                },
            }
        )
        logger.info(f"Evaluation completed and saved for profile: {profile}")
    except Exception as e:
        logger.error(f"Background evaluation failed: {e}")
        await manager.broadcast({"type": "error", "payload": str(e)})


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
