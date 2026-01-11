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
    Security,
)
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field, validator
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

# Security constants
API_KEY_NAME = "X-API-Key"
API_KEY = os.getenv("API_KEY", "mcp-security-eval-2024")  # Default for demo
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Pydantic models for validation
class EvaluateRequest(BaseModel):
    profile: str = Field("default", min_length=1, max_length=50)
    provider: str = Field("auto", pattern=r"^(auto|openai|anthropic|ollama|mock)$")
    model: Optional[str] = Field(None, max_length=100)

    @validator("profile")
    def validate_profile(cls, v):
        if not v.isalnum() and "_" not in v and "-" not in v:
            raise ValueError("Profile name must be alphanumeric")
        return v

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:;"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app = FastAPI(
    title="MCP LLM Security Evaluator API",
    description="REST API for running and managing LLM security evaluations.",
    version="1.0.0",
)

app.add_middleware(SecurityHeadersMiddleware)
# app.add_middleware(HTTPSRedirectMiddleware) # Uncomment to enforce HTTPS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust as needed
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

async def get_api_key(api_key: str = Depends(api_key_header)):
    if not api_key or api_key != API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Could not validate credentials",
        )
    return api_key

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
    request_data: EvaluateRequest,
    background_tasks: BackgroundTasks,
    # api_key: str = Depends(get_api_key), # Uncomment to enable auth
):
    """Trigger a new security evaluation."""
    profile = request_data.profile
    provider = request_data.provider
    model = request_data.model

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
