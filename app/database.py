import os
from typing import Optional
from sqlmodel import SQLModel, create_engine, Session, select
from .models import EvaluationReport, LLMCache
import hashlib
import json
from .security.redaction import redact

# Ensure the data directory exists
os.makedirs("data", exist_ok=True)

sqlite_file_name = "data/evaluator_history.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

# Pre-create file with restrictive permissions if it doesn't exist
if not os.path.exists(sqlite_file_name):
    with open(sqlite_file_name, "w") as f:
        pass
    os.chmod(sqlite_file_name, 0o600)

engine = create_engine(sqlite_url, echo=False)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def generate_cache_key(provider: str, model: str, prompt: str, parameters: dict) -> str:
    """Generate a unique cache key for a prompt and its parameters."""
    param_str = json.dumps(parameters, sort_keys=True)
    raw_key = f"{provider}:{model}:{prompt}:{param_str}"
    return hashlib.sha256(raw_key.encode()).hexdigest()


def get_cached_response(
    provider: str, model: str, prompt: str, parameters: dict
) -> Optional[str]:
    """Retrieve a cached response if available."""
    cache_key = generate_cache_key(provider, model, prompt, parameters)
    with Session(engine) as session:
        statement = select(LLMCache).where(LLMCache.cache_key == cache_key)
        result = session.exec(statement).first()
        if result:
            return result.response
        return None


def save_to_cache(
    provider: str, model: str, prompt: str, response: str, parameters: dict
):
    """Save a response to the cache."""
    cache_key = generate_cache_key(provider, model, prompt, parameters)
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()

    # Redact parameters before saving
    param_str = json.dumps(parameters, sort_keys=True)
    try:
        redacted_params = json.loads(redact(param_str))
    except Exception:
        redacted_params = parameters # Fallback

    cache_entry = LLMCache(
        cache_key=cache_key,
        prompt_hash=prompt_hash,
        provider=provider,
        model=model,
        prompt=redact(prompt),
        response=redact(response),
        parameters=redacted_params,
    )

    with Session(engine) as session:
        try:
            # Check if it already exists to avoid unique constraint error
            statement = select(LLMCache).where(LLMCache.cache_key == cache_key)
            existing = session.exec(statement).first()
            if not existing:
                session.add(cache_entry)
                session.commit()
        except Exception:
            # If concurrent write happens, just ignore
            session.rollback()


def get_session():
    with Session(engine) as session:
        yield session


def save_report_to_db(report: dict):
    """Save an evaluation report to the database."""
    summary = report.get("summary", {})
    provider_info = report.get("provider_info", {})

    # Redact sensitive data in the report JSON before saving
    redacted_report = redact(json.dumps(report))
    try:
        report_json = json.loads(redacted_report)
    except Exception:
        report_json = report # Fallback if json load fails after redaction

    db_report = EvaluationReport(
        overall_security_score=summary.get("overall_security_score", 0.0),
        mcp_security_score=summary.get("mcp_security_score", 0.0),
        leakage_detected=summary.get("leakage_detected", 0),
        total_tests=summary.get("total_tests", 0),
        execution_time=summary.get("execution_time", 0.0),
        provider=provider_info.get("provider", "unknown"),
        is_mock=provider_info.get("is_mock", True),
        report_json=report_json,
    )

    with Session(engine) as session:
        session.add(db_report)
        session.commit()
        session.refresh(db_report)
        return db_report
