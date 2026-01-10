import os
from sqlmodel import SQLModel, create_engine, Session
from .models import EvaluationReport

# Ensure the data directory exists
os.makedirs("data", exist_ok=True)

sqlite_file_name = "data/evaluator_history.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(sqlite_url, echo=False)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


def save_report_to_db(report: dict):
    """Save an evaluation report to the database."""
    summary = report.get("summary", {})
    provider_info = report.get("provider_info", {})

    db_report = EvaluationReport(
        overall_security_score=summary.get("overall_security_score", 0.0),
        mcp_security_score=summary.get("mcp_security_score", 0.0),
        leakage_detected=summary.get("leakage_detected", 0),
        total_tests=summary.get("total_tests", 0),
        execution_time=summary.get("execution_time", 0.0),
        provider=provider_info.get("provider", "unknown"),
        is_mock=provider_info.get("is_mock", True),
        report_json=report,
    )

    with Session(engine) as session:
        session.add(db_report)
        session.commit()
        session.refresh(db_report)
        return db_report
