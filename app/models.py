from datetime import datetime
from typing import Optional, Dict, Any
from sqlmodel import SQLModel, Field, JSON, Column


class EvaluationReport(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    overall_security_score: float
    mcp_security_score: float
    leakage_detected: int
    total_tests: int
    execution_time: float
    provider: str
    is_mock: bool
    status: str = "completed"
    # Store the full report as a JSON blob
    report_json: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

    class Config:
        arbitrary_types_allowed = True
