from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from evaluator.metrics import generate_security_report
from evaluator.runner import SecurityEvaluator


def parse_provider_list(provider_list: str) -> List[str]:
    """Parse a comma-separated provider list for comparison runs."""
    providers = [provider.strip() for provider in provider_list.split(",") if provider.strip()]
    if not providers:
        raise ValueError("At least one provider is required for comparison mode.")
    return providers


def run_provider_comparison(
    providers: List[str],
    config_path: str = "prompts.yaml",
    profile: str = "quick",
    llm_kwargs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run the same evaluation profile against multiple providers."""
    llm_kwargs = llm_kwargs or {}
    reports: Dict[str, Dict[str, Any]] = {}
    comparison_summary = []

    for provider in providers:
        evaluator = SecurityEvaluator(
            config_path=config_path,
            llm_provider=provider,
            profile=profile,
            **llm_kwargs,
        )
        evaluation_results = evaluator.run_evaluation_suite_sync()
        report = generate_security_report(evaluation_results)
        reports[provider] = report

        evaluation_summary = report.get("evaluation_summary", {})
        provider_info = report.get("provider_info", {})
        comparison_summary.append(
            {
                "provider": provider,
                "resolved_provider": provider_info.get("provider", provider),
                "is_mock": provider_info.get("is_mock", False),
                "overall_security_score": report.get("overall_security_score", 0.0),
                "security_score": evaluation_summary.get("security_score", 0.0),
                "mcp_security_score": evaluation_summary.get("mcp_security_score", 0.0),
                "leakage_detected": evaluation_summary.get("leakage_detected", 0),
                "total_tests": evaluation_summary.get("total_tests", 0),
                "execution_time": evaluation_summary.get("execution_time", 0.0),
                "recommendation_count": len(report.get("recommendations", [])),
            }
        )

    comparison_summary.sort(
        key=lambda item: (
            item["overall_security_score"],
            -item["leakage_detected"],
            -item["recommendation_count"],
        ),
        reverse=True,
    )

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "profile": profile,
        "providers": providers,
        "comparison_summary": comparison_summary,
        "reports": reports,
    }


def generate_comparison_html_report(
    comparison_report: Dict[str, Any], output_dir: str = "reports"
) -> str:
    """Generate an HTML provider comparison report."""
    template_dir = Path(__file__).parent.parent / "app" / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("comparison.html")
    html_content = template.render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        comparison=comparison_report,
        summary=comparison_report.get("comparison_summary", []),
    )

    os.makedirs(output_dir, exist_ok=True)
    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_file = os.path.join(output_dir, f"provider_comparison_{timestamp_file}.html")
    with open(html_file, "w", encoding="utf-8") as file_handle:
        file_handle.write(html_content)
    return html_file
