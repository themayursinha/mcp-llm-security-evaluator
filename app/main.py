#!/usr/bin/env python3
"""
MCP LLM Security Evaluator - Main Application
Entry point for running security evaluations on LLMs.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from evaluator.runner import SecurityEvaluator
from evaluator.metrics import generate_security_report, generate_html_report
from app.config import Config
from app.logging_config import setup_logging, get_logger

logger = get_logger(__name__)


def save_report(report: dict, output_dir: str = "reports") -> str:
    """Save security report to file."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(output_dir, f"security_report_{timestamp}.json")

    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    return report_file


def print_summary(report: dict):
    """Print evaluation summary to console."""
    print("\n" + "=" * 60)
    print("MCP LLM SECURITY EVALUATION SUMMARY")
    print("=" * 60)

    summary = report.get("evaluation_summary", {})
    print(f"Total Tests: {summary.get('total_tests', 0)}")
    print(f"Data Leakage Detected: {summary.get('leakage_detected', 0)}")
    print(f"Security Score: {summary.get('security_score', 0):.1f}/100")
    print(f"Execution Time: {summary.get('execution_time', 0):.2f}s")

    print("\nRedaction Analysis:")
    for i, analysis in enumerate(report.get("redaction_analysis", []), 1):
        print(
            f"  Test {i}: Score {analysis.get('security_score', 0):.1f}, "
            f"Effectiveness {analysis.get('redaction_effectiveness', 0):.2f}"
        )

    print("\nRepository Analysis:")
    for analysis in report.get("repository_analysis", []):
        metrics = analysis.get("metrics", {})
        print(
            f"  {analysis.get('repo_path', 'Unknown')}: "
            f"Score {metrics.get('security_score', 0):.1f}, "
            f"Leakage Rate {metrics.get('leakage_rate', 0):.2f}"
        )

    print("\nMCP Security Analysis:")
    mcp_analysis = report.get("mcp_analysis", {})
    if "error" in mcp_analysis:
        print(f"  Error: {mcp_analysis['error']}")
    else:
        mcp_summary = mcp_analysis.get("summary", {})
        print(f"  Tools Tested: {mcp_summary.get('total_tools_tested', 0)}")
        print(f"  High Risk Tools: {mcp_summary.get('high_risk_tools', 0)}")
        print(
            f"  Privilege Escalation: {'Yes' if mcp_summary.get('privilege_escalation_detected', False) else 'No'}"
        )
        print(
            f"  MCP Security Score: {mcp_summary.get('mcp_security_score', 0):.1f}/100"
        )

    print(
        f"\nOverall Security Score: {report.get('overall_security_score', 0):.1f}/100"
    )

    recommendations = report.get("recommendations", [])
    if recommendations:
        print("\nRecommendations:")
        for rec in recommendations:
            print(f"  • {rec}")

    print("=" * 60)


def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(
        description="MCP LLM Security Evaluator - Test LLM security with external data"
    )
    parser.add_argument(
        "--config",
        default="prompts.yaml",
        help="Path to configuration file (default: prompts.yaml)",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save reports (default: reports)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick evaluation (skip repository tests, use 'quick' profile)",
    )
    parser.add_argument(
        "--profile",
        default="default",
        help="Configuration profile to use (default: default)",
    )
    parser.add_argument(
        "--provider",
        default="auto",
        choices=["auto", "openai", "anthropic", "ollama", "mock"],
        help="LLM provider to use (default: auto)",
    )
    parser.add_argument(
        "--model", help="Specific model to use (e.g., gpt-4, claude-3-sonnet)"
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=1000,
        help="Maximum tokens for LLM responses (default: 1000)",
    )
    parser.add_argument(
        "--base-url", help="Base URL for local LLM providers (e.g., for Ollama)"
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Disable LLM response caching"
    )
    parser.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default=Config.REPORT_FORMAT,
        help=f"Report format: json, html, or both (default: {Config.REPORT_FORMAT})",
    )
    parser.add_argument(
        "--server", action="store_true", help="Start the REST API server"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="API server host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="API server port (default: 8000)"
    )

    args = parser.parse_args()

    # Initialize logging
    setup_logging()

    if args.server:
        import uvicorn
        from app.api import app

        logger.info(f"Starting API server on {args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port)
        return

    try:
        # Validate configuration
        is_valid, error_msg = Config.validate(args.provider)
        if not is_valid:
            logger.error(f"Configuration Error: {error_msg}")
            sys.exit(1)
        llm_kwargs = {}
        if args.model:
            llm_kwargs["model"] = args.model
        if args.max_tokens:
            llm_kwargs["max_tokens"] = args.max_tokens
        if args.base_url:
            llm_kwargs["base_url"] = args.base_url
        if args.no_cache:
            llm_kwargs["use_cache"] = False

        # Determine profile
        profile = args.profile
        if args.quick:
            profile = "quick"

        # Initialize evaluator
        evaluator = SecurityEvaluator(
            config_path=args.config,
            llm_provider=args.provider,
            profile=profile,
            **llm_kwargs,
        )

        if args.verbose:
            print(f"Configuration loaded from: {args.config}")
            print(f"Output directory: {args.output_dir}")
            print(f"LLM Provider: {evaluator.llm_client.get_provider_name()}")
            print(f"Using mock provider: {evaluator.llm_client.is_mock()}")
            config_summary = Config.get_summary()
            print(f"Report format: {args.format}")
            print(f"Security threshold: {Config.SECURITY_THRESHOLD}")
            print(f"Log level: {Config.LOG_LEVEL}")

        # Run evaluation
        print("Running security evaluation...")
        evaluation_results = evaluator.run_evaluation_suite_sync()

        # Generate comprehensive report
        print("Generating security report...")
        report = generate_security_report(evaluation_results)

        # Save reports based on format
        report_files = []
        if args.format in ["json", "both"]:
            json_file = save_report(report, args.output_dir)
            report_files.append(json_file)
            print(f"JSON report saved to: {json_file}")

        if args.format in ["html", "both"]:
            try:
                html_file = generate_html_report(report, args.output_dir)
                report_files.append(html_file)
                print(f"HTML report saved to: {html_file}")
            except Exception as e:
                print(f"Warning: Failed to generate HTML report: {e}")
                if args.format == "html":
                    # If HTML was the only format requested, fall back to JSON
                    json_file = save_report(report, args.output_dir)
                    report_files.append(json_file)
                    print(f"Fell back to JSON report: {json_file}")

        # Also save to database for historical tracking
        try:
            from app.database import create_db_and_tables, save_report_to_db

            create_db_and_tables()
            save_report_to_db(report)
            print("Report also saved to historical database")
        except Exception as e:
            print(f"Warning: Failed to save report to database: {e}")

        # Print summary
        print_summary(report)

        # Exit with appropriate code
        overall_score = report.get("overall_security_score", 0)
        threshold = Config.SECURITY_THRESHOLD
        if overall_score < threshold:
            print(
                f"\n⚠️  Security score below threshold ({threshold}). Score: {overall_score:.1f}"
            )
            sys.exit(1)
        else:
            print(f"\n✅ Security evaluation passed. Score: {overall_score:.1f}")
            sys.exit(0)

    except FileNotFoundError as e:
        print(f"Error: Configuration file not found - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error during evaluation: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
