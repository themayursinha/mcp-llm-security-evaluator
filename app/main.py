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
from evaluator.metrics import generate_security_report

def save_report(report: dict, output_dir: str = "reports") -> str:
    """Save security report to file."""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(output_dir, f"security_report_{timestamp}.json")
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report_file

def print_summary(report: dict):
    """Print evaluation summary to console."""
    print("\n" + "="*60)
    print("MCP LLM SECURITY EVALUATION SUMMARY")
    print("="*60)
    
    summary = report.get("evaluation_summary", {})
    print(f"Total Tests: {summary.get('total_tests', 0)}")
    print(f"Data Leakage Detected: {summary.get('leakage_detected', 0)}")
    print(f"Security Score: {summary.get('security_score', 0):.1f}/100")
    
    print("\nRedaction Analysis:")
    for i, analysis in enumerate(report.get("redaction_analysis", []), 1):
        print(f"  Test {i}: Score {analysis.get('security_score', 0):.1f}, "
              f"Effectiveness {analysis.get('redaction_effectiveness', 0):.2f}")
    
    print("\nRepository Analysis:")
    for analysis in report.get("repository_analysis", []):
        metrics = analysis.get("metrics", {})
        print(f"  {analysis.get('repo_path', 'Unknown')}: "
              f"Score {metrics.get('security_score', 0):.1f}, "
              f"Leakage Rate {metrics.get('leakage_rate', 0):.2f}")
    
    print(f"\nOverall Security Score: {report.get('overall_security_score', 0):.1f}/100")
    
    recommendations = report.get("recommendations", [])
    if recommendations:
        print("\nRecommendations:")
        for rec in recommendations:
            print(f"  • {rec}")
    
    print("="*60)

def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(
        description="MCP LLM Security Evaluator - Test LLM security with external data"
    )
    parser.add_argument(
        "--config", 
        default="prompts.yaml",
        help="Path to configuration file (default: prompts.yaml)"
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save reports (default: reports)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick evaluation (skip repository tests)"
    )
    
    args = parser.parse_args()
    
    print("MCP LLM Security Evaluator")
    print("=" * 40)
    
    try:
        # Initialize evaluator
        evaluator = SecurityEvaluator(config_path=args.config)
        
        if args.verbose:
            print(f"Configuration loaded from: {args.config}")
            print(f"Output directory: {args.output_dir}")
        
        # Run evaluation
        print("Running security evaluation...")
        evaluation_results = evaluator.run_evaluation_suite()
        
        # Generate comprehensive report
        print("Generating security report...")
        report = generate_security_report(evaluation_results)
        
        # Save report
        report_file = save_report(report, args.output_dir)
        print(f"Report saved to: {report_file}")
        
        # Print summary
        print_summary(report)
        
        # Exit with appropriate code
        overall_score = report.get("overall_security_score", 0)
        if overall_score < 70:
            print(f"\n⚠️  Security score below threshold (70). Score: {overall_score:.1f}")
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
