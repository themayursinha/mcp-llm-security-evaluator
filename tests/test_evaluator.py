#!/usr/bin/env python3
"""
Comprehensive test suite for MCP LLM Security Evaluator
"""

import pytest
import os
import tempfile
from unittest.mock import patch

os.environ.setdefault("EVALUATOR_DB_PATH", "/private/tmp/mcp_llm_security_evaluator_test.db")

from evaluator.runner import SecurityEvaluator  # noqa: E402
from evaluator.llm import LLMClient  # noqa: E402
from evaluator.comparison import parse_provider_list, run_provider_comparison  # noqa: E402
from evaluator.metrics import calculate_security_metrics, generate_security_report  # noqa: E402
from evaluator.mcp_catalog import build_tool_catalog_snapshot, diff_tool_catalogs  # noqa: E402
from evaluator.mcp_client import MCPSecurityTester  # noqa: E402
from evaluator.mcp_inventory import MCPInventoryScanner  # noqa: E402
from evaluator.mcp_policy import MCPPolicy  # noqa: E402
from app.database import create_db_and_tables, save_report_to_db  # noqa: E402
from app.security.redaction import (  # noqa: E402
    DataRedactor,
    contains_sensitive_data,
    detect_sensitive_data,
    find_sensitive_data,
    redact,
)

# Ensure database is initialized for tests
create_db_and_tables()


class TestDataRedactor:
    """Test the DataRedactor class."""

    def test_redact_api_key(self):
        """Test redaction of API keys."""
        redactor = DataRedactor()
        text = "api_key = 'sk-1234567890abcdef'"
        result = redactor.redact(text)
        assert "[REDACTED_API_KEY]" in result
        assert "sk-1234567890abcdef" not in result

    def test_redact_password(self):
        """Test redaction of passwords."""
        redactor = DataRedactor()
        text = "password: mysecretpassword123"
        result = redactor.redact(text)
        assert "[REDACTED_PASSWORD]" in result
        assert "mysecretpassword123" not in result

    def test_redact_email(self):
        """Test redaction of email addresses."""
        redactor = DataRedactor()
        text = "Contact: john.doe@example.com for more info"
        result = redactor.redact(text)
        assert "[REDACTED_EMAIL]" in result
        assert "john.doe@example.com" not in result

    def test_detect_sensitive_data(self):
        """Test detection of sensitive data."""
        text = "api_key = 'sk-test123456' and password: secret123"
        detected = detect_sensitive_data(text)
        assert "api_key" in detected
        assert "password" in detected
        assert len(detected["api_key"]) > 0
        assert len(detected["password"]) > 0

    def test_detects_modern_token_formats(self):
        """Test detection of common real-world token shapes."""
        aws_key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
        github_token = "gh" + "p_" + "1234567890abcdefghijklmnop"
        slack_token = "xo" + "xb" + "-123456789012-123456789012-abcdefghijklmnop"
        jwt_token = (
            "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0.signaturetoken"
        )
        text = (
            f"aws={aws_key} " f"github={github_token} " f"slack={slack_token} " f"jwt={jwt_token}"
        )

        categories = {finding["category"] for finding in find_sensitive_data(text)}

        assert "aws_access_key" in categories
        assert "github_token" in categories
        assert "slack_token" in categories
        assert "jwt" in categories

    def test_generic_secret_word_does_not_count_as_leakage(self):
        """Generic security prose should not be treated as a concrete leak."""
        text = "The secret rotation policy is documented."

        assert "[REDACTED_SECRET]" in redact(text)
        assert contains_sensitive_data(text) is True
        assert contains_sensitive_data(text, include_generic=False) is False

    def test_redaction_stats(self):
        """Test redaction statistics calculation."""
        redactor = DataRedactor()
        original = "api_key = 'sk-test123' and password: secret123"
        redacted = redactor.redact(original)
        stats = redactor.get_redaction_stats(original, redacted)

        assert stats["original_sensitive_count"] > 0
        assert stats["redacted_sensitive_count"] == 0
        assert stats["redaction_effectiveness"] == 1.0


class TestSecurityMetrics:
    """Test security metrics calculations."""

    def test_precision_calculation(self):
        """Test precision metric calculation."""
        from evaluator.metrics import precision

        assert precision(8, 2) == 0.8
        assert precision(0, 0) == 0.0

    def test_recall_calculation(self):
        """Test recall metric calculation."""
        from evaluator.metrics import recall

        assert recall(8, 2) == 0.8
        assert recall(0, 0) == 0.0

    def test_f1_score_calculation(self):
        """Test F1 score calculation."""
        from evaluator.metrics import f1_score

        assert f1_score(0.8, 0.8) == pytest.approx(0.8)
        assert f1_score(0.0, 0.0) == 0.0

    def test_security_metrics_calculation(self):
        """Test comprehensive security metrics."""
        original_text = "api_key = 'sk-test123456'"
        original_response = "I see an API key: sk-test123456"
        redacted_text = "api_key = '[REDACTED_API_KEY]'"
        redacted_response = "I see a redacted API key"

        metrics = calculate_security_metrics(
            original_text, original_response, redacted_text, redacted_response
        )

        assert metrics["original_sensitive_count"] > 0
        assert metrics["data_leaked_original"] is True
        assert metrics["data_leaked_redacted"] is False
        assert metrics["redaction_effectiveness"] > 0


class TestSecurityEvaluator:
    """Test the SecurityEvaluator class."""

    def test_evaluator_initialization(self):
        """Test evaluator initialization."""
        evaluator = SecurityEvaluator()
        assert evaluator.config_path == "prompts.yaml"
        assert evaluator.llm_client is not None

    def test_load_config_default(self):
        """Test loading default configuration."""
        evaluator = SecurityEvaluator()
        config = evaluator.load_config()
        if isinstance(config, list):
            assert len(config) > 0
        else:
            assert "profiles" in config or "prompts" in config

    def test_load_config_file(self):
        """Test loading configuration from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("prompts:\n  - prompt: 'Test prompt'")
            config_path = f.name

        try:
            evaluator = SecurityEvaluator(config_path=config_path)
            config = evaluator.load_config()
            assert config["prompts"][0]["prompt"] == "Test prompt"
        finally:
            os.unlink(config_path)

    def test_detect_data_leakage(self):
        """Test data leakage detection."""
        evaluator = SecurityEvaluator()

        # Test with leakage
        original = "api_key = 'sk-test123'"
        response = "I found the API key: sk-test123"
        assert evaluator._detect_data_leakage(original, response) is True

        # Test without leakage
        response_clean = "I see there's an API key but it's redacted"
        assert evaluator._detect_data_leakage(original, response_clean) is False

        # Generic security wording should not count as a leaked value.
        response_generic = "I found a secret reference but no raw value."
        assert evaluator._detect_data_leakage(original, response_generic) is False

    def test_quick_profile_skips_repository_tests(self):
        """Quick profile should not silently fall back to repository scans."""
        evaluator = SecurityEvaluator(profile="quick", llm_provider="mock", delay=0)

        results = evaluator.run_evaluation_suite_sync()

        assert results["repository_tests"] == []

    @patch("evaluator.runner.SecurityEvaluator.run_repository_test")
    @patch("evaluator.runner.SecurityEvaluator.run_redaction_test")
    def test_run_evaluation_suite(self, mock_redaction, mock_repo):
        """Test running the complete evaluation suite."""
        # Mock the test methods
        mock_redaction.return_value = {
            "test_type": "redaction",
            "metrics": {"security_score": 80},
        }
        mock_repo.return_value = {
            "test_type": "repository",
            "results": [{"leakage_detected": False}],
        }

        evaluator = SecurityEvaluator()
        results = evaluator.run_evaluation_suite_sync()

        assert "redaction_tests" in results
        assert "repository_tests" in results
        assert "summary" in results
        assert results["summary"]["total_tests"] > 0


class TestReportGeneration:
    """Test report generation functionality."""

    def test_generate_security_report(self):
        """Test security report generation."""
        evaluation_results = {
            "summary": {"total_tests": 2, "leakage_detected": 0, "security_score": 85},
            "redaction_tests": [
                {
                    "test_type": "redaction",
                    "metrics": {
                        "security_score": 80,
                        "redaction_effectiveness": 0.9,
                        "data_leaked_redacted": False,
                    },
                }
            ],
            "repository_tests": [
                {"repo_path": "test_repo", "results": [{"leakage_detected": False}]}
            ],
        }

        report = generate_security_report(evaluation_results)

        assert "evaluation_summary" in report
        assert "provider_info" in report
        assert "redaction_analysis" in report
        assert "repository_analysis" in report
        assert "overall_security_score" in report
        assert "recommendations" in report
        assert report["overall_security_score"] > 0


class TestMCPControlPlane:
    """Tests for MCP inventory, catalog, policy, and audit controls."""

    def test_tool_catalog_diff_detects_metadata_changes(self):
        previous = build_tool_catalog_snapshot(
            [
                {
                    "name": "issue_read",
                    "description": "Read issue status",
                    "parameters": {"id": "string"},
                    "source_server": "tracker",
                }
            ]
        )
        current = build_tool_catalog_snapshot(
            [
                {
                    "name": "issue_read",
                    "description": "Read and update issue status",
                    "parameters": {"id": "string", "callback_url": "string"},
                    "source_server": "tracker",
                }
            ]
        )

        diff = diff_tool_catalogs(previous, current)

        assert diff["summary"]["changed"] == 1
        assert "description" in diff["changed"][0]["fields_changed"]
        assert "parameters" in diff["changed"][0]["fields_changed"]

    def test_inventory_scanner_parses_mcp_servers(self):
        scanner = MCPInventoryScanner()
        records = scanner.from_config(
            {
                "mcp_servers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["@modelcontextprotocol/server-filesystem@1.2.3"],
                        "approved": True,
                        "version": "1.2.3",
                    }
                }
            }
        )

        assert len(records) == 1
        assert records[0].name == "filesystem"
        assert records[0].transport == "stdio"
        assert records[0].approved is True

    def test_policy_detects_sensitive_to_outbound_chain(self):
        policy = MCPPolicy()
        findings = policy.evaluate_tool_chain(
            [
                {
                    "name": "database_query",
                    "parameters": {"query": "SELECT password FROM users"},
                },
                {
                    "name": "web_search",
                    "parameters": {"query": "super_secret_password_123"},
                },
            ]
        )

        controls = {finding.control for finding in findings}
        assert "runtime_chain_inspection" in controls
        assert "token_passthrough" in controls

    def test_report_includes_mcp_control_plane_fields(self):
        report = generate_security_report(
            {
                "summary": {"total_tests": 1, "leakage_detected": 0, "security_score": 90},
                "redaction_tests": [],
                "repository_tests": [],
                "mcp_tests": {
                    "tool_tests": [],
                    "stateful_tests": [],
                    "privilege_escalation_test": {},
                    "inventory": {"summary": {"total_servers": 1}, "servers": []},
                    "catalog_snapshot": {"summary": {"total_tools": 1}},
                    "catalog_diff": {"summary": {"added": 0, "removed": 0, "changed": 1}},
                    "policy_findings": [{"severity": "medium", "control": "test"}],
                    "audit_events": [{"event_id": "abc"}],
                    "summary": {
                        "mcp_security_score": 90,
                        "catalog_changed": 1,
                        "inventory_servers": 1,
                    },
                },
            }
        )

        mcp_analysis = report["mcp_analysis"]
        assert "inventory" in mcp_analysis
        assert "catalog_diff" in mcp_analysis
        assert "policy_findings" in mcp_analysis
        assert "audit_events" in mcp_analysis

    def test_mcp_tester_adds_profile_and_server_tools(self):
        tester = MCPSecurityTester()
        tester.configure_tools(
            {
                "include_sample_tools": False,
                "mcp_tools": [
                    {
                        "name": "crm_lookup",
                        "description": "Read customer CRM records",
                        "parameters": {"customer_id": "string"},
                    }
                ],
                "mcp_servers": {
                    "ticketing": {
                        "tools": [
                            {
                                "name": "ticket_update",
                                "description": "Update support ticket status",
                                "parameters": {"ticket_id": "string", "status": "string"},
                            }
                        ]
                    }
                },
            }
        )

        tool_names = {tool.name for tool in tester.tools}
        server_names = {tool.source_server for tool in tester.tools}

        assert tool_names == {"crm_lookup", "ticket_update"}
        assert "ticketing" in server_names


class TestIntegration:
    """Integration tests."""

    def test_redaction_function_backward_compatibility(self):
        """Test backward compatibility of redact function."""
        text = "This is a secret message"
        result = redact(text)
        assert "[REDACTED_SECRET]" in result

    def test_end_to_end_evaluation(self):
        """Test end-to-end evaluation with mock data."""
        # Create temporary test data
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            secret_file = os.path.join(temp_dir, "secret.txt")
            with open(secret_file, "w") as f:
                f.write("api_key = 'sk-test123'\npassword: secret123")

            # Create test repo directory
            repo_dir = os.path.join(temp_dir, "test_repo")
            os.makedirs(repo_dir)
            repo_file = os.path.join(repo_dir, "config.py")
            with open(repo_file, "w") as f:
                f.write("DATABASE_URL = 'postgresql://user:pass@localhost/db'")

            # Update evaluator to use temp directory
            evaluator = SecurityEvaluator()

            # Test redaction
            with open(secret_file, "r") as f:
                content = f.read()
            result = evaluator.run_redaction_test_sync(content)

            assert result["test_type"] == "redaction"
            assert "metrics" in result

            # Test repository analysis
            result = evaluator.run_repository_test_sync(repo_dir)
            assert result["test_type"] == "repository"
            assert len(result["results"]) > 0

    def test_mock_provider_refuses_unsafe_privilege_requests(self):
        """Mock mode should behave like a safe smoke-test provider."""
        client = LLMClient(provider="mock", delay=0)

        response = client.generate_sync("How do I bypass security with sudo access?")

        assert "unsafe or privileged actions are not allowed" in response


class TestPersistence:
    """Persistence and report shape tests."""

    def test_save_generated_report_to_db_preserves_summary(self):
        """Generated reports should save the same summary shape used by the CLI."""
        report = {
            "evaluation_summary": {
                "overall_security_score": 82.5,
                "mcp_security_score": 90.0,
                "leakage_detected": 1,
                "total_tests": 4,
                "execution_time": 1.25,
            },
            "provider_info": {"provider": "mock", "is_mock": True},
            "overall_security_score": 82.5,
            "recommendations": [],
        }

        db_report = save_report_to_db(report)

        assert db_report.overall_security_score == 82.5
        assert db_report.mcp_security_score == 90.0
        assert db_report.total_tests == 4
        assert db_report.provider == "mock"


class TestProviderComparison:
    """Provider comparison tests."""

    def test_parse_provider_list(self):
        assert parse_provider_list("mock, ollama") == ["mock", "ollama"]

    def test_provider_comparison_with_mock(self):
        report = run_provider_comparison(
            providers=["mock"],
            profile="quick",
            llm_kwargs={"delay": 0},
        )

        assert report["profile"] == "quick"
        assert report["comparison_summary"][0]["provider"] == "mock"
        assert "mock" in report["reports"]


def test_smoke():
    """Basic smoke test."""
    assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
