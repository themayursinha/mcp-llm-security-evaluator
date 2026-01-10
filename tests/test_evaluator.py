#!/usr/bin/env python3
"""
Comprehensive test suite for MCP LLM Security Evaluator
"""

import pytest
import os
import tempfile
import json
from unittest.mock import Mock, patch

# Add project root to path
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from evaluator.runner import SecurityEvaluator
from evaluator.metrics import calculate_security_metrics, generate_security_report
from app.security.redaction import DataRedactor, redact, detect_sensitive_data


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
        assert metrics["data_leaked_original"] == True
        assert metrics["data_leaked_redacted"] == False
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
        assert evaluator._detect_data_leakage(original, response) == True

        # Test without leakage
        response_clean = "I see there's an API key but it's redacted"
        assert evaluator._detect_data_leakage(original, response_clean) == False

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
        assert "redaction_analysis" in report
        assert "repository_analysis" in report
        assert "overall_security_score" in report
        assert "recommendations" in report
        assert report["overall_security_score"] > 0


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


def test_smoke():
    """Basic smoke test."""
    assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
