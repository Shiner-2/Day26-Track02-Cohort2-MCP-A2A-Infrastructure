import tempfile
import unittest
from pathlib import Path

from lab_utils.governance import AuditLogger, GovernanceGuard


class GovernancePolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        audit = AuditLogger(Path(self.tmpdir.name) / "audit.jsonl")
        self.guard = GovernanceGuard(audit=audit)

    def test_unknown_actor_cannot_open_mcp_connection(self):
        decision = self.guard.authorize_mcp_connection("search_agent")

        self.assertTrue(decision.blocked)
        self.assertIn("research-tools", decision.resource)

    def test_search_documents_blocks_password_keyword(self):
        decision = self.guard.authorize_mcp_tool(
            "orchestrator",
            "search_documents",
            {"query": "find password reset notes"},
            trace_id="test-trace",
        )

        self.assertTrue(decision.blocked)
        self.assertIn("password", decision.reason)

    def test_orchestrator_can_dispatch_to_synthesis_agent_with_trace(self):
        decision = self.guard.authorize_a2a_dispatch(
            "orchestrator",
            "synthesis_agent",
            trace_id="test-trace",
        )

        self.assertTrue(decision.allowed)

    def test_sql_with_pii_requires_hitl(self):
        decision = self.guard.authorize_mcp_tool(
            "orchestrator",
            "sql_query",
            {"sql": "SELECT * FROM agent_metrics WHERE email = 'user@vinuni.edu.vn'"},
            trace_id="test-trace",
        )

        self.assertTrue(decision.needs_approval)


if __name__ == "__main__":
    unittest.main()
