"""Bài tập 5.2 (nâng cao) — test đảm bảo caller không hợp lệ không mở được MCP."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from lab_utils.governance.audit import AuditLogger
from lab_utils.governance.guard import GovernanceGuard


@pytest.fixture()
def guard() -> GovernanceGuard:
    audit_path = Path(tempfile.mktemp(suffix=".jsonl"))
    return GovernanceGuard(audit=AuditLogger(log_path=audit_path))


def test_unregistered_caller_cannot_open_mcp_connection(guard: GovernanceGuard) -> None:
    decision = guard.authorize_mcp_connection("rogue_agent")
    assert decision.blocked
    assert "rogue_agent" in decision.reason


def test_orchestrator_can_open_mcp_connection(guard: GovernanceGuard) -> None:
    decision = guard.authorize_mcp_connection("orchestrator")
    assert decision.allowed
    assert "count_words" in decision.metadata["allowed_tools"]


def test_unregistered_caller_cannot_call_mcp_tool(guard: GovernanceGuard) -> None:
    decision = guard.authorize_mcp_tool("rogue_agent", "search_documents", {"query": "MCP"})
    assert decision.blocked


def test_search_documents_blocks_password_keyword(guard: GovernanceGuard) -> None:
    decision = guard.authorize_mcp_tool(
        "orchestrator", "search_documents", {"query": "reset my password"}
    )
    assert decision.blocked
    assert "password" in decision.reason


def test_search_documents_allows_normal_query(guard: GovernanceGuard) -> None:
    decision = guard.authorize_mcp_tool(
        "orchestrator", "search_documents", {"query": "MCP transport options"}
    )
    assert decision.allowed


def test_sql_query_blocks_ddl(guard: GovernanceGuard) -> None:
    decision = guard.authorize_mcp_tool(
        "orchestrator", "sql_query", {"sql": "DROP TABLE agent_metrics"}
    )
    assert decision.blocked


def test_sql_query_allows_select_on_agent_metrics(guard: GovernanceGuard) -> None:
    decision = guard.authorize_mcp_tool(
        "orchestrator", "sql_query", {"sql": "SELECT * FROM agent_metrics"}
    )
    assert decision.allowed
