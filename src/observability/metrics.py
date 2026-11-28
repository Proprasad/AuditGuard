"""
Prometheus metrics for MCP tool calls and LLM calls (audit AG-09).

Labels are bounded: 4 servers x 12 tools, MCP error codes, configured model slugs, LLM mode and a status.
Investigation-level metrics stay in `src/api/metrics.py`.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

MCP_TOOL_CALLS_TOTAL = Counter(
    "auditguard_mcp_tool_calls_total",
    "MCP tool calls by outcome (`ok` or the error code)",
    ["server", "tool", "status"],
)
MCP_TOOL_DURATION = Histogram(
    "auditguard_mcp_tool_duration_seconds", "MCP tool call latency in seconds", ["server", "tool"]
)
LLM_CALLS_TOTAL = Counter("auditguard_llm_calls_total", "LLM chat calls", ["model", "mode", "status"])
LLM_CALL_DURATION = Histogram("auditguard_llm_call_duration_seconds", "LLM chat call latency", ["model", "mode"])
LLM_TOKENS_TOTAL = Counter("auditguard_llm_tokens_total", "LLM tokens by kind", ["model", "kind"])
LLM_COST_USD_TOTAL = Counter("auditguard_llm_cost_usd_total", "Recorded LLM cost in USD", ["model"])
