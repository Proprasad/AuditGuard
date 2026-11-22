"""Prometheus metrics (low-cardinality labels only: mode, disposition, status)."""
from prometheus_client import Counter, Histogram

INVESTIGATIONS_TOTAL = Counter("auditguard_investigations_total", "Total investigations completed to human gate", ["mode", "disposition"])
INVESTIGATION_DURATION = Histogram("auditguard_investigation_duration_seconds", "Investigation duration in seconds", ["mode"])
TOOL_CALLS_TOTAL = Counter("auditguard_tool_calls_total", "Total MCP tool calls executed", ["mode"])
CITATIONS_VERIFIED = Counter("auditguard_citations_verified_total", "Total regulatory citations verified", ["status"])
