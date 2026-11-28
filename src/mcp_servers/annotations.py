"""MCP tool annotations (spec hints) shared by the four AuditGuard servers; listed in docs/tool_catalogue.md."""

from __future__ import annotations

from mcp.types import ToolAnnotations

# Reads and pure computations over the bank snapshot, graph engine and regulatory corpus.
READ_ONLY_TOOL = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
# Draft worksheet upsert: writes, but re-sending the same draft has no further effect.
DRAFT_WRITE_TOOL = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)
# Final disposition commit: irreversible and gated by a single-use human approval token.
COMMIT_WRITE_TOOL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False
)
