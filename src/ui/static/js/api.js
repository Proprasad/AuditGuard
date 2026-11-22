/**
 * AuditGuard Centralized API & SSE Stream Client
 * Ensures clean subscription lifecycle (zero EventSource leaks) and strict backend verification.
 */
export class AuditGuardAPI {
  constructor() {
    this.activeEventSource = null;
  }

  closeStream() {
    if (this.activeEventSource) {
      this.activeEventSource.close();
      this.activeEventSource = null;
    }
  }

  async _json(url, options = {}) {
    const res = await fetch(url, {
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
    });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    if (!res.ok) {
      const err = new Error(data.detail || `HTTP ${res.status}`);
      err.status = res.status;
      err.payload = data;
      throw err;
    }
    return data;
  }

  getHealth() {
    return this._json("/health");
  }

  getAlerts(limit = 50) {
    return this._json(`/api/v1/alerts?limit=${limit}`);
  }

  getCases(limit = 50) {
    return this._json(`/api/v1/cases?limit=${limit}`);
  }

  getCustomers(limit = 100) {
    return this._json(`/api/v1/customers?limit=${limit}`);
  }

  getRegulations(query = "") {
    const qs = query ? `?q=${encodeURIComponent(query)}&top_k=12` : "";
    return this._json(`/api/v1/regulations${qs}`);
  }

  getAuditLogs(limit = 60) {
    return this._json(`/api/v1/audit-logs?limit=${limit}`);
  }

  getAnalytics() {
    return this._json("/api/v1/analytics");
  }

  getConfigInfo() {
    return this._json("/api/v1/config-info");
  }

  updateLlmConfig(body) {
    return this._json("/api/v1/config/llm", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  testLlmConnection(model = "") {
    const qs = model ? `?model=${encodeURIComponent(model)}` : "";
    return this._json(`/api/v1/config/llm/test${qs}`, { method: "POST" });
  }

  issueToken(username = "analyst_04", role = "tier2_analyst") {
    return this._json("/api/v1/auth/token", {
      method: "POST",
      body: JSON.stringify({ username, role }),
    });
  }

  registerInvestigation(alertObj, mode) {
    return this._json("/api/v1/investigations", {
      method: "POST",
      body: JSON.stringify({
        alert_id: alertObj.alert_id,
        mode,
      }),
    });
  }

  getThreadState(threadId) {
    return this._json(`/api/v1/investigations/${encodeURIComponent(threadId)}/state`);
  }

  submitDecision(threadId, body) {
    return this._json(`/api/v1/investigations/${encodeURIComponent(threadId)}/decision`, {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  forgetCustomer(customerId) {
    return this._json(`/api/v1/memory/${encodeURIComponent(customerId)}`, {
      method: "DELETE",
    });
  }

  /**
   * Stream live SSE events for an investigation, cleaning up any prior stream first.
   */
  streamInvestigation(threadId, alertId, mode, handlers = {}) {
    this.closeStream();
    const url = `/api/v1/investigations/${encodeURIComponent(threadId)}/stream?alert_id=${encodeURIComponent(alertId)}&mode=${encodeURIComponent(mode)}`;
    const es = new EventSource(url);
    this.activeEventSource = es;

    const eventNames = [
      "started",
      "plan_updated",
      "agent_updated",
      "tool_called",
      "replan_triggered",
      "verification_completed",
      "interrupt_required",
      "completed",
      "error",
    ];

    for (const evName of eventNames) {
      es.addEventListener(evName, (evt) => {
        if (!evt.data) return;
        try {
          const parsed = JSON.parse(evt.data);
          if (handlers.onEvent) handlers.onEvent(evName, parsed);
          if (handlers[evName]) handlers[evName](parsed);
          if (evName === "interrupt_required" || evName === "completed" || evName === "error") {
            this.closeStream();
          }
        } catch (err) {
          console.error("SSE parse error:", err);
        }
      });
    }

    es.onerror = () => {
      this.closeStream();
    };

    return es;
  }
}

export function formatINR(value) {
  const num = Number(value || 0);
  if (Number.isNaN(num)) return "₹0";
  return "₹" + num.toLocaleString("en-IN", { maximumFractionDigits: 0 });
}

export function formatINRCompact(value) {
  const num = Number(value || 0);
  if (num >= 10000000) return `₹${(num / 10000000).toFixed(2)}Cr`;
  if (num >= 100000) return `₹${(num / 100000).toFixed(1)}L`;
  if (num >= 1000) return `₹${(num / 1000).toFixed(0)}K`;
  return `₹${num.toFixed(0)}`;
}
