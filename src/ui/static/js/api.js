/**
 * AuditGuard Centralized API & SSE Stream Client
 * Ensures clean subscription lifecycle (zero EventSource leaks) and strict backend verification.
 */
export class AuditGuardAPI {
  constructor() {
    this.activeAbort = null;
    this.token = window.sessionStorage.getItem("ag_token") || "";
  }

  isAuthenticated() {
    return Boolean(this.token);
  }

  clearToken() {
    this.token = "";
    window.sessionStorage.removeItem("ag_token");
  }

  async login(username, password) {
    const data = await this._json("/api/v1/auth/token", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    this.token = data.access_token;
    window.sessionStorage.setItem("ag_token", this.token);
    return data;
  }

  _authHeaders() {
    return this.token ? { Authorization: `Bearer ${this.token}` } : {};
  }

  closeStream() {
    if (this.activeAbort) {
      this.activeAbort.abort();
      this.activeAbort = null;
    }
  }

  static _detailMessage(data, status) {
    const d = data.detail;
    if (typeof d === "string") return d;
    if (d && typeof d === "object" && !Array.isArray(d)) return `${d.code || "ERROR"}: ${d.message || ""}`;
    if (Array.isArray(d)) return d.map((e) => `${(e.loc || []).join(".")}: ${e.msg}`).join("; ");
    return `HTTP ${status}`;
  }

  async _json(url, options = {}) {
    const res = await fetch(url, {
      ...options,
      headers: { "Content-Type": "application/json", ...this._authHeaders(), ...(options.headers || {}) },
    });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    if (!res.ok) {
      if (res.status === 401 && url !== "/api/v1/auth/token") this.clearToken();
      const err = new Error(AuditGuardAPI._detailMessage(data, res.status));
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
   * Subscribe (read-only) to the durable event log of an investigation via authenticated fetch streaming.
   */
  streamInvestigation(threadId, _alertId, _mode, handlers = {}) {
    this.closeStream();
    const ctrl = new AbortController();
    this.activeAbort = ctrl;
    const terminal = new Set(["interrupt_required", "verification_failed", "completed", "error"]);

    const dispatch = (name, raw) => {
      let parsed;
      try {
        parsed = JSON.parse(raw);
      } catch (err) {
        console.error("SSE parse error:", err);
        return false;
      }
      if (handlers.onEvent) handlers.onEvent(name, parsed);
      if (handlers[name]) handlers[name](parsed);
      return terminal.has(name);
    };

    (async () => {
      try {
        const res = await fetch(`/api/v1/investigations/${encodeURIComponent(threadId)}/stream`, {
          headers: this._authHeaders(),
          signal: ctrl.signal,
        });
        if (!res.ok) {
          if (res.status === 401) this.clearToken();
          if (handlers.error) handlers.error({ error: `Stream failed (HTTP ${res.status})` });
          return;
        }
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let idx;
          while ((idx = buf.indexOf("\n\n")) >= 0) {
            const block = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            let name = "message";
            let data = "";
            for (const line of block.split("\n")) {
              if (line.startsWith("event:")) name = line.slice(6).trim();
              else if (line.startsWith("data:")) data += line.slice(5).trim();
            }
            if (data && dispatch(name, data)) {
              this.closeStream();
              return;
            }
          }
        }
      } catch (err) {
        if (err.name !== "AbortError" && handlers.error) handlers.error({ error: err.message });
      }
    })();
    return ctrl;
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
