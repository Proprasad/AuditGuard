/**
 * AuditGuard Main Workbench Controller (`app.js`)
 * Coordinates all 9 Sidebar Views, 5 Center Workspace Tabs, Live SSE Trace Streaming,
 * Interactive Transaction Graph, Decimal Charts, Evidence Inspector, and SHA-256 Human Gate.
 */
import { AuditGuardAPI, formatINR } from "./api.js?v=1.2.1";
import { TransactionGraphView } from "./graph-view.js?v=1.2.1";
import { renderDonutChart, renderTimelineChart } from "./charts.js?v=1.2.1";

const api = new AuditGuardAPI();

const state = {
  alerts: [],
  selectedAlert: null,
  mode: "c2_multi",
  activeNav: "investigation",
  activeCenterTab: "graph",
  threadId: null,
  worksheetId: null,
  payloadHash: null,
  approvedHash: null,
  approvalToken: null,
  invState: null,
  invStatus: "idle",
  runSeq: 0,
  tracePaused: false,
  traceEvents: [],
  regulationsCache: {},
};

let graphView = null;

function esc(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

function modeLabel(mode) {
  if (mode === "c2_multi") return "C2 Multi-Agent";
  if (mode === "c1_single") return "C1 Single-Agent";
  return "C0 Fixed Baseline";
}

function dispositionMeta(disp) {
  const d = String(disp || "pending").toLowerCase();
  if (d === "escalate_str") {
    return { code: "ESCALATE_STR", subtitle: "Escalate for STR Review", cls: "disp-escalate" };
  }
  if (d === "close_benign") {
    return { code: "CLOSE_BENIGN", subtitle: "Close as Verified Benign", cls: "disp-benign" };
  }
  if (d === "request_info") {
    return { code: "REQUEST_INFO", subtitle: "Insufficient Data — Request Logs", cls: "disp-info" };
  }
  if (d === "rejected") {
    return { code: "REJECTED", subtitle: "Rejected to Manual Queue", cls: "disp-escalate" };
  }
  return { code: "PENDING", subtitle: "Awaiting Investigation", cls: "" };
}

/* ── Authentication (JWT; credentials come from the server .env seeded accounts) ─ */
function ensureLogin() {
  if (api.isAuthenticated()) return Promise.resolve();
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.style.cssText = "position:fixed;inset:0;background:rgba(2,6,23,.92);z-index:9999;display:flex;align-items:center;justify-content:center;";
    overlay.innerHTML = `
      <form id="loginForm" style="background:#0f172a;border:1px solid #334155;border-radius:12px;padding:28px;width:340px;color:#e2e8f0;font-family:inherit;">
        <h3 style="margin:0 0 14px;">AuditGuard sign-in</h3>
        <input id="loginUser" placeholder="username" autocomplete="username" style="width:100%;margin-bottom:10px;padding:8px;" />
        <input id="loginPass" type="password" placeholder="password" autocomplete="current-password" style="width:100%;margin-bottom:10px;padding:8px;" />
        <div id="loginErr" style="color:#fca5a5;font-size:.85rem;min-height:1.2em;margin-bottom:8px;"></div>
        <button type="submit" style="width:100%;padding:9px;cursor:pointer;">Sign in</button>
      </form>`;
    document.body.appendChild(overlay);
    overlay.querySelector("#loginForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await api.login(overlay.querySelector("#loginUser").value.trim(), overlay.querySelector("#loginPass").value);
        overlay.remove();
        resolve();
      } catch (err) {
        overlay.querySelector("#loginErr").textContent = err.message;
      }
    });
  });
}

/* ── Initialization ──────────────────────────────────────────────────────── */
async function init() {
  graphView = new TransactionGraphView(
    document.getElementById("graphViewport"),
    document.getElementById("graphTooltip"),
    {
      onSelectNode: (node) => renderNodeInspector(node),
      onSelectEdge: (edge) => renderEdgeInspector(edge),
    }
  );

  bindUIEvents();
  await ensureLogin();
  await refreshHealthAndCatalog();

  // Auto-load showcase alert ALT-2026-0412 (or first alert) on boot so the workbench is alive immediately
  if (state.alerts.length > 0) {
    const preferred = state.alerts[0];
    document.getElementById("headerAlertSelect").value = preferred.alert_id;
    state.selectedAlert = preferred;
    await runLiveInvestigation();
  }
}

function updateTopbarLlmPill(llm) {
  const pill = document.getElementById("llmStatusPill");
  if (!pill || !llm) return;
  if (llm.llm_enabled) {
    const shortM = String(llm.c1_and_specialist_model || "live").split("/").pop();
    pill.style.background = "rgba(16,185,129,0.14)";
    pill.style.borderColor = "rgba(16,185,129,0.45)";
    pill.style.color = "#6ee7b7";
    pill.innerHTML = `<span class="health-dot"></span> LLM: Live (${esc(shortM)})`;
  } else {
    pill.style.background = "rgba(245,158,11,0.14)";
    pill.style.borderColor = "rgba(245,158,11,0.45)";
    pill.style.color = "#fcd34d";
    pill.innerHTML = `<span class="health-dot" style="background:#f59e0b;box-shadow:none;"></span> LLM: Offline ($0)`;
  }
}

function syncAlertCatalog(alerts, preferredAlertId = null) {
  state.alerts = alerts || [];
  const sel = document.getElementById("headerAlertSelect");
  const targetId = preferredAlertId || state.selectedAlert?.alert_id || sel.value;
  sel.innerHTML = state.alerts
    .map(
      (a) =>
        `<option value="${esc(a.alert_id)}">${esc(a.alert_id)} · ${formatINR(a.initial_amount_inr)} (${esc(a.full_name || a.seed_account_id)}) [${esc(a.status)}]</option>`
    )
    .join("");
  if (targetId && state.alerts.some((a) => a.alert_id === targetId)) {
    sel.value = targetId;
  }
}

async function refreshHealthAndCatalog() {
  try {
    const [health, alertData, regData, cfgData] = await Promise.all([
      api.getHealth(),
      api.getAlerts(60),
      api.getRegulations(),
      api.getConfigInfo(),
    ]);

    const hp = document.getElementById("healthPill");
    hp.innerHTML = `<span class="health-dot"></span> System Healthy`;
    document.getElementById("sidebarVersion").textContent = `v${health.version || "1.0.0"}`;
    updateTopbarLlmPill(cfgData.llm);

    const openCount = alertData.open_count ?? (alertData.alerts || []).length;
    document.getElementById("navAlertBadge").textContent = openCount;
    document.getElementById("topNotifBadge").textContent = openCount;

    for (const c of regData.clauses || []) {
      state.regulationsCache[c.clause_id] = c;
    }

    syncAlertCatalog(alertData.alerts || []);
  } catch (err) {
    document.getElementById("healthPill").innerHTML = `<span class="health-dot" style="background:#ef4444;box-shadow:none;"></span> Offline`;
    console.error("Bootstrap error:", err);
  }
}

/* ── Event Bindings ──────────────────────────────────────────────────────── */
function bindUIEvents() {
  // Topbar LLM Status Pill -> Opens Settings
  const llmPill = document.getElementById("llmStatusPill");
  if (llmPill) {
    llmPill.addEventListener("click", () => switchSidebarView("settings"));
  }

  // Left Sidebar Navigation
  document.querySelectorAll(".nav-item[data-nav]").forEach((item) => {
    item.addEventListener("click", () => switchSidebarView(item.getAttribute("data-nav")));
  });

  // Sidebar collapse button
  document.getElementById("btnCollapseSidebar").addEventListener("click", () => {
    document.getElementById("appShell").classList.toggle("sidebar-collapsed");
    setTimeout(() => graphView && graphView.fitToScreen(), 180);
  });

  // Header controls
  document.getElementById("headerAlertSelect").addEventListener("change", (e) => {
    const found = state.alerts.find((a) => a.alert_id === e.target.value);
    if (found) {
      state.selectedAlert = found;
      runLiveInvestigation();
    }
  });

  document.getElementById("headerModeSelect").addEventListener("change", (e) => {
    state.mode = e.target.value;
    document.getElementById("sidebarModeLabel").textContent = modeLabel(state.mode);
    runLiveInvestigation();
  });

  document.getElementById("btnRunInvestigation").addEventListener("click", () => runLiveInvestigation());

  document.getElementById("btnExportReport").addEventListener("click", () => {
    if (!state.threadId) return;
    window.open(`/api/v1/investigations/${encodeURIComponent(state.threadId)}/export`, "_blank");
  });

  document.getElementById("btnBackToQueue").addEventListener("click", () => switchSidebarView("alerts"));

  // Topbar Help & Swagger
  document.getElementById("btnHelpModal").addEventListener("click", () => {
    openModal(
      "AuditGuard Architecture & Verification Reference",
      `<p style="color:#cbd5e1;"><strong>Primary Principle:</strong> The detector proposes. The agent investigates. The evidence supports. The human decides.</p>
       <ul style="color:#cbd5e1;padding-left:18px;line-height:1.6;">
         <li><strong>Zero LLM Arithmetic:</strong> All INR outflows, consolidations, and retention percentages are calculated in Python <code>decimal.Decimal</code>.</li>
         <li><strong>Bounded Replanning (Challenge A):</strong> Expands <code>time_window_days</code> [1..30], <code>max_hops</code> [2..5], and <code>amount_tolerance</code> [0.01..0.25] when initial 7-day scans miss staggered/layered legs.</li>
         <li><strong>Cryptographic Human Gate (Challenge B):</strong> Dispositions pause behind <code>interrupt()</code> bound to a canonical <code>SHA-256</code> hash and single-use HMAC token. Any edit invalidates prior approval.</li>
       </ul>
       <p><a href="/api/docs" target="_blank" style="color:#38bdf8;">Open Swagger / OpenAPI Specification (/api/docs) ↗</a></p>`
    );
  });

  // Center Workspace Tabs
  document.querySelectorAll(".tab-btn[data-tab]").forEach((btn) => {
    btn.addEventListener("click", () => switchCenterTab(btn.getAttribute("data-tab")));
  });

  // Graph Toolbar Controls
  document.getElementById("graphLayoutSelect").addEventListener("change", (e) => {
    graphView.setLayout(e.target.value);
  });
  document.getElementById("graphPathSelect").addEventListener("change", (e) => {
    graphView.setFocusedPath(e.target.value);
  });
  document.getElementById("graphSearchInput").addEventListener("input", (e) => {
    graphView.setSearchFilter(e.target.value);
  });
  document.getElementById("btnGraphZoomIn").addEventListener("click", () => graphView.zoomBy(1.18));
  document.getElementById("btnGraphZoomOut").addEventListener("click", () => graphView.zoomBy(0.84));
  document.getElementById("btnGraphFit").addEventListener("click", () => graphView.fitToScreen());
  document.getElementById("btnGraphReset").addEventListener("click", () => {
    document.getElementById("graphSearchInput").value = "";
    document.getElementById("graphPathSelect").value = "all";
    graphView.setSearchFilter("");
    graphView.setFocusedPath("all");
    graphView.setLayout(document.getElementById("graphLayoutSelect").value);
    renderDefaultAlertContext();
  });

  // Live Trace Pause/Resume
  document.getElementById("btnToggleTracePause").addEventListener("click", () => {
    state.tracePaused = !state.tracePaused;
    const pill = document.getElementById("btnToggleTracePause");
    pill.textContent = state.tracePaused ? "Paused" : "Live";
    pill.style.background = state.tracePaused ? "rgba(245,158,11,0.2)" : "rgba(16,185,129,0.16)";
    pill.style.color = state.tracePaused ? "#fcd34d" : "#34d399";
  });

  // Context Reset Link
  document.getElementById("btnResetContext").addEventListener("click", (e) => {
    e.preventDefault();
    renderDefaultAlertContext();
  });

  // Human Approval Gate Actions
  document.getElementById("btnApproveCommit").addEventListener("click", () => handleDecision("approve"));
  document.getElementById("btnToggleEdit").addEventListener("click", () => toggleEditDrawer());
  document.getElementById("btnSubmitEdit").addEventListener("click", () => handleDecision("edit"));
  document.getElementById("btnRejectDisp").addEventListener("click", () => handleDecision("reject"));

  // Modal Close
  document.getElementById("btnCloseModal").addEventListener("click", closeModal);
  document.getElementById("modalBackdrop").addEventListener("click", (e) => {
    if (e.target.id === "modalBackdrop") closeModal();
  });
}

/* ── Live Investigation Execution (SSE) ──────────────────────────────────── */
function resetInvestigationWorkspace() {
  api.closeStream();
  closeModal();

  const alertObj = state.selectedAlert || {};
  const aid = alertObj.alert_id || "selected alert";

  state.threadId = null;
  state.worksheetId = null;
  state.payloadHash = null;
  state.approvedHash = null;
  state.approvalToken = null;
  state.invState = null;
  state.invStatus = "running";
  state.traceEvents = [];

  // KPI ribbon reset
  document.getElementById("kpiRiskCard").className = "kpi-card";
  document.getElementById("kpiRiskValue").textContent = "--%";
  const riskBadge = document.getElementById("kpiRiskBadge");
  riskBadge.className = "tag-badge tag-info";
  riskBadge.textContent = "Running";
  document.getElementById("kpiTotalFlow").textContent = formatINR(alertObj.initial_amount_inr || 0);
  document.getElementById("kpiPathsCount").textContent = "0";
  document.getElementById("kpiMaxHops").textContent = "0";
  document.getElementById("kpiAccountsCount").textContent = "0";
  document.getElementById("kpiDispositionCard").className = "kpi-card kpi-disposition";
  document.getElementById("kpiDispValue").textContent = "RUNNING";
  document.getElementById("kpiDispSub").textContent = `Investigating ${aid}`;

  // Left column reset
  document.getElementById("traceStreamBox").innerHTML = "";
  renderRunningSkeleton();

  // Center graph, charts, findings & secondary tabs reset
  const patternBadge = document.getElementById("graphPatternBadge");
  patternBadge.className = "tag-badge tag-info";
  patternBadge.textContent = "Analyzing...";
  document.getElementById("graphSearchInput").value = "";
  document.getElementById("graphPathSelect").innerHTML = `<option value="all">All Paths</option>`;
  document.getElementById("legSourceCount").textContent = "Source (0)";
  document.getElementById("legInterCount").textContent = "Intermediary (0)";
  document.getElementById("legDestCount").textContent = "Destination (0)";
  if (graphView) graphView.clear(`Investigating ${aid}...`);

  document.getElementById("donutChartBox").innerHTML =
    `<div style="color:#7c8db0;font-size:12px;padding:24px 0;text-align:center;">Computing flow summary...</div>`;
  document.getElementById("timelineChartBox").innerHTML =
    `<div style="color:#7c8db0;font-size:12px;padding:24px 0;text-align:center;">Building flow timeline...</div>`;
  document.getElementById("keyFindingsGrid").innerHTML =
    `<div style="color:#7c8db0;font-size:12px;">Running investigation for ${esc(aid)}...</div>`;
  if (state.activeCenterTab !== "graph") {
    document.getElementById("centerDeepDivePanel").innerHTML =
      `<div style="color:#7c8db0;font-size:12.5px;padding:12px 0;">Running ${esc(modeLabel(state.mode))} investigation for <code>${esc(aid)}</code>...</div>`;
  }

  // Right column reset (new alert summary, hypotheses, citations & approval gate)
  renderDefaultAlertContext();
  document.getElementById("hypothesesBox").innerHTML =
    `<div style="color:#7c8db0;font-size:11.5px;">Evaluating competing hypotheses...</div>`;
  document.getElementById("citationsCountBadge").textContent = "0";
  document.getElementById("citationsBox").innerHTML = "";
  document.getElementById("approvalBanner").className = "approval-banner";
  document.getElementById("gateDispCode").textContent = "RUNNING";
  document.getElementById("gateDispSub").textContent = `Investigating ${aid}`;
  document.getElementById("gateConfidence").textContent = "--%";
  document.getElementById("gateHashBox").textContent = "SHA-256: -";
  document.getElementById("editRationaleInput").value = "";
  document.getElementById("analystNotesInput").value = "";
  document.getElementById("gateFeedback").style.display = "none";
  document.getElementById("editDrawer").style.display = "none";
  document.getElementById("btnApproveCommit").disabled = true;
  document.getElementById("btnToggleEdit").disabled = true;
  document.getElementById("btnRejectDisp").disabled = true;
  document.getElementById("btnExportReport").disabled = true;
}

async function runLiveInvestigation() {
  if (!state.selectedAlert && state.alerts.length > 0) {
    state.selectedAlert = state.alerts[0];
  }
  if (!state.selectedAlert) return;

  // Ensure main workspace view is visible
  if (state.activeNav !== "investigation") {
    switchSidebarView("investigation");
  }

  const runSeq = ++state.runSeq;
  const targetAlert = state.selectedAlert;
  const targetMode = state.mode;

  updateHeaderMetadata();
  resetInvestigationWorkspace();

  try {
    const reg = await api.registerInvestigation(targetAlert, targetMode);
    if (runSeq !== state.runSeq) return;

    state.threadId = reg.thread_id;
    state.invStatus = "running";
    document.getElementById("btnExportReport").disabled = false;

    api.streamInvestigation(state.threadId, targetAlert.alert_id, targetMode, {
      onEvent: (evName, payload) => {
        if (runSeq !== state.runSeq) return;
        appendTraceEvent(evName, payload);
      },
      interrupt_required: (data) => {
        if (runSeq !== state.runSeq) return;
        state.worksheetId = data.worksheet_id;
        state.payloadHash = data.payload_hash;
        state.approvedHash = data.approved_hash;
        state.approvalToken = data.approval_token;
        state.invState = data.state;
        state.invStatus = "interrupt_required";
        renderFullInvestigationState();
      },
      verification_failed: (data) => {
        if (runSeq !== state.runSeq) return;
        state.worksheetId = data.worksheet_id;
        state.payloadHash = data.payload_hash;
        state.approvedHash = null;
        state.approvalToken = null;
        state.invState = data.state;
        state.invStatus = "verification_failed";
        renderFullInvestigationState();
        showGateFeedback(data.message || "Verification failed (fail-closed). Edit the rationale to continue.", "danger");
      },
      error: (errData) => {
        if (runSeq !== state.runSeq) return;
        state.invStatus = "error";
        showGateFeedback(`Investigation error: ${errData.error || errData.message || "Unknown"}`, "danger");
      },
    });
  } catch (err) {
    if (runSeq !== state.runSeq) return;
    state.invStatus = "error";
    showGateFeedback(`Failed to start investigation: ${err.message}`, "danger");
  }
}

function updateHeaderMetadata() {
  const a = state.selectedAlert;
  if (!a) return;
  document.getElementById("invSubtitleAlert").textContent = a.alert_id;
  document.getElementById("invSubtitleAmount").textContent = `INR ${Number(a.initial_amount_inr || 0).toLocaleString("en-IN")}`;
  document.getElementById("invSubtitleMode").textContent = `Scatter-Gather (${modeLabel(state.mode)})`;
  document.getElementById("wfModeSubtitle").textContent = modeLabel(state.mode);
  document.getElementById("sidebarModeLabel").textContent = modeLabel(state.mode);
}

function renderRunningSkeleton() {
  document.getElementById("wfStepsList").innerHTML = `
    <div class="wf-step status-running">
      <div class="wf-step-left"><span class="wf-dot running">●</span><span>Running ${esc(modeLabel(state.mode))}...</span></div>
      <span class="wf-dur">live</span>
    </div>
  `;
}

function appendTraceEvent(evName, payload) {
  const ts = String(payload.timestamp || new Date().toISOString()).slice(11, 19);
  const cat = payload.category || evName;
  const msg = payload.message || `${evName} event`;
  state.traceEvents.push({ ts, cat, msg, payload });

  const box = document.getElementById("traceStreamBox");
  const item = document.createElement("div");
  item.className = "trace-item";
  const detailCopy = { ...payload };
  delete detailCopy.state;
  delete detailCopy.worksheet;

  item.innerHTML = `
    <div class="trace-item-head">
      <span class="trace-dot cat-${esc(cat)}"></span>
      <span class="trace-time">${esc(ts)}</span>
      <span class="trace-msg">${esc(msg)}</span>
    </div>
    <div class="trace-detail">${esc(JSON.stringify(detailCopy, null, 2))}</div>
  `;
  item.addEventListener("click", () => item.classList.toggle("expanded"));
  box.appendChild(item);

  if (!state.tracePaused) {
    box.scrollTop = box.scrollHeight;
  }
}

/* ── Render Complete Investigation State ─────────────────────────────────── */
function renderFullInvestigationState() {
  const st = state.invState || {};
  const ws = st.worksheet || {};
  const fs = st.flow_summary || {};
  const hyps = ws.hypotheses || st.active_hypotheses || [];
  const suspHyp = hyps.find((h) => h.label === "suspicious");
  const suspPct = Math.round(Number(suspHyp ? suspHyp.confidence : ws.confidence_score || 0) * 100);

  // 1. KPI Ribbon
  const riskCard = document.getElementById("kpiRiskCard");
  riskCard.className = "kpi-card " + (suspPct >= 65 ? "kpi-risk-high" : suspPct <= 30 ? "kpi-risk-low" : "");
  document.getElementById("kpiRiskValue").textContent = `${suspPct}%`;
  const riskBadge = document.getElementById("kpiRiskBadge");
  if (suspPct >= 65) {
    riskBadge.className = "tag-badge tag-danger";
    riskBadge.textContent = "High Index";
  } else if (suspPct <= 30) {
    riskBadge.className = "tag-badge tag-ok";
    riskBadge.textContent = "Low Index";
  } else {
    riskBadge.className = "tag-badge tag-warn";
    riskBadge.textContent = "Ambiguous";
  }

  document.getElementById("kpiTotalFlow").textContent = formatINR(fs.total_outflow_inr || state.selectedAlert?.initial_amount_inr || 0);
  document.getElementById("kpiPathsCount").textContent = String(fs.paths_detected ?? (ws.candidate_paths || []).length);
  document.getElementById("kpiMaxHops").textContent = String(fs.max_hops ?? 0);
  document.getElementById("kpiAccountsCount").textContent = String(fs.accounts_involved ?? 0);

  const dm = dispositionMeta(state.invStatus === "committed" ? st.human_decision || ws.recommended_disposition : ws.recommended_disposition);
  const dispCard = document.getElementById("kpiDispositionCard");
  dispCard.className = `kpi-card kpi-disposition ${dm.cls}`;
  document.getElementById("kpiDispValue").textContent = dm.code;
  document.getElementById("kpiDispSub").textContent = dm.subtitle;

  // 2. Left Column: Workflow Steps & Specialist Agents
  renderWorkflowTimeline(st.workflow_steps || [], st.agent_runs || []);

  // 3. Center Column: Transaction Network Graph
  const rootAcc =
    st.alert?.root_account || state.selectedAlert?.seed_account_id || st.kyc_profiles?.[0]?.account_id || "";
  const patternBadge = document.getElementById("graphPatternBadge");
  const multiHopCount = (ws.candidate_paths || []).filter((p) => p.hop_count >= 2).length;
  if (dm.code === "CLOSE_BENIGN") {
    patternBadge.className = "tag-badge tag-ok";
    patternBadge.textContent = "Verified Commercial Flow";
  } else if (multiHopCount > 0) {
    patternBadge.className = "tag-badge tag-warn";
    patternBadge.textContent = st.replan_count > 0 ? `Staggered Scatter-Gather (Replan #${st.replan_count})` : "Scatter-Gather Pattern Detected";
  } else {
    patternBadge.className = "tag-badge tag-info";
    patternBadge.textContent = "Incomplete Downstream Trail";
  }

  // Update Legend counts
  document.getElementById("legSourceCount").textContent = `Source (${fs.source_count ?? 1})`;
  document.getElementById("legInterCount").textContent = `Intermediary (${fs.intermediary_count ?? 0})`;
  document.getElementById("legDestCount").textContent = `Destination (${fs.destination_count ?? 0})`;

  // Populate Path Focus dropdown
  const pathSel = document.getElementById("graphPathSelect");
  pathSel.innerHTML = `<option value="all">All Paths (${(ws.candidate_paths || []).length})</option>` +
    (ws.candidate_paths || [])
      .map((p) => `<option value="${esc(p.path_id)}">Path ${esc(p.path_id)} (${p.hop_count} hops · ${formatINR(p.total_outflow_inr)})</option>`)
      .join("");

  graphView.setData({
    rootAccount: rootAcc,
    transactions: st.transactions || [],
    candidatePaths: ws.candidate_paths || [],
    kycProfiles: st.kyc_profiles || [],
    nodeRoles: fs.node_roles || {},
  });

  // 4. Center Bottom: Donut, Timeline & Key Deterministic Findings
  renderDonutChart(document.getElementById("donutChartBox"), fs);
  renderTimelineChart(document.getElementById("timelineChartBox"), fs.timeline || []);
  renderKeyFindings(fs.deterministic_findings || []);

  // 5. Populate Center Deep-Dive Tabs (Hypotheses, Evidence, Agent Activity)
  renderCenterSecondaryTabs(st, ws);

  // 6. Right Column: Context, Competing Hypotheses, Citations & Human Approval Gate
  renderDefaultAlertContext();
  renderHypothesesPanel(hyps);
  renderCitationsPanel(ws.regulatory_citations || [], st.evidence_registry || {});
  renderApprovalGate(ws, dm);
}

function renderWorkflowTimeline(steps, agents) {
  const container = document.getElementById("wfStepsList");
  let html = "";
  steps.forEach((s) => {
    const st = s.status || "pending";
    const icon = st === "completed" ? "✓" : st === "waiting_approval" ? "●" : st === "failed" ? "✕" : s.step;
    const dur = s.duration_ms > 0 ? `${Math.round(s.duration_ms)}ms` : "";
    html += `
      <div class="wf-step status-${esc(st)}">
        <div class="wf-step-left">
          <span class="wf-dot ${esc(st)}">${icon}</span>
          <span>${s.step}. ${esc(s.name)}</span>
        </div>
        <span class="wf-dur">${esc(dur)}</span>
      </div>
    `;
    if (s.step === 3 && agents.length > 0) {
      html += `<div class="wf-agents-sublist">` +
        agents
          .map(
            (ag, idx) => `
          <div class="wf-agent-chip" data-agent-idx="${idx}">
            <span>❖ ${esc(ag.agent_name)}</span>
            <span style="color:#34d399;font-weight:700;">✓</span>
          </div>`
          )
          .join("") +
        `</div>`;
    }
  });
  container.innerHTML = html;

  container.querySelectorAll(".wf-agent-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const ag = agents[Number(chip.getAttribute("data-agent-idx"))];
      if (!ag) return;
      openModal(
        `Agent Execution Telemetry — ${ag.agent_name}`,
        `<table class="kv-table">
           <tr><td class="kv-key">Agent ID</td><td class="kv-val"><code>${esc(ag.agent_id)}</code></td></tr>
           <tr><td class="kv-key">Assigned Task</td><td class="kv-val">${esc(ag.task)}</td></tr>
           <tr><td class="kv-key">Execution Status</td><td class="kv-val">${esc(ag.status).toUpperCase()}</td></tr>
           <tr><td class="kv-key">Duration</td><td class="kv-val">${ag.duration_ms} ms</td></tr>
           <tr><td class="kv-key">MCP Tool Calls</td><td class="kv-val">${ag.tool_calls}</td></tr>
         </table>
         <div style="margin-top:12px;padding:10px;background:#080d1a;border:1px solid #1b2845;border-radius:6px;color:#cbd5e1;">
           <strong>Result Summary:</strong><br/>${esc(ag.summary)}
         </div>`
      );
    });
  });
}

function renderKeyFindings(findings) {
  const box = document.getElementById("keyFindingsGrid");
  box.innerHTML = findings.slice(0, 3).map((f) => `
    <div class="finding-tile">
      <div class="finding-icon">◈</div>
      <div>
        <div class="finding-title">${esc(f.title)} <span style="font-size:9.5px;color:#38bdf8;font-weight:600;">[Deterministic]</span></div>
        <div class="finding-desc">${esc(f.summary)}</div>
      </div>
    </div>
  `).join("");
}

function renderDefaultAlertContext() {
  const a = state.selectedAlert || {};
  const st = state.invState || {};
  const rootAcc = st.alert?.root_account || a.seed_account_id || "";
  const rootKyc = (st.kyc_profiles || []).find((k) => k.account_id === rootAcc) || st.kyc_profiles?.[0] || {};
  document.getElementById("contextPanelTitle").textContent = "Alert & Customer Context";
  document.getElementById("contextTableBody").innerHTML = `
    <tr><td class="kv-key">Alert ID</td><td class="kv-val">${esc(a.alert_id || "-")}</td></tr>
    <tr><td class="kv-key">Customer ID</td><td class="kv-val"><code>${esc(rootKyc.customer_id || a.customer_id || `CUST-${a.seed_account_id}`)}</code></td></tr>
    <tr><td class="kv-key">Seed Account</td><td class="kv-val"><code>${esc(a.seed_account_id || "-")}</code></td></tr>
    <tr><td class="kv-key">Alert Amount</td><td class="kv-val">${formatINR(a.initial_amount_inr || 0)}</td></tr>
    <tr><td class="kv-key">Entity / Risk</td><td class="kv-val">${esc(rootKyc.entity_name || a.full_name || "-")} (${esc(String(rootKyc.risk_category || a.risk_rating || "N/A").toUpperCase())})</td></tr>
    <tr><td class="kv-key">Declared Income</td><td class="kv-val">${rootKyc.declared_annual_income_inr ? formatINR(rootKyc.declared_annual_income_inr) + "/yr" : "N/A"}</td></tr>
    <tr><td class="kv-key">Triggered On</td><td class="kv-val">${esc(String(a.triggered_at || "").slice(0, 16).replace("T", " "))}</td></tr>
  `;
}

function renderNodeInspector(node) {
  const k = node.kyc || {};
  document.getElementById("contextPanelTitle").textContent = `Selected Account: ${node.id}`;
  document.getElementById("contextTableBody").innerHTML = `
    <tr><td class="kv-key">Account ID</td><td class="kv-val"><code>${esc(node.id)}</code></td></tr>
    <tr><td class="kv-key">Graph Role</td><td class="kv-val" style="text-transform:capitalize;">${esc(node.role)}</td></tr>
    <tr><td class="kv-key">Entity Name</td><td class="kv-val">${esc(k.entity_name || "External / Unindexed")}</td></tr>
    <tr><td class="kv-key">Customer ID</td><td class="kv-val"><code>${esc(k.customer_id || `CUST-${node.id}`)}</code></td></tr>
    <tr><td class="kv-key">Bank / Type</td><td class="kv-val">${esc(k.bank_name || "Simulated Bank")} · ${esc(k.entity_type || "individual")}</td></tr>
    <tr><td class="kv-key">KYC Risk Rating</td><td class="kv-val">${esc(String(k.risk_category || "unknown").toUpperCase())}</td></tr>
    <tr><td class="kv-key">Commercial Reg.</td><td class="kv-val">${node.isRegistered ? `ACTIVE (${esc(k.registry_type || "VERIFIED")})` : "NOT_FOUND"}</td></tr>
    <tr><td class="kv-key">Connected TXNs</td><td class="kv-val">${node.txCount}</td></tr>
  `;
}

function renderEdgeInspector(edge) {
  const tx = edge.txs[0] || {};
  document.getElementById("contextPanelTitle").textContent = `Transaction Evidence: ${edge.id}`;
  document.getElementById("contextTableBody").innerHTML = `
    <tr><td class="kv-key">Evidence ID</td><td class="kv-val"><code>${esc(edge.id)}</code></td></tr>
    <tr><td class="kv-key">Originator</td><td class="kv-val"><code>${esc(edge.source)}</code></td></tr>
    <tr><td class="kv-key">Beneficiary</td><td class="kv-val"><code>${esc(edge.target)}</code></td></tr>
    <tr><td class="kv-key">Transfer Amount</td><td class="kv-val">${formatINR(edge.amount_inr)} (${edge.txs.length} leg${edge.txs.length > 1 ? "s" : ""})</td></tr>
    <tr><td class="kv-key">Channel</td><td class="kv-val">${esc(edge.channel)}</td></tr>
    <tr><td class="kv-key">Timestamp</td><td class="kv-val">${esc(String(tx.timestamp || "").slice(0, 19).replace("T", " "))}</td></tr>
    <tr><td class="kv-key">Scrubbed Memo</td><td class="kv-val">${esc(String(tx.memo || "-").replace(/<[^>]+>/g, ""))}</td></tr>
  `;
}

function renderHypothesesPanel(hyps) {
  const box = document.getElementById("hypothesesBox");
  if (!hyps.length) {
    box.innerHTML = `<div style="color:#7c8db0;font-size:11.5px;">No hypotheses generated.</div>`;
    return;
  }
  box.innerHTML = hyps.map((h, i) => {
    const pct = Math.round(Number(h.confidence || 0) * 100);
    const isSusp = h.label === "suspicious";
    const title = isSusp ? "H1: Suspicious (ML / Layering)" : "H2: Benign (Business / Settlement)";
    const sup = (h.supporting_evidence || []).map((s) => `<li>+ ${esc(s)}</li>`).join("");
    const con = (h.contradicting_evidence || []).map((c) => `<li style="color:#94a3b8;">− ${esc(c)}</li>`).join("");
    return `
      <div class="hyp-card" data-hyp-idx="${i}">
        <div class="hyp-row">
          <span>${title}</span>
          <span>${pct}%</span>
        </div>
        <div class="hyp-bar-track">
          <div class="hyp-bar-fill ${isSusp ? "suspicious" : "benign"}" style="width:${pct}%;"></div>
        </div>
        <div class="hyp-details">
          <div style="margin-bottom:4px;color:#e2e8f0;">${esc(h.explanation)}</div>
          <ul style="margin:4px 0 0 0;padding-left:15px;">${sup || "<li>No supporting items</li>"}${con}</ul>
        </div>
      </div>
    `;
  }).join("");

  box.querySelectorAll(".hyp-card").forEach((el) => {
    el.addEventListener("click", () => el.classList.toggle("expanded"));
  });
}

function renderCitationsPanel(citations, evidenceRegistry) {
  document.getElementById("citationsCountBadge").textContent = String(citations.length);
  const box = document.getElementById("citationsBox");
  box.innerHTML = citations
    .map((cid) => `<span class="cite-pill" data-cite-id="${esc(cid)}">${esc(cid)}</span>`)
    .join("");

  box.querySelectorAll(".cite-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      const cid = pill.getAttribute("data-cite-id");
      const rec = evidenceRegistry[cid] || state.regulationsCache[cid] || {};
      openModal(
        `Verified Regulatory Evidence — ${cid}`,
        `<table class="kv-table">
           <tr><td class="kv-key">Passage ID</td><td class="kv-val"><code>${esc(cid)}</code></td></tr>
           <tr><td class="kv-key">Source Document</td><td class="kv-val">${esc(rec.source || rec.title || "Indian AML Corpus")}</td></tr>
           <tr><td class="kv-key">Effective Date</td><td class="kv-val">${esc(rec.effective_date || "Active")}</td></tr>
           <tr><td class="kv-key">Verification</td><td class="kv-val"><span class="tag-badge tag-ok">VERIFIED IN REGISTRY</span></td></tr>
         </table>
         <div style="margin-top:12px;padding:12px;background:#080d1a;border:1px solid #1b2845;border-radius:7px;color:#e2e8f0;line-height:1.55;">
           ${esc(rec.text || "Clause verified in compliance-kb.")}
         </div>`
      );
    });
  });
}

function renderApprovalGate(ws, dm) {
  const banner = document.getElementById("approvalBanner");
  banner.className = `approval-banner ${dm.cls}`;
  document.getElementById("gateDispCode").textContent = dm.code;
  document.getElementById("gateDispSub").textContent = dm.subtitle;
  document.getElementById("gateConfidence").textContent = `${Math.round(Number(ws.confidence_score || 0) * 100)}%`;
  document.getElementById("gateHashBox").textContent = `SHA-256: ${state.payloadHash || ws.payload_hash || "-"}`;
  document.getElementById("editRationaleInput").value = ws.recommendation_rationale || "";
  document.getElementById("editDispositionSelect").value = ws.recommended_disposition || "escalate_str";

  const isLocked = state.invStatus === "committed" || state.invStatus === "rejected";
  document.getElementById("btnApproveCommit").disabled = isLocked;
  document.getElementById("btnToggleEdit").disabled = isLocked;
  document.getElementById("btnRejectDisp").disabled = isLocked;
}

/* ── Center Secondary Deep-Dive Tabs ─────────────────────────────────────── */
function switchCenterTab(tabName) {
  state.activeCenterTab = tabName;
  document.querySelectorAll(".tab-btn[data-tab]").forEach((b) => {
    b.classList.toggle("active", b.getAttribute("data-tab") === tabName);
  });

  const graphSection = document.getElementById("centerGraphOverview");
  const deepDiveSection = document.getElementById("centerDeepDivePanel");

  if (tabName === "graph") {
    graphSection.style.display = "flex";
    deepDiveSection.style.display = "none";
    setTimeout(() => graphView && graphView.fitToScreen(), 50);
  } else {
    graphSection.style.display = "none";
    deepDiveSection.style.display = "block";
    renderCenterSecondaryTabs(state.invState || {}, state.invState?.worksheet || {});
  }
}

function renderCenterSecondaryTabs(st, ws) {
  const panel = document.getElementById("centerDeepDivePanel");
  const tab = state.activeCenterTab;
  if (tab === "graph") return;

  if (tab === "flow") {
    const paths = ws.candidate_paths || [];
    panel.innerHTML = `
      <div class="panel-header"><h3 class="panel-title">Decimal Flow Conservation &amp; Reconstructed Paths</h3></div>
      <p style="color:#94a3b8;margin-top:0;">Every path metric below is computed deterministically via NetworkX + Python <code>decimal.Decimal</code>.</p>
      <table class="data-table">
        <thead><tr><th>Path ID</th><th>Traversal Chain</th><th>Hops</th><th>Outflow (INR)</th><th>Consolidated (INR)</th><th>Net Retained</th><th>Span</th></tr></thead>
        <tbody>
          ${
            paths.map((p) => `
              <tr>
                <td><code>${esc(p.path_id)}</code></td>
                <td>${esc((p.nodes || []).join(" → "))}</td>
                <td>${p.hop_count}</td>
                <td>₹${esc(p.total_outflow_inr)}</td>
                <td>₹${esc(p.total_consolidated_inr)}</td>
                <td>₹${esc(p.net_difference_inr)} (${esc(p.retention_pct)}%)</td>
                <td>${p.time_span_days}d</td>
              </tr>`).join("") || `<tr><td colspan="7">No multi-hop candidate paths reconstructed in window.</td></tr>`
          }
        </tbody>
      </table>
    `;
  } else if (tab === "hypotheses") {
    const hyps = ws.hypotheses || [];
    panel.innerHTML = `
      <div class="panel-header"><h3 class="panel-title">Competing Investigation Hypotheses Matrix</h3></div>
      <p style="color:#94a3b8;margin-top:0;">AI agents evaluate suspicious and legitimate explanations side-by-side without declaring criminal guilt.</p>
      ${hyps.map((h) => `
        <div style="padding:12px;background:#090f1f;border:1px solid #1b2845;border-radius:8px;margin-bottom:10px;">
          <div style="display:flex;justify-content:space-between;font-weight:700;color:#fff;">
            <span>${esc(h.label).toUpperCase()} — ${esc(h.explanation)}</span>
            <span>Assessment Score: ${Math.round(Number(h.confidence || 0) * 100)}%</span>
          </div>
          <div style="margin-top:8px;color:#6ee7b7;font-size:12px;"><strong>Supporting Evidence:</strong> ${(h.supporting_evidence || []).map(esc).join(" · ") || "None"}</div>
          <div style="margin-top:4px;color:#fda4af;font-size:12px;"><strong>Contradicting Evidence:</strong> ${(h.contradicting_evidence || []).map(esc).join(" · ") || "None"}</div>
          <div style="margin-top:6px;font-size:11px;color:#7dd3fc;">Citations: ${(h.regulatory_citations || []).map((c) => `<code>${esc(c)}</code>`).join(", ") || "None"}</div>
        </div>
      `).join("")}
    `;
  } else if (tab === "evidence") {
    const reg = st.evidence_registry || {};
    const entries = Object.entries(reg);
    panel.innerHTML = `
      <div class="panel-header"><h3 class="panel-title">Immutable Evidence Registry (${entries.length} Verified Items)</h3></div>
      <table class="data-table">
        <thead><tr><th>Evidence ID</th><th>Category</th><th>Summary / Source</th><th>Status</th></tr></thead>
        <tbody>
          ${entries.map(([eid, val]) => {
            const cat = eid.startsWith("TX") ? "Transaction" : eid.startsWith("KYC") ? "KYC Profile" : eid.startsWith("REG-") || eid.startsWith("SOP-") ? "Regulatory Clause" : eid.startsWith("REGISTRY") ? "Commercial Registry" : "Graph Calculation";
            const summary = val.text ? val.text.slice(0, 95) + "..." : val.entity_name ? `${val.entity_name} (risk=${val.risk_category || val.registry_status})` : val.sender_account ? `${val.sender_account} → ${val.receiver_account} (${formatINR(val.amount_inr)})` : JSON.stringify(val).slice(0, 90);
            return `<tr><td><code>${esc(eid)}</code></td><td>${cat}</td><td>${esc(summary)}</td><td><span class="tag-badge tag-ok">VERIFIED</span></td></tr>`;
          }).join("")}
        </tbody>
      </table>
    `;
  } else if (tab === "agents") {
    const runs = st.agent_runs || [];
    panel.innerHTML = `
      <div class="panel-header"><h3 class="panel-title">Specialist Agent Execution Telemetry (${esc(modeLabel(state.mode))})</h3></div>
      <table class="data-table">
        <thead><tr><th>Agent</th><th>Task</th><th>Calls</th><th>Duration</th><th>Status</th><th>Finding Summary</th></tr></thead>
        <tbody>
          ${runs.map((r) => `
            <tr>
              <td><strong>${esc(r.agent_name)}</strong></td>
              <td>${esc(r.task)}</td>
              <td>${r.tool_calls}</td>
              <td>${r.duration_ms} ms</td>
              <td><span class="tag-badge tag-ok">${esc(r.status).toUpperCase()}</span></td>
              <td>${esc(r.summary)}</td>
            </tr>`).join("")}
        </tbody>
      </table>
    `;
  }
}

/* ── Human Approval Gate Actions (Approve / Edit / Reject) ───────────────── */
function toggleEditDrawer() {
  const dr = document.getElementById("editDrawer");
  dr.style.display = dr.style.display === "none" ? "block" : "none";
}

async function handleDecision(action) {
  if (!state.threadId) return;
  const notes = document.getElementById("analystNotesInput").value;
  const payload = { action, notes };

  if (action === "approve") {
    if (!state.approvalToken) {
      try {
        const prep = await api.prepareDecision(state.threadId, state.approvedHash || state.payloadHash);
        state.approvedHash = prep.approved_hash;
        state.approvalToken = prep.approval_token;
      } catch (err) {
        showGateFeedback(`Approval preparation failed: ${err.message}`, "err");
        return;
      }
    }
    payload.approved_hash = state.approvedHash;
    payload.approval_token = state.approvalToken;
  }

  if (action === "edit") {
    payload.edit = {
      recommended_disposition: document.getElementById("editDispositionSelect").value,
      recommendation_rationale: document.getElementById("editRationaleInput").value,
    };
  }

  try {
    const res = await api.submitDecision(state.threadId, payload);

    if (action === "edit") {
      state.payloadHash = res.payload_hash;
      state.approvedHash = res.approved_hash;
      state.approvalToken = res.approval_token;
      state.invStatus = "interrupt_required";
      if (state.invState?.worksheet) {
        state.invState.worksheet.recommended_disposition = payload.edit.recommended_disposition;
        state.invState.worksheet.recommendation_rationale = payload.edit.recommendation_rationale;
      }
      document.getElementById("editDrawer").style.display = "none";
      renderFullInvestigationState();
      showGateFeedback(
        `Worksheet edited & re-verified! Previous hash (${String(res.previous_hash_invalidated || "").slice(0, 10)}...) invalidated → Fresh SHA-256 (${res.payload_hash.slice(0, 10)}...) requires approval.`,
        "warn"
      );
      appendTraceEvent("worksheet_edited", {
        category: "human_gate",
        message: `Analyst edited worksheet -> Old hash invalidated, new SHA-256=${res.payload_hash.slice(0, 12)}...`,
      });
    } else if (action === "reject") {
      state.invStatus = "rejected";
      const updated = await api.getThreadState(state.threadId);
      state.invState = updated.state;
      renderFullInvestigationState();
      showGateFeedback(`Disposition rejected and logged to manual review queue.`, "danger");
    } else {
      state.invStatus = "committed";
      const updated = await api.getThreadState(state.threadId);
      state.invState = updated.state;
      renderFullInvestigationState();
      await refreshHealthAndCatalog();
      showGateFeedback(
        `Committed to Case DB! Receipt: ${res.receipt?.case_id || "OK"} (${res.receipt?.audit_entry_id || "AUD-OK"})`,
        "ok"
      );
      appendTraceEvent("case_committed", {
        category: "verifier",
        message: `Human approved exact SHA-256 -> Committed ${res.receipt?.case_id || ""}`,
      });
    }
  } catch (err) {
    showGateFeedback(`Backend rejected action (${err.status || "Error"}): ${err.message}`, "danger");
  }
}

function showGateFeedback(msg, tone) {
  const el = document.getElementById("gateFeedback");
  el.style.display = "block";
  el.textContent = msg;
  if (tone === "ok") {
    el.style.background = "rgba(16,185,129,0.18)";
    el.style.border = "1px solid rgba(16,185,129,0.45)";
    el.style.color = "#6ee7b7";
  } else if (tone === "warn") {
    el.style.background = "rgba(245,158,11,0.18)";
    el.style.border = "1px solid rgba(245,158,11,0.45)";
    el.style.color = "#fcd34d";
  } else {
    el.style.background = "rgba(244,63,94,0.18)";
    el.style.border = "1px solid rgba(244,63,94,0.45)";
    el.style.color = "#fda4af";
  }
}

/* ── Sidebar Multi-View Router (All 9 Sections Functional) ───────────────── */
async function switchSidebarView(navName) {
  state.activeNav = navName;
  document.querySelectorAll(".nav-item[data-nav]").forEach((el) => {
    el.classList.toggle("active", el.getAttribute("data-nav") === navName);
  });

  const mainInv = document.getElementById("viewInvestigation");
  const subView = document.getElementById("viewSecondary");

  if (navName === "investigation") {
    mainInv.style.display = "block";
    subView.style.display = "none";
    setTimeout(() => graphView && graphView.fitToScreen(), 60);
    return;
  }

  if (navName === "graph_explorer") {
    // Dedicated full-screen Graph Explorer mode using the main workspace focused on graph
    mainInv.style.display = "block";
    subView.style.display = "none";
    switchCenterTab("graph");
    setTimeout(() => graphView && graphView.fitToScreen(), 60);
    return;
  }

  mainInv.style.display = "none";
  subView.style.display = "block";
  subView.innerHTML = `<div class="panel-card">Loading ${esc(navName)}...</div>`;

  try {
    if (navName === "alerts") {
      const data = await api.getAlerts(60);
      syncAlertCatalog(data.alerts || []);
      subView.innerHTML = `
        <div class="panel-card">
          <div class="panel-header">
            <h2 class="inv-title">Alerts Queue (${data.total} Seeded Multi-Bank Alerts)</h2>
          </div>
          <table class="data-table">
            <thead><tr><th>Alert ID</th><th>Seed Account</th><th>Customer</th><th>Amount (INR)</th><th>Risk</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>
              ${data.alerts.map((a) => `
                <tr>
                  <td><strong><code>${esc(a.alert_id)}</code></strong></td>
                  <td><code>${esc(a.seed_account_id)}</code></td>
                  <td>${esc(a.full_name || "-")}</td>
                  <td>${formatINR(a.initial_amount_inr)}</td>
                  <td><span class="tag-badge ${String(a.risk_rating).toUpperCase() === "HIGH" ? "tag-danger" : "tag-info"}">${esc(a.risk_rating || "MEDIUM")}</span></td>
                  <td>${esc(a.status)}</td>
                  <td><button class="btn-action btn-run btn-open-alert" data-aid="${esc(a.alert_id)}">Investigate →</button></td>
                </tr>`).join("")}
            </tbody>
          </table>
        </div>
      `;
      subView.querySelectorAll(".btn-open-alert").forEach((b) => {
        b.addEventListener("click", () => {
          const aid = b.getAttribute("data-aid");
          const found = state.alerts.find((x) => x.alert_id === aid) || data.alerts.find((x) => x.alert_id === aid);
          if (found) {
            state.selectedAlert = found;
            syncAlertCatalog(state.alerts.length ? state.alerts : data.alerts || [], found.alert_id);
            switchSidebarView("investigation");
            runLiveInvestigation();
          }
        });
      });
    } else if (navName === "cases") {
      const data = await api.getCases(50);
      subView.innerHTML = `
        <div class="panel-card">
          <div class="panel-header"><h2 class="inv-title">Committed Case Dispositions (${data.total_committed})</h2></div>
          <table class="data-table">
            <thead><tr><th>Case ID</th><th>Alert ID</th><th>Worksheet</th><th>Final Disposition</th><th>Approver</th><th>SHA-256 Hash</th><th>Committed At</th></tr></thead>
            <tbody>
              ${data.cases.map((c) => `
                <tr>
                  <td><code>${esc(c.case_id)}</code></td>
                  <td><code>${esc(c.alert_id)}</code></td>
                  <td><code>${esc(c.worksheet_id)}</code></td>
                  <td><span class="tag-badge tag-ok">${esc(c.disposition).toUpperCase()}</span></td>
                  <td>${esc(c.approver_id)}</td>
                  <td><code>${esc(String(c.payload_hash || "").slice(0, 16))}...</code></td>
                  <td>${esc(String(c.committed_at || "").slice(0, 19).replace("T", " "))}</td>
                </tr>`).join("") || `<tr><td colspan="7">No committed cases yet — approve an investigation worksheet to commit.</td></tr>`}
            </tbody>
          </table>
        </div>
      `;
    } else if (navName === "customers") {
      const data = await api.getCustomers(80);
      subView.innerHTML = `
        <div class="panel-card">
          <div class="panel-header"><h2 class="inv-title">Customers, KYC Profiles &amp; Right-to-be-Forgotten Memory (${data.total})</h2></div>
          <table class="data-table">
            <thead><tr><th>Customer ID</th><th>Entity Name</th><th>Account / Bank</th><th>KYC Risk</th><th>Declared Income</th><th>Registry</th><th>LTM Episodes</th><th>Forget API</th></tr></thead>
            <tbody>
              ${data.customers.map((c) => `
                <tr>
                  <td><code>${esc(c.customer_id)}</code></td>
                  <td><strong>${esc(c.full_name)}</strong></td>
                  <td><code>${esc(c.account_id || "-")}</code> · ${esc(c.bank_name || "-")}</td>
                  <td><span class="tag-badge ${c.risk_rating === "HIGH" ? "tag-danger" : c.risk_rating === "LOW" ? "tag-ok" : "tag-warn"}">${esc(c.risk_rating)}</span></td>
                  <td>${formatINR(c.declared_annual_income_inr)}</td>
                  <td>${c.registry_status === "ACTIVE" ? `<span class="tag-badge tag-ok">${esc(c.registry_type)}</span>` : `<span style="color:#7c8db0;">NONE</span>`}</td>
                  <td>${c.episodes_count}</td>
                  <td><button class="btn-action btn-forget-cust" data-cid="${esc(c.customer_id)}">Wipe Memory</button></td>
                </tr>`).join("")}
            </tbody>
          </table>
        </div>
      `;
      subView.querySelectorAll(".btn-forget-cust").forEach((b) => {
        b.addEventListener("click", async () => {
          const cid = b.getAttribute("data-cid");
          const out = await api.forgetCustomer(cid);
          b.textContent = `Wiped (${out.episodes_removed})`;
          b.disabled = true;
        });
      });
    } else if (navName === "regulations") {
      const data = await api.getRegulations();
      subView.innerHTML = `
        <div class="panel-card">
          <div class="panel-header">
            <h2 class="inv-title">Regulatory Knowledge Base (${data.total} Indian AML &amp; SOP Clauses)</h2>
            <div style="display:flex;gap:8px;">
              <input id="regSearchInput" class="ctrl-select" style="width:280px;" placeholder="Hybrid BM25 + Vector + RRF search..." />
              <button id="btnRegSearch" class="btn-action btn-run">Search KB</button>
            </div>
          </div>
          <div id="regResultsTable">${renderRegTable(data.clauses)}</div>
        </div>
      `;
      document.getElementById("btnRegSearch").addEventListener("click", async () => {
        const q = document.getElementById("regSearchInput").value;
        const res = await api.getRegulations(q);
        document.getElementById("regResultsTable").innerHTML = renderRegTable(res.clauses);
      });
    } else if (navName === "audit") {
      const data = await api.getAuditLogs(60);
      subView.innerHTML = `
        <div class="panel-card">
          <div class="panel-header"><h2 class="inv-title">Append-Only Cryptographic Audit Trail (${data.total} Events)</h2></div>
          <table class="data-table">
            <thead><tr><th>Log ID</th><th>Timestamp</th><th>Event Type</th><th>Actor</th><th>Thread ID</th><th>SHA-256 Hash</th></tr></thead>
            <tbody>
              ${data.audit_logs.map((l) => `
                <tr>
                  <td>#${l.log_id}</td>
                  <td><code>${esc(String(l.created_at || "").slice(0, 19).replace("T", " "))}</code></td>
                  <td><strong>${esc(l.event_type)}</strong></td>
                  <td>${esc(l.actor)}</td>
                  <td><code>${esc(l.thread_id)}</code></td>
                  <td><code>${esc(l.payload_hash ? l.payload_hash.slice(0, 18) + "..." : "-")}</code></td>
                </tr>`).join("")}
            </tbody>
          </table>
        </div>
      `;
    } else if (navName === "analytics") {
      const data = await api.getAnalytics();
      const s = data.summary || {};
      subView.innerHTML = `
        <div class="panel-card">
          <div class="panel-header"><h2 class="inv-title">Operational &amp; Compliance Analytics</h2></div>
          <div class="findings-grid" style="margin-bottom:16px;">
            <div class="finding-tile"><div><div class="finding-title">Total Queued/Processed Alerts</div><div class="kpi-value">${s.total_alerts || 0}</div></div></div>
            <div class="finding-tile"><div><div class="finding-title">Indexed Multi-Bank Transfers</div><div class="kpi-value">${s.total_transactions || 0} (${formatINR(s.total_tx_volume_inr || 0)})</div></div></div>
            <div class="finding-tile"><div><div class="finding-title">Human-Committed Cases / Audit Logs</div><div class="kpi-value">${s.total_committed_cases || 0} cases · ${s.total_audit_events || 0} logs</div></div></div>
          </div>
          <p><a href="/metrics" target="_blank" style="color:#38bdf8;">View Raw Prometheus Metrics Scrape Endpoint (/metrics) ↗</a></p>
        </div>
      `;
    } else if (navName === "settings") {
      const cfg = await api.getConfigInfo();
      const llm = cfg.llm || {};
      const modelOptions = (llm.supported_models || ["openai/gpt-5-mini", "openai/gpt-4.1-mini"]).map(
        (m) => `<option value="${esc(m)}" ${m === llm.c1_and_specialist_model ? "selected" : ""}>${esc(m)}</option>`
      ).join("");
      const supOptions = (llm.supported_models || ["openai/gpt-5-mini", "openai/gpt-4.1-mini"]).map(
        (m) => `<option value="${esc(m)}" ${m === llm.c2_supervisor_model ? "selected" : ""}>${esc(m)}</option>`
      ).join("");

      subView.innerHTML = `
        <div class="panel-card" style="margin-bottom:14px;">
          <div class="panel-header">
            <h2 class="inv-title">OpenRouter Live LLM Configuration (Enable / Disable)</h2>
            <span class="tag-badge ${llm.llm_enabled ? "tag-ok" : "tag-warn"}">
              ${llm.llm_enabled ? "LIVE LLM ENABLED" : "OFFLINE ENGINE (LLM DISABLED)"}
            </span>
          </div>
          <p style="color:#94a3b8;margin-top:0;font-size:12.5px;">
            Key Status: <code>${esc(llm.key_preview || "not_configured")}</code> &nbsp;|&nbsp;
            Endpoint: <code>${esc(llm.base_url || "https://openrouter.ai/api/v1")}</code>
          </p>
          <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;margin-bottom:12px;">
            <div>
              <div style="font-size:11px;color:#94a3b8;margin-bottom:4px;">C1 Investigator / C2 Specialist Model</div>
              <select id="llmFastModelSelect" class="ctrl-select" style="min-width:230px;">${modelOptions}</select>
            </div>
            <div>
              <div style="font-size:11px;color:#94a3b8;margin-bottom:4px;">C2 Supervisor / Critic Model</div>
              <select id="llmStrongModelSelect" class="ctrl-select" style="min-width:230px;">${supOptions}</select>
            </div>
            <button id="btnToggleLlm" class="btn-action ${llm.llm_enabled ? "btn-reject" : "btn-approve"}" style="padding:8px 14px;">
              ${llm.llm_enabled ? "Disable Live LLM (Switch Offline)" : "Enable Live OpenRouter LLM"}
            </button>
            <button id="btnSaveModels" class="btn-action btn-run" style="padding:8px 14px;">Apply Selected Models</button>
            <button id="btnPingLlm" class="btn-action" style="padding:8px 14px;">Test OpenRouter Key</button>
          </div>
          <div id="llmTestStatus" style="font-size:12px;color:#7dd3fc;"></div>
        </div>
        <div class="panel-card">
          <div class="panel-header"><h2 class="inv-title">System Configuration &amp; Policy Bounds</h2></div>
          <pre style="background:#080d1a;padding:14px;border-radius:8px;border:1px solid #1b2845;color:#cbd5e1;font-family:var(--font-mono);overflow-x:auto;">${esc(JSON.stringify(cfg, null, 2))}</pre>
        </div>
      `;

      document.getElementById("btnToggleLlm").addEventListener("click", async (ev) => {
        const btn = ev.currentTarget;
        const box = document.getElementById("llmTestStatus");
        btn.disabled = true;
        btn.textContent = "Updating...";
        try {
          const updated = await api.updateLlmConfig({
            enabled: !llm.llm_enabled,
            model: document.getElementById("llmFastModelSelect").value,
            strong_model: document.getElementById("llmStrongModelSelect").value,
          });
          updateTopbarLlmPill(updated);
          await switchSidebarView("settings");
          const msgBox = document.getElementById("llmTestStatus");
          if (msgBox) {
            msgBox.style.color = updated.llm_enabled ? "#6ee7b7" : "#fcd34d";
            msgBox.textContent = updated.llm_enabled
              ? `✓ Live OpenRouter LLM Enabled (${updated.c1_and_specialist_model}) — synced to .env`
              : "✓ Live LLM Disabled — Running Offline Deterministic Engine ($0.00/case) — synced to .env";
          }
        } catch (err) {
          btn.disabled = false;
          if (box) {
            box.style.color = "#fda4af";
            box.textContent = `Failed to update LLM mode: ${err.message}`;
          }
        }
      });
      document.getElementById("btnSaveModels").addEventListener("click", async (ev) => {
        const btn = ev.currentTarget;
        btn.disabled = true;
        btn.textContent = "Applying...";
        const updated = await api.updateLlmConfig({
          model: document.getElementById("llmFastModelSelect").value,
          strong_model: document.getElementById("llmStrongModelSelect").value,
        });
        updateTopbarLlmPill(updated);
        await switchSidebarView("settings");
        const msgBox = document.getElementById("llmTestStatus");
        if (msgBox) {
          msgBox.style.color = "#6ee7b7";
          msgBox.textContent = `✓ Saved models (${updated.c1_and_specialist_model} / ${updated.c2_supervisor_model}) — synced to .env`;
        }
      });
      document.getElementById("btnPingLlm").addEventListener("click", async () => {
        const box = document.getElementById("llmTestStatus");
        const m = document.getElementById("llmFastModelSelect").value;
        box.textContent = `Testing live OpenRouter connection with ${m}...`;
        const res = await api.testLlmConnection(m);
        box.textContent = res.ok
          ? `Connected! Model: ${res.model} | Reply: "${res.reply}" | Tokens: ${res.tokens}`
          : `Connection failed: ${res.error}`;
      });
    }
  } catch (err) {
    subView.innerHTML = `<div class="panel-card" style="color:#fda4af;">Failed to load view: ${esc(err.message)}</div>`;
  }
}

function renderRegTable(clauses) {
  return `
    <table class="data-table">
      <thead><tr><th>Clause ID</th><th>Source Document</th><th>Category</th><th>Effective Date</th><th>Regulatory Passage</th></tr></thead>
      <tbody>
        ${(clauses || []).map((c) => `
          <tr>
            <td><code>${esc(c.clause_id)}</code></td>
            <td><strong>${esc(c.title)}</strong></td>
            <td><span class="tag-badge tag-info">${esc(c.category)}</span></td>
            <td>${esc(c.effective_date)}</td>
            <td style="color:#cbd5e1;">${esc(c.text)}</td>
          </tr>`).join("")}
      </tbody>
    </table>
  `;
}

function openModal(title, bodyHtml) {
  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalBody").innerHTML = bodyHtml;
  document.getElementById("modalBackdrop").classList.add("open");
}

function closeModal() {
  document.getElementById("modalBackdrop").classList.remove("open");
}

window.addEventListener("DOMContentLoaded", init);
