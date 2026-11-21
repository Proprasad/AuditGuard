/**
 * AuditGuard Financial Charts (Zero-CDN Deterministic SVG Renderers)
 * 1. Fund Flow Summary Donut Chart (Consolidated vs. Retained)
 * 2. Cumulative Flow Timeline Line/Area Chart (Outflow vs. Consolidation over Days)
 */
import { formatINR, formatINRCompact } from "./api.js";

export function renderDonutChart(containerEl, flowSummary) {
  if (!containerEl) return;
  const total = Number(flowSummary?.total_outflow_num || 0);
  const cons = Number(flowSummary?.total_consolidated_num || 0);
  const ret = Number(flowSummary?.total_retained_num || 0);
  const consPct = Number(flowSummary?.consolidated_pct || 0);
  const retPct = Number(flowSummary?.retained_pct || 0);

  const r = 50;
  const c = 2 * Math.PI * r;
  const consDash = total > 0 ? (Math.min(100, consPct) / 100) * c : 0;
  const retDash = total > 0 ? (Math.min(100, retPct) / 100) * c : 0;

  containerEl.innerHTML = `
    <div class="donut-wrap">
      <svg width="132" height="132" viewBox="0 0 132 132" aria-label="Fund Flow Summary Donut">
        <circle cx="66" cy="66" r="${r}" fill="none" stroke="#1b2845" stroke-width="14"></circle>
        ${
          consDash > 0
            ? `<circle cx="66" cy="66" r="${r}" fill="none" stroke="#3b82f6" stroke-width="14"
                 stroke-dasharray="${consDash} ${c - consDash}"
                 transform="rotate(-90 66 66)" stroke-linecap="butt"></circle>`
            : ""
        }
        ${
          retDash > 0
            ? `<circle cx="66" cy="66" r="${r}" fill="none" stroke="#f43f5e" stroke-width="14"
                 stroke-dasharray="${retDash} ${c - retDash}"
                 stroke-dashoffset="${-consDash}"
                 transform="rotate(-90 66 66)" stroke-linecap="butt"></circle>`
            : ""
        }
        <text x="66" y="63" text-anchor="middle" fill="#ffffff" font-size="13.5" font-weight="700">${formatINR(total)}</text>
        <text x="66" y="79" text-anchor="middle" fill="#7c8db0" font-size="9.5">Total Outflow</text>
      </svg>
      <div class="donut-legend">
        <div class="donut-legend-row">
          <span style="display:flex;align-items:center;gap:6px;color:#cbd5e1;">
            <span class="legend-dot" style="background:#3b82f6;"></span>Consolidated (Dest.)
          </span>
          <strong style="color:#ffffff;">${formatINR(cons)} <span style="color:#7c8db0;font-weight:500;">(${consPct.toFixed(1)}%)</span></strong>
        </div>
        <div class="donut-legend-row">
          <span style="display:flex;align-items:center;gap:6px;color:#cbd5e1;">
            <span class="legend-dot" style="background:#f43f5e;"></span>Retained / Uncons.
          </span>
          <strong style="color:#ffffff;">${formatINR(ret)} <span style="color:#7c8db0;font-weight:500;">(${retPct.toFixed(1)}%)</span></strong>
        </div>
        <div style="font-size:10.5px;color:#526282;border-top:1px solid #1b2845;padding-top:6px;">
          Computed via Python <code>decimal.Decimal</code> (0% LLM math)
        </div>
      </div>
    </div>
  `;
}

export function renderTimelineChart(containerEl, timelineSeries) {
  if (!containerEl) return;
  const series = Array.isArray(timelineSeries) && timelineSeries.length > 0
    ? timelineSeries
    : [
        { label: "Day 0", cumulative_outflow_inr: 0, cumulative_consolidated_inr: 0 },
        { label: "Day 1", cumulative_outflow_inr: 0, cumulative_consolidated_inr: 0 },
      ];

  const W = 380;
  const H = 142;
  const padL = 44;
  const padR = 14;
  const padT = 14;
  const padB = 26;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  const maxVal = Math.max(
    1,
    ...series.map((p) => Math.max(p.cumulative_outflow_inr || 0, p.cumulative_consolidated_inr || 0))
  );

  const xAt = (i) => padL + (series.length === 1 ? plotW / 2 : (i / (series.length - 1)) * plotW);
  const yAt = (v) => padT + plotH - (Math.max(0, v) / maxVal) * plotH;

  const outPts = series.map((p, i) => `${xAt(i).toFixed(1)},${yAt(p.cumulative_outflow_inr).toFixed(1)}`).join(" ");
  const consPts = series.map((p, i) => `${xAt(i).toFixed(1)},${yAt(p.cumulative_consolidated_inr).toFixed(1)}`).join(" ");

  const outArea = `${padL},${padT + plotH} ${outPts} ${xAt(series.length - 1).toFixed(1)},${padT + plotH}`;
  const consArea = `${padL},${padT + plotH} ${consPts} ${xAt(series.length - 1).toFixed(1)},${padT + plotH}`;

  const yTicks = [0, 0.5, 1].map((t) => {
    const val = maxVal * t;
    const y = yAt(val);
    return `
      <line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="#1b2845" stroke-dasharray="3 3" />
      <text x="${padL - 6}" y="${y + 3}" text-anchor="end" fill="#7c8db0" font-size="9.5">${formatINRCompact(val)}</text>
    `;
  }).join("");

  const xLabels = series.map((p, i) => `
    <text x="${xAt(i)}" y="${H - 7}" text-anchor="middle" fill="#7c8db0" font-size="9.5">${p.label}</text>
  `).join("");

  const dots = series.map((p, i) => `
    <circle cx="${xAt(i)}" cy="${yAt(p.cumulative_outflow_inr)}" r="3.2" fill="#38bdf8">
      <title>${p.label} — Outflow: ${formatINR(p.cumulative_outflow_inr)}</title>
    </circle>
    <circle cx="${xAt(i)}" cy="${yAt(p.cumulative_consolidated_inr)}" r="3.2" fill="#a855f7">
      <title>${p.label} — Consolidated: ${formatINR(p.cumulative_consolidated_inr)}</title>
    </circle>
  `).join("");

  containerEl.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" width="100%" height="142" aria-label="Flow Timeline Chart">
      <defs>
        <linearGradient id="gradOut" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.26"/>
          <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.0"/>
        </linearGradient>
        <linearGradient id="gradCons" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#a855f7" stop-opacity="0.24"/>
          <stop offset="100%" stop-color="#a855f7" stop-opacity="0.0"/>
        </linearGradient>
      </defs>
      ${yTicks}
      <polygon points="${outArea}" fill="url(#gradOut)"></polygon>
      <polygon points="${consArea}" fill="url(#gradCons)"></polygon>
      <polyline points="${outPts}" fill="none" stroke="#38bdf8" stroke-width="2"></polyline>
      <polyline points="${consPts}" fill="none" stroke="#a855f7" stroke-width="2"></polyline>
      ${dots}
      ${xLabels}
    </svg>
    <div style="display:flex;justify-content:center;gap:16px;font-size:11px;color:#cbd5e1;margin-top:2px;">
      <span style="display:inline-flex;align-items:center;gap:5px;"><span class="legend-dot" style="background:#38bdf8;"></span>Outflow (Cumulative)</span>
      <span style="display:inline-flex;align-items:center;gap:5px;"><span class="legend-dot" style="background:#a855f7;"></span>Consolidated (Cumulative)</span>
    </div>
  `;
}
