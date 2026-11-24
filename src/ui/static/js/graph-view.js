/**
 * AuditGuard Interactive Transaction Network Graph Component (`graph-view.js`)
 *
 * - Builds directed multigraph strictly from real backend `transactions` & `candidate_paths`
 * - Supports Topological Hierarchical layout (any hop depth), Force-Directed layout, and Circular layout
 * - Supports Zoom In/Out, Wheel Zoom, Canvas Pan, Node Drag, Fit-to-Screen, Search Filter, and Path Focus
 * - Renders glowing FinTech circular node badges (Green Source, Blue Intermediary, Amber Destination,
 *   Red High-Risk KYC Halo, Grey Unknown) + directed edges with formatted INR labels + dashed detected paths
 */
import { formatINR } from "./api.js?v=1.2.1";

const SVG_NS = "http://www.w3.org/2000/svg";

const ROLE_COLORS = {
  source: { stroke: "#10b981", fill: "#062c22", glow: "rgba(16,185,129,0.45)", label: "Source" },
  intermediary: { stroke: "#3b82f6", fill: "#0c2147", glow: "rgba(59,130,246,0.45)", label: "Intermediary" },
  destination: { stroke: "#f59e0b", fill: "#362106", glow: "rgba(245,158,11,0.45)", label: "Destination" },
  unknown: { stroke: "#64748b", fill: "#1e293b", glow: "rgba(100,116,139,0.35)", label: "Incomplete" },
};

export class TransactionGraphView {
  constructor(viewportEl, tooltipEl, callbacks = {}) {
    this.viewportEl = viewportEl;
    this.tooltipEl = tooltipEl;
    this.callbacks = callbacks;

    this.nodes = [];
    this.edges = [];
    this.paths = [];
    this.layoutMode = "hierarchical";
    this.focusedPathId = "all";
    this.searchQuery = "";
    this.selectedId = null;

    // Camera transform
    this.scale = 1;
    this.tx = 0;
    this.ty = 0;

    this._isPanning = false;
    this._dragNode = null;
    this._panStart = { x: 0, y: 0 };

    this._initSVG();
  }

  _initSVG() {
    this.viewportEl.querySelectorAll("svg").forEach((el) => el.remove());
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("aria-label", "Interactive Transaction Flow Network");

    svg.innerHTML = `
      <defs>
        <filter id="glow-source" x="-40%" y="-40%" width="180%" height="180%">
          <feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="#10b981" flood-opacity="0.65"/>
        </filter>
        <filter id="glow-intermediary" x="-40%" y="-40%" width="180%" height="180%">
          <feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="#3b82f6" flood-opacity="0.65"/>
        </filter>
        <filter id="glow-destination" x="-40%" y="-40%" width="180%" height="180%">
          <feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="#f59e0b" flood-opacity="0.65"/>
        </filter>
        <filter id="glow-risk" x="-45%" y="-45%" width="190%" height="190%">
          <feDropShadow dx="0" dy="0" stdDeviation="7" flood-color="#f43f5e" flood-opacity="0.8"/>
        </filter>
        <marker id="arrow-normal" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse">
          <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill="#94a3b8"/>
        </marker>
        <marker id="arrow-highlight" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill="#38bdf8"/>
        </marker>
      </defs>
      <g class="camera-layer">
        <g class="paths-layer"></g>
        <g class="edges-layer"></g>
        <g class="nodes-layer"></g>
      </g>
    `;

    this.svg = svg;
    this.cameraG = svg.querySelector(".camera-layer");
    this.pathsG = svg.querySelector(".paths-layer");
    this.edgesG = svg.querySelector(".edges-layer");
    this.nodesG = svg.querySelector(".nodes-layer");
    this.viewportEl.prepend(svg);

    this._bindCanvasEvents();
  }

  _bindCanvasEvents() {
    this.svg.addEventListener("wheel", (e) => {
      e.preventDefault();
      const rect = this.svg.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const factor = e.deltaY < 0 ? 1.12 : 0.89;
      const nextScale = Math.min(2.6, Math.max(0.42, this.scale * factor));
      this.tx = mx - ((mx - this.tx) / this.scale) * nextScale;
      this.ty = my - ((my - this.ty) / this.scale) * nextScale;
      this.scale = nextScale;
      this._applyTransform();
    }, { passive: false });

    this.svg.addEventListener("mousedown", (e) => {
      if (e.target.closest(".graph-node") || e.target.closest(".graph-edge")) return;
      this._isPanning = true;
      this._panStart = { x: e.clientX - this.tx, y: e.clientY - this.ty };
    });

    window.addEventListener("mousemove", (e) => {
      if (this._dragNode) {
        const rect = this.svg.getBoundingClientRect();
        this._dragNode.x = (e.clientX - rect.left - this.tx) / this.scale;
        this._dragNode.y = (e.clientY - rect.top - this.ty) / this.scale;
        this._renderGeometryOnly();
        return;
      }
      if (!this._isPanning) return;
      this.tx = e.clientX - this._panStart.x;
      this.ty = e.clientY - this._panStart.y;
      this._applyTransform();
    });

    window.addEventListener("mouseup", () => {
      this._isPanning = false;
      this._dragNode = null;
    });
  }

  _applyTransform() {
    if (this.cameraG) {
      this.cameraG.setAttribute("transform", `translate(${this.tx.toFixed(1)}, ${this.ty.toFixed(1)}) scale(${this.scale.toFixed(3)})`);
    }
  }

  zoomBy(factor) {
    const rect = this.svg.getBoundingClientRect();
    const cx = rect.width / 2;
    const cy = rect.height / 2;
    const next = Math.min(2.6, Math.max(0.42, this.scale * factor));
    this.tx = cx - ((cx - this.tx) / this.scale) * next;
    this.ty = cy - ((cy - this.ty) / this.scale) * next;
    this.scale = next;
    this._applyTransform();
  }

  fitToScreen() {
    if (!this.nodes.length) return;
    const rect = this.svg.getBoundingClientRect();
    const W = rect.width || 680;
    const H = rect.height || 350;

    const minX = Math.min(...this.nodes.map((n) => n.x)) - 75;
    const maxX = Math.max(...this.nodes.map((n) => n.x)) + 75;
    const minY = Math.min(...this.nodes.map((n) => n.y)) - 58;
    const maxY = Math.max(...this.nodes.map((n) => n.y)) + 68;

    const bw = Math.max(120, maxX - minX);
    const bh = Math.max(120, maxY - minY);
    const padX = 36;
    const padY = 24;

    this.scale = Math.min(1.25, Math.max(0.5, Math.min((W - padX * 2) / bw, (H - padY * 2) / bh)));
    this.tx = (W - bw * this.scale) / 2 - minX * this.scale + 22;
    this.ty = (H - bh * this.scale) / 2 - minY * this.scale;
    this._applyTransform();
  }

  setLayout(mode) {
    this.layoutMode = mode;
    this._computeLayout();
    this.render();
    this.fitToScreen();
  }

  setFocusedPath(pathId) {
    this.focusedPathId = pathId || "all";
    this.render();
  }

  setSearchFilter(query) {
    this.searchQuery = (query || "").trim().toLowerCase();
    this.render();
  }

  clear(message = "Loading transaction flow network...") {
    this.nodes = [];
    this.edges = [];
    this.paths = [];
    this.focusedPathId = "all";
    this.searchQuery = "";
    this.selectedId = null;
    this.scale = 1;
    this.tx = 0;
    this.ty = 0;
    this._hideTooltip();
    this._applyTransform();
    if (this.pathsG) this.pathsG.innerHTML = "";
    if (this.edgesG) this.edgesG.innerHTML = "";
    if (this.nodesG) {
      this.nodesG.innerHTML = "";
      const txt = document.createElementNS(SVG_NS, "text");
      txt.setAttribute("x", "50%");
      txt.setAttribute("y", "50%");
      txt.setAttribute("text-anchor", "middle");
      txt.setAttribute("fill", "#7c8db0");
      txt.setAttribute("font-size", "13");
      txt.textContent = message;
      this.nodesG.appendChild(txt);
    }
  }

  /**
   * Populate graph strictly from backend investigation state.
   */
  setData({ rootAccount, transactions = [], candidatePaths = [], kycProfiles = [], nodeRoles = {} }) {
    this.focusedPathId = "all";
    this.searchQuery = "";
    this._hideTooltip();
    const kycMap = {};
    for (const k of kycProfiles) {
      if (k.account_id) kycMap[k.account_id] = k;
    }

    const accountSet = new Set();
    if (rootAccount) accountSet.add(rootAccount);
    for (const tx of transactions) {
      if (tx.sender_account) accountSet.add(tx.sender_account);
      if (tx.receiver_account) accountSet.add(tx.receiver_account);
    }

    const txCountByAcc = {};
    for (const acc of accountSet) txCountByAcc[acc] = 0;
    for (const tx of transactions) {
      if (tx.sender_account) txCountByAcc[tx.sender_account] = (txCountByAcc[tx.sender_account] || 0) + 1;
      if (tx.receiver_account) txCountByAcc[tx.receiver_account] = (txCountByAcc[tx.receiver_account] || 0) + 1;
    }

    // Build nodes
    const senders = new Set(transactions.map((t) => t.sender_account).filter(Boolean));
    const receivers = new Set(transactions.map((t) => t.receiver_account).filter(Boolean));

    this.nodes = Array.from(accountSet).map((accId) => {
      let role = nodeRoles[accId];
      if (!role) {
        const s = senders.has(accId);
        const r = receivers.has(accId);
        if (accId === rootAccount && s && !r) role = "source";
        else if (s && !r) role = "source";
        else if (s && r) role = "intermediary";
        else if (r && !s) role = "destination";
        else role = "unknown";
      }
      const kyc = kycMap[accId] || {};
      return {
        id: accId,
        role,
        kyc,
        risk: String(kyc.risk_category || "").toLowerCase(),
        isHighRisk: String(kyc.risk_category || "").toLowerCase() === "high",
        isRegistered: Boolean(kyc.is_commercially_registered || kyc.registry_check?.is_registered),
        txCount: txCountByAcc[accId] || 0,
        x: 0,
        y: 0,
      };
    });

    // Aggregate parallel transfers between same pair so labels stay ultra-crisp, while keeping all underlying TXNs
    const pairMap = new Map();
    transactions.forEach((tx, idx) => {
      const s = tx.sender_account;
      const r = tx.receiver_account;
      if (!s || !r) return;
      const key = `${s}->${r}`;
      if (!pairMap.has(key)) {
        pairMap.set(key, {
          id: tx.tx_id || `EDGE-${idx}`,
          source: s,
          target: r,
          amount_inr: 0,
          txs: [],
          latest_timestamp: tx.timestamp || "",
          channel: tx.channel || "NEFT",
        });
      }
      const entry = pairMap.get(key);
      entry.amount_inr += Number(tx.amount_inr || 0);
      entry.txs.push(tx);
    });

    this.edges = Array.from(pairMap.values());
    this.paths = candidatePaths || [];
    this.selectedId = null;

    this._computeLayout();
    this.render();
    this.fitToScreen();
  }

  _computeLayout() {
    const rect = this.svg.getBoundingClientRect();
    const W = Math.max(rect.width || 680, 560);
    const H = Math.max(rect.height || 350, 310);

    if (!this.nodes.length) return;

    if (this.layoutMode === "circular") {
      const cx = W / 2;
      const cy = H / 2;
      const rad = Math.min(W, H) * 0.34;
      this.nodes.forEach((n, i) => {
        const ang = (2 * Math.PI * i) / this.nodes.length - Math.PI / 2;
        n.x = cx + rad * Math.cos(ang);
        n.y = cy + rad * Math.sin(ang);
      });
      return;
    }

    if (this.layoutMode === "force") {
      // Deterministic Fruchterman-Reingold spring layout
      const area = W * H;
      const k = Math.sqrt(area / Math.max(this.nodes.length, 1)) * 0.72;
      this.nodes.forEach((n, i) => {
        const ang = (2 * Math.PI * i) / this.nodes.length;
        n.x = W / 2 + Math.cos(ang) * 120;
        n.y = H / 2 + Math.sin(ang) * 90;
      });
      const nodeById = Object.fromEntries(this.nodes.map((n) => [n.id, n]));
      for (let iter = 0; iter < 65; iter++) {
        const disp = Object.fromEntries(this.nodes.map((n) => [n.id, { x: 0, y: 0 }]));
        for (let i = 0; i < this.nodes.length; i++) {
          for (let j = i + 1; j < this.nodes.length; j++) {
            const u = this.nodes[i];
            const v = this.nodes[j];
            const dx = u.x - v.x || 0.1;
            const dy = u.y - v.y || 0.1;
            const dist = Math.hypot(dx, dy) || 0.1;
            const rep = (k * k) / dist;
            disp[u.id].x += (dx / dist) * rep;
            disp[u.id].y += (dy / dist) * rep;
            disp[v.id].x -= (dx / dist) * rep;
            disp[v.id].y -= (dy / dist) * rep;
          }
        }
        for (const e of this.edges) {
          const u = nodeById[e.source];
          const v = nodeById[e.target];
          if (!u || !v) continue;
          const dx = u.x - v.x;
          const dy = u.y - v.y;
          const dist = Math.hypot(dx, dy) || 0.1;
          const att = (dist * dist) / k;
          disp[u.id].x -= (dx / dist) * att;
          disp[u.id].y -= (dy / dist) * att;
          disp[v.id].x += (dx / dist) * att;
          disp[v.id].y += (dy / dist) * att;
        }
        const temp = Math.max(4, 38 * (1 - iter / 65));
        for (const n of this.nodes) {
          const d = Math.hypot(disp[n.id].x, disp[n.id].y) || 1;
          n.x = Math.min(W - 60, Math.max(90, n.x + (disp[n.id].x / d) * Math.min(d, temp)));
          n.y = Math.min(H - 55, Math.max(55, n.y + (disp[n.id].y / d) * Math.min(d, temp)));
        }
      }
      return;
    }

    // Default: Topological Hierarchical BFS Layout (Source -> Tier 1 -> ... -> Destination)
    const adj = {};
    const indeg = {};
    for (const n of this.nodes) {
      adj[n.id] = [];
      indeg[n.id] = 0;
    }
    for (const e of this.edges) {
      if (adj[e.source]) adj[e.source].push(e.target);
      if (indeg[e.target] !== undefined) indeg[e.target] += 1;
    }

    const ranks = {};
    const queue = [];
    for (const n of this.nodes) {
      if (n.role === "source" || indeg[n.id] === 0) {
        ranks[n.id] = 0;
        queue.push(n.id);
      }
    }
    if (!queue.length && this.nodes.length) {
      ranks[this.nodes[0].id] = 0;
      queue.push(this.nodes[0].id);
    }

    while (queue.length) {
      const curr = queue.shift();
      const r = ranks[curr] || 0;
      for (const nxt of adj[curr] || []) {
        if (ranks[nxt] === undefined || ranks[nxt] < r + 1) {
          if (r + 1 <= 6) {
            ranks[nxt] = r + 1;
            queue.push(nxt);
          }
        }
      }
    }
    for (const n of this.nodes) {
      if (ranks[n.id] === undefined) ranks[n.id] = 1;
    }

    const maxRank = Math.max(1, ...Object.values(ranks));
    // Ensure terminal destinations align cleanly on the rightmost column
    for (const n of this.nodes) {
      if (n.role === "destination" && maxRank >= 2) {
        ranks[n.id] = maxRank;
      }
    }

    const layers = {};
    for (const n of this.nodes) {
      const rk = ranks[n.id];
      if (!layers[rk]) layers[rk] = [];
      layers[rk].push(n);
    }

    const sortedRanks = Object.keys(layers).map(Number).sort((a, b) => a - b);
    const leftX = 165;
    const rightX = Math.max(leftX + 260, W - 105);
    const colSpan = sortedRanks.length > 1 ? (rightX - leftX) / (sortedRanks.length - 1) : 0;

    sortedRanks.forEach((rk, colIdx) => {
      const colNodes = layers[rk];
      const x = sortedRanks.length === 1 ? W / 2 : leftX + colIdx * colSpan;
      const topY = 66;
      const botY = H - 68;
      colNodes.forEach((node, rowIdx) => {
        node.x = x;
        node.y = colNodes.length === 1
          ? H / 2
          : topY + (rowIdx / (colNodes.length - 1)) * (botY - topY);
      });
    });
  }

  _activeEdgePairs() {
    const pairs = new Set();
    const targetPaths = this.focusedPathId === "all"
      ? this.paths.filter((p) => p.hop_count >= 2)
      : this.paths.filter((p) => p.path_id === this.focusedPathId);

    for (const p of targetPaths) {
      const ns = p.nodes || [];
      for (let i = 0; i < ns.length - 1; i++) {
        pairs.add(`${ns[i]}->${ns[i + 1]}`);
      }
    }
    return pairs;
  }

  _showTooltip(evt, html) {
    if (!this.tooltipEl) return;
    const rect = this.viewportEl.getBoundingClientRect();
    this.tooltipEl.innerHTML = html;
    this.tooltipEl.style.display = "block";
    const x = Math.min(rect.width - 250, Math.max(10, evt.clientX - rect.left + 14));
    const y = Math.min(rect.height - 110, Math.max(10, evt.clientY - rect.top + 14));
    this.tooltipEl.style.left = `${x}px`;
    this.tooltipEl.style.top = `${y}px`;
  }

  _hideTooltip() {
    if (this.tooltipEl) this.tooltipEl.style.display = "none";
  }

  _nodeIconSVG(role) {
    if (role === "source") {
      // Crisp User / Originator icon
      return `
        <circle cx="0" cy="-5" r="5.5" fill="none" stroke="#ffffff" stroke-width="1.8"/>
        <path d="M -9.5 9 C -9.5 3.5, 9.5 3.5, 9.5 9" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round"/>
      `;
    }
    // Crisp Bank Institution Pillars icon
    return `
      <path d="M -10 -3 L 0 -9.5 L 10 -3 Z" fill="none" stroke="#ffffff" stroke-width="1.6" stroke-linejoin="round"/>
      <line x1="-7" y1="-3" x2="-7" y2="6" stroke="#ffffff" stroke-width="1.6"/>
      <line x1="0" y1="-3" x2="0" y2="6" stroke="#ffffff" stroke-width="1.6"/>
      <line x1="7" y1="-3" x2="7" y2="6" stroke="#ffffff" stroke-width="1.6"/>
      <line x1="-10" y1="6.5" x2="10" y2="6.5" stroke="#ffffff" stroke-width="1.8"/>
    `;
  }

  _edgeEndpoints(u, v, rOffset = 29) {
    const dx = v.x - u.x;
    const dy = v.y - u.y;
    const dist = Math.hypot(dx, dy) || 1;
    return {
      x1: u.x + (dx / dist) * rOffset,
      y1: u.y + (dy / dist) * rOffset,
      x2: v.x - (dx / dist) * (rOffset + 4),
      y2: v.y - (dy / dist) * (rOffset + 4),
    };
  }

  _renderGeometryOnly() {
    // Fast drag update without recreating DOM
    this.render();
  }

  render() {
    if (!this.nodes.length) {
      this.pathsG.innerHTML = "";
      this.edgesG.innerHTML = "";
      this.nodesG.innerHTML = `
        <text x="50%" y="50%" text-anchor="middle" fill="#7c8db0" font-size="13">
          No transaction edges available for this alert.
        </text>
      `;
      return;
    }

    const nodeMap = Object.fromEntries(this.nodes.map((n) => [n.id, n]));
    const highlightedPairs = this._activeEdgePairs();

    // 1. Render dashed detected path underlays + solid directed edges
    let pathsMarkup = "";
    let edgesMarkup = "";

    this.edges.forEach((edge) => {
      const u = nodeMap[edge.source];
      const v = nodeMap[edge.target];
      if (!u || !v) return;

      const pts = this._edgeEndpoints(u, v, 28);
      const pairKey = `${edge.source}->${edge.target}`;
      const isHighlighted = highlightedPairs.size === 0 || highlightedPairs.has(pairKey);
      const isDimmed = (this.focusedPathId !== "all" && !isHighlighted) ||
        (this.searchQuery && !edge.source.toLowerCase().includes(this.searchQuery) && !edge.target.toLowerCase().includes(this.searchQuery));

      const opacity = isDimmed ? 0.22 : 1.0;
      const midX = (pts.x1 + pts.x2) / 2;
      const midY = (pts.y1 + pts.y2) / 2;

      if (highlightedPairs.has(pairKey)) {
        pathsMarkup += `
          <line x1="${pts.x1.toFixed(1)}" y1="${(pts.y1 + 5).toFixed(1)}"
                x2="${pts.x2.toFixed(1)}" y2="${(pts.y2 + 5).toFixed(1)}"
                stroke="#38bdf8" stroke-opacity="${(0.55 * opacity).toFixed(2)}"
                stroke-width="1.5" stroke-dasharray="5 4" />
        `;
      }

      const isSelected = this.selectedId === edge.id;
      const strokeColor = isSelected ? "#38bdf8" : highlightedPairs.has(pairKey) ? "#cbd5e1" : "#94a3b8";
      const marker = isSelected || highlightedPairs.has(pairKey) ? "url(#arrow-highlight)" : "url(#arrow-normal)";
      const amtText = formatINR(edge.amount_inr);

      edgesMarkup += `
        <g class="graph-edge" data-edge-id="${edge.id}" style="opacity:${opacity};cursor:pointer;">
          <line x1="${pts.x1.toFixed(1)}" y1="${pts.y1.toFixed(1)}"
                x2="${pts.x2.toFixed(1)}" y2="${pts.y2.toFixed(1)}"
                stroke="transparent" stroke-width="14" />
          <line x1="${pts.x1.toFixed(1)}" y1="${pts.y1.toFixed(1)}"
                x2="${pts.x2.toFixed(1)}" y2="${pts.y2.toFixed(1)}"
                stroke="${strokeColor}" stroke-width="${isSelected ? 2.6 : 1.7}"
                marker-end="${marker}" />
          <rect x="${(midX - 36).toFixed(1)}" y="${(midY - 19).toFixed(1)}"
                width="72" height="16" rx="4"
                fill="#090f1f" fill-opacity="0.88" stroke="#1e293b" stroke-width="0.8" />
          <text x="${midX.toFixed(1)}" y="${(midY - 8).toFixed(1)}"
                text-anchor="middle" fill="#f8fafc" font-size="10.5" font-weight="600">${amtText}</text>
        </g>
      `;
    });

    this.pathsG.innerHTML = pathsMarkup;
    this.edgesG.innerHTML = edgesMarkup;

    // 2. Render glowing circular nodes
    let nodesMarkup = "";
    this.nodes.forEach((node) => {
      const palette = ROLE_COLORS[node.role] || ROLE_COLORS.unknown;
      const matchesSearch = !this.searchQuery ||
        node.id.toLowerCase().includes(this.searchQuery) ||
        String(node.kyc?.entity_name || "").toLowerCase().includes(this.searchQuery);
      const opacity = matchesSearch ? 1.0 : 0.22;
      const isSel = this.selectedId === node.id;
      const filterId = node.isHighRisk ? "glow-risk" : `glow-${node.role === "unknown" ? "intermediary" : node.role}`;

      const roleCaption = node.role === "source" ? "(Source)" : node.role === "destination" ? "(Destination)" : "";

      nodesMarkup += `
        <g class="graph-node" data-node-id="${node.id}"
           transform="translate(${node.x.toFixed(1)}, ${node.y.toFixed(1)})"
           style="opacity:${opacity};cursor:pointer;">
          ${
            node.isHighRisk
              ? `<circle cx="0" cy="0" r="29" fill="none" stroke="#f43f5e" stroke-width="1.6" stroke-dasharray="3 3"/>`
              : ""
          }
          ${
            isSel
              ? `<circle cx="0" cy="0" r="31" fill="none" stroke="#38bdf8" stroke-width="2.2"/>`
              : ""
          }
          <circle cx="0" cy="0" r="24" fill="${palette.fill}" stroke="${palette.stroke}"
                  stroke-width="2.3" filter="url(#${filterId})" />
          ${this._nodeIconSVG(node.role)}
          <text x="0" y="38" text-anchor="middle" fill="#f1f5f9" font-size="11" font-weight="700">${node.id}</text>
          ${
            roleCaption
              ? `<text x="0" y="51" text-anchor="middle" fill="#94a3b8" font-size="10">${roleCaption}</text>`
              : ""
          }
        </g>
      `;
    });

    this.nodesG.innerHTML = nodesMarkup;

    // Bind node & edge listeners
    this.nodesG.querySelectorAll(".graph-node").forEach((el) => {
      const id = el.getAttribute("data-node-id");
      const node = nodeMap[id];
      if (!node) return;

      el.addEventListener("mousedown", (e) => {
        e.stopPropagation();
        this._dragNode = node;
      });

      el.addEventListener("click", (e) => {
        e.stopPropagation();
        this.selectedId = node.id;
        this.render();
        if (this.callbacks.onSelectNode) this.callbacks.onSelectNode(node);
      });

      el.addEventListener("mousemove", (e) => {
        const k = node.kyc || {};
        this._showTooltip(
          e,
          `<div style="font-weight:700;color:#fff;margin-bottom:3px;">${node.id} <span style="color:#38bdf8;">(${ROLE_COLORS[node.role]?.label})</span></div>
           <div>Entity: <strong>${k.entity_name || "Unverified"}</strong></div>
           <div>Bank: ${k.bank_name || "Multi-Bank"} · KYC Risk: <strong style="text-transform:uppercase;">${k.risk_category || "N/A"}</strong></div>
           <div>Registry: ${node.isRegistered ? `ACTIVE (${k.registry_type || "VERIFIED"})` : "NOT FOUND"}</div>
           <div>Connected Transfers: ${node.txCount}</div>`
        );
      });
      el.addEventListener("mouseleave", () => this._hideTooltip());
    });

    this.edgesG.querySelectorAll(".graph-edge").forEach((el) => {
      const eid = el.getAttribute("data-edge-id");
      const edge = this.edges.find((x) => x.id === eid);
      if (!edge) return;

      el.addEventListener("click", (e) => {
        e.stopPropagation();
        this.selectedId = edge.id;
        this.render();
        if (this.callbacks.onSelectEdge) this.callbacks.onSelectEdge(edge);
      });

      el.addEventListener("mousemove", (e) => {
        const tx0 = edge.txs[0] || {};
        this._showTooltip(
          e,
          `<div style="font-weight:700;color:#38bdf8;margin-bottom:3px;">${edge.id}${edge.txs.length > 1 ? ` (+${edge.txs.length - 1} more)` : ""}</div>
           <div>Flow: <strong>${edge.source} → ${edge.target}</strong></div>
           <div>Amount: <strong>${formatINR(edge.amount_inr)}</strong> (${edge.channel})</div>
           <div>Timestamp: ${String(tx0.timestamp || "").slice(0, 19).replace("T", " ")}</div>
           <div style="color:#94a3b8;">Memo: ${String(tx0.memo || "N/A").replace(/<[^>]+>/g, "")}</div>`
        );
      });
      el.addEventListener("mouseleave", () => this._hideTooltip());
    });

    this._applyTransform();
  }
}
