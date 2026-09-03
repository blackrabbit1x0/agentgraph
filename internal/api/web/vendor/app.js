// AgentGraph dashboard application.
// Security notes: every dynamic value rendered via innerHTML is passed
// through esc(); click handlers are closures (never string-interpolated
// onclick attributes); Cytoscape selections use .filter() instead of
// selector strings built from node IDs.
'use strict';

const TYPE_COLORS = {
  AI_AGENT: '#f778ba', MCP_SERVER: '#bc8cff', TOOL: '#d2a8ff',
  IDENTITY: '#58a6ff', SECRET: '#ff7b72', REPOSITORY: '#3fb950',
  CI_PIPELINE: '#d29922', CLOUD_ROLE: '#ffa657', CLOUD_RESOURCE: '#f0883e',
  DATABASE: '#f85149', HOST: '#8b949e', API: '#79c0ff', DATASET: '#e3b341',
};
const TYPE_LABEL = {
  AI_AGENT: 'AI Agent', MCP_SERVER: 'MCP Server', TOOL: 'Tool',
  IDENTITY: 'Identity', SECRET: 'Secret', REPOSITORY: 'Repository',
  CI_PIPELINE: 'CI Pipeline', CLOUD_ROLE: 'Cloud Role', CLOUD_RESOURCE: 'Cloud Resource',
  DATABASE: 'Database', HOST: 'Host', API: 'API', DATASET: 'Dataset',
};

let cy = null;
let selectedAgent = null;

// esc escapes a value for safe interpolation into HTML text and
// double-quoted attribute contexts.
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// authToken returns the API token from sessionStorage, if any.
function authToken() {
  try { return sessionStorage.getItem('agentgraph_token') || ''; } catch { return ''; }
}

// api fetches an API endpoint. On 401 it prompts for the token once,
// stores it, and retries.
async function api(path) {
  const doFetch = () => {
    const headers = {};
    const t = authToken();
    if (t) headers['Authorization'] = 'Bearer ' + t;
    return fetch(path, { headers });
  };
  let res = await doFetch();
  if (res.status === 401) {
    const t = window.prompt('AgentGraph API token:');
    if (t !== null) {
      try { sessionStorage.setItem('agentgraph_token', t); } catch { /* ignore */ }
      res = await doFetch();
    }
  }
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch { /* keep statusText */ }
    throw new Error(msg);
  }
  return res.json();
}

function shortName(id) {
  const parts = String(id).split('/');
  return parts[parts.length - 1] || id;
}

function initGraph(snapshot) {
  const nodes = snapshot.nodes.map(n => ({
    data: {
      id: n.id, label: shortName(n.Name || n.id), fullLabel: n.Name || n.id,
      type: n.Type, crown: !!n.crown_jewel,
      criticality: n.criticality || 0,
      metadata: n.metadata || {},
    },
  }));
  const edges = snapshot.edges.map(e => ({
    data: {
      id: e.source + '|' + e.type + '|' + e.target,
      source: e.source, target: e.target, label: e.type,
      confidence: e.confidence || 1,
    },
  }));

  cy = cytoscape({
    container: document.getElementById('cy'),
    elements: [...nodes, ...edges],
    layout: { name: 'dagre', rankDir: 'LR', nodeSep: 40, rankSep: 90, animate: true },
    style: [
      { selector: 'node', style: {
        'background-color': 'data(color)',
        'label': 'data(label)', 'color': '#c9d1d9', 'font-size': 10,
        'width': 30, 'height': 30,
        'border-width': 2, 'border-color': '#30363d',
        'text-valign': 'bottom', 'text-margin-y': 6,
        'text-wrap': 'wrap', 'text-max-width': 90,
      }},
      { selector: 'node[crown = true]', style: {
        'border-width': 3, 'border-color': '#e3b341',
        'shape': 'diamond', 'width': 36, 'height': 36,
      }},
      { selector: 'node[type = "AI_AGENT"]', style: { 'width': 40, 'height': 40, 'font-size': 11 }},
      { selector: 'edge', style: {
        'width': 1.5, 'line-color': '#30363d',
        'target-arrow-color': '#30363d', 'target-arrow-shape': 'triangle',
        'curve-style': 'bezier', 'arrow-scale': 0.7,
      }},
      { selector: 'edge[label = "CAN_ADMIN"], edge[label = "CAN_EXECUTE"], edge[label = "CAN_IMPERSONATE"]',
        style: { 'line-color': '#f85149', 'target-arrow-color': '#f85149', 'width': 2.5 }},
      { selector: 'edge[label = "CAN_ASSUME"]', style: { 'line-color': '#ffa657', 'target-arrow-color': '#ffa657' }},
      { selector: 'edge[label = "CONTAINS_SECRET"], edge[label = "HAS_SECRET"]',
        style: { 'line-color': '#ff7b72', 'target-arrow-color': '#ff7b72' }},
      { selector: '.highlighted', style: { 'line-color': '#58a6ff', 'target-arrow-color': '#58a6ff', 'width': 3 }},
      { selector: '.faded', style: { 'opacity': 0.15 }},
      { selector: '.pathnode', style: { 'border-color': '#58a6ff', 'border-width': 3 }},
    ],
  });

  cy.nodes().forEach(n => {
    n.style('background-color', TYPE_COLORS[n.data('type')] || '#8b949e');
  });

  cy.on('tap', 'node', evt => {
    const n = evt.target;
    const meta = n.data('metadata') || {};
    const rows = [];
    const addRow = (k, v) => {
      const div = document.createElement('div');
      div.className = 'krow';
      const ke = document.createElement('span'); ke.className = 'k'; ke.textContent = k;
      const ve = document.createElement('span'); ve.className = 'v'; ve.textContent = v;
      div.appendChild(ke); div.appendChild(ve);
      rows.push(div);
    };
    addRow('Type', TYPE_LABEL[n.data('type')] || n.data('type'));
    addRow('ID', n.id());
    if (n.data('crown')) addRow('Crown Jewel', 'yes');
    if (n.data('criticality')) addRow('Criticality', n.data('criticality') + '/100');
    for (const [k, v] of Object.entries(meta)) {
      addRow(k, typeof v === 'object' ? JSON.stringify(v) : v);
    }
    const details = document.getElementById('details');
    details.replaceChildren(...rows);
    if (n.data('type') === 'AI_AGENT') {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = 'Analyze blast radius';
      btn.addEventListener('click', () => selectAgent(n.id()));
      const wrap = document.createElement('div');
      wrap.style.marginTop = '10px';
      wrap.appendChild(btn);
      details.appendChild(wrap);
    }
  });
}

function renderStats(snapshot, counts) {
  const el = document.getElementById('stats');
  el.replaceChildren();
  const add = (html) => {
    const span = document.createElement('span');
    span.innerHTML = html;
    el.appendChild(span);
  };
  add(`Agents <b>${esc(counts.agents)}</b>`);
  add(`Nodes <b>${esc(snapshot.nodes.length)}</b>`);
  add(`Edges <b>${esc(snapshot.edges.length)}</b>`);
  add(`Critical paths <b style="color:var(--critical)">${esc(counts.critical)}</b>`);
  add(`High paths <b style="color:var(--high)">${esc(counts.high)}</b>`);
  add(`Crown jewels exposed <b class="crown">${esc(counts.crownExposed)}</b>`);
}

function renderAgents(agents) {
  const el = document.getElementById('agents');
  el.replaceChildren();
  agents.sort((a, b) => b.exposure_score - a.exposure_score);
  for (const a of agents) {
    const div = document.createElement('div');
    div.className = 'agent-item';
    const name = document.createElement('span');
    name.className = 'name'; name.textContent = a.id;
    const risk = document.createElement('span');
    risk.className = 'risk';
    const sev = document.createElement('span');
    sev.className = 'sev sev-' + a.exposure_risk;
    sev.textContent = a.exposure_risk;
    risk.append(document.createTextNode(a.exposure_score + ' '), sev);
    div.append(name, risk);
    div.addEventListener('click', () => selectAgent(a.id));
    if (a.id === selectedAgent) div.classList.add('active');
    el.appendChild(div);
  }
}

async function selectAgent(id) {
  selectedAgent = id;
  document.querySelectorAll('.agent-item').forEach(el => el.classList.remove('active'));
  cy.elements().removeClass('faded highlighted pathnode');

  const rad = await api(`/api/v1/agents/${encodeURIComponent(id)}/blast-radius`);
  const details = document.getElementById('details');
  details.replaceChildren();
  const addRow = (k, v, cls) => {
    const div = document.createElement('div');
    div.className = 'krow';
    const ke = document.createElement('span'); ke.className = 'k'; ke.textContent = k;
    const ve = document.createElement('span'); ve.className = 'v'; ve.textContent = v;
    if (cls) ve.classList.add(cls);
    div.append(ke, ve);
    details.appendChild(div);
  };
  addRow('Agent', rad.agent);
  const riskWrap = document.createElement('span');
  riskWrap.className = 'v';
  const sev = document.createElement('span');
  sev.className = 'sev sev-' + rad.exposure_risk;
  sev.textContent = rad.exposure_risk;
  riskWrap.append(document.createTextNode(rad.exposure_score + ' '), sev);
  {
    const div = document.createElement('div');
    div.className = 'krow';
    const ke = document.createElement('span'); ke.className = 'k'; ke.textContent = 'Exposure';
    div.append(ke, riskWrap);
    details.appendChild(div);
  }
  addRow('Reachable nodes', rad.reachable_nodes);
  addRow('Secrets', rad.secrets);
  addRow('Cloud roles', rad.cloud_roles);
  if (rad.highest_privilege) addRow('Highest privilege', rad.highest_privilege);
  if (rad.crown_jewels && rad.crown_jewels.length) {
    addRow('Crown jewels', rad.crown_jewels.join(', '), 'crown');
  }
  addRow('Paths', `${rad.total_paths} (${rad.critical_paths} critical)`);
  if (rad.most_dangerous_path) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.style.margin = '10px 0 4px';
    p.textContent = `Most dangerous path (risk ${rad.most_dangerous_path.risk_score})`;
    details.appendChild(p);
  }
  {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = 'Recommend remediation';
    btn.addEventListener('click', () => runRemediation(id));
    const wrap = document.createElement('div');
    wrap.style.marginTop = '10px';
    wrap.appendChild(btn);
    const rem = document.createElement('div');
    rem.id = 'remediation';
    wrap.appendChild(rem);
    details.appendChild(wrap);
  }

  if (rad.most_dangerous_path) highlightPath(rad.most_dangerous_path);

  await renderAgentPaths(id);
}

function highlightPath(p) {
  cy.elements().removeClass('faded highlighted pathnode');
  const ids = p.hops.map(h => h.node);
  const idSet = new Set(ids);
  const chain = [];
  for (let i = 0; i < ids.length - 1; i++) {
    const from = ids[i], to = ids[i + 1];
    cy.edges().filter(e => e.data('source') === from && e.data('target') === to)
      .forEach(e => chain.push(e));
  }
  cy.elements().addClass('faded');
  cy.nodes().filter(n => idSet.has(n.id())).removeClass('faded').addClass('pathnode');
  chain.forEach(e => { e.removeClass('faded'); e.addClass('highlighted'); });
}

async function renderAgentPaths(id) {
  const el = document.getElementById('paths');
  el.replaceChildren();
  const loading = document.createElement('p');
  loading.className = 'muted'; loading.textContent = 'Loading paths...';
  el.appendChild(loading);
  const res = await api(`/api/v1/paths?from=${encodeURIComponent(id)}`);
  el.replaceChildren();
  for (const p of res.paths.slice(0, 20)) {
    const div = document.createElement('div');
    div.className = 'path';
    const head = document.createElement('div');
    const b = document.createElement('b'); b.textContent = p.id;
    head.append(b, document.createTextNode(
      ` ${Number(p.confidence).toFixed(2)} conf \u00b7 ${p.hops.length - 1} hops`));
    const hops = document.createElement('div');
    hops.className = 'hops';
    hops.textContent = p.hops.map(h => shortName(h.node)).join(' \u2192 ');
    div.append(head, hops);
    div.addEventListener('click', () => {
      document.querySelectorAll('.path').forEach(e => e.classList.remove('active'));
      div.classList.add('active');
      highlightPath(p);
    });
    el.appendChild(div);
  }
}

async function runRemediation(id) {
  const el = document.getElementById('remediation');
  if (!el) return;
  el.replaceChildren();
  const p = document.createElement('p');
  p.className = 'muted'; p.style.marginTop = '12px'; p.textContent = 'Computing...';
  el.appendChild(p);
  try {
    const rec = await api(`/api/v1/agents/${encodeURIComponent(id)}/remediations`);
    const e = rec.remove_edge;
    el.replaceChildren();
    const addRow = (k, v, color) => {
      const div = document.createElement('div');
      div.className = 'krow';
      const ke = document.createElement('span'); ke.className = 'k'; ke.textContent = k;
      const ve = document.createElement('span'); ve.className = 'v'; ve.textContent = v;
      if (color) ve.style.color = color;
      div.append(ke, ve);
      el.appendChild(div);
    };
    addRow('Remove', '');
    const edge = document.createElement('div');
    edge.style.wordBreak = 'break-all';
    edge.textContent = `${e.source}\n\u2500 ${e.type} \u2500\u25b6\n${e.target}`;
    edge.style.whiteSpace = 'pre';
    el.appendChild(edge);
    addRow('Paths', `${rec.paths_before} \u2192 ${rec.paths_after}`);
    addRow('Critical left', `${rec.critical_after} / ${rec.critical_before}`);
    addRow('Risk reduction', `${rec.risk_reduction_pct}%`, 'var(--low)');
  } catch (err) {
    el.replaceChildren();
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = 'Error: ' + err.message;
    el.appendChild(p);
  }
}

// Live alert feed via server-sent events (requires serve --watch).
function initAlertFeed() {
  if (typeof EventSource === 'undefined') return;
  const feed = document.getElementById('alert-feed');
  const badge = document.getElementById('live-badge');
  const status = document.getElementById('alert-status');
  let es;
  try {
    es = new EventSource('/api/v1/alerts/stream');
  } catch (e) {
    return; // runtime detection off; keep the hint text
  }
  es.onopen = () => {
    badge.style.display = 'inline-block';
    badge.classList.remove('off');
    if (status) status.remove();
  };
  es.onerror = () => {
    badge.classList.add('off');
  };
  es.addEventListener('alert', ev => {
    badge.style.display = 'inline-block';
    badge.classList.remove('off');
    if (status) status.remove();
    let a;
    try { a = JSON.parse(ev.data); } catch { return; }
    const div = document.createElement('div');
    div.className = 'alert-item ' + a.level;
    const head = document.createElement('div');
    const sev = document.createElement('span');
    sev.className = 'sev sev-' + (a.level === 'COMPLETE' ? 'CRITICAL' : a.level);
    sev.textContent = a.level;
    head.append(document.createTextNode(a.agent + ' \u2192 ' + a.target + ' '), sev);
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = `${a.stages_observed}/${a.total_stages} stages \u00b7 risk ${a.risk}/100` +
      (a.next_node ? ` \u00b7 next: ${a.next_node}` : '');
    div.append(head, meta);
    div.addEventListener('click', () => highlightPathByID(a.path_id, a.agent));
    feed.prepend(div);
    while (feed.children.length > 30) feed.removeChild(feed.lastChild);
  });
}

// Re-fetch paths and highlight the alert's path by ID.
async function highlightPathByID(pathID, agent) {
  try {
    const res = await api(`/api/v1/paths?from=${encodeURIComponent(agent)}`);
    const p = res.paths.find(x => x.id === pathID);
    if (p) highlightPath(p);
  } catch (e) { /* non-fatal */ }
}

function renderLegend() {
  const el = document.getElementById('legend');
  el.replaceChildren();
  for (const [t, label] of Object.entries(TYPE_LABEL)) {
    const item = document.createElement('span');
    item.className = 'item';
    const dot = document.createElement('span');
    dot.className = 'dot';
    dot.style.background = TYPE_COLORS[t];
    item.append(dot, document.createTextNode(label));
    el.appendChild(item);
  }
  const cj = document.createElement('span');
  cj.className = 'item';
  const dot = document.createElement('span');
  dot.className = 'dot';
  dot.style.background = '#e3b341';
  dot.style.transform = 'rotate(45deg)';
  cj.append(dot, document.createTextNode('Crown Jewel'));
  el.appendChild(cj);
}

async function main() {
  renderLegend();
  initAlertFeed();
  const snapshot = await api('/api/v1/graph');
  initGraph(snapshot);

  const agents = await api('/api/v1/agents');
  renderAgents(agents.agents);

  const paths = await api('/api/v1/paths');
  const cjNodes = new Set(snapshot.nodes.filter(n => n.crown_jewel).map(n => n.id));
  const crownExposed = new Set(paths.paths.filter(p => cjNodes.has(p.target)).map(p => p.target));

  renderStats(snapshot, {
    agents: agents.agents.length,
    critical: agents.agents.reduce((s, a) => s + a.critical_paths, 0),
    high: agents.agents.filter(a => a.top_path_risk >= 60 && a.top_path_risk < 80).length,
    crownExposed: crownExposed.size,
  });
}

window.addEventListener('DOMContentLoaded', () => {
  main().catch(err => {
    const details = document.getElementById('details');
    details.replaceChildren();
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = 'Failed to load: ' + err.message;
    details.appendChild(p);
  });
});
