"use strict";
// Caseboard UI. All values from the API are written with textContent (never
// innerHTML), so alert or note text can not inject markup into the page.

const SEVERITIES = ["low", "medium", "high", "critical"];
const STATUSES = ["open", "investigating", "resolved", "closed"];
const selectedAlerts = new Set();
const expandedAlerts = new Set();

const $ = (id) => document.getElementById(id);

/** Create an element. `props` sets className/text/dataset/attributes; children are appended. */
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key === "data") Object.assign(el.dataset, value);
    else if (key === "on") for (const [evt, fn] of Object.entries(value)) el.addEventListener(evt, fn);
    else el.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined) el.append(child);
  }
  return el;
}

function badge(value, allowed) {
  const safe = allowed.includes(value) ? value : "low";
  return h("span", { class: `badge badge-${safe}`, text: String(value) });
}

function fmt(ts) {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

function showError(message) {
  const el = $("error");
  el.textContent = message;
  el.classList.toggle("active", Boolean(message));
}

async function api(path, options = {}) {
  const init = { method: options.method ?? "GET", headers: {} };
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const res = await fetch("/api" + path, init);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error ?? `Request failed (${res.status})`);
  return data;
}

/** Run an async action and show any failure in the error banner. */
function guard(fn) {
  return async (...args) => {
    try {
      showError("");
      await fn(...args);
    } catch (err) {
      showError(err.message);
    }
  };
}

function showPanel(name) {
  document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
  $("panel-" + name).classList.add("active");
  document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("active", b.dataset.panel === name));
}

function parseRaw(alert) {
  try {
    const doc = JSON.parse(alert.raw);
    return doc && typeof doc === "object" ? doc : {};
  } catch {
    return {};
  }
}

function entityText(doc) {
  const parts = [];
  if (doc.host?.name) parts.push(`host ${doc.host.name}`);
  if (doc.user?.name) parts.push(`user ${doc.user.name}`);
  if (doc.network?.src_ip) parts.push(`src ${doc.network.src_ip}`);
  if (doc.network?.dst_ip) parts.push(`dst ${doc.network.dst_ip}`);
  return parts.join(" · ");
}

// --- Alerts ---------------------------------------------------------------

const loadAlerts = guard(async () => {
  const untriaged = $("untriaged-only").checked;
  const alerts = await api("/alerts" + (untriaged ? "?untriaged=true" : ""));

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const a of alerts) if (a.severity in counts) counts[a.severity]++;
  $("alert-summary").replaceChildren(
    h("div", { class: "stat" }, h("b", { text: String(alerts.length) }), h("span", { text: "alerts" })),
    ...[...SEVERITIES].reverse().map((s) => h("div", { class: "stat" }, h("b", { text: String(counts[s]) }), h("span", { text: s }))),
  );

  const known = new Set(alerts.map((a) => a.id));
  for (const id of [...selectedAlerts]) if (!known.has(id)) selectedAlerts.delete(id);

  const rows = alerts.flatMap((a) => {
    const doc = parseRaw(a);
    const detail = h(
      "tr",
      { class: expandedAlerts.has(a.id) ? "detail-row" : "detail-row hidden" },
      h("td", { colspan: "7" }, h("div", { text: doc.summary ?? "No summary." }), h("pre", { text: JSON.stringify(doc, null, 2) })),
    );
    const row = h(
      "tr",
      {},
      h("td", {}, h("input", {
        type: "checkbox",
        class: "check",
        "aria-label": "Select alert",
        checked: selectedAlerts.has(a.id),
        on: { change: (e) => (e.target.checked ? selectedAlerts.add(a.id) : selectedAlerts.delete(a.id)) },
      })),
      h("td", { text: fmt(a.time) }),
      h("td", {}, h("button", { type: "button", class: "link", text: a.title, on: { click: () => {
        const hidden = detail.classList.toggle("hidden");
        if (hidden) expandedAlerts.delete(a.id); else expandedAlerts.add(a.id);
      } } })),
      h("td", {}, badge(a.severity, SEVERITIES)),
      h("td", { class: "entity", text: entityText(doc) }),
      h("td", {}, h("code", { class: "rule", text: a.ruleId })),
      h("td", {}, a.caseId
        ? h("button", { type: "button", class: "link", text: a.caseId.slice(0, 13) + "…", on: { click: () => openCase(a.caseId) } })
        : h("span", { class: "muted", text: "—" })),
    );
    return [row, detail];
  });

  $("alerts-body").replaceChildren(
    ...(rows.length ? rows : [h("tr", {}, h("td", { colspan: "7", class: "muted", text: "No alerts yet. POST alerts to /api/alerts/ingest." }))]),
  );
});

const createCaseFromSelected = guard(async () => {
  const title = $("case-from-alerts-title").value.trim();
  if (selectedAlerts.size === 0) throw new Error("Select at least one alert.");
  if (!title) throw new Error("Enter a case title.");
  const c = await api("/cases", { method: "POST", body: { title, alertIds: [...selectedAlerts] } });
  selectedAlerts.clear();
  $("case-from-alerts-title").value = "";
  await openCase(c.id);
});

// --- Cases ----------------------------------------------------------------

const loadCases = guard(async () => {
  const cases = await api("/cases");
  if (cases.length === 0) {
    $("cases-list").replaceChildren(h("p", { class: "muted", text: "No cases yet. Select alerts in the inbox and create a case." }));
    return;
  }
  $("cases-list").replaceChildren(
    h(
      "table",
      {},
      h("thead", {}, h("tr", {}, ...["Title", "Severity", "Status", "Created"].map((t) => h("th", { text: t })))),
      h("tbody", {}, cases.map((c) => h(
        "tr",
        {},
        h("td", {}, h("button", { type: "button", class: "link", text: c.title, on: { click: () => openCase(c.id) } })),
        h("td", {}, badge(c.severity, SEVERITIES)),
        h("td", {}, badge(c.status, STATUSES)),
        h("td", { text: fmt(c.createdAt) }),
      ))),
    ),
  );
});

const submitNewCase = guard(async () => {
  const title = $("nc-title").value.trim();
  if (!title) throw new Error("Enter a case title.");
  const c = await api("/cases", { method: "POST", body: { title, severity: $("nc-severity").value } });
  $("nc-title").value = "";
  $("new-case-form").classList.add("hidden");
  await openCase(c.id);
});

function renderTimelineEntry(e) {
  let content = e.content;
  if (e.kind === "evidence") {
    try {
      const obj = JSON.parse(e.content);
      content = `Evidence: ${obj.ref}${obj.description ? " — " + obj.description : ""}`;
    } catch { /* keep raw content */ }
  }
  return h(
    "div",
    { class: "timeline-entry" },
    h("span", { class: "tl-kind", text: e.kind }),
    h("div", { class: "tl-content" }, h("div", { text: content }), h("div", { class: "tl-meta", text: `${fmt(e.createdAt)} by ${e.createdBy}` })),
  );
}

const openCase = guard(async (id) => {
  const c = await api("/cases/" + encodeURIComponent(id));
  const statusSelect = h("select", { id: "status-select" }, STATUSES.map((s) => h("option", { value: s, text: s, selected: s === c.status })));
  const noteInput = h("textarea", { placeholder: "Add a note...", maxlength: "10000" });

  $("case-detail").replaceChildren(
    h("div", { class: "case-head" }, h("h3", { text: c.title }), badge(c.severity, SEVERITIES), badge(c.status, STATUSES)),
    h("p", { class: "meta", text: `ID: ${c.id}  |  Created: ${fmt(c.createdAt)}  |  Updated: ${fmt(c.updatedAt)}` }),
    h(
      "div",
      { class: "case-actions" },
      statusSelect,
      h("button", { type: "button", class: "btn", text: "Update status", on: { click: guard(async () => {
        await api("/cases/" + encodeURIComponent(c.id), { method: "PATCH", body: { status: statusSelect.value } });
        await openCase(c.id);
      }) } }),
      h("button", { type: "button", class: "btn btn-ghost", text: "Export JSON", on: { click: guard(() => exportCase(c.id)) } }),
    ),
    h("p", { class: "section-title", text: `Linked Alerts (${c.alerts.length})` }),
    c.alerts.length === 0
      ? h("p", { class: "muted", text: "None" })
      : h(
          "table",
          {},
          h("thead", {}, h("tr", {}, ...["Time", "Title", "Severity", "Entity", "Rule"].map((t) => h("th", { text: t })))),
          h("tbody", {}, c.alerts.map((a) => h(
            "tr",
            {},
            h("td", { text: fmt(a.time) }),
            h("td", { text: a.title }),
            h("td", {}, badge(a.severity, SEVERITIES)),
            h("td", { class: "entity", text: entityText(parseRaw(a)) }),
            h("td", {}, h("code", { class: "rule", text: a.ruleId })),
          ))),
        ),
    h("p", { class: "section-title", text: "Timeline" }),
    h("div", {}, c.timeline.length ? c.timeline.map(renderTimelineEntry) : h("p", { class: "muted", text: "No timeline entries yet." })),
    h(
      "div",
      { class: "note-form" },
      noteInput,
      h("button", { type: "button", class: "btn", text: "Add Note", on: { click: guard(async () => {
        const content = noteInput.value.trim();
        if (!content) return;
        await api(`/cases/${encodeURIComponent(c.id)}/notes`, { method: "POST", body: { content } });
        await openCase(c.id);
      }) } }),
    ),
  );

  showPanel("case-detail");
});

async function exportCase(id) {
  const data = await api(`/cases/${encodeURIComponent(id)}/export`);
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = h("a", { href: url, download: `${id}.json` });
  a.click();
  URL.revokeObjectURL(url);
}

// --- Wiring ---------------------------------------------------------------

document.querySelectorAll("[data-panel]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const name = btn.dataset.panel;
    showPanel(name);
    if (name === "alerts") loadAlerts();
    if (name === "cases") loadCases();
  });
});
$("untriaged-only").addEventListener("change", loadAlerts);
$("create-case-from-selected").addEventListener("click", createCaseFromSelected);
$("show-new-case").addEventListener("click", () => $("new-case-form").classList.remove("hidden"));
$("cancel-new-case").addEventListener("click", () => $("new-case-form").classList.add("hidden"));
$("submit-new-case").addEventListener("click", submitNewCase);

loadAlerts();
// Keep the inbox fresh while it is the visible panel.
setInterval(() => {
  if ($("panel-alerts").classList.contains("active") && !document.hidden) loadAlerts();
}, 10000);
