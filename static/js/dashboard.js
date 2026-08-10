/* ==========================================================================
   Nano Blocker — dashboard.js
   Shared UI helpers + per-page controllers.  All mutations go through the
   authenticated JSON API (POST/DELETE) with the CSRF token attached.
   ========================================================================== */
(function () {
  "use strict";

  /* ------------------------------------------------------------------------
     Core helpers
     ------------------------------------------------------------------------ */
  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : "";
  }

  async function api(path, opts) {
    opts = opts || {};
    const headers = opts.headers || {};
    headers["Content-Type"] = "application/json";
    headers["X-CSRFToken"] = csrfToken();
    const res = await fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      credentials: "same-origin",
    });
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      const err = new Error((data && data.message) || "Request failed");
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data || {};
  }

  /* ---- toasts ---- */
  const toastContainer = () => document.getElementById("toastContainer");

  function toast(message, type) {
    const box = toastContainer();
    if (!box) return;
    const el = document.createElement("div");
    el.className = "toast toast-" + (type || "info");
    el.textContent = message;
    box.appendChild(el);
    setTimeout(() => {
      el.classList.add("leaving");
      setTimeout(() => el.remove(), 220);
    }, 4200);
  }

  /* ---- modals ---- */
  function openModal(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.hidden = false;
    document.body.style.overflow = "hidden";
  }
  function closeModal(el) {
    const modal = el && el.closest(".modal");
    if (modal) { modal.hidden = true; }
    if (!document.querySelector(".modal:not([hidden])")) {
      document.body.style.overflow = "";
    }
  }
  function closeAllModals() {
    document.querySelectorAll(".modal").forEach((m) => { m.hidden = true; });
    document.body.style.overflow = "";
  }

  /* ---- confirm dialog ---- */
  function confirmDialog(message, detail, onConfirm, opts) {
    opts = opts || {};
    const modal = document.getElementById("confirm-modal");
    if (!modal) { onConfirm(); return; }
    document.getElementById("confirmMessage").textContent = message;
    const detailEl = document.getElementById("confirmDetail");
    detailEl.textContent = detail || "";
    detailEl.style.display = detail ? "" : "none";
    const ok = document.getElementById("confirmOk");
    ok.className = "btn " + (opts.danger ? "btn-danger" : "btn-primary");
    ok.onclick = function () {
      closeModal(modal);
      onConfirm();
    };
    modal.hidden = false;
    document.body.style.overflow = "hidden";
  }

  /* ---- misc ---- */
  function esc(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
  }
  function formatTime(iso) {
    if (!iso) return "–";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const pad = (n) => String(n).padStart(2, "0");
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
      " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
  }
  function formatDuration(seconds) {
    if (seconds == null || seconds < 0) return "–";
    seconds = Math.round(seconds);
    if (seconds === 0) return "expiring…";
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    const parts = [];
    if (h) parts.push(h + "h");
    if (m) parts.push(m + "m");
    parts.push(s + "s");
    return parts.join(" ");
  }

  /* Badge helper — status is always text + color, never color alone. */
  function badge(text, kind) {
    return '<span class="badge badge-' + (kind || "muted") + '">' + esc(text) + "</span>";
  }
  const STATUS_BADGE = {
    BLOCKED: "danger", ALLOWED: "success", ACTIVE: "success", EXPIRED: "muted",
    ERROR: "danger", PARTIAL: "warning", DISABLED: "muted", SUCCESS: "success",
    FAILED: "danger", INFO: "info", running: "success", stopped: "warning",
    unavailable: "danger", inactive: "warning", active: "success", app: "info",
    manual: "muted",
  };
  function statusBadge(status) {
    const key = String(status || "").toLowerCase();
    return badge(status, STATUS_BADGE[key] || "muted");
  }
  function methodBadge(method) {
    const label = { dns: "DNS", ufw: "UFW", both: "DNS + UFW" }[method] || method;
    return '<span class="badge badge-violet">' + esc(label) + "</span>";
  }

  /* ------------------------------------------------------------------------
     Global behaviours (run on every authenticated page)
     ------------------------------------------------------------------------ */
  function bindGlobals() {
    // open / close via data attributes
    document.addEventListener("click", function (e) {
      const openBtn = e.target.closest("[data-open-modal]");
      if (openBtn) { openModal(openBtn.getAttribute("data-open-modal")); return; }
      const closeBtn = e.target.closest("[data-close-modal]");
      if (closeBtn) { closeModal(closeBtn); return; }
      if (e.target.closest("[data-dismiss-banner]")) {
        const banner = e.target.closest(".platform-banner");
        if (banner) banner.remove();
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeAllModals();
    });

    // sidebar toggle (mobile)
    const toggle = document.getElementById("sidebarToggle");
    const sidebar = document.getElementById("sidebar");
    if (toggle && sidebar) {
      toggle.addEventListener("click", function () {
        const open = sidebar.classList.toggle("open");
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
    }

    // temporary block duration preset
    const preset = document.querySelector("[data-duration-preset]");
    const customWrap = document.getElementById("temp-custom-wrap");
    if (preset && customWrap) {
      const sync = function () {
        customWrap.hidden = preset.value !== "custom";
      };
      preset.addEventListener("change", sync);
      sync();
    }

    // shared forms
    bindSharedForms();

    // live status pills
    refreshStatusPills();
  }

  function bindSharedForms() {
    const DURATION_PRESETS = { "5m": 5, "15m": 15, "30m": 30, "1h": 60, "6h": 360, "24h": 1440 };

    const configs = {
      "block-domain": { url: "/api/domains/block", method: "POST" },
      "unblock-domain": { url: "/api/domains/unblock", method: "POST" },
      "temporary-block": {
        url: "/api/temporary/block",
        method: "POST",
        prepare: function (data, form) {
          const presetVal = (form.querySelector('[name="duration_preset"]') || {}).value;
          if (presetVal === "custom") {
            data.duration_minutes = Number((form.querySelector('[name="duration_minutes"]') || {}).value || 0);
          } else {
            data.duration_minutes = DURATION_PRESETS[presetVal] || 0;
          }
          delete data.duration_preset;
          return data;
        },
      },
      "blacklist-add": { url: "/api/lists/blacklist", method: "POST" },
      "whitelist-add": { url: "/api/lists/whitelist", method: "POST" },
      "password-change": { url: "/api/auth/password", method: "POST" },
    };

    document.querySelectorAll("form[data-form]").forEach(function (form) {
      form.addEventListener("submit", async function (e) {
        e.preventDefault();
        const name = form.getAttribute("data-form");
        const cfg = configs[name];
        if (!cfg) return;
        const data = {};
        new FormData(form).forEach(function (value, key) { data[key] = value; });
        const finalData = cfg.prepare ? cfg.prepare(data, form) : data;
        const btn = form.querySelector('button[type="submit"]');
        if (btn) btn.disabled = true;
        try {
          const result = await api(cfg.url, { method: cfg.method, body: finalData });
          toast(result.message || "Done.", "success");
          const modal = form.closest(".modal");
          if (modal) closeModal(modal);
          form.reset();
          if (window.__refreshPage) window.__refreshPage();
        } catch (err) {
          toast(err.message || "Operation failed.", "error");
        } finally {
          if (btn) btn.disabled = false;
        }
      });
    });
  }

  async function refreshStatusPills() {
    const pillUfw = document.getElementById("pillUfw");
    const pillDns = document.getElementById("pillDns");
    if (!pillUfw && !pillDns) return;
    try {
      const data = await api("/api/dashboard/stats");
      if (pillUfw) {
        const state = data.ufw.status || "unavailable";
        const cls = state === "active" ? "on" : state === "inactive" ? "off" : "unavailable";
        const label = state === "active" ? "UFW Active"
          : state === "inactive" ? "UFW Inactive" : "UFW Unavailable";
        pillUfw.setAttribute("data-status", cls);
        pillUfw.querySelector(".pill-label").textContent = label;
      }
      if (pillDns) {
        const state = data.dns || "unavailable";
        const cls = state === "running" ? "on" : state === "stopped" ? "off" : "unavailable";
        const label = state === "running" ? "DNS Running"
          : state === "stopped" ? "DNS Stopped" : "DNS Unavailable";
        pillDns.setAttribute("data-status", cls);
        pillDns.querySelector(".pill-label").textContent = label;
      }
    } catch (e) { /* pills stay on "checking…" */ }
  }

  /* ------------------------------------------------------------------------
     Dashboard page
     ------------------------------------------------------------------------ */
  const dashboard = {
    async init() {
      window.__refreshPage = () => this.load();
      await this.load();
    },
    async load() {
      try {
        const data = await api("/api/dashboard/stats");
        // stat tiles
        const counts = data.counts || {};
        document.querySelectorAll("[data-stat]").forEach(function (el) {
          const key = el.getAttribute("data-stat");
          const valEl = el.querySelector(".stat-value");
          if (valEl) valEl.textContent = counts[key] != null ? counts[key] : "–";
        });
        // UFW card
        const ufw = data.ufw || {};
        const setText = function (id, txt) { const el = document.getElementById(id); if (el) el.textContent = txt; };
        const ufwStatus = ufw.status || "unavailable";
        setText("ufwStatus", ufwStatus === "active" ? "ACTIVE" : ufwStatus === "inactive" ? "INACTIVE" : "UNAVAILABLE");
        setText("ufwIncoming", ufw.default_incoming || "–");
        setText("ufwOutgoing", ufw.default_outgoing || "–");
        const ufwBadge = document.getElementById("ufwBadge");
        if (ufwBadge) ufwBadge.outerHTML = statusBadge(ufwStatus === "active" ? "ACTIVE" : ufwStatus === "inactive" ? "INACTIVE" : "ERROR");
        const ufwNote = document.getElementById("ufwNote");
        if (ufwNote && ufw.error) ufwNote.textContent = ufw.error;
        // DNS card
        const dnsState = data.dns || "unavailable";
        setText("dnsService", dnsState === "running" ? "Running" : dnsState === "stopped" ? "Stopped" : "Unavailable");
        const dnsBadge = document.getElementById("dnsBadge");
        if (dnsBadge) dnsBadge.outerHTML = statusBadge(dnsState === "running" ? "ACTIVE" : dnsState === "stopped" ? "STOPPED" : "ERROR");
        // activity
        this.renderActivity(data.activity || []);
      } catch (e) {
        toast(e.message || "Could not load dashboard.", "error");
      }
    },
    renderActivity(rows) {
      const tbody = document.getElementById("activityRows");
      if (!tbody) return;
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No security activity yet.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (r) {
        return "<tr>" +
          "<td class='mono'>" + esc(formatTime(r.created_at)) + "</td>" +
          "<td>" + badge(r.event_type, "info") + "</td>" +
          "<td class='mono'>" + esc(r.target || "–") + "</td>" +
          "<td>" + statusBadge(r.status) + "</td>" +
          "<td class='text-muted'>" + esc(r.message || "") + "</td>" +
          "</tr>";
      }).join("");
    },
  };

  /* ------------------------------------------------------------------------
     Domains page
     ------------------------------------------------------------------------ */
  const domains = {
    searchTerm: "",
    async init() {
      window.__refreshPage = () => this.load();
      const search = document.getElementById("domainSearch");
      if (search) {
        search.addEventListener("input", () => {
          this.searchTerm = search.value.trim();
          this.load();
        });
      }
      this.bindActions();
      await this.load();
    },
    bindActions() {
      const tbody = document.getElementById("domainRows");
      if (!tbody) return;
      tbody.addEventListener("click", async (e) => {
        const btn = e.target.closest("[data-action]");
        if (!btn) return;
        const action = btn.getAttribute("data-action");
        const id = btn.getAttribute("data-id");
        const domain = btn.getAttribute("data-domain");
        if (action === "block") {
          // pre-fill + open shared modal
          const input = document.getElementById("block-domain");
          if (input) input.value = domain;
          openModal("block-modal");
        } else if (action === "unblock") {
          confirmDialog(
            "Unblock " + domain + "?",
            "Removes the DNS block and any Nano Blocker UFW rules for this domain.",
            async () => {
              try {
                const r = await api("/api/domains/unblock", { method: "POST", body: { domain: domain } });
                toast(r.message, "success");
                this.load();
              } catch (err) { toast(err.message, "error"); }
            }
          );
        } else if (action === "refresh") {
          btn.disabled = true;
          try {
            const r = await api("/api/domains/refresh", { method: "POST", body: { id: Number(id) } });
            toast(r.message, "success");
            this.load();
          } catch (err) { toast(err.message, "error"); btn.disabled = false; }
        } else if (action === "details") {
          this.showDetails(Number(id));
        }
      });
    },
    async load() {
      const tbody = document.getElementById("domainRows");
      if (!tbody) return;
      try {
        const url = this.searchTerm ? "/api/domains?search=" + encodeURIComponent(this.searchTerm) : "/api/domains";
        const data = await api(url);
        this.render(data.domains || []);
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" class="table-empty">Failed to load domains.</td></tr>';
      }
    },
    render(rows) {
      const tbody = document.getElementById("domainRows");
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No domains yet. Use "Add Domain" to block your first domain.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map((d) => {
        const blocked = d.status === "blocked";
        const ips = d.ips || [];
        const ipCell = ips.length
          ? '<ul class="ip-list">' + ips.slice(0, 3).map((ip) => "<li>" + esc(ip) + "</li>").join("") +
            (ips.length > 3 ? '<li class="ip-more">+' + (ips.length - 3) + " more</li>" : "") + "</ul>"
          : '<span class="text-muted">–</span>';
        const actions =
          (blocked
            ? '<button class="btn btn-ghost btn-sm" data-action="unblock" data-domain="' + esc(d.domain) + '">Unblock</button>' +
              '<button class="btn btn-ghost btn-sm" data-action="refresh" data-id="' + d.id + '">Refresh IPs</button>'
            : '<button class="btn btn-primary btn-sm" data-action="block" data-domain="' + esc(d.domain) + '">Block</button>' +
              '<button class="btn btn-ghost btn-sm" data-action="refresh" data-id="' + d.id + '">Refresh IPs</button>') +
          '<button class="btn btn-ghost btn-sm" data-action="details" data-id="' + d.id + '">Details</button>';
        return "<tr>" +
          "<td class='mono'>" + esc(d.domain) + "</td>" +
          "<td>" + statusBadge(blocked ? "BLOCKED" : "ALLOWED") + "</td>" +
          "<td>" + methodBadge(d.method) + "</td>" +
          "<td>" + ipCell + "</td>" +
          "<td>" + esc(d.reason || "–") + "</td>" +
          "<td class='mono'>" + esc(formatTime(d.created_at)) + "</td>" +
          '<td class="cell-actions">' + actions + "</td>" +
          "</tr>";
      }).join("");
    },
    async showDetails(id) {
      const body = document.getElementById("domainDetailBody");
      openModal("domain-detail-modal");
      if (!body) return;
      body.innerHTML = '<div class="table-empty">Loading…</div>';
      try {
        const r = await api("/api/domains/" + id);
        const d = r.domain;
        const ips = d.ips || [];
        body.innerHTML =
          '<div class="detail-grid">' +
          '<div class="kv"><span>Domain</span><strong class="mono">' + esc(d.domain) + "</strong></div>" +
          '<div class="kv"><span>Status</span><strong>' + statusBadge(d.status === "blocked" ? "BLOCKED" : "ALLOWED") + "</strong></div>" +
          '<div class="kv"><span>Method</span><strong>' + methodBadge(d.method) + "</strong></div>" +
          '<div class="kv"><span>Created</span><strong class="mono">' + esc(formatTime(d.created_at)) + "</strong></div>" +
          '<div class="kv"><span>Updated</span><strong class="mono">' + esc(formatTime(d.updated_at)) + "</strong></div>" +
          '<div class="kv"><span>Reason</span><strong>' + esc(d.reason || "–") + "</strong></div>" +
          "</div>" +
          '<div class="detail-section"><h4>Resolved IPs (' + ips.length + ")</h4>" +
          (ips.length
            ? '<ul class="ip-list">' + ips.map((i) => "<li>" + esc(i.ip_address) + " · resolved " + esc(formatTime(i.last_resolved)) + "</li>").join("") + "</ul>"
            : '<p class="text-muted">No IPs resolved for this domain.</p>') +
          "</div>" +
          '<p class="status-note">Enforcement: ' +
          (d.method === "dns" ? "DNS filtering only" : d.method === "ufw" ? "UFW only" : "DNS filtering + UFW IP rules") +
          ".</p>";
      } catch (err) {
        body.innerHTML = '<div class="table-empty">' + esc(err.message) + "</div>";
      }
    },
  };

  /* ------------------------------------------------------------------------
     Firewall page
     ------------------------------------------------------------------------ */
  const firewall = {
    async init() {
      window.__refreshPage = () => { this.loadStatus(); this.loadRules(); };
      this.bindControls();
      this.bindAddRule();
      this.bindRuleActions();
      await this.loadStatus();
      await this.loadRules();
    },
    async loadStatus() {
      try {
        const r = await api("/api/ufw/status");
        const s = r.status || {};
        const status = s.status || "unavailable";
        const label = status === "active" ? "UFW is Active"
          : status === "inactive" ? "UFW is Inactive" : "UFW Unavailable";
        const el = document.getElementById("fwStatusLabel");
        if (el) el.textContent = label;
        const badge = document.getElementById("fwBadge");
        if (badge) badge.outerHTML = statusBadge(status === "active" ? "ACTIVE" : status === "inactive" ? "INACTIVE" : "ERROR");
        const setText = (id, t) => { const e = document.getElementById(id); if (e) e.textContent = t; };
        setText("fwIncoming", s.default_incoming || "–");
        setText("fwOutgoing", s.default_outgoing || "–");
        if (r.error) { const n = document.getElementById("fwStatusNote"); if (n) n.textContent = r.error; }
      } catch (e) {
        const el = document.getElementById("fwStatusLabel");
        if (el) el.textContent = "Unable to reach UFW";
      }
    },
    async loadRules() {
      const tbody = document.getElementById("ruleRows");
      if (!tbody) return;
      try {
        const r = await api("/api/ufw/rules");
        const rules = r.rules || [];
        if (!rules.length) {
          tbody.innerHTML = '<tr><td colspan="10" class="table-empty">No active UFW rules.</td></tr>';
          return;
        }
        tbody.innerHTML = rules.map((rule) => {
          const comment = cleanComment(rule.comment);
          const origin = rule.origin === "app" ? "APP" : "MANUAL";
          return "<tr>" +
            "<td class='mono'>" + rule.number + "</td>" +
            "<td>" + badge(rule.action, rule.action === "ALLOW" ? "success" : "danger") + "</td>" +
            "<td>" + badge(rule.direction, "info") + "</td>" +
            "<td class='mono'>" + esc(rule.from || "any") + "</td>" +
            "<td class='mono'>" + esc(rule.to || "any") + "</td>" +
            "<td class='mono'>" + esc(rule.port || "–") + "</td>" +
            "<td>" + esc((rule.protocol || "any").toUpperCase()) + "</td>" +
            "<td>" + esc(comment || "–") + "</td>" +
            "<td>" + badge(origin, origin === "APP" ? "info" : "muted") + "</td>" +
            '<td class="cell-actions"><button class="btn btn-danger btn-sm" data-del="' + rule.number + '" data-manual="' + (rule.origin !== "app") + '">Delete</button></td>' +
            "</tr>";
        }).join("");
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="10" class="table-empty">' + esc(e.message) + "</td></tr>";
      }
    },
    bindRuleActions() {
      const tbody = document.getElementById("ruleRows");
      if (!tbody) return;
      tbody.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-del]");
        if (!btn) return;
        const num = Number(btn.getAttribute("data-del"));
        const manual = btn.getAttribute("data-manual") === "true";
        const msg = manual
          ? "Delete UFW rule #" + num + "?"
          : "Delete UFW rule #" + num + "?";
        const detail = manual
          ? "This rule was NOT created by Nano Blocker. Removing it is destructive — confirm to proceed."
          : "This rule was created by Nano Blocker and will be removed.";
        confirmDialog(msg, detail, async () => {
          try {
            const r = await api("/api/ufw/rules/" + num, { method: "DELETE", body: { force: manual } });
            toast(r.message, "success");
            this.loadRules();
            this.loadStatus();
          } catch (err) { toast(err.message, "error"); }
        }, { danger: true });
      });
    },
    bindControls() {
      document.querySelectorAll("[data-action]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const action = btn.getAttribute("data-action");
          const run = async (body) => {
            try {
              const r = await api("/api/ufw/" + action.split("-")[1], { method: "POST", body: body });
              toast(r.message, "success");
              this.loadStatus();
              this.loadRules();
            } catch (err) { toast(err.message, "error"); }
          };
          if (action === "ufw-disable") {
            confirmDialog("Disable UFW?", "All traffic will follow the default policies. Nano Blocker rules stay in place but are not enforced while UFW is off.", () => run({ confirm: true }), { danger: true });
          } else if (action === "ufw-reset") {
            confirmDialog("Reset the entire UFW ruleset?", "This deletes ALL UFW rules, including ones created outside Nano Blocker, and disables UFW. This is irreversible.", () => run({ confirm: true }), { danger: true });
          } else {
            run({});
          }
        });
      });
    },
    bindAddRule() {
      const form = document.getElementById("addRuleForm");
      if (!form) return;
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const data = {};
        new FormData(form).forEach((v, k) => { data[k] = v; });
        const btn = form.querySelector('button[type="submit"]');
        if (btn) btn.disabled = true;
        try {
          const r = await api("/api/ufw/rules", { method: "POST", body: data });
          toast(r.message, "success");
          form.reset();
          this.loadRules();
          this.loadStatus();
        } catch (err) { toast(err.message, "error"); }
        finally { if (btn) btn.disabled = false; }
      });
    },
  };

  function cleanComment(comment) {
    // UFW comments we write may carry " | IDB-USER-xxxx" — hide the tag.
    // The tag's UUID hex can include lowercase letters, so match both cases.
    return String(comment || "").replace(/\s*\|\s*IDB-[A-Za-z0-9-]+$/i, "").trim();
  }

  /* ------------------------------------------------------------------------
     Lists page
     ------------------------------------------------------------------------ */
  const lists = {
    tab: "blacklist",
    searchTerm: "",
    async init() {
      window.__refreshPage = () => this.load();
      this.bindTabs();
      this.bindSearch();
      this.bindRows();
      await this.load();
    },
    bindTabs() {
      const tabs = document.getElementById("listTabs");
      if (!tabs) return;
      tabs.addEventListener("click", (e) => {
        const btn = e.target.closest(".tab");
        if (!btn) return;
        document.querySelectorAll("#listTabs .tab").forEach((t) => {
          t.classList.toggle("active", t === btn);
          t.setAttribute("aria-selected", t === btn ? "true" : "false");
        });
        this.tab = btn.getAttribute("data-tab");
        this.searchTerm = "";
        const search = document.getElementById("listSearch");
        if (search) search.value = "";
        this.load();
      });
    },
    bindSearch() {
      const search = document.getElementById("listSearch");
      if (!search) return;
      let timer = null;
      search.addEventListener("input", () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
          this.searchTerm = search.value.trim();
          this.load();
        }, 250);
      });
    },
    bindRows() {
      const tbody = document.getElementById("listRows");
      if (!tbody) return;
      tbody.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-action]");
        if (!btn) return;
        const id = btn.getAttribute("data-id");
        const value = btn.getAttribute("data-value");
        const action = btn.getAttribute("data-action");
        if (action === "toggle") {
          api("/api/lists/" + this.tab + "/" + id + "/toggle", { method: "POST", body: {} })
            .then((r) => { toast(r.message, "success"); this.load(); })
            .catch((err) => toast(err.message, "error"));
        } else if (action === "delete") {
          confirmDialog(
            "Remove '" + value + "' from the " + this.tab + "?",
            "This cannot be undone.",
            () => {
              api("/api/lists/" + this.tab + "/" + id, { method: "DELETE", body: {} })
                .then((r) => { toast(r.message, "success"); this.load(); })
                .catch((err) => toast(err.message, "error"));
            },
            { danger: true }
          );
        }
      });
    },
    async load() {
      const tbody = document.getElementById("listRows");
      if (!tbody) return;
      const title = document.getElementById("listTitle");
      const sub = document.getElementById("listSubtitle");
      const addBtn = document.getElementById("listAddBtn");
      if (title) title.textContent = this.tab === "blacklist" ? "Blacklist" : "Whitelist";
      if (sub) sub.textContent = this.tab === "blacklist"
        ? "Known-bad domains and IP addresses."
        : "Trusted values that override domain blocking.";
      if (addBtn) {
        addBtn.onclick = () => openModal(this.tab === "blacklist" ? "blacklist-modal" : "whitelist-modal");
      }
      try {
        const url = "/api/lists/" + this.tab + (this.searchTerm ? "?search=" + encodeURIComponent(this.searchTerm) : "");
        const r = await api(url);
        const entries = r.entries || [];
        if (!entries.length) {
          tbody.innerHTML = '<tr><td colspan="6" class="table-empty">No ' + this.tab + " entries yet.</td></tr>";
          return;
        }
        tbody.innerHTML = entries.map((entry) => {
          const enabled = !!entry.enabled;
          return "<tr>" +
            "<td class='mono'>" + esc(entry.value) + "</td>" +
            "<td>" + badge(entry.value_type.toUpperCase(), entry.value_type === "ip" ? "violet" : "info") + "</td>" +
            "<td>" + esc(entry.reason || "–") + "</td>" +
            "<td class='mono'>" + esc(formatTime(entry.created_at)) + "</td>" +
            "<td>" + statusBadge(enabled ? "ACTIVE" : "DISABLED") + "</td>" +
            '<td class="cell-actions">' +
            '<button class="btn btn-ghost btn-sm" data-action="toggle" data-id="' + entry.id + '">' + (enabled ? "Disable" : "Enable") + "</button>" +
            '<button class="btn btn-danger btn-sm" data-action="delete" data-id="' + entry.id + '" data-value="' + esc(entry.value) + '">Delete</button>' +
            "</td></tr>";
        }).join("");
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" class="table-empty">' + esc(e.message) + "</td></tr>";
      }
    },
  };

  /* ------------------------------------------------------------------------
     Temporary + Logs page
     ------------------------------------------------------------------------ */
  const temporary = {
    category: "all",
    searchTerm: "",
    _ticker: null,
    async init() {
      window.__refreshPage = () => { this.loadBlocks(); this.loadLogs(); };
      this.bindLogControls();
      await this.loadBlocks();
      await this.loadLogs();
      this.startTicker();
    },
    startTicker() {
      if (this._ticker) clearInterval(this._ticker);
      this._ticker = setInterval(() => {
        document.querySelectorAll("[data-remaining]").forEach((el) => {
          let secs = Number(el.getAttribute("data-remaining"));
          if (secs > 0) {
            secs -= 1;
            el.setAttribute("data-remaining", secs);
            el.textContent = formatDuration(secs);
            if (secs <= 0) { this.loadBlocks(); }
          }
        });
      }, 1000);
    },
    async loadBlocks() {
      const tbody = document.getElementById("tempRows");
      if (!tbody) return;
      try {
        const r = await api("/api/temporary");
        const blocks = r.blocks || [];
        if (!blocks.length) {
          tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No temporary blocks.</td></tr>';
          return;
        }
        tbody.innerHTML = blocks.map((b) => {
          const active = b.status === "active";
          const remaining = active ? b.remaining_seconds : 0;
          return "<tr>" +
            "<td class='mono'>" + esc(b.target) + "</td>" +
            "<td>" + badge(b.target_type.toUpperCase(), b.target_type === "ip" ? "violet" : "info") + "</td>" +
            "<td>" + esc(b.reason || "–") + "</td>" +
            "<td class='mono'>" + esc(formatTime(b.created_at)) + "</td>" +
            "<td class='mono'>" + esc(formatTime(b.expires_at)) + "</td>" +
            '<td class="mono">' + (active ? '<span data-remaining="' + remaining + '">' + esc(formatDuration(remaining)) + "</span>" : "–") + "</td>" +
            "<td>" + statusBadge(active ? "ACTIVE" : "EXPIRED") + "</td>" +
            '<td class="cell-actions">' +
            (active ? '<button class="btn btn-ghost btn-sm" data-expire="' + b.id + '">Expire Now</button>' : "–") +
            "</td></tr>";
        }).join("");
        tbody.querySelectorAll("[data-expire]").forEach((btn) => {
          btn.addEventListener("click", () => {
            const id = btn.getAttribute("data-expire");
            confirmDialog("Expire this temporary block now?", "Enforcement for this target will be removed immediately.", async () => {
              try {
                const res = await api("/api/temporary/" + id + "/expire", { method: "POST", body: {} });
                toast(res.message, "success");
                this.loadBlocks();
              } catch (err) { toast(err.message, "error"); }
            });
          });
        });
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="8" class="table-empty">' + esc(e.message) + "</td></tr>";
      }
    },
    async loadLogs() {
      const tbody = document.getElementById("logRows");
      if (!tbody) return;
      try {
        const params = new URLSearchParams();
        if (this.category) params.set("category", this.category);
        if (this.searchTerm) params.set("search", this.searchTerm);
        const r = await api("/api/logs?" + params.toString());
        const logs = r.logs || [];
        if (!logs.length) {
          tbody.innerHTML = '<tr><td colspan="6" class="table-empty">No log entries match.</td></tr>';
          return;
        }
        tbody.innerHTML = logs.map((l) => "<tr>" +
          "<td class='mono'>" + esc(formatTime(l.created_at)) + "</td>" +
          "<td>" + esc(l.username) + "</td>" +
          "<td>" + badge(l.event_type, "info") + "</td>" +
          "<td class='mono'>" + esc(l.target || "–") + "</td>" +
          "<td>" + statusBadge(l.status) + "</td>" +
          "<td>" + esc(l.message || "") + "</td>" +
          "</tr>").join("");
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" class="table-empty">' + esc(e.message) + "</td></tr>";
      }
    },
    bindLogControls() {
      const chips = document.getElementById("logChips");
      if (chips) {
        chips.addEventListener("click", (e) => {
          const chip = e.target.closest(".chip");
          if (!chip) return;
          document.querySelectorAll("#logChips .chip").forEach((c) => c.classList.remove("active"));
          chip.classList.add("active");
          this.category = chip.getAttribute("data-category");
          this.loadLogs();
        });
      }
      const search = document.getElementById("logSearch");
      if (search) {
        let timer = null;
        search.addEventListener("input", () => {
          clearTimeout(timer);
          timer = setTimeout(() => {
            this.searchTerm = search.value.trim();
            this.loadLogs();
          }, 250);
        });
      }
      const clearBtn = document.getElementById("clearLogs");
      if (clearBtn) {
        clearBtn.addEventListener("click", () => {
          confirmDialog("Clear all security logs?", "Every log entry will be permanently removed from the database.", async () => {
            try {
              const r = await api("/api/logs", { method: "DELETE", body: { confirm: true } });
              toast(r.message, "success");
              this.loadLogs();
            } catch (err) { toast(err.message, "error"); }
          }, { danger: true });
        });
      }
      const exportBtn = document.getElementById("exportLogs");
      if (exportBtn) {
        exportBtn.addEventListener("click", () => {
          window.location.href = "/api/logs/export";
        });
      }
    },
  };

  /* ------------------------------------------------------------------------
     Bootstrap
     ------------------------------------------------------------------------ */
  document.addEventListener("DOMContentLoaded", function () {
    bindGlobals();
    const page = document.body.getAttribute("data-page");
    if (page === "dashboard") dashboard.init();
    else if (page === "domains") domains.init();
    else if (page === "firewall") firewall.init();
    else if (page === "lists") lists.init();
    else if (page === "temporary") temporary.init();
  });

  window.IDB = {
    api, toast, openModal, closeModal, confirmDialog, formatTime, formatDuration,
    badge, statusBadge,
  };
})();
