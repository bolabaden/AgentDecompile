(function () {
  "use strict";

  const API = {
    actions: "/dashboard/api/actions",
    jobs: "/dashboard/api/jobs"
  };

  const PREFERRED = {
    home: ["corpus.ghidra-bulk", "corpus.cross-place", "mcp.status", "mcp.list-functions"],
    binary: [
      "corpus.ghidra-bulk",
      "corpus.cross-place",
      "mcp.decompile-function",
      "mcp.list-functions",
      "mcp.get-function",
      "recover.inspect"
    ],
    function: [
      "mcp.decompile-function",
      "mcp.get-function",
      "mcp.get-references",
      "mcp.list-cross-references",
      "mcp.analyze-data-flow",
      "mcp.manage-comments",
      "mcp.match-function"
    ],
    logical: ["corpus.cross-place", "corpus.propagate-source", "corpus.logical-build"],
    operations: ["corpus.ghidra-bulk", "corpus.cross-place", "corpus.run", "mcp.status"],
    work: [],
    atlas: ["corpus.genproject", "mcp.decompile-function", "mcp.get-function"],
    report: ["corpus.export-run-report", "corpus.ingest-recovered", "mcp.reconstruct"],
    functions: ["mcp.list-functions", "mcp.search-symbols", "corpus.logical-build"]
  };

  let catalog = [];
  let defaults = {};
  let binaries = [];
  let currentAction = null;

  function $(id) {
    return document.getElementById(id);
  }

  function pageContext() {
    const node = $("page-context");
    const data = { page: "work" };
    if (!node) return data;
    Array.from(node.attributes).forEach(function (attr) {
      if (!attr.name.startsWith("data-")) return;
      data[attr.name.slice(5).replace(/-([a-z])/g, function (_, ch) { return ch.toUpperCase(); })] = attr.value;
    });
    if (data.page === undefined) data.page = node.getAttribute("data-page") || "work";
    return data;
  }

  function announce(message) {
    if (window.KotorXidUI && window.KotorXidUI.announce) {
      window.KotorXidUI.announce(message);
    }
  }

  function contextPayload() {
    const page = pageContext();
    const extra = binaries.find(function (row) { return row.slug === page.slug; }) || {};
    return {
      page: page.page || "work",
      slug: page.slug || extra.slug || "",
      program: page.program || extra.program || extra.repo || "",
      repo: page.repo || extra.repo || "",
      addr: page.addr || "",
      name: page.name || "",
      logical_id: page.logicalId || "",
      db: defaults.db || "",
      work_dir: defaults.work_dir || "",
      kb: defaults.kb || ""
    };
  }

  function matchesPage(action, page) {
    const pages = action.pages || [];
    return page === "work" || pages.indexOf(page) !== -1 || pages.indexOf("work") !== -1;
  }

  function preferredActions(page) {
    const wanted = PREFERRED[page] || [];
    const byId = {};
    catalog.forEach(function (action) { byId[action.id] = action; });
    const first = wanted.map(function (id) { return byId[id]; }).filter(Boolean);
    if (first.length) return first;
    return catalog.filter(function (action) { return matchesPage(action, page); }).slice(0, 8);
  }

  function buttonFor(action) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "action-btn" + (action.danger ? " action-danger" : "");
    button.dataset.action = action.id;
    button.textContent = action.title;
    button.addEventListener("click", function () { openForm(action.id); });
    return button;
  }

  function renderContextual() {
    const page = pageContext().page || "work";
    const bar = $("action-bar");
    const contextual = $("action-contextual");
    const actions = preferredActions(page);
    function fill(root) {
      if (!root) return;
      root.innerHTML = "";
      actions.forEach(function (action) { root.appendChild(buttonFor(action)); });
    }
    fill(bar);
    fill(contextual);
  }

  function renderCatalog(filter) {
    const root = $("action-catalog");
    if (!root) return;
    const query = (filter || "").trim().toLowerCase();
    root.innerHTML = "";
    const groups = { corpus: [], recover: [], mcp: [] };
    catalog.forEach(function (action) {
      const hay = (action.id + " " + action.title + " " + action.summary).toLowerCase();
      if (query && hay.indexOf(query) === -1) return;
      (groups[action.group] || groups.mcp).push(action);
    });
    Object.keys(groups).forEach(function (group) {
      if (!groups[group].length) return;
      const section = document.createElement("section");
      section.className = "action-group";
      const heading = document.createElement("h2");
      heading.textContent = group === "mcp" ? "MCP tools" : group === "corpus" ? "Corpus CLI" : "Recover";
      section.appendChild(heading);
      const list = document.createElement("div");
      list.className = "action-list";
      groups[group].forEach(function (action) {
        const row = document.createElement("div");
        row.className = "action-row";
        const title = document.createElement("strong");
        title.textContent = action.title;
        const summary = document.createElement("span");
        summary.className = "sub";
        summary.textContent = action.summary || action.id;
        row.appendChild(title);
        row.appendChild(summary);
        row.appendChild(buttonFor(action));
        list.appendChild(row);
      });
      section.appendChild(list);
      root.appendChild(section);
    });
  }

  function fieldControl(field, value) {
    const id = "af-" + field.name;
    const wrap = document.createElement("label");
    wrap.className = "action-field";
    wrap.setAttribute("for", id);
    const caption = document.createElement("span");
    caption.textContent = field.name + (field.required ? " (required)" : "");
    wrap.appendChild(caption);
    let input;
    if (field.kind === "bool") {
      input = document.createElement("input");
      input.type = "checkbox";
      input.checked = Boolean(value);
    } else if (field.kind === "text") {
      input = document.createElement("textarea");
      input.rows = 4;
      input.value = value == null ? "" : String(value);
    } else if (field.choices && field.choices.length) {
      input = document.createElement("select");
      const blank = document.createElement("option");
      blank.value = "";
      blank.textContent = "—";
      input.appendChild(blank);
      field.choices.forEach(function (choice) {
        const option = document.createElement("option");
        option.value = choice;
        option.textContent = choice;
        if (String(value) === choice) option.selected = true;
        input.appendChild(option);
      });
    } else {
      input = document.createElement("input");
      input.type = field.kind === "int" || field.kind === "float" ? "number" : "text";
      if (field.kind === "int") input.step = "1";
      input.value = value == null ? "" : String(value);
    }
    input.id = id;
    input.name = field.name;
    wrap.appendChild(input);
    return wrap;
  }

  function readForm(form) {
    const params = {};
    form.querySelectorAll("[name]").forEach(function (input) {
      if (input.type === "checkbox") {
        if (input.checked) params[input.name] = true;
        return;
      }
      if (input.value !== "") params[input.name] = input.value;
    });
    return params;
  }

  function defaultValue(field, ctx) {
    if (field.default != null && field.default !== "") return field.default;
    const map = {
      program: ctx.program,
      slug: ctx.slug,
      addr: ctx.addr || ctx.name,
      repo: ctx.repo,
      db: ctx.db,
      work_dir: ctx.work_dir,
      kb: ctx.kb
    };
    return map[field.from_context] || "";
  }

  function openForm(actionId) {
    const action = catalog.find(function (item) { return item.id === actionId; });
    const form = $("action-form");
    const dock = $("action-dock");
    if (!action || !form) return;
    currentAction = action;
    const ctx = contextPayload();
    form.hidden = false;
    form.innerHTML = "";
    const heading = document.createElement("h2");
    heading.textContent = action.title;
    const help = document.createElement("p");
    help.className = "sub";
    help.textContent = action.summary || action.id;
    form.appendChild(heading);
    form.appendChild(help);
    (action.fields || []).forEach(function (field) {
      form.appendChild(fieldControl(field, defaultValue(field, ctx)));
    });
    if (action.danger) {
      const confirm = document.createElement("label");
      confirm.className = "action-field";
      confirm.innerHTML = '<span>Confirm this changes program or corpus state</span>';
      const box = document.createElement("input");
      box.type = "checkbox";
      box.name = "__confirm";
      confirm.appendChild(box);
      form.appendChild(confirm);
    }
    const actions = document.createElement("div");
    actions.className = "action-form-buttons";
    const run = document.createElement("button");
    run.type = "submit";
    run.textContent = "Run";
    const preview = document.createElement("button");
    preview.type = "button";
    preview.textContent = "Preview command";
    preview.addEventListener("click", function () { submitAction(true); });
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "Close";
    close.addEventListener("click", function () {
      form.hidden = true;
      form.innerHTML = "";
      currentAction = null;
    });
    actions.appendChild(run);
    actions.appendChild(preview);
    actions.appendChild(close);
    form.appendChild(actions);
    setDockOpen(true);
    if (dock) dock.hidden = false;
    run.focus();
  }

  async function submitAction(dryRun) {
    if (!currentAction) return;
    const form = $("action-form");
    const params = readForm(form);
    const confirm = Boolean(params.__confirm);
    delete params.__confirm;
    const response = await fetch(API.jobs, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: currentAction.id,
        params: params,
        context: contextPayload(),
        confirm: confirm || !currentAction.danger,
        dryRun: Boolean(dryRun)
      })
    });
    const payload = await response.json();
    if (!response.ok) {
      announce(payload.error || "Action failed");
      window.alert(payload.error || "Action failed");
      return;
    }
    if (payload.dryRun) {
      window.alert((payload.argv || []).join(" "));
      return;
    }
    announce("Started " + currentAction.title);
    refreshJobs();
  }

  async function cancelJob(jobId) {
    await fetch(API.jobs + "/" + encodeURIComponent(jobId) + "/cancel", { method: "POST" });
    refreshJobs();
  }

  async function showJob(jobId) {
    const response = await fetch(API.jobs + "/" + encodeURIComponent(jobId));
    const payload = await response.json();
    if (!payload.job) return;
    const log = payload.job.log || payload.job.error || "";
    window.alert(log.slice(-4000) || payload.job.status);
  }

  function renderJobs(jobs) {
    const root = $("action-jobs");
    const pulse = $("job-pulse");
    if (pulse) {
      const running = jobs.filter(function (job) {
        return job.status === "running" || job.status === "queued" || job.status === "cancelling";
      }).length;
      pulse.textContent = running ? (running + " running") : (jobs[0] ? jobs[0].status : "no jobs");
      pulse.className = "chip" + (running ? " st-partial" : "");
    }
    if (!root) return;
    root.innerHTML = "";
    jobs.slice(0, 8).forEach(function (job) {
      const row = document.createElement("div");
      row.className = "job-row job-" + job.status;
      const title = document.createElement("button");
      title.type = "button";
      title.className = "job-open";
      title.textContent = job.title + " — " + job.status;
      title.addEventListener("click", function () { showJob(job.id); });
      row.appendChild(title);
      if (job.status === "running" || job.status === "queued" || job.status === "cancelling") {
        const stop = document.createElement("button");
        stop.type = "button";
        stop.textContent = "Cancel";
        stop.addEventListener("click", function () { cancelJob(job.id); });
        row.appendChild(stop);
      }
      root.appendChild(row);
    });
  }

  function setDockOpen(open) {
    const dock = $("action-dock");
    const panel = dock && dock.querySelector(".action-dock-panel");
    const toggle = dock && dock.querySelector(".action-toggle");
    if (!dock || !panel || !toggle) return;
    dock.hidden = false;
    panel.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    toggle.textContent = open ? "Hide work" : "Work";
  }

  async function refreshJobs() {
    const response = await fetch(API.jobs);
    if (!response.ok) return;
    const payload = await response.json();
    renderJobs(payload.jobs || []);
  }

  async function loadCatalog() {
    const page = pageContext().page || "work";
    const response = await fetch(API.actions + "?page=" + encodeURIComponent(page));
    if (!response.ok) return;
    const payload = await response.json();
    catalog = payload.actions || [];
    defaults = (payload.context && payload.context.defaults) || {};
    binaries = (payload.context && payload.context.binaries) || [];
    renderContextual();
    renderCatalog(($("action-filter") || {}).value || "");
    const dock = $("action-dock");
    if (dock) dock.hidden = false;
  }

  function install() {
    const dock = $("action-dock");
    if (dock) {
      const toggle = dock.querySelector(".action-toggle");
      if (toggle) {
        toggle.addEventListener("click", function () {
          const panel = dock.querySelector(".action-dock-panel");
          setDockOpen(panel && panel.hidden);
        });
      }
    }
    const form = $("action-form");
    if (form) {
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        submitAction(false);
      });
    }
    const filter = $("action-filter");
    if (filter) {
      filter.addEventListener("input", function () { renderCatalog(filter.value); });
    }
    loadCatalog();
    refreshJobs();
    window.setInterval(refreshJobs, 4000);
  }

  window.AgentDecompileActions = Object.freeze({
    openForm: openForm,
    refreshJobs: refreshJobs,
    loadCatalog: loadCatalog
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", install, { once: true });
  } else {
    install();
  }
})();
