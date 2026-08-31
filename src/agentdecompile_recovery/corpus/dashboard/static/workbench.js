(function () {
  "use strict";

  const API = {
    binaries: "/dashboard/api/workbench/binaries",
    functions: "/dashboard/api/workbench/functions",
    detail: "/dashboard/api/workbench/function",
    actions: "/api/v1/actions",
    jobs: "/api/v1/jobs",
    panel: "/dashboard/panel"
  };

  const TOOL_PANELS = {
    pipeline: "steps",
    crossmatch: "crossmatch",
    recovery: "recovery",
    stabs: "stabs",
    knowledge: "knowledge",
    roundtrip: "roundtrip",
    directives: "directives"
  };

  const MCP_GROUPS = {
    read: ["status", "list-functions", "list-exports", "list-imports", "list-strings", "list-symbols", "list-namespaces", "get-function", "get-current-function", "get-current-address", "get-call-graph", "get-references", "list-cross-references", "search-functions", "search-strings", "search-bytes", "search-constants", "search-symbols"],
    decompile: ["decompile-function", "decompile", "analyze-data-flow", "analyze-program", "analyze-vtables", "run-batch-decompile"],
    mutate: ["rename-function", "rename-variable", "rename-data-label", "manage-function", "manage-symbols", "manage-comments", "manage-data-types", "manage-structures", "manage-bookmarks", "create-structure", "edit-structure", "create-enum", "edit-enum"],
    match: ["match-function", "run-decomp-match", "reconstruct"],
    batch: ["run-batch-export-gzf", "run-batch-bsim-signatures", "run-batch-sast-scan"],
    project: ["open", "open-project", "checkout", "checkout-status", "close", "list-open-programs"]
  };

  let binaries = [];
  let actions = [];
  let slug = "";
  let rows = [];
  let total = 0;
  let offset = 0;
  let query = "";
  let selected = null;
  let tool = "graph";
  let lastJobs = "";

  function $(id) { return document.getElementById(id); }

  function dualBar(decomp, validate) {
    const d = decomp || {};
    const v = validate || {};
    const dTotal = Math.max(1, (d.none || 0) + (d.asm || 0) + (d.c || 0));
    const vTotal = Math.max(1, (v.none || 0) + (v.obj || 0) + (v.linked || 0));
    function segs(parts, keys) {
      return keys.map(function (key) {
        const pct = ((parts[key] || 0) / (key[0] === "n" ? (keys[0] === "none" && parts === d ? dTotal : vTotal) : (parts === d ? dTotal : vTotal))) * 100;
        return '<i class="seg-' + key + '" style="width:' + pct + '%"></i>';
      }).join("");
    }
    return '<div class="dual-bar" title="decomp vs validate">'
      + '<div class="track-decomp">' + segs(d, ["none", "asm", "c"]) + "</div>"
      + '<div class="track-validate">' + segs(v, ["none", "obj", "linked"]) + "</div>"
      + "</div>";
  }

  function rowBar(decomp, validate) {
    const d = { none: decomp === "none" ? 1 : 0, asm: decomp === "asm" ? 1 : 0, c: decomp === "c" ? 1 : 0 };
    const v = { none: validate === "none" ? 1 : 0, obj: validate === "obj" ? 1 : 0, linked: validate === "linked" ? 1 : 0 };
    return dualBar(d, v);
  }

  function setContext(extra) {
    const node = $("page-context");
    if (!node) return;
    const bin = binaries.find(function (row) { return row.slug === slug; }) || {};
    node.setAttribute("data-page", extra && extra.page || "home");
    node.setAttribute("data-slug", slug);
    node.setAttribute("data-program", bin.program || bin.repo || "");
    node.setAttribute("data-repo", bin.repo || "");
    if (selected) {
      node.setAttribute("data-addr", selected.addr || "");
      node.setAttribute("data-name", selected.name || "");
      if (selected.logicalId) node.setAttribute("data-logical-id", String(selected.logicalId));
    }
  }

  function renderBinaries() {
    const host = $("wb-binary-list");
    if (!host) return;
    host.innerHTML = binaries.map(function (row) {
      const on = row.slug === slug ? " on" : "";
      return '<li class="' + on + '" data-slug="' + row.slug + '">'
        + '<button type="button" class="wb-bin" data-slug="' + row.slug + '">' + row.slug + "</button>"
        + " <span>" + (row.funcs || 0) + "</span>"
        + dualBar(row.decomp, row.validate)
        + "</li>";
    }).join("") || "<li>Drop a binary or register a path.</li>";
  }

  async function registerPath() {
    const path = ($("wb-bin-path") && $("wb-bin-path").value || "").trim();
    if (!path) return;
    const res = await fetch(API.binaries, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        path: path,
        slug: $("wb-bin-slug") && $("wb-bin-slug").value || "",
        role: $("wb-bin-role") && $("wb-bin-role").value || "member",
        label: $("wb-bin-label") && $("wb-bin-label").value || ""
      })
    });
    const data = await res.json();
    react("corpus.add-binary", data);
    if (data.ok && data.binary) slug = data.binary.slug;
    await loadBinaries();
    await loadFuncs();
  }

  async function uploadFiles(fileList) {
    const files = Array.from(fileList || []);
    for (const file of files) {
      const body = new FormData();
      body.append("file", file, file.name);
      if ($("wb-bin-slug") && $("wb-bin-slug").value) body.append("slug", $("wb-bin-slug").value);
      if ($("wb-bin-role") && $("wb-bin-role").value) body.append("role", $("wb-bin-role").value);
      const res = await fetch(API.binaries, { method: "POST", body: body });
      const data = await res.json();
      react("corpus.add-binary", data);
      if (data.ok && data.binary) slug = data.binary.slug;
    }
    await loadBinaries();
    await loadFuncs();
  }

  async function removeSelected() {
    if (!slug) return;
    if (!window.confirm("Remove " + slug + " from the store?")) return;
    const res = await fetch(API.binaries + "/" + encodeURIComponent(slug), {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ confirm: true })
    });
    const data = await res.json();
    react("corpus.remove-binary", data);
    slug = "";
    await loadBinaries();
    rows = [];
    renderFuncs();
  }

  function renderFuncs() {
    const host = $("wb-func-window");
    const meta = $("wb-func-meta");
    if (meta) meta.textContent = (total || 0) + " functions";
    if (!host) return;
    const rowH = 28;
    host.innerHTML = '<div style="height:' + (rows.length * rowH) + 'px;position:relative">'
      + rows.map(function (row, i) {
        const on = selected && selected.address === row.address ? " on" : "";
        return '<div class="wb-func-row' + on + '" data-i="' + i + '" style="position:absolute;top:' + (i * rowH) + 'px;left:0;right:0">'
          + "<code>" + row.addr + "</code><span>" + row.name + "</span>"
          + rowBar(row.decomp, row.validate) + "</div>";
      }).join("") + "</div>";
  }

  async function loadBinaries() {
    const res = await fetch(API.binaries, { cache: "no-store" });
    const data = await res.json();
    binaries = data.binaries || [];
    if (!slug && binaries[0]) slug = binaries[0].slug;
    renderBinaries();
  }

  async function loadFuncs() {
    if (!slug) return;
    const url = API.functions + "?slug=" + encodeURIComponent(slug)
      + "&q=" + encodeURIComponent(query)
      + "&offset=" + offset + "&limit=80";
    const res = await fetch(url, { cache: "no-store" });
    const data = await res.json();
    rows = data.results || [];
    total = data.total || 0;
    renderFuncs();
  }

  async function selectRow(row) {
    selected = row;
    setContext({ page: "function" });
    renderFuncs();
    const res = await fetch(API.detail + "?slug=" + encodeURIComponent(slug) + "&addr=" + encodeURIComponent(row.addr), { cache: "no-store" });
    const data = await res.json();
    const host = $("wb-inspect-body");
    if (!host) return;
    const sibs = (data.siblings || []).map(function (s) {
      return '<li><button type="button" data-sib-slug="' + s.slug + '" data-sib-addr="' + s.addr + '">' + s.slug + " " + s.addr + "</button></li>";
    }).join("");
    host.innerHTML = "<h3>" + (row.name || "") + " <code>" + row.addr + "</code></h3>"
      + '<p class="wb-hint">logical ' + (row.logicalId || "unbound") + "</p>"
      + (sibs ? "<h4>Siblings</h4><ul>" + sibs + "</ul>" : "")
      + '<pre class="wb-preview">' + (data.preview || "No recovered C on disk.") + "</pre>"
      + '<div id="wb-reaction" class="wb-reaction">No tool result yet.</div>';
    if (tool === "graph") loadGraph();
  }

  async function loadGraph() {
    const body = $("wb-stage-body");
    if (!body || !selected) {
      if (body) body.innerHTML = "<p class=\"wb-hint\">Select a function to open the call graph.</p>";
      return;
    }
    const url = "/dashboard/functions?binary=" + encodeURIComponent(slug)
      + "&addr=" + encodeURIComponent(selected.addr) + "&partial=1";
    const res = await fetch("/dashboard/function/" + encodeURIComponent(slug) + "/" + encodeURIComponent(selected.addr));
    body.innerHTML = await res.text();
  }

  async function loadPanel(id) {
    const body = $("wb-stage-body");
    if (!body) return;
    const res = await fetch(API.panel + "?id=" + encodeURIComponent(id), { cache: "no-store" });
    body.innerHTML = await res.text();
  }

  async function loadAtlas() {
    const body = $("wb-stage-body");
    if (!body) return;
    const res = await fetch("/atlas");
    body.innerHTML = await res.text();
  }

  async function loadReport() {
    const body = $("wb-stage-body");
    if (!body) return;
    const res = await fetch("/report");
    body.innerHTML = await res.text();
  }

  function mcpGroup(name) {
    for (const key of Object.keys(MCP_GROUPS)) {
      if (MCP_GROUPS[key].indexOf(name) >= 0) return key;
    }
    return "other";
  }

  function renderMcp(filter) {
    const groups = {};
    actions.forEach(function (a) {
      const g = a.group === "mcp" ? "mcp-" + mcpGroup(a.command) : a.group;
      (groups[g] = groups[g] || []).push(a);
    });
    const keys = Object.keys(groups);
    const active = filter || keys[0] || "mcp-read";
    const body = $("wb-stage-body");
    if (!body) return;
    body.innerHTML = '<div class="wb-mcp-groups">'
      + keys.map(function (key) {
        return '<button type="button" data-mcp-group="' + key + '"' + (key === active ? ' class="on"' : "") + ">" + key + " (" + groups[key].length + ")</button>";
      }).join("")
      + "</div>"
      + '<label class="wb-search"><input id="wb-mcp-q" placeholder="Filter tools"></label>'
      + '<div id="wb-mcp-list"></div>'
      + '<form id="wb-mcp-form" class="wb-tool-form"></form>';
    paintMcpList(groups[active] || [], "");
  }

  function paintMcpList(list, q) {
    const host = $("wb-mcp-list");
    if (!host) return;
    const needle = (q || "").toLowerCase();
    host.innerHTML = list.filter(function (a) {
      return !needle || a.id.indexOf(needle) >= 0 || a.title.toLowerCase().indexOf(needle) >= 0;
    }).map(function (a) {
      return '<button type="button" data-action="' + a.id + '">' + a.title + "</button> ";
    }).join("");
  }

  function fillForm(action) {
    const form = $("wb-mcp-form") || $("action-form");
    if (!form || !action) return;
    form.hidden = false;
    form.dataset.actionId = action.id;
    const ctx = selected || {};
    form.innerHTML = "<h3>" + action.title + "</h3><p class=\"wb-hint\">" + (action.summary || "") + "</p>"
      + (action.fields || []).map(function (field) {
        let value = "";
        if (field.from_context === "addr") value = ctx.addr || "";
        if (field.from_context === "program" || field.name === "programPath") {
          const bin = binaries.find(function (row) { return row.slug === slug; }) || {};
          value = bin.program || bin.repo || "";
        }
        return "<label>" + field.name + (field.required ? " *" : "")
          + '<input name="' + field.name + '" value="' + String(value).replace(/"/g, "&quot;") + '"></label>';
      }).join("")
      + '<label><input type="checkbox" name="confirm"> confirm mutating run</label>'
      + '<button type="submit">Run ' + action.title + "</button>";
  }

  async function runAction(actionId, params, confirm) {
    const res = await fetch("/api/v1/actions/" + actionId.replace(".", "/"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(Object.assign({}, params, { confirm: !!confirm }))
    });
    const data = await res.json();
    react(actionId, data);
    return data;
  }

  function react(actionId, data) {
    const box = $("wb-reaction") || $("wb-stage-body");
    if (!box) return;
    const job = data.job || data;
    const html = '<div class="wb-reaction"><b>' + actionId + "</b> "
      + (data.dryRun ? "dry run" : (job.status || resStatus(data)))
      + "<pre class=\"wb-preview\">" + JSON.stringify(data, null, 2).slice(0, 4000) + "</pre></div>";
    if ($("wb-reaction")) $("wb-reaction").outerHTML = html;
    else box.insertAdjacentHTML("afterbegin", html);
    if (actionId.indexOf("decompile") >= 0 || actionId.indexOf("rename") >= 0 || actionId.indexOf("ghidra-bulk") >= 0) {
      loadBinaries();
      loadFuncs();
      if (selected) selectRow(selected);
    }
  }

  function resStatus(data) {
    if (data.error) return data.error;
    if (data.ok) return "ok";
    return "done";
  }

  async function setTool(next) {
    tool = next;
    document.querySelectorAll(".wb-strip [data-tool]").forEach(function (btn) {
      btn.classList.toggle("on", btn.getAttribute("data-tool") === tool);
    });
    const url = new URL(window.location.href);
    url.searchParams.set("tool", tool);
    if (slug) url.searchParams.set("slug", slug);
    if (selected) url.searchParams.set("addr", selected.addr);
    history.replaceState({}, "", url);
    if (TOOL_PANELS[tool]) return loadPanel(TOOL_PANELS[tool]);
    if (tool === "prompt" || tool === "map" || tool === "score") return loadAtlas();
    if (tool === "report") return loadReport();
    if (tool === "review" || tool === "logical" || tool === "artifacts") {
      const hash = tool === "artifacts" ? "" : "#" + tool;
      const res = await fetch("/dashboard/functions" + (slug ? "?binary=" + encodeURIComponent(slug) : "") + hash);
      $("wb-stage-body").innerHTML = await res.text();
      return;
    }
    if (tool === "mcp") return renderMcp();
    return loadGraph();
  }

  async function pollJobs() {
    const res = await fetch(API.jobs, { cache: "no-store" });
    const data = await res.json();
    const jobs = data.jobs || [];
    const pulse = $("job-pulse");
    const running = jobs.filter(function (j) { return j.status === "running" || j.status === "queued"; });
    if (pulse) pulse.textContent = running.length ? running.length + " running" : (jobs[0] ? jobs[0].status : "no jobs");
    const sig = jobs.map(function (j) { return j.id + j.status + j.returncode; }).join("|");
    if (sig !== lastJobs) {
      lastJobs = sig;
      loadBinaries();
      loadFuncs();
    }
    jobs.filter(function (j) { return j.status === "running"; }).forEach(function (j) {
      fetch(API.jobs + "/" + j.id).then(function (r) { return r.json(); }).then(function (detail) {
        const box = $("wb-reaction");
        if (box && detail.job && detail.job.log) {
          box.innerHTML = "<b>" + detail.job.actionId + "</b> live<pre class=\"wb-preview\">"
            + String(detail.job.log).slice(-2000) + "</pre>";
        }
      });
    });
  }

  async function boot() {
    window.AgentDecompileUI = { announce: function (msg) { const pulse = $("job-pulse"); if (pulse) pulse.title = msg; } };
    window.KotorXidUI = window.AgentDecompileUI;
    const params = new URLSearchParams(window.location.search);
    slug = params.get("slug") || params.get("binary") || "";
    tool = params.get("tool") || "graph";
    const addr = params.get("addr") || "";
    const act = await fetch(API.actions, { cache: "no-store" }).then(function (r) { return r.json(); });
    actions = act.actions || [];
    await loadBinaries();
    await loadFuncs();
    if (addr) {
      const hit = rows.find(function (row) { return row.addr === addr; });
      if (hit) await selectRow(hit);
    }
    await setTool(tool);
    setInterval(pollJobs, 1500);
    pollJobs();
  }

  document.addEventListener("click", function (ev) {
    const bin = ev.target.closest("[data-slug]");
    if (bin && ev.target.closest(".wb-binaries")) {
      slug = bin.getAttribute("data-slug");
      offset = 0;
      setContext({});
      loadFuncs();
      renderBinaries();
      return;
    }
    const row = ev.target.closest(".wb-func-row");
    if (row) {
      const item = rows[Number(row.getAttribute("data-i"))];
      if (item) selectRow(item);
      return;
    }
    const strip = ev.target.closest("[data-tool]");
    if (strip) {
      setTool(strip.getAttribute("data-tool"));
      return;
    }
    const group = ev.target.closest("[data-mcp-group]");
    if (group) {
      renderMcp(group.getAttribute("data-mcp-group"));
      return;
    }
    const actionBtn = ev.target.closest("[data-action]");
    if (actionBtn) {
      const action = actions.find(function (a) { return a.id === actionBtn.getAttribute("data-action"); });
      fillForm(action);
      return;
    }
    if (ev.target.id === "wb-run") {
      setTool("mcp");
    }
    if (ev.target.id === "wb-bin-remove") {
      removeSelected();
    }
    if (ev.target.id === "wb-drop") {
      const picker = $("wb-bin-file");
      if (picker) picker.click();
    }
  });

  document.addEventListener("dragover", function (ev) {
    if (!ev.target.closest("#wb-drop")) return;
    ev.preventDefault();
    $("wb-drop").classList.add("on");
  });
  document.addEventListener("dragleave", function (ev) {
    if (ev.target.id === "wb-drop") $("wb-drop").classList.remove("on");
  });
  document.addEventListener("drop", function (ev) {
    const zone = ev.target.closest("#wb-drop");
    if (!zone) return;
    ev.preventDefault();
    zone.classList.remove("on");
    uploadFiles(ev.dataTransfer && ev.dataTransfer.files);
  });

  document.addEventListener("input", function (ev) {
    if (ev.target.id === "wb-q") {
      query = ev.target.value;
      offset = 0;
      loadFuncs();
    }
    if (ev.target.id === "wb-bin-file" && ev.target.files && ev.target.files.length) {
      uploadFiles(ev.target.files);
    }
    if (ev.target.id === "wb-mcp-q") {
      const groupBtn = document.querySelector("[data-mcp-group].on");
      const g = groupBtn ? groupBtn.getAttribute("data-mcp-group") : "mcp-read";
      const list = actions.filter(function (a) {
        const key = a.group === "mcp" ? "mcp-" + mcpGroup(a.command) : a.group;
        return key === g;
      });
      paintMcpList(list, ev.target.value);
    }
  });

  document.addEventListener("submit", function (ev) {
    const form = ev.target;
    if (form.id === "wb-bin-form") {
      ev.preventDefault();
      registerPath();
      return;
    }
    if (form.id !== "wb-mcp-form" && form.id !== "action-form") return;
    ev.preventDefault();
    const actionId = form.dataset.actionId;
    if (!actionId) return;
    const params = {};
    Array.from(form.elements).forEach(function (el) {
      if (!el.name || el.name === "confirm") return;
      if (el.type === "checkbox") params[el.name] = el.checked;
      else if (el.value) params[el.name] = el.value;
    });
    runAction(actionId, params, form.confirm && form.confirm.checked);
  });

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
