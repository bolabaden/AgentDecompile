(function () {
  "use strict";

  var API = {
    snapshot: "/dashboard/api/workbench/explorer",
    functions: "/dashboard/api/workbench/functions",
    activity: "/dashboard/api/workbench/activity",
    activityEvents: "/dashboard/api/workbench/activity/events",
    preparations: "/dashboard/api/workbench/preparations",
    prepare: "/dashboard/api/workbench/prepare",
    jobs: "/dashboard/api/jobs"
  };
  var ACTIVE = { queued: 1, running: 1, waiting: 1, cancelling: 1 };
  var PREF = "explorer-island.";

  var state = {
    selection: readSelection(),
    binaries: [],
    unresolved: [],
    sessions: [],
    libraryError: "",
    libraryLoading: true,
    entities: [],
    revision: 0,
    connection: "connecting",
    activityError: "",
    run: null,
    workflowError: "",
    workflowBusy: "",
    preparedKeys: {},
    stoppedKey: "",
    treeFocus: { "binary-tree": "", "function-tree": "" },
    treeActions: {},
    source: null,
    reconnectTimer: 0,
    budgetHours: 24,
    binarySearch: readPref("binary-search", ""),
    functionSearch: readPref("function-search", ""),
    functionFilter: readPref("function-filter", "all"),
    functionLimit: readPref("function-limit", "all"),
    expanded: readPref("expanded", {}),
    rows: [],
    total: 0,
    functionLoading: false,
    functionError: "",
    binFrac: Number(readPref("bin-frac", 32)) || 32,
    workFrac: Number(readPref("work-frac", 32)) || 32
  };

  function $(id) {
    return document.getElementById(id);
  }

  function readPref(key, fallback) {
    try {
      var raw = localStorage.getItem(PREF + key);
      return raw == null ? fallback : JSON.parse(raw);
    } catch (_err) {
      return fallback;
    }
  }

  function writePref(key, value) {
    try {
      localStorage.setItem(PREF + key, JSON.stringify(value));
    } catch (_err) {
      /* Quota or private mode. Selection still lives in the URL. */
    }
  }

  function params() {
    return new URLSearchParams(window.location.search);
  }

  function readSelection() {
    var q = params();
    var stored = readPref("selection", {});
    return {
      locator: q.get("locator") || q.get("path") || stored.locator || "",
      slug: q.get("slug") || q.get("binary") || stored.slug || "",
      program: q.get("program") || stored.program || "",
      addr: q.get("addr") || q.get("fn") || stored.addr || "",
      logicalId: q.get("logicalId") || q.get("logical") || stored.logicalId || ""
    };
  }

  function writeSelection(next) {
    var prev = state.selection;
    state.selection = {
      locator: next.locator || "",
      slug: next.slug || "",
      program: next.program || "",
      addr: next.addr || "",
      logicalId: next.logicalId || ""
    };
    writePref("selection", state.selection);
    var q = new URLSearchParams();
    Object.keys(state.selection).forEach(function (key) {
      if (state.selection[key]) q.set(key, state.selection[key]);
    });
    var search = q.toString();
    var url = window.location.pathname + (search ? "?" + search : "");
    if (url !== window.location.pathname + window.location.search) {
      history.replaceState(state.selection, "", url);
    }
    if ((prev.locator || "") !== state.selection.locator
      || (prev.slug || "") !== state.selection.slug
      || (prev.program || "") !== state.selection.program) {
      state.revision = 0;
      watchActivity();
    }
  }

  function selectionKey() {
    return JSON.stringify([
      state.selection.locator || "",
      state.selection.program || "",
      state.selection.slug || ""
    ]);
  }

  function binaryKey(row) {
    if (row.libraryId) return String(row.libraryId);
    if (row.sha256) return "sha256:" + row.sha256;
    return String(row.id || row.slug || "");
  }

  function labelOf(row) {
    return String(row.label || row.name || row.title || row.slug || (row.locator || "").split("/").pop() || "Unnamed");
  }

  function normAddr(value) {
    return String(value || "").toLowerCase().replace(/^0x0*/, "");
  }

  function readable(value) {
    return String(value || "").replace(/^mcp\./, "").replace(/[_-]/g, " ");
  }

  function isOpen(id) {
    return state.expanded[id] !== false;
  }

  function toggleOpen(id) {
    state.expanded[id] = !isOpen(id);
    writePref("expanded", state.expanded);
    renderTrees();
  }

  function treeDomId(tree, key) {
    return (tree === "binary-tree" ? "bt-" : "ft-") + encodeURIComponent(key);
  }

  function markTreeFocus(tree, id, scroll) {
    state.treeFocus[tree] = id || "";
    var host = $(tree);
    if (!host) return;
    var items = host.querySelectorAll("[role=treeitem]");
    var el = id ? document.getElementById(id) : null;
    if (!el || !host.contains(el)) {
      el = host.querySelector("[aria-selected='true']") || items[0] || null;
      state.treeFocus[tree] = el ? el.id : "";
    }
    if (el) host.setAttribute("aria-activedescendant", el.id);
    else host.removeAttribute("aria-activedescendant");
    items.forEach(function (node) {
      node.classList.toggle("keyboard-focus", node === el);
    });
    if (scroll && el) el.scrollIntoView({ block: "nearest" });
  }

  function findEntity(kind, record, locator) {
    var list = state.entities || [];
    for (var i = 0; i < list.length; i++) {
      var item = list[i];
      if (item.kind !== kind) continue;
      if (kind === "project") {
        if (item.locator === locator) return item;
      } else if (kind === "function") {
        if (normAddr(item.addr) === normAddr(record.addr)) return item;
      } else if (item.slug === record.slug || (item.aliasSlugs || []).indexOf(record.slug) >= 0 || (record.sha256 && item.sha256 === record.sha256)) {
        return item;
      }
    }
    return null;
  }

  function selectPreparation(runs, selection) {
    var locator = selection.locator || "";
    var program = selection.program || "";
    var slug = selection.slug || "";
    if (!locator && !slug) return null;
    var applicable = (runs || []).filter(function (run) {
      if (locator) {
        if (run.locator !== locator) return false;
        if (program && run.program && run.program !== program && (run.programs || []).indexOf(program) < 0) return false;
        return true;
      }
      return run.slug === slug;
    });
    applicable.sort(function (a, b) {
      return Number(!!ACTIVE[b.status]) - Number(!!ACTIVE[a.status]) || Number(b.updatedAt || 0) - Number(a.updatedAt || 0);
    });
    return applicable[0] || null;
  }

  function text(value) {
    return document.createTextNode(value == null ? "" : String(value));
  }

  function node(tag, attrs, kids) {
    var el = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (key) {
      if (key === "className") el.className = attrs[key];
      else if (key === "dataset") Object.assign(el.dataset, attrs[key]);
      else if (key.slice(0, 2) === "on") el.addEventListener(key.slice(2).toLowerCase(), attrs[key]);
      else if (attrs[key] === false || attrs[key] == null) return;
      else if (attrs[key] === true) el.setAttribute(key, "");
      else el.setAttribute(key, String(attrs[key]));
    });
    (kids || []).forEach(function (child) {
      if (child) el.appendChild(typeof child === "string" ? text(child) : child);
    });
    return el;
  }

  var KIND_MARK = {
    human: "H",
    debug: "S",
    stabs: "S",
    match: "M",
    assembly: "A",
    substrate: "A",
    analysis: "G",
    "analysis-unknown": "?",
    advisory: "C",
    source: "C",
    context: "·",
    "recorded-proof": "R",
    verified: "V",
    protection: "X"
  };
  var NODE_MARK = { project: "P", binary: "B", function: "F", group: "G" };
  var NODE_WORD = { project: "Project", binary: "Binary", function: "Function", group: "Group" };
  var STATUS_WORD = {
    running: "Running",
    queued: "Queued",
    waiting: "Waiting",
    cancelling: "Stopping",
    paused: "Paused",
    failed: "Failed",
    blocked: "Blocked",
    interrupted: "Interrupted",
    completed: "Completed",
    idle: "Idle"
  };

  function statusWord(status) {
    return STATUS_WORD[status] || (status ? String(status) : "Idle");
  }

  function activityStrip(entity, fallback) {
    var progress = entity && entity.progress;
    var measured = progress && progress.kind === "measured" && Number.isFinite(progress.total) && progress.total > 0;
    var active = entity && entity.status === "running" && progress && progress.kind === "indeterminate";
    var stage = readable(entity && entity.stage);
    var action = readable(entity && entity.action);
    var operation = stage && ["not queued", "unknown", "execute script"].indexOf(stage.toLowerCase()) < 0
      ? stage
      : (action === "execute script" ? "Run project operation" : action || fallback || "Not queued");
    var current = (entity && entity.error) || operation;
    var queue = entity && entity.queue && entity.queue.position;
    var wrap = node("div", { className: "entity-activity" + (active ? " is-active" : "") });
    wrap.appendChild(node("span", { className: "entity-operation", title: current }, [
      statusWord(entity && entity.status) + " · " + (queue != null ? "#" + queue + " · " : "") + String(current).replace(/_/g, " ")
    ]));
    wrap.appendChild(node("span", { className: "entity-eta" }, [
      (entity && entity.eta && entity.eta.label) || "ETA unavailable"
    ]));
    if (measured) {
      var bar = node("progress", { "aria-label": current });
      bar.max = progress.total;
      bar.value = Math.max(0, Math.min(progress.total, progress.completed));
      wrap.appendChild(bar);
    } else if (active) {
      wrap.appendChild(node("progress", { "aria-label": current + " in progress" }));
    } else {
      wrap.appendChild(node("span", { className: "entity-idle-track" }));
    }
    return wrap;
  }

  function isProofKind(kind) {
    return kind === "recorded-proof" || kind === "verified";
  }

  function chip(facet) {
    var mark = KIND_MARK[facet.kind] || "·";
    return node("span", { className: "entity-chip", "data-kind": facet.kind, title: facet.source || facet.label }, [
      node("span", { className: "entity-chip-mark", "aria-hidden": "true" }, [mark]),
      node("span", { className: "entity-chip-label" }, [facet.label])
    ]);
  }

  function evidenceItems(entity, record) {
    var items = ((entity && entity.evidence) || (entity && entity.facets) || []).filter(function (facet) {
      return !isProofKind(facet.kind);
    });
    if ((record.source === "USER_DEFINED" || record.nameSource === "human" || record.humanAuthored) && !items.some(function (f) { return f.kind === "human"; })) {
      items.push({ kind: "human", label: "Human name" });
    }
    if (record.decomp === "asm" && !items.some(function (f) { return f.kind === "assembly" || f.kind === "substrate"; })) {
      items.push({ kind: "assembly", label: "Assembly substrate" });
    }
    if (record.decomp === "c" && !items.some(function (f) { return f.kind === "advisory" || f.kind === "source"; })) {
      items.push({ kind: "advisory", label: "C witness" });
    }
    return items;
  }

  function proofItems(entity) {
    var items = ((entity && entity.proof) || []).slice();
    ((entity && entity.proofReceipts) || []).forEach(function (receipt) {
      var label = receipt.label || "Recorded receipt";
      var source = receipt.path || receipt.href || "";
      if (!items.some(function (item) { return item.label === label && item.source === source; })) {
        items.push({ kind: "recorded-proof", label: label, source: source });
      }
    });
    return items;
  }

  function dimensionRow(name, items, empty) {
    return node("div", { className: "entity-dimension", "data-dimension": name.toLowerCase() }, [
      node("span", { className: "entity-dimension-name" }, [name]),
      items.length
        ? node("span", { className: "entity-dimension-items" }, items.map(chip))
        : node("span", { className: "entity-dimension-empty" }, [empty])
    ]);
  }

  function dimensionBlock(entity, record, fallback) {
    var wrap = node("div", { className: "entity-dimensions" });
    wrap.appendChild(dimensionRow("Evidence", evidenceItems(entity, record || {}), "No evidence recorded"));
    wrap.appendChild(dimensionRow("Proof", proofItems(entity), "No proof recorded"));
    var activity = node("div", { className: "entity-dimension", "data-dimension": "activity" });
    activity.appendChild(node("span", { className: "entity-dimension-name" }, ["Activity"]));
    activity.appendChild(activityStrip(entity, fallback));
    wrap.appendChild(activity);
    return wrap;
  }

  function protectionLabel(row) {
    var item = row.protection || {};
    return item.label || item.encryption || item.status || "Protection unknown";
  }

  function matchesBinarySearch(row) {
    var q = String(state.binarySearch || "").toLowerCase();
    if (!q) return true;
    return (labelOf(row) + " " + (row.platform || "") + " " + (row.sha256 || "")).toLowerCase().indexOf(q) >= 0;
  }

  function projectRows() {
    var map = {};
    (state.sessions || []).forEach(function (item) {
      if (item.locator) map[item.locator] = item;
    });
    (state.binaries || []).forEach(function (bin) {
      (bin.projectBindings || []).forEach(function (bind) {
        if (bind.locator && !map[bind.locator]) {
          map[bind.locator] = { locator: bind.locator, title: bind.locator.split("/").pop() };
        }
      });
    });
    if (state.selection.locator && !map[state.selection.locator]) {
      map[state.selection.locator] = {
        locator: state.selection.locator,
        title: state.selection.locator.split("/").pop()
      };
    }
    return Object.keys(map).map(function (key) { return map[key]; });
  }

  function membersOf(project) {
    return (state.binaries || []).filter(function (bin) {
      return (bin.projectBindings || []).some(function (bind) { return bind.locator === project.locator; })
        || (bin.imported && bin.locator === project.locator)
        || (project.imports || []).indexOf(bin.slug) >= 0;
    });
  }

  function renderBinaryTree() {
    var host = $("binary-tree");
    var empty = $("binary-empty");
    host.replaceChildren();
    var projects = projectRows();
    var assigned = {};
    projects.forEach(function (project) {
      membersOf(project).forEach(function (bin) { assigned[binaryKey(bin)] = true; });
    });
    var unassigned = (state.binaries || []).filter(function (bin) { return !assigned[binaryKey(bin)]; });
    var count = 0;

    function addBinary(parent, bin, locator, level) {
      if (!matchesBinarySearch(bin)) return;
      count += 1;
      var binding = (bin.projectBindings || []).find(function (item) { return item.locator === locator; }) || {};
      var record = Object.assign({}, bin, binding.program ? { program: binding.program } : {});
      var entity = findEntity("binary", bin, locator);
      var selected = record.slug === state.selection.slug && (locator || "") === (state.selection.locator || "");
      var id = "binary:" + (locator || "") + ":" + (bin.slug || "") + ":" + (record.program || "");
      host.appendChild(treeRow({
        tree: "binary-tree",
        id: id,
        parent: parent,
        kind: "binary",
        level: level,
        name: labelOf(bin),
        selected: selected,
        entity: entity,
        meta: (bin.platform || "Platform unknown") + " · " + protectionLabel(bin),
        record: record,
        onChoose: function () {
          writeSelection({
            slug: record.slug || "",
            program: record.program || "",
            locator: locator || (record.imported ? record.locator : "") || "",
            addr: "",
            logicalId: ""
          });
          state.rows = [];
          loadFunctions();
          loadSnapshot();
          renderAll();
        }
      }));
    }

    projects.forEach(function (project) {
      var members = membersOf(project);
      if (state.binarySearch && labelOf(project).toLowerCase().indexOf(state.binarySearch.toLowerCase()) < 0 && !members.some(matchesBinarySearch)) {
        return;
      }
      var id = "project:" + project.locator;
      var selected = state.selection.locator === project.locator && !state.selection.slug;
      host.appendChild(treeRow({
        tree: "binary-tree",
        id: id,
        kind: "project",
        level: 1,
        name: labelOf(project),
        selected: selected,
        expanded: isOpen(id),
        entity: findEntity("project", project, project.locator),
        meta: project.locator,
        record: project,
        onToggle: function () { toggleOpen(id); },
        onChoose: function () {
          writeSelection({ locator: project.locator || "", slug: "", program: "", addr: "", logicalId: "" });
          state.rows = [];
          loadSnapshot();
          renderAll();
        }
      }));
      if (isOpen(id)) members.forEach(function (bin) { addBinary(id, bin, project.locator, 2); });
    });

    var leftover = unassigned.filter(matchesBinarySearch);
    if (leftover.length) {
      var uid = "unassigned";
      host.appendChild(treeRow({
        tree: "binary-tree",
        id: uid,
        kind: "group",
        level: 1,
        name: "Unassigned binaries",
        expanded: isOpen(uid),
        record: { count: leftover.length },
        onToggle: function () { toggleOpen(uid); },
        onChoose: function () { toggleOpen(uid); }
      }));
      if (isOpen(uid)) leftover.forEach(function (bin) { addBinary(uid, bin, "", 2); });
    }

    (state.unresolved || []).forEach(function (bin) {
      if (!matchesBinarySearch(bin)) return;
      count += 1;
      host.appendChild(treeRow({
        tree: "binary-tree",
        id: "unresolved:" + (bin.slug || ""),
        kind: "binary",
        level: 2,
        name: labelOf(bin),
        record: bin,
        meta: "Resolve source identity",
        onChoose: function () {
          writeSelection({ slug: bin.slug || "", program: "", locator: "", addr: "", logicalId: "" });
          state.rows = [];
          loadFunctions();
          loadSnapshot();
          renderAll();
        }
      }));
    });

    empty.hidden = count > 0 || projects.length > 0;
    if (!count && !projects.length) {
      empty.hidden = false;
      empty.textContent = state.libraryLoading
        ? "Loading projects and binaries…"
        : (state.libraryError || "Open a project or add binaries to begin.");
    }
    markTreeFocus("binary-tree", state.treeFocus["binary-tree"], false);
  }

  function renderFunctionTree() {
    var host = $("function-tree");
    host.replaceChildren();
    var groups = {};
    (state.rows || []).forEach(function (row) {
      var name = row.humanModule || row.userModule || row.compilationUnit || row.sourceFile || row.sourceUnit || row.module || row.namespace || "Unassigned";
      (groups[name] || (groups[name] = [])).push(row);
    });
    Object.keys(groups).forEach(function (name) {
      var id = "functions:" + name;
      host.appendChild(treeRow({
        tree: "function-tree",
        id: id,
        kind: "group",
        level: 1,
        name: name,
        expanded: isOpen(id),
        record: { count: groups[name].length },
        onToggle: function () { toggleOpen(id); },
        onChoose: function () { toggleOpen(id); }
      }));
      if (!isOpen(id)) return;
      groups[name].forEach(function (row) {
        var entity = findEntity("function", row);
        host.appendChild(treeRow({
          tree: "function-tree",
          id: "function:" + (row.addr || ""),
          parent: id,
          kind: "function",
          level: 2,
          name: row.name || row.addr,
          addr: row.addr,
          selected: row.addr === state.selection.addr,
          entity: entity,
          record: row,
          onChoose: function () {
            writeSelection(Object.assign({}, state.selection, {
              addr: row.addr || "",
              logicalId: String(row.logicalId || "")
            }));
            renderTrees();
          }
        }));
      });
    });
    $("function-context").textContent = state.selection.program || state.selection.slug || "Select a binary";
    $("function-total").textContent = state.total ? String(state.total) : "";
    var status = $("function-status");
    if (state.functionLoading) status.textContent = "Loading function inventory…";
    else if (state.functionError) status.textContent = "Inventory unavailable";
    else if (state.rows.length && state.functionLimit !== "all" && state.rows.length < state.total) {
      status.textContent = state.rows.length + " of " + state.total + " shown";
    } else if (state.rows.length) status.textContent = state.total + " functions";
    else if (state.selection.slug || state.selection.program) status.textContent = "No functions recorded yet";
    else status.textContent = "No binary selected";
    markTreeFocus("function-tree", state.treeFocus["function-tree"], false);
  }

  function treeRow(spec) {
    var pad = 8 + (Math.max(1, spec.level || 1) - 1) * 14;
    var key = spec.id || spec.name || "";
    var domId = spec.tree ? treeDomId(spec.tree, key) : "";
    var parentId = spec.tree && spec.parent ? treeDomId(spec.tree, spec.parent) : "";
    if (domId) {
      state.treeActions[domId] = {
        onChoose: spec.onChoose,
        onToggle: spec.onToggle,
        expanded: spec.expanded,
        parent: parentId
      };
    }
    var row = node("div", {
      id: domId || null,
      className: "explorer-node " + (spec.kind || "") + (spec.selected ? " inspected" : ""),
      role: "treeitem",
      "aria-level": spec.level || 1,
      "aria-selected": spec.selected ? "true" : "false",
      "aria-expanded": spec.expanded == null ? null : (spec.expanded ? "true" : "false"),
      "data-status": (spec.entity && spec.entity.status) || "unknown",
      onclick: function () {
        if (spec.tree && domId) markTreeFocus(spec.tree, domId, false);
        spec.onChoose();
      }
    });
    row.style.paddingLeft = pad + "px";
    var title = node("div", { className: "explorer-node-title" });
    if (spec.expanded != null) {
      title.appendChild(node("button", {
        className: "explorer-chevron",
        type: "button",
        tabindex: "-1",
        "aria-label": (spec.expanded ? "Collapse " : "Expand ") + spec.name,
        onclick: function (ev) {
          ev.stopPropagation();
          spec.onToggle();
          if (spec.tree) $(spec.tree).focus();
        }
      }, [spec.expanded ? "▾" : "▸"]));
    } else {
      title.appendChild(node("span", { className: "explorer-marker " + spec.kind }, [
        node("span", { "aria-hidden": "true" }, [NODE_MARK[spec.kind] || "·"]),
        node("span", { className: "sr-only" }, [NODE_WORD[spec.kind] || spec.kind || "Item"])
      ]));
    }
    if (spec.kind === "function" && spec.addr) {
      title.appendChild(node("code", { className: "explorer-address" }, [
        node("span", { className: "sr-only" }, ["Address "]),
        spec.addr
      ]));
    }
    title.appendChild(node("span", { className: "explorer-name", title: spec.name }, [spec.name]));
    if (spec.kind === "group" && spec.record && spec.record.count != null) {
      title.appendChild(node("span", { className: "explorer-total" }, [String(spec.record.count)]));
    }
    row.appendChild(title);
    if (spec.kind !== "group") {
      if (spec.meta) row.appendChild(node("div", { className: "explorer-row-meta" }, [spec.meta]));
      row.appendChild(dimensionBlock(spec.entity, spec.record || {}, "Not queued"));
    }
    return row;
  }

  function workflowTitle(run) {
    if (!run) return state.libraryLoading ? "Checking workflow…" : (state.selection.locator || state.selection.slug ? "No workflow for this selection" : "Select a binary to see its workflow");
    return ({
      queued: "Preparation queued",
      running: "Preparing project",
      completed: "Preparation completed",
      partial: "Preparation needs attention",
      cancelling: "Stopping preparation",
      paused: "Workflow paused",
      interrupted: "Workflow interrupted"
    })[run.status] || ("Preparation " + run.status);
  }

  function renderWorkflow() {
    var body = $("workflow-body");
    var run = state.run;
    body.replaceChildren();
    $("workflow-connection").textContent = state.connection === "live"
      ? "Live"
      : (state.connection === "polling" ? "Polling" : (state.activityError ? "Retrying" : "Connecting"));
    body.appendChild(node("div", { className: "workflow-status", role: "status" }, [
      node("strong", {}, [workflowTitle(run)])
    ]));
    if (!run) {
      if (state.selection.locator || state.selection.slug) {
        var start = node("button", { type: "button", onclick: function () { startWorkflow(); } }, ["Start workflow"]);
        start.disabled = Boolean(state.workflowBusy);
        body.appendChild(node("div", { className: "workflow-controls" }, [start]));
      }
      if (state.workflowError) body.appendChild(node("p", { className: "workflow-error" }, ["Error: " + state.workflowError]));
      return;
    }
    body.appendChild(node("p", { className: "workflow-scope" }, [
      run.program ? "Program · " + run.program : "Project-wide · " + (run.locator || state.selection.locator)
    ]));
    var current = (run.stages || []).find(function (stage) {
      return stage.status === "running" || stage.status === "waiting" || stage.status === "cancelling" || stage.status === "queued";
    });
    if (current) {
      body.appendChild(node("div", { className: "workflow-current" }, [
        node("span", {}, [current.title || "Current stage"]),
        current.currentProgram ? node("code", { title: current.currentProgram }, [current.currentProgram]) : null,
        current.currentAction ? node("span", {}, [readable(current.currentAction)]) : null
      ]));
    }
    var rail = node("ol", { className: "workflow-rail", "aria-label": "Workflow stages" });
    (run.stages || []).forEach(function (stage) {
      var measured = Number.isFinite(stage.total) && stage.total > 0 && Number.isFinite(stage.completed);
      var working = stage.status === "running" && !measured;
      var item = node("li", { className: working ? "is-active" : "", "data-state": stage.status });
      item.appendChild(node("div", {}, [
        node("strong", {}, [stage.title || stage.key || "Stage"]),
        " ",
        node("span", {}, [statusWord(stage.status)])
      ]));
      if (measured) {
        var bar = node("progress", { "aria-label": stage.title || "Stage" });
        bar.max = stage.total;
        bar.value = stage.completed;
        item.appendChild(bar);
        item.appendChild(node("small", {}, [stage.completed + " / " + stage.total + " completed"]));
      } else if (working) {
        item.appendChild(node("progress", { "aria-label": (stage.title || "Stage") + " in progress" }));
        item.appendChild(node("small", {}, ["Progress not measured"]));
      } else {
        item.appendChild(node("div", { className: "workflow-track" }));
        item.appendChild(node("small", {}, [stage.status === "queued" ? "Waiting for preceding work" : (stage.total === 0 ? "No applicable items" : "Not started")]));
      }
      if (stage.reason) item.appendChild(node("small", {}, [String(stage.reason).split("\n")[0]]));
      rail.appendChild(item);
    });
    body.appendChild(rail);
    if (run.admissionPending) {
      body.appendChild(node("p", { className: "workflow-scope" }, ["Waiting for a project worker."]));
    }
    if (run.error || run.reason) {
      body.appendChild(node("p", { className: "workflow-error" }, ["Error: " + (run.error || run.reason)]));
    }
    var controls = node("div", { className: "workflow-controls" });
    if (ACTIVE[run.status]) {
      controls.appendChild(controlButton("pause", "Pause workflow"));
      controls.appendChild(controlButton("stop", "Stop workflow"));
    }
    if (run.status === "paused") controls.appendChild(controlButton("resume", "Resume workflow"));
    if (run.status === "cancelled" || run.status === "blocked") {
      var restart = node("button", { type: "button", onclick: function () { startWorkflow(); } }, ["Start workflow"]);
      restart.disabled = Boolean(state.workflowBusy);
      controls.appendChild(restart);
    }
    var hours = node("input", {
      type: "number",
      min: "1",
      max: "168",
      value: String(state.budgetHours),
      "aria-label": "Workflow budget hours"
    });
    hours.addEventListener("change", function () {
      state.budgetHours = Number(hours.value);
    });
    controls.appendChild(node("label", {}, ["Hours from now ", hours]));
    controls.appendChild(controlButton("budget", "Set budget"));
    if (state.workflowBusy) controls.appendChild(node("span", { role: "status" }, ["Submitting " + state.workflowBusy + "…"]));
    body.appendChild(controls);
    if (state.workflowError) body.appendChild(node("p", { className: "workflow-error" }, ["Error: " + state.workflowError]));
    var events = run.events || [];
    if (events.length) {
      var list = node("ol", { className: "workflow-events" });
      events.slice(-12).forEach(function (event) {
        list.appendChild(node("li", {}, [
          node("time", {}, [event.at ? new Date(event.at * 1000).toLocaleTimeString() : ""]),
          " ",
          String(event.message || "").split("\n")[0]
        ]));
      });
      var details = node("details", { className: "workflow-events" }, [
        node("summary", {}, ["Activity history (" + events.length + ")"]),
        list
      ]);
      body.appendChild(details);
    }
  }

  function controlButton(operation, title) {
    var button = node("button", { type: "button" }, [title]);
    button.disabled = Boolean(state.workflowBusy);
    button.addEventListener("click", function () { controlWorkflow(operation); });
    return button;
  }

  function renderFeed() {
    var bits = [state.connection === "live" ? "Live activity" : (state.connection === "polling" ? "Polling activity" : "Connecting")];
    if (state.activityError) bits.push("Keeping last state");
    if (state.run && state.run.status) bits.push("Workflow " + state.run.status);
    $("explorer-feed").textContent = bits.join(" · ");
  }

  function renderTrees() {
    renderBinaryTree();
    renderFunctionTree();
    markTreeFocus("binary-tree", state.treeFocus["binary-tree"], false);
    markTreeFocus("function-tree", state.treeFocus["function-tree"], false);
  }

  function renderAll() {
    document.documentElement.style.setProperty("--bin-frac", state.binFrac + "%");
    document.documentElement.style.setProperty("--work-frac", state.workFrac + "%");
    renderTrees();
    renderWorkflow();
    renderFeed();
  }

  function applySnapshot(data) {
    if (!data || data.ok === false) {
      state.libraryError = (data && data.libraryError) || (data && data.error) || "Library unavailable";
      state.libraryLoading = false;
      return;
    }
    state.binaries = data.binaries || [];
    state.unresolved = data.unresolvedBinaries || [];
    state.sessions = data.sessions || [];
    state.libraryError = data.libraryError || "";
    state.libraryLoading = false;
    if (Object.prototype.hasOwnProperty.call(data, "run")) state.run = data.run || null;
    if (data.activity && Array.isArray(data.activity.entities)) {
      state.entities = data.activity.entities;
      if (Number.isSafeInteger(data.activity.revision)) state.revision = data.activity.revision;
      if (data.activity.ok) {
        state.activityError = "";
        if (state.connection === "connecting") state.connection = "polling";
      } else {
        state.activityError = data.activity.error || "Activity unavailable";
      }
    }
  }

  function loadSnapshot() {
    var q = new URLSearchParams({
      locator: state.selection.locator || "",
      slug: state.selection.slug || "",
      program: state.selection.program || ""
    });
    return fetch(API.snapshot + "?" + q.toString(), { signal: AbortSignal.timeout(15000) })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        applySnapshot(data);
        maybeStartWorkflow();
        renderAll();
      })
      .catch(function (err) {
        state.libraryError = String(err && err.message || err);
        state.libraryLoading = false;
        renderAll();
      });
  }

  function loadFunctions() {
    if (!state.selection.slug && !state.selection.program) {
      state.functionLoading = false;
      state.rows = [];
      state.total = 0;
      renderFunctionTree();
      return;
    }
    state.functionLoading = true;
    renderFunctionTree();
    var q = new URLSearchParams({
      slug: state.selection.slug || "",
      program: state.selection.program || "",
      locator: state.selection.locator || "",
      q: state.functionSearch || "",
      filter: state.functionFilter || "all",
      offset: "0",
      limit: String(state.functionLimit || "all")
    });
    fetch(API.functions + "?" + q.toString(), { signal: AbortSignal.timeout(state.functionLimit === "all" ? 60000 : 15000) })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        state.rows = data.results || [];
        state.total = data.total || 0;
        state.functionError = data.error || "";
        state.functionLoading = false;
        renderFunctionTree();
      })
      .catch(function (err) {
        state.functionError = String(err && err.message || err);
        state.functionLoading = false;
        renderFunctionTree();
      });
  }

  function loadPreparations() {
    fetch(API.preparations, { signal: AbortSignal.timeout(8000) })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        state.run = selectPreparation(data.runs || [], state.selection);
        state.workflowError = data.error || "";
        maybeStartWorkflow();
        renderWorkflow();
        renderFeed();
      })
      .catch(function (err) {
        state.workflowError = String(err && err.message || err);
        renderWorkflow();
      });
  }

  function maybeStartWorkflow() {
    if (state.libraryLoading) return;
    if (!state.selection.locator && !state.selection.slug) return;
    if (state.workflowBusy) return;
    var status = state.run && state.run.status;
    if (status === "queued" || status === "running" || status === "waiting" || status === "paused" || status === "cancelling") return;
    if (status === "cancelled" || status === "blocked") return;
    var key = selectionKey();
    // A stop on this selection must not auto-queue again.
    if (state.stoppedKey === key) return;
    var resume = status === "interrupted";
    var stamp = key + (resume ? ":resume" : ":start");
    if (state.preparedKeys[stamp]) return;
    state.preparedKeys[stamp] = true;
    startWorkflow(resume, stamp);
  }

  function startWorkflow(resume, stamp) {
    if (state.workflowBusy) return;
    if (!stamp) {
      state.stoppedKey = "";
      stamp = selectionKey() + (resume ? ":resume" : ":start");
      state.preparedKeys[stamp] = true;
    }
    state.workflowBusy = "start";
    state.workflowError = "";
    renderWorkflow();
    fetch(API.prepare, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        locator: state.selection.locator || "",
        program: state.selection.program || "",
        slug: state.selection.slug || "",
        resume: Boolean(resume)
      })
    }).then(function (res) { return res.json().then(function (data) { return { res: res, data: data }; }); })
      .then(function (pair) {
        if (pair.data && pair.data.run) state.run = pair.data.run;
        if (!pair.data || pair.data.ok === false) state.workflowError = (pair.data && pair.data.error) || "Start failed";
        state.workflowBusy = "";
        renderWorkflow();
        loadPreparations();
      })
      .catch(function (err) {
        state.workflowError = String(err && err.message || err);
        state.workflowBusy = "";
        renderWorkflow();
      });
  }

  function controlWorkflow(operation) {
    if (!state.run || state.workflowBusy) return;
    if (operation === "stop") state.stoppedKey = selectionKey();
    state.workflowBusy = operation;
    state.workflowError = "";
    renderWorkflow();
    var params = { preparation_id: state.run.id, operation: operation };
    if (operation === "budget") params.seconds = Math.round(Number(state.budgetHours || 24) * 3600);
    fetch(API.jobs, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "workbench.workflow-control",
        params: params,
        context: state.selection,
        confirm: true
      })
    }).then(function (res) { return res.json(); })
      .then(function (data) {
        if (data && data.error) state.workflowError = data.error;
        state.workflowBusy = "";
        renderWorkflow();
        loadPreparations();
      })
      .catch(function (err) {
        state.workflowError = String(err && err.message || err);
        state.workflowBusy = "";
        renderWorkflow();
      });
  }

  function activityQuery() {
    var query = new URLSearchParams({
      locator: state.selection.locator || "",
      slug: state.selection.slug || ""
    });
    if (state.selection.program) query.set("program", state.selection.program);
    return query;
  }

  function watchActivity() {
    if (state.reconnectTimer) {
      clearTimeout(state.reconnectTimer);
      state.reconnectTimer = 0;
    }
    var query = activityQuery();
    if (state.revision) query.set("after", String(state.revision));
    if (state.source) {
      state.source.close();
      state.source = null;
    }
    try {
      var source = new EventSource(API.activityEvents + "?" + query.toString());
      state.source = source;
      source.addEventListener("snapshot", function (ev) {
        try { acceptActivity(JSON.parse(ev.data), true); } catch (_err) { /* Keep last entities. */ }
      });
      source.addEventListener("activity", function (ev) {
        try { acceptActivity(JSON.parse(ev.data), false); } catch (_err) { /* Keep last entities. */ }
      });
      source.addEventListener("heartbeat", function () {
        state.connection = "live";
        renderFeed();
      });
      source.addEventListener("unavailable", function (ev) {
        state.connection = "polling";
        try {
          var data = JSON.parse(ev.data);
          state.activityError = (data && data.error) || "Activity unavailable";
        } catch (_err) {
          state.activityError = "Activity unavailable";
        }
        renderFeed();
        pollActivity();
      });
      source.onerror = function () {
        if (state.source !== source) return;
        state.connection = "polling";
        source.close();
        state.source = null;
        renderFeed();
        pollActivity();
        state.reconnectTimer = setTimeout(function () {
          state.reconnectTimer = 0;
          if (!state.source) watchActivity();
        }, 2000);
      };
    } catch (_err) {
      pollActivity();
    }
  }

  function acceptActivity(data, reset) {
    if (!data || !Array.isArray(data.entities)) return;
    if (!reset && Number.isSafeInteger(data.revision) && data.revision < state.revision) return;
    state.entities = data.entities;
    if (Number.isSafeInteger(data.revision)) state.revision = data.revision;
    state.connection = "live";
    state.activityError = data.error || "";
    renderTrees();
    renderFeed();
  }

  function pollActivity() {
    fetch(API.activity + "?" + activityQuery().toString(), { signal: AbortSignal.timeout(8000) })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (data && Array.isArray(data.entities)) {
          state.entities = data.entities;
          if (Number.isSafeInteger(data.revision)) state.revision = data.revision;
          if (state.connection !== "live") state.connection = "polling";
          state.activityError = data.error || "";
          renderTrees();
          renderFeed();
        }
      })
      .catch(function (err) {
        state.activityError = String(err && err.message || err);
        if (state.connection !== "live") state.connection = "disconnected";
        renderFeed();
      });
  }

  function bindResize() {
    function drag(bar, axis) {
      bar.addEventListener("pointerdown", function (ev) {
        ev.preventDefault();
        bar.setPointerCapture(ev.pointerId);
        var start = axis === "x" ? ev.clientX : ev.clientY;
        var startFrac = axis === "x" ? state.binFrac : state.workFrac;
        var shell = $("app").getBoundingClientRect();
        function move(next) {
          var delta = axis === "x" ? next.clientX - start : start - next.clientY;
          var size = axis === "x" ? shell.width : shell.height;
          var frac = Math.max(18, Math.min(70, startFrac + (delta / size) * 100));
          if (axis === "x") {
            state.binFrac = frac;
            writePref("bin-frac", frac);
          } else {
            state.workFrac = frac;
            writePref("work-frac", frac);
          }
          renderAll();
        }
        function up() {
          bar.removeEventListener("pointermove", move);
          bar.removeEventListener("pointerup", up);
        }
        bar.addEventListener("pointermove", move);
        bar.addEventListener("pointerup", up);
      });
    }
    drag($("split-x"), "x");
    drag($("split-y"), "y");
    function nudge(axis, dir) {
      var shell = $("app").getBoundingClientRect();
      var size = axis === "x" ? shell.width : shell.height;
      var step = (16 / Math.max(size, 1)) * 100;
      var frac = Math.max(18, Math.min(70, (axis === "x" ? state.binFrac : state.workFrac) + dir * step));
      if (axis === "x") {
        state.binFrac = frac;
        writePref("bin-frac", frac);
      } else {
        state.workFrac = frac;
        writePref("work-frac", frac);
      }
      renderAll();
    }
    function keys(bar, axis) {
      bar.addEventListener("keydown", function (ev) {
        var dir = axis === "x"
          ? (ev.key === "ArrowLeft" ? -1 : ev.key === "ArrowRight" ? 1 : 0)
          : (ev.key === "ArrowUp" ? 1 : ev.key === "ArrowDown" ? -1 : 0);
        if (!dir) return;
        ev.preventDefault();
        nudge(axis, dir);
      });
    }
    keys($("split-x"), "x");
    keys($("split-y"), "y");
  }

  function bindValue(id, value, event, onChange) {
    var el = $(id);
    if (!el) return;
    el.value = value;
    el.addEventListener(event, onChange);
  }

  function bindControls() {
    bindValue("binary-search", state.binarySearch, "input", function (ev) {
      state.binarySearch = ev.target.value;
      writePref("binary-search", state.binarySearch);
      renderBinaryTree();
    });
    bindValue("function-search", state.functionSearch, "input", function (ev) {
      state.functionSearch = ev.target.value;
      writePref("function-search", state.functionSearch);
      loadFunctions();
    });
    bindValue("function-filter", state.functionFilter, "change", function (ev) {
      state.functionFilter = ev.target.value;
      writePref("function-filter", state.functionFilter);
      loadFunctions();
    });
    bindValue("function-limit", state.functionLimit || "all", "change", function (ev) {
      state.functionLimit = ev.target.value || "all";
      writePref("function-limit", state.functionLimit);
      loadFunctions();
    });
    window.addEventListener("popstate", function () {
      state.selection = readSelection();
      state.rows = [];
      state.revision = 0;
      loadSnapshot();
      loadFunctions();
      watchActivity();
    });
    bindTreeKeys("binary-tree");
    bindTreeKeys("function-tree");
  }

  function bindTreeKeys(tree) {
    var host = $(tree);
    if (!host) return;
    host.addEventListener("keydown", function (ev) {
      if (ev.target.closest && ev.target.closest("input, select, button")) return;
      var items = [].slice.call(host.querySelectorAll("[role=treeitem]"));
      if (!items.length) return;
      var index = items.findIndex(function (el) { return el.id === state.treeFocus[tree]; });
      if (index < 0) index = 0;
      function go(i) {
        i = Math.max(0, Math.min(items.length - 1, i));
        markTreeFocus(tree, items[i].id, true);
      }
      if (ev.key === "ArrowDown") { ev.preventDefault(); go(index + 1); }
      else if (ev.key === "ArrowUp") { ev.preventDefault(); go(index - 1); }
      else if (ev.key === "Home") { ev.preventDefault(); go(0); }
      else if (ev.key === "End") { ev.preventDefault(); go(items.length - 1); }
      else if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        var choose = state.treeActions[items[index].id];
        if (choose && choose.onChoose) choose.onChoose();
      } else if (ev.key === "ArrowRight") {
        ev.preventDefault();
        var open = state.treeActions[items[index].id];
        if (open && open.expanded === false && open.onToggle) open.onToggle();
        else go(index + 1);
      } else if (ev.key === "ArrowLeft") {
        ev.preventDefault();
        var close = state.treeActions[items[index].id];
        if (close && close.expanded === true && close.onToggle) close.onToggle();
        else if (close && close.parent) {
          var parent = items.findIndex(function (el) { return el.id === close.parent; });
          if (parent >= 0) go(parent);
        }
      }
    });
  }

  bindControls();
  bindResize();
  writeSelection(state.selection);
  renderAll();
  loadSnapshot();
  loadFunctions();
  watchActivity();
  setInterval(function () {
    loadSnapshot();
    loadPreparations();
    if (state.connection !== "live") pollActivity();
  }, 5000);
})();
