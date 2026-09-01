/* AgentDecompile workbench — React 18 + htm. Session tabs stay sticky; surfaces stay in flow. */
(function () {
  "use strict";

  const e = React.createElement;
  const html = htm.bind(e);
  const { useCallback, useEffect, useMemo, useRef, useState } = React;

  const API = {
    binaries: "/dashboard/api/workbench/binaries",
    functions: "/dashboard/api/workbench/functions",
    detail: "/dashboard/api/workbench/function",
    browse: "/dashboard/api/workbench/browse",
    classify: "/dashboard/api/workbench/classify",
    inspect: "/dashboard/api/workbench/inspect",
    resolveDrop: "/dashboard/api/workbench/resolve-drop",
    stageDrop: "/dashboard/api/workbench/stage-drop",
    projects: "/dashboard/api/workbench/projects",
    save: "/dashboard/api/workbench/save",
    saveAs: "/dashboard/api/workbench/save-as",
    sessions: "/dashboard/api/workbench/sessions",
    ghidraDefaults: "/dashboard/api/workbench/ghidra-defaults",
    actions: "/api/v1/actions",
    jobs: "/api/v1/jobs",
    serverShutdown: "/dashboard/api/server/shutdown",
    serverRestart: "/dashboard/api/server/restart",
    panel: "/dashboard/panel"
  };

  const SURFACES = [
    { id: "wb-overview", title: "Overview", keys: ["overview", "corpus"] },
    { id: "wb-ingest", title: "Project", keys: ["add", "drop", "gpr", "upload", "project", "source", "binary"] },
    { id: "wb-sources", title: "Project", keys: ["source", "binary"] },
    { id: "wb-functions", title: "Functions", keys: ["function", "func", "addr"] },
    { id: "wb-inspect", title: "Inspector", keys: ["inspect", "sibling", "preview"] },
    { id: "wb-graph", title: "Call graph", keys: ["graph", "call"] },
    { id: "wb-jobs", title: "Jobs", keys: ["job", "pulse"] },
    { id: "wb-atlas", title: "Atlas", keys: ["atlas", "map", "score", "prompt"] },
    { id: "wb-report", title: "Report", keys: ["report"] },
    { id: "wb-fnbrowse", title: "Functions", keys: ["function", "func", "addr", "browse", "page"] },
    { id: "wb-review", title: "Review", keys: ["review"] },
    { id: "wb-logical", title: "Logical identities", keys: ["logical", "identity", "sibling"] },
    { id: "wb-artifacts", title: "Artifacts", keys: ["artifact"] },
    { id: "wb-pipeline", title: "Pipeline", keys: ["pipeline", "steps"] },
    { id: "wb-match", title: "Cross-match", keys: ["match", "cross"] },
    { id: "wb-recovery", title: "Recovery", keys: ["recovery"] },
    { id: "wb-stabs", title: "STABS", keys: ["stabs", "donor"] },
    { id: "wb-knowledge", title: "Knowledge", keys: ["knowledge"] },
    { id: "wb-roundtrip", title: "Roundtrip", keys: ["roundtrip", "rebuild"] },
    { id: "wb-processes", title: "Process log", keys: ["process", "log"] },
    { id: "wb-mission", title: "Mission", keys: ["mission", "directive"] },
    { id: "wb-corpus", title: "Corpus table", keys: ["corpus"] },
    { id: "wb-tools", title: "Commands", keys: ["mcp", "cli", "tool", "command", "swagger"] }
  ];

  /* Three working tabs plus More. Atlas, Cross-match, Report and the rest
     stay reachable from More, View, and the command palette — they are not
     a second row of chrome. */
  const EDITOR_PRIMARY = [
    { id: "decompile", title: "Listing" },
    { id: "wb-fnbrowse", title: "Functions" },
    { id: "graph", title: "Graph" }
  ];

  function slugFromDiskPath(filePath, fileName) {
    const parts = String(filePath || "").replace(/\\/g, "/").split("/").filter(Boolean);
    let base = (fileName || parts[parts.length - 1] || "binary").trim();
    if (base.indexOf(".") > 0 && base === (parts[parts.length - 1] || "")) {
      base = base.replace(/\.[^.]+$/, "") || base;
    }
    const platforms = {
      win32: 1, win64: 1, macos: 1, darwin: 1,
      "linux-x86": 1, "linux-x64": 1, "linux-arm64": 1, "linux-armhf": 1, "linux-aarch64": 1
    };
    let platform = "";
    for (let i = parts.length - 2; i >= 0; i--) {
      const key = String(parts[i] || "").toLowerCase();
      if (platforms[key]) { platform = key; break; }
    }
    if (!platform) return base;
    const lower = base.toLowerCase();
    if (lower.endsWith("-" + platform)) return base;
    if (platform.indexOf("linux-") === 0 && lower.endsWith("-linux")) base = base.slice(0, -6);
    else if (platform.indexOf("win") === 0 && lower.endsWith("-win")) base = base.slice(0, -4);
    return base + "-" + platform;
  }

  function importSlug(item) {
    if (!item) return "";
    if (typeof item === "string") return item.trim();
    if (typeof item === "object") {
      return String(item.slug || item.id || item.name || item.path || "").trim();
    }
    return "";
  }

  function sessionImportSlugs(session) {
    if (!session) return [];
    const out = [];
    const seen = new Set();
    (session.imports || []).forEach(function (item) {
      const name = importSlug(item);
      if (!name || seen.has(name)) return;
      seen.add(name);
      out.push(name);
    });
    return out;
  }

  function mergeImportSlugs(existing, extra, projectSlug) {
    const skip = new Set();
    if (projectSlug) skip.add(String(projectSlug).trim());
    const out = [];
    const seen = new Set();
    function add(name) {
      const slugName = String(name || "").trim();
      if (!slugName || skip.has(slugName) || seen.has(slugName)) return;
      seen.add(slugName);
      out.push(slugName);
    }
    (existing || []).forEach(add);
    (extra || []).forEach(add);
    return out;
  }

  function importsContain(session, slugName) {
    if (!slugName) return false;
    return sessionImportSlugs(session).indexOf(slugName) >= 0;
  }

  function params() {
    return new URLSearchParams(window.location.search);
  }

  function dualBar(decomp, validate) {
    const d = decomp || {};
    const v = validate || {};
    const dTotal = Math.max(1, (d.none || 0) + (d.asm || 0) + (d.c || 0));
    const vTotal = Math.max(1, (v.none || 0) + (v.obj || 0) + (v.linked || 0));
    function segs(parts, total, keys) {
      return keys.map(function (key) {
        const pct = ((parts[key] || 0) / total) * 100;
        return html`<i className=${"seg-" + key} style=${{ width: pct + "%" }} />`;
      });
    }
    return html`<div className="dual-bar" title="decomp vs validate">
      <div className="track-decomp">${segs(d, dTotal, ["none", "asm", "c"])}</div>
      <div className="track-validate">${segs(v, vTotal, ["none", "obj", "linked"])}</div>
    </div>`;
  }

  function rowBar(decomp, validate) {
    return dualBar(
      { none: decomp === "none" ? 1 : 0, asm: decomp === "asm" ? 1 : 0, c: decomp === "c" ? 1 : 0 },
      { none: validate === "none" ? 1 : 0, obj: validate === "obj" ? 1 : 0, linked: validate === "linked" ? 1 : 0 }
    );
  }

  function kindLabel(row) {
    const kind = (row && row.kind) || "binary";
    if (kind === "ghidra-project") return "gpr";
    if (kind === "shared-fs") return "shared-fs";
    if (kind === "shared-project" || kind === "shared-http") return "shared-http";
    if (kind === "draft") return "draft";
    return "bin";
  }

  function styleKind(kind) {
    if (kind === "ghidra-project" || kind === "gpr") return "gpr";
    if (kind === "shared-fs") return "shared-fs";
    if (kind === "shared-project" || kind === "shared-http") return "shared-http";
    if (kind === "draft") return "draft";
    return "bin";
  }

  function kindTitle(kind) {
    if (kind === "ghidra-project" || kind === "gpr" || kind === "project-dir") return "Local Ghidra project";
    if (kind === "dir") return "Folder";
    if (kind === "shared-fs") return "Shared server (filesystem)";
    if (kind === "shared-project" || kind === "shared-http") return "Shared server (HTTP)";
    if (kind === "draft") return "New session";
    if (kind === "binary" || kind === "bin") return "Binary";
    return kind || "Unknown";
  }

  function formatBytes(n) {
    const size = Number(n || 0);
    if (size < 1024) return size + " B";
    if (size < 1048576) return (size / 1024).toFixed(1) + " KB";
    return (size / 1048576).toFixed(1) + " MB";
  }

  function formatWhen(ts) {
    if (!ts) return "";
    const date = new Date(Number(ts) * 1000);
    if (Number.isNaN(date.getTime())) return String(ts);
    return date.toLocaleString();
  }

  function programName(item) {
    return typeof item === "string" ? item : (item && (item.name || item.id)) || "";
  }

  function tabHasRealProject(session) {
    if (!session) return false;
    if (String(session.kind || "") === "draft") return false;
    return Boolean(String(session.locator || "").trim());
  }

  function preservedImports(session, nextProjectSlug) {
    if (!session) return [];
    return sessionImportSlugs(session).filter(function (slug) {
      return slug !== String(session.projectSlug || "").trim()
        && slug !== String(nextProjectSlug || "").trim();
    });
  }

  function tabProjectName(session, fallback) {
    const title = (session && session.title) || "";
    if (title && title !== "Untitled") return title;
    const stem = String(fallback || "Project").replace(/\.[^.]+$/, "");
    return stem || "Project";
  }

  const SLUG_FIELD_NAMES = new Set(["id", "slug", "binary-id", "binary_id", "binary-id"]);
  const PATH_FIELD_NAMES = new Set(["binary", "path", "repo-path", "repo_path", "archive", "directory", "from-json", "manifest", "snapshot-dir", "snapshot_dir"]);
  const PROGRAM_FIELD_NAMES = new Set(["program", "programpath", "program-path", "from", "repo"]);
  const WORK_DIR_FIELD_NAMES = new Set(["work-dir", "work_dir", "out-dir", "out_dir", "outdir", "out", "workspace", "snapshot-dir", "snapshot_dir"]);
  const DB_FIELD_NAMES = new Set(["db", "corpus"]);
  const ADDR_FIELD_NAMES = new Set(["addr", "address", "addressorsymbol", "address-or-symbol", "target", "function", "identifier", "functionidentifier"]);
  const ROLE_CHOICES = ["member", "donor", "layout source"];

  function normFieldName(name) {
    return String(name || "").toLowerCase().replace(/_/g, "-");
  }

  function toolWidgetKind(field) {
    if (!field) return "text";
    if (field.kind === "bool") return "bool";
    if (field.choices && field.choices.length) return "choices";
    const name = normFieldName(field.name);
    if (field.from_context === "slug" || SLUG_FIELD_NAMES.has(name)) return "slug";
    if (field.from_context === "addr" || ADDR_FIELD_NAMES.has(name)) return "addr";
    if (field.from_context === "db" || DB_FIELD_NAMES.has(name)) return "db";
    if (field.from_context === "work_dir" || WORK_DIR_FIELD_NAMES.has(name)) return "workdir";
    if (field.from_context === "kb" || name === "kb") return "kb";
    if (field.from_context === "program" || PROGRAM_FIELD_NAMES.has(name)) return "program";
    if (name === "role") return "role";
    if (field.kind === "path" && (PATH_FIELD_NAMES.has(name) || name.indexOf("dir") >= 0)) return "path";
    if (field.kind === "int" || field.kind === "float") return "number";
    if (field.kind === "text") return "textarea";
    return "text";
  }

  function defaultToolValue(field, ctx) {
    if (!field) return "";
    if (field.default != null && field.default !== "") return String(field.default);
    const alias = {
      program: ctx.program || ctx.slug || "",
      slug: ctx.slug || "",
      repo: ctx.repo || "",
      addr: ctx.addr || "",
      name: ctx.name || "",
      db: ctx.db || "",
      work_dir: ctx.work_dir || "",
      kb: ctx.kb || ""
    };
    if (field.from_context && alias[field.from_context]) return alias[field.from_context];
    const name = normFieldName(field.name);
    if (SLUG_FIELD_NAMES.has(name)) return ctx.slug || "";
    if (name === "binary" && field.kind === "path") {
      const row = ctx.tabRows.find(function (item) { return item.slug === ctx.slug; }) || ctx.tabRows[0];
      return (row && row.repo) || ctx.repo || "";
    }
    if (PROGRAM_FIELD_NAMES.has(name)) return ctx.program || ctx.repo || ctx.slug || "";
    if (DB_FIELD_NAMES.has(name)) return ctx.db || "";
    if (WORK_DIR_FIELD_NAMES.has(name)) return ctx.work_dir || "";
    if (name === "kb") return ctx.kb || "";
    if (ADDR_FIELD_NAMES.has(name)) return ctx.addr || "";
    return "";
  }

  function ToolField({ field, value, ctx, listPrefix }) {
    const kind = toolWidgetKind(field);
    const label = field.name + (field.required ? " *" : "");
    const hint = field.help ? html`<span className="wb-field-hint">${field.help}</span>` : null;
    const safeList = (listPrefix || "wb") + "-" + normFieldName(field.name);

    if (kind === "bool") {
      return html`<label key=${field.name} className="wb-tool-field wb-tool-field-bool">
        <span>${label}</span>
        <input type="checkbox" name=${field.name} defaultChecked=${Boolean(value)} />
        ${hint}
      </label>`;
    }

    if (kind === "choices") {
      return html`<label key=${field.name} className="wb-tool-field">
        <span>${label}</span>
        <select name=${field.name} defaultValue=${value || ""} required=${field.required}>
          ${!field.required ? html`<option value="">—</option>` : null}
          ${(field.choices || []).map(function (choice) {
            return html`<option key=${choice} value=${choice}>${choice}</option>`;
          })}
        </select>
        ${hint}
      </label>`;
    }

    if (kind === "slug") {
      const slugs = ctx.tabSlugs.length ? ctx.tabSlugs.slice() : ctx.allBinaries.map(function (row) { return row.slug; });
      const unique = [];
      const seen = new Set();
      slugs.forEach(function (item) {
        if (!item || seen.has(item)) return;
        seen.add(item);
        unique.push(item);
      });
      const picked = value || ctx.slug || unique[0] || "";
      return html`<label key=${field.name} className="wb-tool-field">
        <span>${label}</span>
        <select name=${field.name} defaultValue=${picked} required=${field.required}>
          ${!field.required ? html`<option value="">— pick binary —</option>` : null}
          ${unique.length ? unique.map(function (item) {
            const row = ctx.allBinaries.find(function (bin) { return bin.slug === item; });
            const meta = row ? (row.kind || "bin") + (row.funcs ? " · " + row.funcs + " fn" : "") : "";
            return html`<option key=${item} value=${item}>${item}${meta ? " (" + meta + ")" : ""}</option>`;
          }) : html`<option value="">No binaries in this tab</option>`}
        </select>
        ${hint}
      </label>`;
    }

    if (kind === "program") {
      const programs = (ctx.programs || []).slice();
      const extras = ctx.tabRows.map(function (row) { return row.slug; }).filter(Boolean);
      extras.forEach(function (item) {
        if (programs.indexOf(item) < 0) programs.push(item);
      });
      const picked = value || ctx.program || programs[0] || ctx.slug || "";
      if (programs.length) {
        return html`<label key=${field.name} className="wb-tool-field">
          <span>${label}</span>
          <select name=${field.name} defaultValue=${picked} required=${field.required}>
            ${!field.required ? html`<option value="">—</option>` : null}
            ${programs.map(function (item) {
              return html`<option key=${item} value=${item}>${item}</option>`;
            })}
          </select>
          ${hint}
        </label>`;
      }
    }

    if (kind === "addr") {
      const addrs = (ctx.functions || []).slice(0, 200);
      if (addrs.length) {
        const picked = value || ctx.addr || "";
        return html`<label key=${field.name} className="wb-tool-field">
          <span>${label}</span>
          <select name=${field.name} defaultValue=${picked} required=${field.required}>
            ${!field.required ? html`<option value="">—</option>` : null}
            ${addrs.map(function (row) {
              return html`<option key=${row.addr} value=${row.addr}>${row.addr} ${row.name || ""}</option>`;
            })}
          </select>
          ${hint}
        </label>`;
      }
    }

    if (kind === "db") {
      const paths = [];
      if (ctx.db) paths.push(ctx.db);
      if (ctx.work_dir) paths.push(ctx.work_dir.replace(/\/?$/, "/") + "corpus.sqlite");
      return html`<label key=${field.name} className="wb-tool-field">
        <span>${label}</span>
        <input name=${field.name} list=${safeList} defaultValue=${value || paths[0] || ""} required=${field.required} />
        <datalist id=${safeList}>${paths.map(function (item) {
          return html`<option key=${item} value=${item} />`;
        })}</datalist>
        ${hint}
      </label>`;
    }

    if (kind === "workdir") {
      const paths = [];
      if (ctx.work_dir) {
        paths.push(ctx.work_dir);
        paths.push(ctx.work_dir.replace(/\/?$/, "/") + "extract/stabs");
        paths.push(ctx.work_dir.replace(/\/?$/, "/") + "target");
        paths.push(ctx.work_dir.replace(/\/?$/, "/") + "imports");
      }
      if (ctx.recovered) paths.push(ctx.recovered);
      return html`<label key=${field.name} className="wb-tool-field">
        <span>${label}</span>
        <input name=${field.name} list=${safeList} defaultValue=${value || paths[0] || ""} required=${field.required} />
        <datalist id=${safeList}>${paths.map(function (item) {
          return html`<option key=${item} value=${item} />`;
        })}</datalist>
        ${hint}
      </label>`;
    }

    if (kind === "kb") {
      const paths = ctx.kb ? [ctx.kb] : [];
      return html`<label key=${field.name} className="wb-tool-field">
        <span>${label}</span>
        <input name=${field.name} list=${safeList} defaultValue=${value || paths[0] || ""} required=${field.required} />
        <datalist id=${safeList}>${paths.map(function (item) {
          return html`<option key=${item} value=${item} />`;
        })}</datalist>
        ${hint}
      </label>`;
    }

    if (kind === "path") {
      const paths = ctx.tabRows.map(function (row) { return row.repo; }).filter(Boolean);
      const corpusPaths = ctx.allBinaries.map(function (row) { return row.repo; }).filter(Boolean);
      corpusPaths.forEach(function (item) {
        if (paths.indexOf(item) < 0) paths.push(item);
      });
      return html`<label key=${field.name} className="wb-tool-field">
        <span>${label}</span>
        <input name=${field.name} list=${safeList} defaultValue=${value || paths[0] || ""} required=${field.required} />
        <datalist id=${safeList}>${paths.map(function (item) {
          return html`<option key=${item} value=${item} />`;
        })}</datalist>
        ${hint}
      </label>`;
    }

    if (kind === "role") {
      return html`<label key=${field.name} className="wb-tool-field">
        <span>${label}</span>
        <select name=${field.name} defaultValue=${value || "member"}>
          ${ROLE_CHOICES.map(function (choice) {
            return html`<option key=${choice} value=${choice}>${choice}</option>`;
          })}
        </select>
        ${hint}
      </label>`;
    }

    if (kind === "number") {
      return html`<label key=${field.name} className="wb-tool-field">
        <span>${label}</span>
        <input type="number" name=${field.name} step=${field.kind === "int" ? "1" : "any"}
          defaultValue=${value || ""} required=${field.required} />
        ${hint}
      </label>`;
    }

    if (kind === "textarea") {
      return html`<label key=${field.name} className="wb-tool-field">
        <span>${label}</span>
        <textarea name=${field.name} rows="4" defaultValue=${value || ""} required=${field.required}></textarea>
        ${hint}
      </label>`;
    }

    return html`<label key=${field.name} className="wb-tool-field">
      <span>${label}</span>
      <input type="text" name=${field.name} defaultValue=${value || ""} required=${field.required} />
      ${hint}
    </label>`;
  }

  function runScripts(host) {
    host.querySelectorAll("script").forEach(function (node) {
      const run = document.createElement("script");
      if (node.src) run.src = node.src;
      else run.textContent = node.textContent;
      node.replaceWith(run);
    });
  }

  function sanitizeLegacy(host) {
    if (!host) return;
    host.querySelectorAll(
      ".skip-link, header.top, header.topbar, nav.workspace-nav, footer.foot, .tail, .wrap > header, .hero, .livepri"
    ).forEach(function (node) { node.remove(); });
    host.querySelectorAll("details.binladder, .perbinary details.binladder").forEach(function (node) {
      node.open = false;
    });
    host.querySelectorAll(".ladder .step").forEach(function (node, index) {
      if (index >= 6) return;
      node.open = node.classList.contains("st-not-started") || node.classList.contains("st-failed");
    });
  }

  function TabRoster({ programs, imports, selectedSlug, selectedProgram, onPickProgram, onPickImport }) {
    const programList = programs || [];
    const importList = imports || [];
    if (!programList.length && !importList.length) {
      return html`<div className="wb-tab-roster wb-empty">Nothing in this tab yet. File → Open, then Add binaries…</div>`;
    }
    return html`<div className="wb-tab-roster" id="wb-tab-roster">
      <p className="wb-hint">Same roster as Explorer. Ghidra programs are not corpus store rows.</p>
      ${importList.length ? html`<table className="wb-roster-table">
        <caption className="wb-kicker">Imports · corpus store</caption>
        <thead><tr><th>Slug</th><th>Kind</th></tr></thead>
        <tbody>
          ${importList.map(function (item) {
            const row = item.row || {};
            const on = selectedSlug && selectedSlug === row.slug && !selectedProgram;
            return html`<tr key=${item.key} className=${on ? "on" : ""}>
              <td><button type="button" className="wb-text-action"
                onClick=${function () { onPickImport(row); }}>${item.name}</button></td>
              <td>${item.kind || "binary"}</td>
            </tr>`;
          })}
        </tbody>
      </table>` : html`<p className="wb-hint">No imports in this tab.</p>`}
      ${programList.length ? html`<table className="wb-roster-table">
        <caption className="wb-kicker">Programs · open Ghidra project</caption>
        <thead><tr><th>Program</th><th>Kind</th></tr></thead>
        <tbody>
          ${programList.map(function (name) {
            const on = selectedProgram === name;
            return html`<tr key=${"prog-" + name} className=${on ? "on" : ""}>
              <td><button type="button" className="wb-text-action"
                onClick=${function () { onPickProgram(name); }}>${name}</button></td>
              <td>Ghidra program</td>
            </tr>`;
          })}
        </tbody>
      </table>` : html`<p className="wb-hint">No Ghidra programs listed on this project.</p>`}
    </div>`;
  }

  /* Legacy panels answer immediately with a `data-pending="1"` placeholder while the
     store read finishes. The full legacy page re-polls those blocks; an island inside
     the SPA has to do the same or the panel stays on "reading … 0s so far" forever. */
  const PENDING_DELAYS = [900, 1200, 1800, 2500, 3500, 5000, 5000, 5000, 8000, 8000, 8000, 8000];

  /* File → Reload has to reach the legacy fragments too, and those are mounted all over
     the tree. A tiny bus beats threading a nonce through every call site. */
  const ISLAND_BUS = { subs: [] };
  function reloadIslands() {
    ISLAND_BUS.subs.slice().forEach(function (fn) { fn(); });
  }

  function HtmlIsland({ url, refreshKey, className, compact }) {
    const ref = useRef(null);
    const [manualKey, setManualKey] = useState(0);
    useEffect(function () {
      function bump() { setManualKey(function (n) { return n + 1; }); }
      ISLAND_BUS.subs.push(bump);
      return function () {
        const at = ISLAND_BUS.subs.indexOf(bump);
        if (at >= 0) ISLAND_BUS.subs.splice(at, 1);
      };
    }, []);
    useEffect(function () {
      if (!url) return undefined;
      let dead = false;
      let timer = null;

      function stillPending() {
        return Boolean(ref.current && ref.current.querySelector('[data-pending="1"]'));
      }

      function announce(waiting, attempt) {
        if (!ref.current) return;
        const old = ref.current.querySelector(".wb-island-pending");
        if (old) old.remove();
        const bar = document.createElement("p");
        bar.className = "wb-island-pending" + (waiting ? "" : " stalled");
        const note = document.createElement("span");
        note.textContent = waiting
          ? "Still reading the store (" + attempt + ")…"
          : "The store read has not finished yet.";
        bar.appendChild(note);
        const again = document.createElement("button");
        again.type = "button";
        again.className = "wb-btn";
        again.textContent = "Refresh";
        again.addEventListener("click", function () { setManualKey(function (n) { return n + 1; }); });
        bar.appendChild(again);
        ref.current.insertBefore(bar, ref.current.firstChild);
      }

      function load(attempt) {
        fetch(url, { cache: "no-store" }).then(function (res) {
          return res.text().then(function (text) {
            return { ok: res.ok, status: res.status, text: text };
          });
        }).then(function (payload) {
          if (dead || !ref.current) return;
          if (!payload.ok) {
            const atlas = /\/atlas/.test(url);
            const report = /\/report/.test(url);
            if (payload.status === 404 && (atlas || report)) {
              ref.current.innerHTML = '<p class="wb-hint">' + (atlas ? "Atlas" : "Report")
                + " is not on this dashboard-only process. Open the full MCP HTTP app, or stay on Overview.</p>";
              return;
            }
            ref.current.innerHTML = '<p class="wb-hint">Panel failed (' + payload.status + ").</p>";
            return;
          }
          if (!(payload.text || "").trim()) {
            ref.current.innerHTML = '<p class="wb-hint">This panel returned no HTML.</p>';
            return;
          }
          ref.current.innerHTML = '<div class="wb-legacy' + (compact ? " wb-legacy-compact" : "") + '">' + payload.text + "</div>";
          sanitizeLegacy(ref.current);
          runScripts(ref.current);
          if (!stillPending()) return;
          const wait = PENDING_DELAYS[attempt];
          announce(Boolean(wait), attempt + 1);
          if (!wait) return;
          timer = window.setTimeout(function () { if (!dead) load(attempt + 1); }, wait);
        }).catch(function (err) {
          if (!dead && ref.current) {
            ref.current.innerHTML = '<p class="wb-hint">' + String(err.message || err) + "</p>";
          }
        });
      }

      load(0);
      return function () {
        dead = true;
        if (timer) window.clearTimeout(timer);
      };
    }, [url, refreshKey, compact, manualKey]);
    return html`<div ref=${ref} className=${className || "wb-island"} />`;
  }

  function DockPanel({ id, title, children, className, actions }) {
    return html`<section id=${id} className=${"wb-dock" + (className ? " " + className : "")} aria-labelledby=${id + "-title"}>
      <header className="wb-dock-title">
        <span id=${id + "-title"}>${title}</span>
        ${actions || null}
      </header>
      <div className="wb-dock-body">${children}</div>
    </section>`;
  }

  function TabBar({ tabs, active, onSelect, id }) {
    return html`<div id=${id || "wb-tabbar"} className="wb-tabbar" role="tablist">
      ${tabs.map(function (tab) {
        return html`<button key=${tab.id} type="button" role="tab" aria-selected=${active === tab.id}
          className=${active === tab.id ? "on" : ""}
          onClick=${function () { onSelect(tab.id); }}>${tab.label}</button>`;
      })}
    </div>`;
  }

  const BOTTOM_TABS = [
    { id: "pipeline", label: "Pipeline" },
    { id: "atlas", label: "Atlas" },
    { id: "report", label: "Report" },
    { id: "tools", label: "Tools" },
    { id: "output", label: "Output" }
  ];

  const CENTER_TABS = [
    { id: "decompile", label: "Decompile" },
    { id: "graph", label: "Call Graph" }
  ];

  const QUICK_ACTION_SETS = {
    explorer: [
      { ui: "upload", label: "Add files…" },
      { ui: "import", label: "Open…" },
      { id: "corpus.extract-stabs", label: "Extract STABS", needsProject: true },
      { id: "corpus.init-store", label: "Init store" },
      { id: "corpus.init", label: "Init corpus", needsProject: true, mutating: true }
    ],
    project: [
      { id: "corpus.ghidra-bulk", label: "Ghidra bulk", mutating: true },
      { id: "corpus.workspace", label: "Workspace", mutating: true },
      { id: "corpus.cross-place", label: "Cross-place" },
      { id: "corpus.compile-link", label: "Compile link", mutating: true }
    ],
    pipeline: [
      { id: "corpus.stages", label: "Stages" },
      { id: "corpus.run", label: "Run pipeline", danger: true }
    ],
    function: [
      { id: "mcp.decompile-function", label: "Decompile", needsFunction: true },
      { id: "mcp.match-function", label: "Match", needsFunction: true, mutating: true },
      { id: "mcp.get-references", label: "Xrefs", needsFunction: true },
      { id: "mcp.analyze-data-flow", label: "Data flow", needsFunction: true }
    ],
    binary: [
      { id: "recover.inspect", label: "Inspect", needsSlug: true },
      { id: "corpus.ghidra-bulk", label: "Ghidra bulk", needsSlug: true, mutating: true }
    ],
    report: [
      { id: "corpus.export-run-report", label: "Export report" },
      { id: "corpus.ingest-recovered", label: "Ingest recovered", mutating: true }
    ],
    stabs: [
      { id: "corpus.extract-stabs", label: "Extract STABS", needsProject: true },
      { id: "corpus.stabs-report", label: "STABS report" }
    ]
  };

  function quickActionDisabled(item, flags) {
    if (item.needsFunction && flags.needsFunction) return true;
    if (item.needsSlug && flags.needsSlug) return true;
    if (item.needsProject && flags.needsProject) return true;
    return false;
  }

  function QuickActions({ items, catalog, onPress, flags }) {
    if (!items || !items.length) return null;
    const gate = flags || {};
    return html`<div className="wb-quick-actions" role="toolbar" aria-label="Quick actions">
      ${items.map(function (item, index) {
        const act = item.id ? catalog.find(function (row) { return row.id === item.id; }) : null;
        const label = item.label || (act && act.title) || item.id || "Action";
        const off = quickActionDisabled(item, gate);
        return html`<button key=${item.id || item.ui || String(index)} type="button"
          className=${"wb-qact" + (item.danger ? " danger" : "") + (off ? " off" : "")}
          disabled=${off}
          title=${act && act.summary ? act.summary : label}
          onClick=${function () { if (!off) onPress(item); }}>${label}</button>`;
      })}
    </div>`;
  }

  function Surface({ id, title, children, compact, actions }) {
    return html`<section id=${id} className=${"wb-surface" + (compact ? " wb-surface-compact" : "")} aria-labelledby=${id + "-title"}>
      <header className=${"wb-surface-head" + (actions ? " has-actions" : "")}>
        <h2 id=${id + "-title"}>${title}</h2>
        ${actions || null}
      </header>
      ${children}
    </section>`;
  }

  function Modal({ open, title, onClose, children, footer, error }) {
    const boxRef = useRef(null);
    useEffect(function () {
      if (!open || !boxRef.current) return;
      const first = boxRef.current.querySelector("input, select, textarea, button.wb-btn-primary");
      if (first && typeof first.focus === "function") first.focus();
    }, [open]);
    if (!open) return null;
    /* Tab stays inside the dialog, the way a modal window behaves on a desktop. */
    function onKeyDown(ev) {
      if (ev.key !== "Tab" || !boxRef.current) return;
      const focusable = Array.prototype.filter.call(
        boxRef.current.querySelectorAll("a[href], button, input, select, textarea, [tabindex]"),
        function (node) { return !node.disabled && node.offsetParent !== null; }
      );
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (ev.shiftKey && document.activeElement === first) {
        ev.preventDefault();
        last.focus();
      } else if (!ev.shiftKey && document.activeElement === last) {
        ev.preventDefault();
        first.focus();
      }
    }
    return html`<div className="wb-modal-backdrop" onClick=${onClose}>
      <div className="wb-modal" role="dialog" aria-modal="true" aria-labelledby="wb-modal-title"
        ref=${boxRef}
        onKeyDown=${onKeyDown}
        onClick=${function (ev) { ev.stopPropagation(); }}>
        <header className="wb-modal-head">
          <h2 id="wb-modal-title">${title}</h2>
          <button type="button" className="wb-modal-close" aria-label="Close" onClick=${onClose}>×</button>
        </header>
        <div className="wb-modal-body">
          ${error ? html`<p className="wb-dialog-error" role="alert">${error}</p>` : null}
          ${children}
        </div>
        ${footer ? html`<footer className="wb-modal-foot">${footer}</footer>` : null}
      </div>
    </div>`;
  }

  const MORE_SURFACE_IDS = new Set([
    "wb-overview", "wb-atlas", "wb-report", "wb-pipeline",
    "wb-jobs", "wb-match", "wb-recovery", "wb-stabs", "wb-knowledge",
    "wb-roundtrip", "wb-processes", "wb-mission", "wb-corpus", "wb-review",
    "wb-logical", "wb-artifacts", "wb-tools"
  ]);


  const CORPUS_NAV = [
    { id: "wb-overview", title: "Overview", more: true },
    { id: "wb-atlas", title: "Atlas", more: true },
    { id: "wb-match", title: "Cross-match", more: true },
    { id: "wb-report", title: "Report", more: true },
    { id: "wb-pipeline", title: "Pipeline", more: true },
    { id: "wb-recovery", title: "Recovery", more: true },
    { id: "wb-stabs", title: "STABS", more: true },
    { id: "wb-knowledge", title: "Knowledge", more: true },
    { id: "wb-logical", title: "Logical identities", more: true },
    { id: "wb-review", title: "Review", more: true },
    { id: "wb-corpus", title: "Corpus", more: true },
    { id: "wb-tools", title: "Commands", more: true }
  ];

  const EDITOR_TABS = EDITOR_PRIMARY.concat(CORPUS_NAV);

  /* The browse page's old anchors and query keys still arrive from bookmarks,
     redirects and other panels, so they select a window instead of a second page. */
  const BROWSE_ANCHOR_WINDOW = {
    functions: "wb-fnbrowse",
    logical: "wb-logical",
    review: "wb-review",
    graph: "graph",
    builds: "wb-corpus"
  };

  function bootWindow() {
    const hash = String((window.location.hash || "").replace(/^#/, "")).toLowerCase();
    if (BROWSE_ANCHOR_WINDOW[hash]) return editorTabFor(BROWSE_ANCHOR_WINDOW[hash]);
    const want = String(params().get("window") || "").trim();
    if (!want) return "decompile";
    if (BROWSE_ANCHOR_WINDOW[want.toLowerCase()]) {
      return editorTabFor(BROWSE_ANCHOR_WINDOW[want.toLowerCase()]);
    }
    return editorTabFor(want);
  }

  function editorTabFor(id) {
    if (!id) return "decompile";
    if (id === "wb-inspect" || id === "wb-functions" || id === "inspect" || id === "wb-ingest") return "decompile";
    if (id === "wb-graph") return "graph";
    return id;
  }

  const RECENT_ACTIONS_KEY = "wb-recent-actions";

  function readRecentActionIds() {
    try {
      const raw = localStorage.getItem(RECENT_ACTIONS_KEY);
      const list = raw ? JSON.parse(raw) : [];
      return Array.isArray(list) ? list.filter(function (item) { return typeof item === "string"; }) : [];
    } catch (_err) {
      return [];
    }
  }

  function pushRecentActionId(actionId) {
    if (!actionId) return;
    try {
      const next = [actionId].concat(readRecentActionIds().filter(function (item) {
        return item !== actionId;
      })).slice(0, 8);
      localStorage.setItem(RECENT_ACTIONS_KEY, JSON.stringify(next));
    } catch (_err) { /* private mode */ }
  }

  function readUiPref(key, fallback) {
    try {
      const value = localStorage.getItem(key);
      return value != null && value !== "" ? value : fallback;
    } catch (_err) {
      return fallback;
    }
  }

  function writeUiPref(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (_err) { /* private mode */ }
  }

  function scrollToSurface(surfaceId) {
    const node = document.getElementById(surfaceId);
    if (node) {
      node.classList.add("wb-surface-flash");
      window.setTimeout(function () { node.classList.remove("wb-surface-flash"); }, 1400);
    }
  }

  function readActionParams(form, action, ctx) {
    if (!form || !action) return {};
    const params = {};
    (action.fields || []).forEach(function (field) {
      const el = form.elements.namedItem(field.name);
      if (!el) return;
      let value;
      if (field.kind === "bool") {
        value = el.checked;
        if (!value && !field.required) return;
      } else {
        value = el.value;
        if (value === "" || value == null) return;
      }
      const def = defaultToolValue(field, ctx);
      if (field.kind === "bool") {
        if (Boolean(value) === Boolean(def === true || def === "true")) return;
      } else if (String(value) === String(def || "")) return;
      params[field.name] = value;
    });
    return params;
  }

  function formatJobSummary(data) {
    if (!data) return "";
    if (data.job) {
      const job = data.job;
      return "Job " + job.id + " — " + (job.status || "started")
        + (job.actionId ? " (" + job.actionId + ")" : "");
    }
    if (data.ok === false && data.error) return String(data.error);
    if (data.argv && data.argv.length) return "Dry run: " + data.argv.slice(0, 8).join(" ");
    return "";
  }

  function actionUsesAddr(act) {
    if (!act) return false;
    if ((act.fields || []).some(function (field) {
      return ADDR_FIELD_NAMES.has(normFieldName(field.name)) || field.from_context === "addr";
    })) return true;
    const id = String(act.id || "");
    return /function|rename-variable|get-references|analyze-data-flow|match-function/.test(id);
  }

  function toggleAddrList(list, addr) {
    const next = (list || []).slice();
    const i = next.indexOf(addr);
    if (i >= 0) next.splice(i, 1);
    else if (addr) next.push(addr);
    return next;
  }

  function rangeAddrList(rows, fromAddr, toAddr) {
    const addrs = (rows || []).map(function (row) { return row.addr; });
    const a = addrs.indexOf(fromAddr);
    const b = addrs.indexOf(toAddr);
    if (a < 0 && b < 0) return [];
    if (a < 0) return toAddr ? [toAddr] : [];
    if (b < 0) return fromAddr ? [fromAddr] : [];
    const lo = Math.min(a, b);
    const hi = Math.max(a, b);
    return addrs.slice(lo, hi + 1);
  }

  function mergeAddrLists(base, extra) {
    const seen = {};
    const out = [];
    (base || []).concat(extra || []).forEach(function (addr) {
      if (!addr || seen[addr]) return;
      seen[addr] = true;
      out.push(addr);
    });
    return out;
  }

  function jobLiveAnnouncement(prevList, nextList) {
    const prev = {};
    (prevList || []).forEach(function (job) { prev[job.id] = job.status; });
    const parts = [];
    (nextList || []).forEach(function (job) {
      const was = prev[job.id];
      if (was === job.status) return;
      if (!was && (job.status === "running" || job.status === "queued")) {
        parts.push("Job " + job.id + " started");
      } else if (job.status === "error" || job.status === "failed") {
        parts.push("Job " + job.id + " failed");
      } else if (job.status === "done" || job.status === "finished" || job.status === "ok" || job.status === "completed") {
        parts.push("Job " + job.id + " finished. A finished job is not a match.");
      } else if (job.status === "cancelled" || job.status === "canceled") {
        parts.push("Job " + job.id + " cancelled");
      }
    });
    return parts.join(". ");
  }

  function JobLiveRegion({ text }) {
    return html`<div id="wb-job-live" className="sr-only" aria-live="polite" aria-atomic="true">${text || ""}</div>`;
  }

  /* Accelerators are stored as specs and rendered per platform, so a Linux menu never
     promises "⌘". Ctrl+N / Ctrl+T / Ctrl+W / Ctrl+J / Ctrl+digit belong to the browser and
     cannot be intercepted by a page, so tab and window verbs ride Alt instead. */
  const IS_MAC = /mac|iphone|ipad/i.test(
    (window.navigator && (window.navigator.platform || window.navigator.userAgent)) || ""
  );

  function accelLabel(spec) {
    if (!spec) return "";
    if (IS_MAC) {
      return spec.replace(/mod\+/g, "⌘").replace(/alt\+/g, "⌥").replace(/shift\+/g, "⇧");
    }
    return spec.replace(/mod\+/g, "Ctrl+").replace(/alt\+/g, "Alt+").replace(/shift\+/g, "Shift+");
  }

  const WORKBENCH_COMMANDS = [
    { id: "file.new-project", title: "New Project…", accel: "alt+N", group: "File" },
    { id: "file.new-tab", title: "New Tab", accel: "alt+T", group: "File" },
    { id: "file.open", title: "Open…", accel: "mod+O", group: "File" },
    { id: "file.open-url", title: "Open from URL…", accel: "mod+shift+U", group: "File" },
    { id: "file.save", title: "Save", accel: "mod+S", group: "File" },
    { id: "file.save-as", title: "Save As…", accel: "mod+shift+S", group: "File" },
    { id: "file.add-binaries", title: "Add binaries…", accel: "mod+I", group: "File" },
    { id: "file.reload", title: "Reload from disk", accel: "alt+R", group: "File" },
    { id: "file.close-tab", title: "Close Tab", accel: "alt+W", group: "File" },
    { id: "edit.rename-tab", title: "Rename Tab", accel: "F2", group: "Edit" },
    { id: "view.palette", title: "Command palette", accel: "mod+K", group: "View" },
    { id: "view.explorer", title: "Explorer", accel: "mod+shift+E", group: "View" },
    { id: "view.listing", title: "Listing", accel: "alt+1", group: "View" },
    { id: "view.browse", title: "Functions", accel: "alt+F", group: "View" },
    { id: "view.graph", title: "Call Graph", accel: "alt+2", group: "View" },
    { id: "view.logical", title: "Logical identities", accel: "alt+L", group: "View" },
    { id: "view.overview", title: "Overview", accel: "alt+3", group: "View" },
    { id: "view.atlas", title: "Atlas", accel: "alt+4", group: "View" },
    { id: "view.cross-match", title: "Cross-match", accel: "alt+5", group: "View" },
    { id: "view.inspect", title: "Inspector", accel: "alt+6", group: "View" },
    { id: "view.tools", title: "Commands", accel: "alt+7", group: "View" },
    { id: "view.jobs", title: "Jobs", accel: "alt+J", group: "View" },
    { id: "view.pipeline", title: "Pipeline", group: "View" },
    { id: "view.report", title: "Report", group: "View" },
    { id: "view.recovery", title: "Recovery", group: "View" },
    { id: "view.stabs", title: "STABS", group: "View" },
    { id: "view.knowledge", title: "Knowledge", group: "View" },
    { id: "view.review", title: "Review", group: "View" },
    { id: "view.corpus", title: "Corpus table", group: "View" },
    { id: "view.density-compact", title: "Compact density", group: "View" },
    { id: "view.density-comfortable", title: "Comfortable density", group: "View" },
    { id: "view.jobs-rail", title: "Jobs dock on side (wide screens)", group: "View" },
    { id: "view.jobs-bottom", title: "Jobs dock on bottom", group: "View" },
    { id: "analyze.program", title: "Analyze program", accel: "mod+shift+A", group: "Analyze" },
    { id: "analyze.bsim-ingest", title: "Ingest repository into BSim", accel: "mod+shift+B", group: "Analyze" },
    { id: "analyze.bsim-report", title: "Report BSim database", group: "Analyze" },
    { id: "analyze.bsim-create", title: "Create BSim database", group: "Analyze" },
    { id: "run.cross-place", title: "Run Cross-place", accel: "mod+shift+X", group: "Run" },
    { id: "run.last", title: "Run last action", accel: "Enter", group: "Run" },
    { id: "help.access", title: "Keyboard & five ways…", accel: "shift+?", group: "Help" },
    { id: "help.classic-overview", title: "Classic overview (legacy)", group: "Help" }
  ];

  const COMMAND_BY_ID = {};
  WORKBENCH_COMMANDS.forEach(function (cmd) { COMMAND_BY_ID[cmd.id] = cmd; });

  const COMMAND_ACCEL = {};
  WORKBENCH_COMMANDS.forEach(function (cmd) {
    if (cmd.accel) COMMAND_ACCEL[cmd.title] = accelLabel(cmd.accel);
  });

  /* Context menus quote the catalog so a shortcut only ever has to be spelled once. */
  function decorateCommandItem(item) {
    if (typeof item === "string") return item;
    const cmd = COMMAND_BY_ID[item.id];
    if (!cmd) return item;
    return Object.assign({}, item, {
      title: item.title || cmd.title,
      accel: item.accel || accelLabel(cmd.accel)
    });
  }

  function surfaceTitle(id) {
    const hit = EDITOR_TABS.concat(SURFACES).find(function (item) {
      return item.id === id || item.id === editorTabFor(id);
    });
    return (hit && hit.title) || id;
  }

  function ContextMenu({ menu, onPick, onClose }) {
    if (!menu || !menu.items || !menu.items.length) return null;
    return html`<div className="wb-ctx-backdrop" onClick=${onClose}
      onContextMenu=${function (ev) { ev.preventDefault(); onClose(); }}>
      <ul className="wb-ctx-menu" role="menu" style=${{ left: menu.x + "px", top: menu.y + "px" }}>
        ${menu.items.map(function (item, index) {
          if (item === "—") return html`<li key=${"s" + index} className="wb-ctx-sep" role="separator" />`;
          return html`<li key=${item.id || item.title} role="none">
            <button type="button" className=${"wb-ctx-item" + (item.danger ? " danger" : "")} role="menuitem"
              data-cmd=${item.id || ""}
              onClick=${function () { onPick(item); }}>
              <span>${item.title}</span>
              ${item.accel ? html`<span className="wb-accel">${item.accel}</span>` : null}
            </button>
          </li>`;
        })}
      </ul>
    </div>`;
  }

  function ConfirmDialog({ open, title, message, confirmLabel, danger, onConfirm, onCancel }) {
    const goRef = useRef(null);
    useEffect(function () {
      if (open && goRef.current) goRef.current.focus();
    }, [open]);
    if (!open) return null;
    return html`<div className="wb-modal-backdrop wb-confirm-backdrop" onClick=${onCancel}>
      <div className="wb-modal wb-confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="wb-confirm-title"
        onClick=${function (ev) { ev.stopPropagation(); }}
        onKeyDown=${function (ev) {
          if (ev.key === "Enter") { ev.preventDefault(); if (onConfirm) onConfirm(); }
          if (ev.key === "Escape") { ev.preventDefault(); if (onCancel) onCancel(); }
        }}>
        <header className="wb-modal-head">
          <h2 id="wb-confirm-title">${title || "Confirm"}</h2>
        </header>
        <div className="wb-modal-body">
          ${message ? html`<p>${message}</p>` : null}
        </div>
        <footer className="wb-modal-foot wb-confirm">
          <button type="button" className="wb-btn" onClick=${onCancel}>Cancel</button>
          <button type="button" className=${"wb-btn wb-btn-primary" + (danger ? " danger" : "")}
            ref=${goRef} onClick=${onConfirm}>${confirmLabel || "Confirm"}</button>
        </footer>
      </div>
    </div>`;
  }

  function CorpusNavBar({ active, onJump, moreOpen, onMoreToggle }) {
    const primaryIds = {};
    EDITOR_PRIMARY.forEach(function (item) { primaryIds[item.id] = true; });
    const overflow = EDITOR_TABS.filter(function (item) { return !primaryIds[item.id]; });
    /* An overflow window that is open gets its own pill, so the strip always shows what
       the editor is displaying instead of hiding it behind "More". */
    const promoted = overflow.find(function (item) { return item.id === active; }) || null;
    const more = overflow.filter(function (item) { return !promoted || item.id !== promoted.id; });
    return html`<nav id="wb-corpus-nav" className="wb-corpus-nav wb-editor-tabs" aria-label="Windows">
      ${EDITOR_PRIMARY.map(function (item) {
        const on = active === item.id ? " on" : "";
        return html`<button type="button" key=${item.id} className=${"wb-corpus-nav-item" + on}
          data-surface=${item.id}
          onClick=${function () { onJump(item.id); }}>${item.title}</button>`;
      })}
      ${promoted ? html`<button type="button" key=${promoted.id} className="wb-corpus-nav-item on wb-nav-promoted"
        data-surface=${promoted.id}
        onClick=${function () { onJump(promoted.id); }}>${promoted.title}</button>` : null}
      <details className=${"wb-editor-more" + (promoted ? " on" : "")} open=${Boolean(moreOpen)}
        onToggle=${function (ev) {
          if (onMoreToggle) onMoreToggle(Boolean(ev.target.open));
        }}>
        <summary>More</summary>
        <div className="wb-editor-more-list">
          ${more.map(function (item) {
            return html`<button type="button" key=${item.id} className="wb-corpus-nav-item"
              data-surface=${item.id}
              onClick=${function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                onJump(item.id);
              }}>${item.title}</button>`;
          })}
        </div>
      </details>
    </nav>`;
  }

  function CommandPalette({ open, query, onQuery, actions, surfaces, jobs, recentActionIds, commands, onPickAction, onPickSurface, onPickJob, onPickCommand, onClose }) {
    const inputRef = useRef(null);
    const [activeIdx, setActiveIdx] = useState(0);
    useEffect(function () {
      if (open && inputRef.current) inputRef.current.focus();
    }, [open]);
    useEffect(function () {
      if (open) setActiveIdx(0);
    }, [open, query]);
    if (!open) return null;
    const needle = (query || "").trim().toLowerCase();
    function matchText(text) {
      if (!needle) return true;
      return String(text || "").toLowerCase().indexOf(needle) >= 0;
    }
    const actionHits = (actions || []).filter(function (act) {
      return matchText(act.title) || matchText(act.id) || matchText(act.summary);
    }).slice(0, 12);
    const recentHits = (recentActionIds || []).map(function (actionId) {
      return (actions || []).find(function (act) { return act.id === actionId; });
    }).filter(Boolean).filter(function (act) {
      if (needle) {
        return matchText(act.title) || matchText(act.id) || matchText(act.summary);
      }
      return true;
    }).slice(0, 6);
    const recentIds = new Set(recentHits.map(function (act) { return act.id; }));
    const filteredActionHits = actionHits.filter(function (act) { return !recentIds.has(act.id); });
    const surfaceHits = (surfaces || []).filter(function (item) {
      return matchText(item.title) || matchText(item.id)
        || (item.keys || []).some(function (key) { return matchText(key); });
    }).slice(0, 14);
    const jobHits = (jobs || []).filter(function (job) {
      return matchText(job.id) || matchText(job.actionId) || matchText(job.status);
    }).slice(0, 8);
    const commandHits = (commands || []).filter(function (cmd) {
      return matchText(cmd.title) || matchText(cmd.id) || matchText(cmd.group);
    }).slice(0, 10);
    const picks = [];
    commandHits.forEach(function (cmd) {
      picks.push({ kind: "command", key: "cmd-" + cmd.id, id: cmd.id, title: cmd.title, meta: accelLabel(cmd.accel) || cmd.group });
    });
    recentHits.forEach(function (act) {
      picks.push({ kind: "action", key: "recent-" + act.id, id: act.id, title: act.title || act.id, meta: "recent" });
    });
    filteredActionHits.forEach(function (act) {
      picks.push({ kind: "action", key: "action-" + act.id, id: act.id, title: act.title || act.id, meta: act.id });
    });
    surfaceHits.forEach(function (item) {
      picks.push({ kind: "surface", key: "surface-" + item.id, id: item.id, title: item.title, meta: item.id });
    });
    jobHits.forEach(function (job) {
      picks.push({
        kind: "job",
        key: "job-" + job.id,
        id: job.id,
        title: job.actionId || job.id,
        meta: job.status
      });
    });
    const safeIdx = picks.length ? Math.min(activeIdx, picks.length - 1) : 0;
    function activatePick(idx) {
      const pick = picks[idx];
      if (!pick) return;
      if (pick.kind === "command") onPickCommand(pick.id);
      else if (pick.kind === "action") onPickAction(pick.id);
      else if (pick.kind === "surface") onPickSurface(pick.id);
      else onPickJob(pick.id);
    }
    function onPaletteInputKey(ev) {
      if (ev.key === "Escape") {
        onClose();
        return;
      }
      if (!picks.length) return;
      if (ev.key === "ArrowDown") {
        ev.preventDefault();
        setActiveIdx(function (prev) { return Math.min(prev + 1, picks.length - 1); });
      } else if (ev.key === "ArrowUp") {
        ev.preventDefault();
        setActiveIdx(function (prev) { return Math.max(prev - 1, 0); });
      } else if (ev.key === "Enter") {
        ev.preventDefault();
        activatePick(safeIdx);
      }
    }
    let pickCursor = 0;
    function itemClass(idx) {
      return "wb-palette-item" + (idx === safeIdx ? " active" : "");
    }
    return html`<div className="wb-palette-backdrop" onClick=${onClose}>
      <div className="wb-palette" role="dialog" aria-label="Command palette" onClick=${function (ev) { ev.stopPropagation(); }}>
        <input ref=${inputRef} type="search" className="wb-palette-input" placeholder="Run an action or go to a surface…"
          value=${query} onInput=${function (ev) { onQuery(ev.target.value); }}
          onKeyDown=${onPaletteInputKey} autocomplete="off" aria-activedescendant=${picks.length ? "wb-palette-pick-" + safeIdx : undefined} />
        ${commandHits.length ? html`<section className="wb-palette-section">
          <h3>Workbench</h3>
          <ul>${commandHits.map(function (cmd) {
            const idx = pickCursor++;
            return html`<li key=${"cmd-" + cmd.id}>
              <button type="button" id=${"wb-palette-pick-" + idx} className=${itemClass(idx)}
                data-cmd=${cmd.id}
                onMouseEnter=${function () { setActiveIdx(idx); }}
                onClick=${function () { onPickCommand(cmd.id); }}>
                <strong>${cmd.title}</strong>
                <span>${accelLabel(cmd.accel) || cmd.group}</span>
              </button>
            </li>`;
          })}</ul>
        </section>` : null}
        ${recentHits.length ? html`<section className="wb-palette-section">
          <h3>Recent actions</h3>
          <ul>${recentHits.map(function (act) {
            const idx = pickCursor++;
            return html`<li key=${"recent-" + act.id}>
              <button type="button" id=${"wb-palette-pick-" + idx} className=${itemClass(idx)}
                onMouseEnter=${function () { setActiveIdx(idx); }}
                onClick=${function () { onPickAction(act.id); }}>
                <strong>${act.title || act.id}</strong>
                <span>recent</span>
              </button>
            </li>`;
          })}</ul>
        </section>` : null}
        ${filteredActionHits.length ? html`<section className="wb-palette-section">
          <h3>Actions</h3>
          <ul>${filteredActionHits.map(function (act) {
            const idx = pickCursor++;
            return html`<li key=${act.id}>
              <button type="button" id=${"wb-palette-pick-" + idx} className=${itemClass(idx)}
                onMouseEnter=${function () { setActiveIdx(idx); }}
                onClick=${function () { onPickAction(act.id); }}>
                <strong>${act.title || act.id}</strong>
                <span>${act.id}</span>
              </button>
            </li>`;
          })}</ul>
        </section>` : null}
        ${surfaceHits.length ? html`<section className="wb-palette-section">
          <h3>Go to</h3>
          <ul>${surfaceHits.map(function (item) {
            const idx = pickCursor++;
            return html`<li key=${item.id}>
              <button type="button" id=${"wb-palette-pick-" + idx} className=${itemClass(idx)}
                onMouseEnter=${function () { setActiveIdx(idx); }}
                onClick=${function () { onPickSurface(item.id); }}>
                <strong>${item.title}</strong>
                <span>${item.id}</span>
              </button>
            </li>`;
          })}</ul>
        </section>` : null}
        ${jobHits.length ? html`<section className="wb-palette-section">
          <h3>Recent jobs</h3>
          <ul>${jobHits.map(function (job) {
            const idx = pickCursor++;
            return html`<li key=${job.id}>
              <button type="button" id=${"wb-palette-pick-" + idx} className=${itemClass(idx)}
                onMouseEnter=${function () { setActiveIdx(idx); }}
                onClick=${function () { onPickJob(job.id); }}>
                <strong>${job.actionId || job.id}</strong>
                <span>${job.status}</span>
              </button>
            </li>`;
          })}</ul>
        </section>` : null}
        ${!picks.length
          ? html`<p className="wb-hint">No matches. Try “ghidra”, “cross-match”, or “jobs”.</p>`
          : html`<p className="wb-hint wb-palette-kbd">↑↓ to move · Enter to select · Esc to close</p>`}
      </div>
    </div>`;
  }

  function ActionStrip({ action, ctx, expanded, onToggleExpand, onRun, onClose, formRef, danger, checkedCount }) {
    if (!action) return null;
    const fields = action.fields || [];
    const batch = Number(checkedCount || 0) > 1 && actionUsesAddr(action);
    const title = action.title || action.id;
    const summary = action.summary && action.summary !== action.id && action.summary !== title
      ? action.summary : "";
    return html`<div id="wb-action-strip" className=${"wb-action-strip" + (danger ? " danger" : "")}>
      <div className="wb-action-strip-head">
        <strong>${title}</strong>
        ${summary ? html`<span className="wb-hint">${summary}</span>` : null}
        ${batch ? html`<span className="wb-sel-chip">${checkedCount} selected</span>` : null}
        <div className="wb-action-strip-btns">
          <button type="button" className="wb-btn wb-btn-primary" onClick=${onRun}>${batch ? "Run " + checkedCount : "Run"}</button>
          ${fields.length ? html`<button type="button" className="wb-btn" onClick=${onToggleExpand}>
            ${expanded ? "Hide fields" : "Fields…"}</button>` : null}
          <button type="button" className="wb-btn" onClick=${onClose} aria-label="Close action strip">×</button>
        </div>
      </div>
      ${expanded && fields.length ? html`<form ref=${formRef} className="wb-tool-form wb-tools-layout" onSubmit=${function (ev) { ev.preventDefault(); onRun(); }}>
        ${fields.map(function (field) {
          return html`<${ToolField} key=${field.name} field=${field} ctx=${ctx} listPrefix=${action.id} />`;
        })}
      </form>` : null}
    </div>`;
  }

  function JobsDock({ jobs, expanded, onToggle, selectedId, jobDetail, onSelectJob, onCancel, pinned }) {
    const list = jobs || [];
    const running = list.filter(function (job) { return job.status === "running" || job.status === "queued"; });
    if (!list.length && !pinned) return null;
    const detail = jobDetail || null;
    const logText = detail && detail.log ? String(detail.log).slice(-12000) : "";
    return html`<aside id="wb-jobs-dock" className=${"wb-jobs-dock" + (expanded ? " open" : "") + (pinned ? " pinned" : "")}>
      <header className="wb-jobs-dock-head">
        <button type="button" className="wb-jobs-dock-toggle" onClick=${onToggle}>
          Jobs${running.length ? " · " + running.length + " running" : ""}
        </button>
        <span className="wb-hint">A finished job is not a match.</span>
      </header>
      ${expanded ? html`<div className="wb-jobs-dock-body">
        <ul className="wb-job-list">
          ${list.length ? list.map(function (job) {
            const on = job.id === selectedId;
            const live = job.status === "running" || job.status === "queued";
            return html`<li key=${job.id} className=${on ? "on" : ""}>
              <button type="button" className="wb-job-row" onClick=${function () { onSelectJob(job.id); }}>
                <code>${job.id}</code>
                <span>${job.actionId || ""}</span>
                <span className=${"st-" + (job.status || "unknown")}>${job.status}</span>
              </button>
              ${live ? html`<button type="button" className="wb-btn danger wb-job-cancel"
                onClick=${function (ev) { ev.stopPropagation(); onCancel(job.id); }}>Cancel</button>` : null}
            </li>`;
          }) : html`<li className="wb-hint">No jobs yet.</li>`}
        </ul>
        ${selectedId && logText ? html`<pre className="wb-job-log">${logText}</pre>`
          : selectedId ? html`<p className="wb-hint">Loading log…</p>` : null}
      </div>` : null}
    </aside>`;
  }

  const PAGE_SIZES = [50, 80, 100, 200];

  function FuncPager({ offset, limit, shown, total, onOffset, onLimit, compact }) {
    const first = total ? offset + 1 : 0;
    const last = offset + shown;
    const canBack = offset > 0;
    const canNext = last < total;
    return html`<div className=${"wb-pager" + (compact ? " wb-pager-compact" : "")}>
      <button type="button" className="wb-btn wb-btn-mini" disabled=${!canBack}
        aria-label="First page" onClick=${function () { onOffset(0); }}>⏮</button>
      <button type="button" className="wb-btn wb-btn-mini" disabled=${!canBack}
        aria-label="Previous page" onClick=${function () { onOffset(Math.max(0, offset - limit)); }}>◀</button>
      <span className="wb-pager-count">${total ? first + "–" + last + " of " + total : "0 of 0"}</span>
      <button type="button" className="wb-btn wb-btn-mini" disabled=${!canNext}
        aria-label="Next page" onClick=${function () { onOffset(offset + limit); }}>▶</button>
      ${compact ? null : html`<label className="wb-pager-size">
        <span className="sr-only">Rows per page</span>
        <select value=${String(limit)} onChange=${function (ev) { onLimit(Number(ev.target.value)); }}>
          ${PAGE_SIZES.map(function (size) {
            return html`<option key=${size} value=${String(size)}>${size} rows</option>`;
          })}
        </select>
      </label>`}
    </div>`;
  }

  function shortPath(text) {
    const value = String(text || "");
    if (value.length <= 56) return value;
    return "…" + value.slice(-53);
  }

  function App() {
    const start = params();
    const [binaries, setBinaries] = useState([]);
    const [slug, setSlug] = useState(start.get("slug") || start.get("binary") || "");
    const [rows, setRows] = useState([]);
    const [total, setTotal] = useState(0);
    const [query, setQuery] = useState(start.get("q") || "");
    const [selected, setSelected] = useState(null);
    const [detail, setDetail] = useState(null);
    const [actions, setActions] = useState([]);
    const [jobs, setJobs] = useState([]);
    const [programProgress, setProgramProgress] = useState({});
    const [reaction, setReaction] = useState(null);
    const [path, setPath] = useState("");
    const [newSlug, setNewSlug] = useState("");
    const [role, setRole] = useState("member");
    const [label, setLabel] = useState("");
    const [browse, setBrowse] = useState({ path: "", parent: "", entries: [] });
    const [preview, setPreview] = useState(null);
    const [sharedHost, setSharedHost] = useState("127.0.0.1");
    const [sharedPort, setSharedPort] = useState("13100");
    const [sharedRepo, setSharedRepo] = useState("");
    const [sharedProgram, setSharedProgram] = useState("");
    const [sharedUrl, setSharedUrl] = useState("");
    const [ingestNote, setIngestNote] = useState("");
    const [toast, setToast] = useState("");
    const [toastKind, setToastKind] = useState("");
    const [lastNote, setLastNote] = useState("Ready");
    const [statusError, setStatusError] = useState("");
    const [dialogError, setDialogError] = useState("");
    const [ctxMenu, setCtxMenu] = useState(null);
    const [dialog, setDialog] = useState("");
    const [openTab, setOpenTab] = useState("local");
    const [openPaste, setOpenPaste] = useState("");
    const [funcNote, setFuncNote] = useState("");
    const [program, setProgram] = useState("");
    const [sessions, setSessions] = useState([]);
    const [activeSession, setActiveSession] = useState("");
    const [sessionRevision, setSessionRevision] = useState(0);
    const [dossier, setDossier] = useState(null);
    const [editingTab, setEditingTab] = useState("");
    const [menu, setMenu] = useState("");
    const [saveAsTarget, setSaveAsTarget] = useState("ghidra-project");
    const [saveAsName, setSaveAsName] = useState("");
    const [saveAsDest, setSaveAsDest] = useState("");
    const [saveAsUrl, setSaveAsUrl] = useState("");
    const [editRole, setEditRole] = useState("member");
    const [editLabel, setEditLabel] = useState("");
    const [probes, setProbes] = useState([]);
    const [centerTab, setCenterTab] = useState(function () { return bootWindow(); });
    const [bottomTab, setBottomTab] = useState("pipeline");
    const [dropCandidates, setDropCandidates] = useState([]);
    const [treeExpanded, setTreeExpanded] = useState(true);
    const [envDefaults, setEnvDefaults] = useState({ db: "", work_dir: "", kb: "", mcp_url: "" });
    const [recoveredRoot, setRecoveredRoot] = useState("");
    const [paletteOpen, setPaletteOpen] = useState(false);
    const [paletteQuery, setPaletteQuery] = useState("");
    const [commandFilter, setCommandFilter] = useState("");
    const [funcOffset, setFuncOffset] = useState(0);
    const [funcLimit, setFuncLimit] = useState(80);
    const DEFAULT_FUNCTION_ACTION = "mcp.decompile-function";
    const [pendingActionId, setPendingActionId] = useState("");
    const [lastActionId, setLastActionId] = useState(DEFAULT_FUNCTION_ACTION);
    const [actionExpanded, setActionExpanded] = useState(false);
    const [confirmDialog, setConfirmDialog] = useState(null);
    const [jobsDockOpen, setJobsDockOpen] = useState(false);
    const [selectedJobId, setSelectedJobId] = useState("");
    const [jobDetail, setJobDetail] = useState(null);
    const [moreOpen, setMoreOpen] = useState(false);
    const [density, setDensity] = useState(function () { return readUiPref("wb-density", "compact"); });
    const [jobsRail, setJobsRail] = useState(function () { return readUiPref("wb-jobs-rail", "0") === "1"; });
    const [recentActionIds, setRecentActionIds] = useState(readRecentActionIds);
    const [checkedAddrs, setCheckedAddrs] = useState([]);
    const [checkAnchor, setCheckAnchor] = useState("");
    const [jobLiveText, setJobLiveText] = useState("");
    const jobsSnapshotRef = useRef([]);
    const pipelineChainedRef = useRef({});
    const chainAfterAnalyzeRef = useRef(function () {});
    const funcSeqRef = useRef(0);
    const funcSlugRef = useRef(slug);
    const fileRef = useRef(null);
    const folderRef = useRef(null);
    const dropRef = useRef(null);
    const actionFormRef = useRef(null);

    const current = useMemo(function () {
      return binaries.find(function (row) { return row.slug === slug; }) || {};
    }, [binaries, slug]);

    const running = jobs.filter(function (job) {
      return job.status === "running" || job.status === "queued";
    });

    const setContext = useCallback(function (row) {
      const node = document.getElementById("page-context");
      if (!node) return;
      node.setAttribute("data-page", row ? "function" : "home");
      node.setAttribute("data-slug", slug);
      node.setAttribute("data-program", program || current.program || current.repo || "");
      node.setAttribute("data-repo", current.repo || "");
      if (row) {
        node.setAttribute("data-addr", row.addr || "");
        node.setAttribute("data-name", row.name || "");
        if (row.logicalId) node.setAttribute("data-logical-id", String(row.logicalId));
      }
    }, [slug, current, program]);

    const reactJob = useCallback(function (id, data) {
      setReaction({ id: id, data: data });
    }, []);

    const loadBinaries = useCallback(async function () {
      const res = await fetch(API.binaries, { cache: "no-store" });
      const data = await res.json();
      const list = data.binaries || [];
      setBinaries(list);
      setRecoveredRoot(data.recovered || "");
      setSlug(function (prev) {
        if (prev && list.some(function (row) { return row.slug === prev; })) return prev;
        return prev || "";
      });
    }, []);

    const loadFuncs = useCallback(async function (nextSlug, nextQuery) {
      const useSlug = nextSlug !== undefined ? nextSlug : slug;
      if (!useSlug && !program) {
        setRows([]);
        setTotal(0);
        setFuncNote("");
        return;
      }
      const seq = funcSeqRef.current + 1;
      funcSeqRef.current = seq;
      const url = API.functions + "?slug=" + encodeURIComponent(useSlug)
        + "&q=" + encodeURIComponent(nextQuery !== undefined ? nextQuery : query)
        + "&offset=" + Math.max(0, funcOffset) + "&limit=" + funcLimit
        + (program ? "&program=" + encodeURIComponent(program) : "");
      const res = await fetch(url, { cache: "no-store" });
      const data = await res.json();
      if (seq !== funcSeqRef.current) return;
      setRows(data.results || []);
      setTotal(data.total || 0);
      if (!data.ok && data.error) setFuncNote(data.error);
      else if (!(data.results || []).length) {
        setFuncNote(data.error || (program
          ? (program + " has no functions listed yet. Analyze → Ingest repository into BSim.")
          : (funcOffset ? "Past the end of this build. Go back a page." : "Pick a program in Explorer.")));
      } else setFuncNote("");
    }, [slug, query, program, funcOffset, funcLimit]);

    const selectRow = useCallback(async function (row) {
      setSelected(row);
      setContext(row);
      const res = await fetch(
        API.detail + "?slug=" + encodeURIComponent(slug) + "&addr=" + encodeURIComponent(row.addr),
        { cache: "no-store" }
      );
      setDetail(await res.json());
    }, [slug, setContext]);

    function onFuncRowClick(ev, row) {
      if (!row) return;
      if (ev.shiftKey) {
        const from = checkAnchor || (selected && selected.addr) || row.addr;
        setCheckedAddrs(function (prev) {
          return mergeAddrLists(prev, rangeAddrList(rows, from, row.addr));
        });
        setCheckAnchor(row.addr);
        selectRow(row);
        return;
      }
      if (ev.ctrlKey || ev.metaKey) {
        setCheckedAddrs(function (prev) { return toggleAddrList(prev, row.addr); });
        setCheckAnchor(row.addr);
        selectRow(row);
        return;
      }
      selectRow(row);
    }

    function onFuncCheck(ev, row) {
      ev.preventDefault();
      ev.stopPropagation();
      if (!row) return;
      if (ev.shiftKey) {
        const from = checkAnchor || (selected && selected.addr) || row.addr;
        setCheckedAddrs(function (prev) {
          return mergeAddrLists(prev, rangeAddrList(rows, from, row.addr));
        });
      } else {
        setCheckedAddrs(function (prev) { return toggleAddrList(prev, row.addr); });
      }
      setCheckAnchor(row.addr);
    }

    const loadActions = useCallback(async function () {
      const res = await fetch(API.actions, { cache: "no-store" });
      const data = await res.json();
      const list = data.actions || [];
      setActions(list);
      if (data.context && data.context.defaults) setEnvDefaults(data.context.defaults);
    }, []);

    const loadBrowse = useCallback(async function (nextPath) {
      const res = await fetch(API.browse + "?path=" + encodeURIComponent(nextPath || ""), { cache: "no-store" });
      const data = await res.json();
      setBrowse(data);
      if (data.kind === "ghidra-project" && data.path) {
        setPath(data.path);
        setPreview(data);
      }
    }, []);

    const loadPreview = useCallback(async function (locator) {
      if (!locator) {
        setPreview(null);
        setDossier(null);
        return;
      }
      const res = await fetch(API.inspect + "?locator=" + encodeURIComponent(locator), { cache: "no-store" });
      const data = await res.json();
      setPreview(data);
      setDossier(data);
    }, []);

    /* The status bar carries durable state. A failure is an event, so it goes to the toast
       and to a status slot that clears itself instead of sitting there for the session. */
    function showToast(message, kind) {
      const text = String(message || "");
      const tone = kind || "";
      setToast(text);
      setToastKind(tone);
      setIngestNote(text);
      window.clearTimeout(showToast._errTimer);
      if (tone === "error") {
        setStatusError(text);
        if (text) {
          showToast._errTimer = window.setTimeout(function () { setStatusError(""); }, 20000);
        }
      } else {
        setStatusError("");
        if (text) setLastNote(text);
      }
      if (text) {
        window.clearTimeout(showToast._timer);
        showToast._timer = window.setTimeout(function () {
          setToast("");
          setToastKind("");
        }, tone === "error" ? 8000 : 5000);
      }
    }

    const putSessions = useCallback(async function (nextActive, nextSessions, revision) {
      const rev = revision !== undefined ? revision : sessionRevision;
      try {
        const res = await fetch(API.sessions, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ active: nextActive, sessions: nextSessions, revision: rev })
        });
        const data = await res.json();
        if (!res.ok || data.ok === false) {
          showToast(data.error || "Could not save tab state.", "error");
          return data;
        }
        if (data.revision != null) setSessionRevision(data.revision);
        if (data.sessions) {
          setSessions(data.sessions);
          if (data.active) setActiveSession(data.active);
        }
        if (data.merged) showToast("Tab state merged", "success");
        return data;
      } catch (_err) {
        showToast("Could not save tab state.", "error");
        return null;
      }
    }, [sessionRevision]);

    const persistSessions = useCallback(async function (nextSessions, nextActive) {
      setSessions(nextSessions);
      setActiveSession(nextActive);
      await putSessions(nextActive, nextSessions);
    }, [putSessions]);

    const patchActiveSession = useCallback(async function (patch) {
      const list = sessions.map(function (item) {
        return item.id === activeSession ? Object.assign({}, item, patch) : item;
      });
      setSessions(list);
      await putSessions(activeSession, list);
    }, [activeSession, sessions, putSessions]);

    function closeDialog() {
      setDialog("");
      setDialogError("");
      setMenu("");
    }

    function resetTabState() {
      setSlug("");
      setProgram("");
      setSelected(null);
      setDetail(null);
      setDossier(null);
      setPreview(null);
      setQuery("");
      setIngestNote("");
      setDialog("");
      setRows([]);
      setTotal(0);
      setCheckedAddrs([]);
      setCheckAnchor("");
    }

    function restoreTabSession(item) {
      resetTabState();
      if (!item || !item.locator) return;
      setSlug(item.projectSlug || "");
      setProgram(item.program || "");
      loadPreview(item.locator);
    }

    function selectProgram(name) {
      const picked = (name || "").trim();
      setProgram(picked);
      patchActiveSession({ program: picked });
      if (currentSession && currentSession.projectSlug) {
        setSlug(currentSession.projectSlug);
      }
    }

    const currentSession = useMemo(function () {
      return sessions.find(function (item) { return item.id === activeSession; }) || sessions[0] || null;
    }, [sessions, activeSession]);

    const sessionOverviewSlugs = useMemo(function () {
      const slugs = [];
      const seen = new Set();
      function addName(name) {
        if (!name || seen.has(name)) return;
        seen.add(name);
        slugs.push(name);
      }
      if (currentSession) {
        addName(currentSession.projectSlug);
        sessionImportSlugs(currentSession).forEach(addName);
      }
      return slugs;
    }, [currentSession]);

    const overviewUrl = useMemo(function () {
      let url = "/dashboard/overview-fragment?embed=1";
      sessionOverviewSlugs.forEach(function (name) {
        url += "&slug=" + encodeURIComponent(name);
      });
      ((dossier && dossier.ok ? (dossier.programs || []) : []).map(programName).filter(Boolean)).forEach(function (name) {
        url += "&program=" + encodeURIComponent(name);
      });
      return url;
    }, [sessionOverviewSlugs, dossier]);

    useEffect(function () {
      window.AgentDecompileUI = {
        announce: function (msg) {
          const pulse = document.getElementById("job-pulse");
          if (pulse) pulse.title = msg;
        }
      };
      window.KotorXidUI = window.AgentDecompileUI;
      loadBinaries();
      loadActions();
      loadBrowse("");
      fetch(API.sessions, { cache: "no-store" }).then(function (res) { return res.json(); }).then(function (data) {
        const list = data.sessions || [];
        setSessions(list);
        const activeId = data.active || (list[0] && list[0].id) || "";
        setActiveSession(activeId);
        if (data.revision != null) setSessionRevision(data.revision);
        const cur = list.find(function (item) { return item.id === activeId; }) || list[0];
        /* A deep link that names a build wins over the restored tab, otherwise
           /dashboard?window=…&binary=X silently shows a different build. */
        const pinned = start.get("slug") || start.get("binary") || "";
        if (cur && cur.locator) {
          if (!pinned) setSlug(cur.projectSlug || "");
          setProgram(cur.program || "");
          loadPreview(cur.locator);
        } else if (!pinned && cur && (cur.imports || []).length) {
          const first = importSlug(cur.imports[0]);
          if (first) setSlug(first);
        }
      }).catch(function () { /* next write creates a draft */ });
      fetch(API.ghidraDefaults, { cache: "no-store" }).then(function (res) { return res.json(); }).then(function (data) {
        if (data.host) setSharedHost(String(data.host));
        if (data.port) setSharedPort(String(data.port));
        if (data.repository) setSharedRepo(String(data.repository));
      }).catch(function () { /* keep defaults */ });
      function loadProbes() {
        fetch("/dashboard/healthz", { cache: "no-store" }).then(function (res) { return res.json(); }).then(function (data) {
          if (Array.isArray(data.probes)) setProbes(data.probes);
        }).catch(function () { /* optional */ });
      }
      loadProbes();
      const probeTimer = window.setInterval(loadProbes, 15000);
      function onKey(ev) {
        const mod = ev.ctrlKey || ev.metaKey;
        if (!mod) return;
        const key = (ev.key || "").toLowerCase();
        if (key === "s" && ev.shiftKey) {
          ev.preventDefault();
          openSaveAsDialog();
        } else if (key === "s") {
          ev.preventDefault();
          saveProject();
        } else if (key === "o" && ev.shiftKey) {
          ev.preventDefault();
          openProjectDialog("remote");
        } else if (key === "o") {
          ev.preventDefault();
          openProjectDialog();
        } else if (key === "n") {
          ev.preventDefault();
          createProject();
        } else if (key === "w") {
          ev.preventDefault();
        } else if (key === "i") {
          ev.preventDefault();
        } else if (key === "j") {
          ev.preventDefault();
        }
      }
      window.addEventListener("keydown", onKey);
      return function () {
        window.clearInterval(probeTimer);
        window.removeEventListener("keydown", onKey);
      };
    }, [loadBinaries, loadActions, loadBrowse, loadPreview]);

    useEffect(function () {
      /* Reset paging on the same tick as the slug change so we do not fetch the
         old offset against the new build and then overwrite the first page. */
      if (funcSlugRef.current !== slug + "\0" + (program || "")) {
        funcSlugRef.current = slug + "\0" + (program || "");
        if (funcOffset !== 0) {
          setFuncOffset(0);
          return;
        }
      }
      loadFuncs(slug, query);
    }, [slug, program, query, funcOffset, funcLimit, loadFuncs]);

    /* A deep link from the old browse page names an address; land on that row so
       the link means the same thing it used to. Disarm after the first page so
       a later build cannot steal the selection. */
    const bootAddrRef = useRef(start.get("addr") || "");
    useEffect(function () {
      const want = bootAddrRef.current;
      if (!want || !rows.length) return;
      const hit = rows.find(function (row) {
        return row.addr === want || String(row.address) === String(parseInt(want, 16));
      });
      bootAddrRef.current = "";
      if (hit) selectRow(hit);
    }, [rows, selectRow]);

    useEffect(function () {
      if (!current.slug) return;
      setEditRole(current.role || "member");
      setEditLabel(current.label || "");
    }, [current.slug, current.role, current.label]);

    useEffect(function () {
      if (!menu) return undefined;
      function onDoc(ev) {
        const bar = document.getElementById("wb-menubar");
        if (bar && !bar.contains(ev.target)) setMenu("");
      }
      document.addEventListener("mousedown", onDoc);
      return function () { document.removeEventListener("mousedown", onDoc); };
    }, [menu]);

    useEffect(function () {
      if (!moreOpen) return undefined;
      function onDoc(ev) {
        const nav = document.getElementById("wb-corpus-nav");
        const more = nav && nav.querySelector(".wb-editor-more");
        if (more && !more.contains(ev.target)) setMoreOpen(false);
      }
      document.addEventListener("mousedown", onDoc);
      return function () { document.removeEventListener("mousedown", onDoc); };
    }, [moreOpen]);

    useEffect(function () {
      const tool = params().get("tool") || params().get("focus") || params().get("window") || "";
      if (!tool) return;
      const hit = SURFACES.find(function (item) {
        return item.id === tool || item.id === "wb-" + tool || item.keys.indexOf(tool) >= 0;
      });
      if (hit) {
        setCenterTab(editorTabFor(hit.id));
        if (MORE_SURFACE_IDS.has(hit.id)) setMoreOpen(true);
        scrollToSurface(hit.id);
      }
    }, [binaries]);

    useEffect(function () {
      if (running.length) setJobsDockOpen(true);
    }, [running.length]);

    useEffect(function () {
      if (!selectedJobId) {
        setJobDetail(null);
        return undefined;
      }
      let dead = false;
      fetch(API.jobs + "/" + encodeURIComponent(selectedJobId), { cache: "no-store" })
        .then(function (res) { return res.json(); })
        .then(function (data) {
          if (!dead) setJobDetail(data.job || null);
        })
        .catch(function () { if (!dead) setJobDetail(null); });
      return function () { dead = true; };
    }, [selectedJobId, jobs]);

    useEffect(function () {
      function onPaletteKey(ev) {
        const mod = ev.ctrlKey || ev.metaKey;
        if (mod && (ev.key || "").toLowerCase() === "k") {
          ev.preventDefault();
          setPaletteOpen(function (prev) { return !prev; });
          setPaletteQuery("");
          setMenu("");
        }
        if (ev.key === "Escape") {
          setPaletteOpen(false);
          setConfirmDialog(null);
          setCtxMenu(null);
        }
      }
      window.addEventListener("keydown", onPaletteKey);
      return function () { window.removeEventListener("keydown", onPaletteKey); };
    }, []);

    useEffect(function () {
      function editingTarget(target) {
        if (!target) return false;
        const tag = (target.tagName || "").toUpperCase();
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
        return Boolean(target.isContentEditable);
      }
      function scrollSelectedFunc() {
        window.requestAnimationFrame(function () {
          const el = document.querySelector("#wb-func-window .wb-func-row.on");
          if (el) el.scrollIntoView({ block: "nearest" });
        });
      }
      function onFuncNav(ev) {
        if (paletteOpen || dialog || confirmDialog) return;
        if (editingTarget(ev.target)) return;
        if (!rows.length) return;
        const key = ev.key || "";
        if (key === "j" || key === "k") {
          ev.preventDefault();
          const idx = selected
            ? rows.findIndex(function (row) { return row.addr === selected.addr; })
            : -1;
          const next = key === "j"
            ? (idx < 0 ? 0 : Math.min(idx + 1, rows.length - 1))
            : (idx < 0 ? rows.length - 1 : Math.max(idx - 1, 0));
          const dest = rows[next];
          selectRow(dest);
          if (ev.shiftKey && dest) {
            const from = checkAnchor || (selected && selected.addr) || dest.addr;
            setCheckedAddrs(function (prev) {
              return mergeAddrLists(prev, rangeAddrList(rows, from, dest.addr));
            });
          }
          scrollSelectedFunc();
          return;
        }
        if ((key === "x" || key === "X" || key === " ") && selected) {
          ev.preventDefault();
          setCheckedAddrs(function (prev) { return toggleAddrList(prev, selected.addr); });
          setCheckAnchor(selected.addr);
          return;
        }
        if (key === "Escape" && checkedAddrs.length) {
          ev.preventDefault();
          setCheckedAddrs([]);
          setCheckAnchor("");
          return;
        }
        if (key === "Enter" && selected && lastActionId && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
          if (editingTarget(document.activeElement)) return;
          const act = actions.find(function (item) { return item.id === lastActionId; });
          if (!act) return;
          ev.preventDefault();
          openActionStrip(lastActionId);
        }
      }
      window.addEventListener("keydown", onFuncNav);
      return function () { window.removeEventListener("keydown", onFuncNav); };
    }, [paletteOpen, dialog, confirmDialog, rows, selected, lastActionId, actions, selectRow, checkAnchor, checkedAddrs]);

    useEffect(function () {
      setCheckedAddrs([]);
      setCheckAnchor("");
    }, [slug, program]);

    useEffect(function () {
      const live = {};
      rows.forEach(function (row) { live[row.addr] = true; });
      setCheckedAddrs(function (prev) {
        const next = prev.filter(function (addr) { return live[addr]; });
        return next.length === prev.length ? prev : next;
      });
    }, [rows]);

    useEffect(function () {
      document.body.classList.toggle("wb-density-compact", density === "compact");
      writeUiPref("wb-density", density);
    }, [density]);

    useEffect(function () {
      document.body.classList.toggle("wb-jobs-rail", jobsRail);
      writeUiPref("wb-jobs-rail", jobsRail ? "1" : "0");
    }, [jobsRail]);

    useEffect(function () {
      let last = "";
      async function poll() {
        try {
          const res = await fetch(API.jobs, { cache: "no-store" });
          const data = await res.json();
          const list = data.jobs || [];
          const note = jobLiveAnnouncement(jobsSnapshotRef.current, list);
          jobsSnapshotRef.current = list;
          if (note) {
            setJobLiveText(note);
            showToast(note, /failed|cancelled/.test(note) ? "error" : "success");
          }
          setJobs(list);
          const nextProgress = {};
          list.forEach(function (job) {
            chainAfterAnalyzeRef.current(job);
            const params = job.params || {};
            const key = String(params.program || params.binary || params.name || "").trim();
            if (!key) return;
            const pct = typeof job.progress === "number" ? job.progress : (job.status === "ok" ? 100 : job.status === "queued" ? 4 : 22);
            nextProgress[key] = { pct: pct, tool: job.actionId || "", status: job.status };
          });
          if (Object.keys(nextProgress).length) {
            setProgramProgress(function (prev) { return Object.assign({}, prev, nextProgress); });
          }
          const sig = list.map(function (job) { return job.id + job.status + job.returncode; }).join("|");
          if (sig !== last) {
            last = sig;
            loadBinaries();
            loadFuncs();
          }
          const live = list.find(function (job) { return job.status === "running"; });
          if (live) {
            const detailRes = await fetch(API.jobs + "/" + live.id, { cache: "no-store" });
            const body = await detailRes.json();
            if (body.job) setReaction({ id: body.job.actionId || live.id, data: body });
          }
        } catch (_err) { /* keep last frame */ }
      }
      poll();
      const timer = setInterval(poll, 1500);
      return function () { clearInterval(timer); };
    }, [loadBinaries, loadFuncs]);

    async function registerLocator(locator, extraSlug, options) {
      const value = (locator || "").trim();
      if (!value) return { ok: false, error: "locator is required" };
      const shared = /^(ghidra:\/\/|https?:\/\/)/i.test(value);
      const res = await fetch(API.binaries, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          path: shared ? "" : value,
          url: shared ? value : "",
          slug: extraSlug || newSlug,
          role: role,
          label: (options && options.label) || label
        })
      });
      const data = await res.json();
      reactJob("corpus.add-binary", data);
      if (!options || !options.quiet) {
        setIngestNote(data.ok ? "Registered " + (data.binary && data.binary.slug) : (data.error || "register failed"));
        if (data.ok && data.binary && !(options && options.intoProject)) {
          setSlug(data.binary.slug);
          const programs = data.binary.programs || [];
          if (programs.length) selectProgram(programs[0]);
        }
      }
      await loadBinaries();
      return data;
    }

    function triggerFileUpload() {
      if (!fileRef.current) return;
      fileRef.current.value = "";
      fileRef.current.click();
    }

    function triggerFolderUpload() {
      if (!folderRef.current) return;
      folderRef.current.value = "";
      folderRef.current.click();
    }

    async function importIntoTab(binarySlug) {
      const name = (binarySlug || "").trim();
      if (!name || !activeSession) return;
      let base = sessions;
      try {
        const res = await fetch(API.sessions, { cache: "no-store" });
        const data = await res.json();
        if (data.sessions && data.sessions.length) base = data.sessions;
      } catch (_err) { /* use in-memory copy */ }
      const list = base.map(function (item) {
        if (item.id !== activeSession) return item;
        return Object.assign({}, item, {
          imports: mergeImportSlugs(sessionImportSlugs(item), [name], item.projectSlug || "")
        });
      });
      await persistSessions(list, activeSession);
    }

    async function createTabProject(preferredName) {
      const session = sessions.find(function (item) { return item.id === activeSession; }) || currentSession;
      if (tabHasRealProject(session)) {
        return { ok: true, list: sessions, id: activeSession, projectSlug: session.projectSlug || "" };
      }
      const projectName = tabProjectName(session, preferredName);
      const res = await fetch(API.projects, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: projectName })
      });
      const data = await res.json();
      if (!data.ok) {
        showToast(data.error || "Could not create a project.", "error");
        return null;
      }
      return openLocator(data.locator || data.gpr, data.slug || projectName);
    }

    async function openLocator(locator, title, options) {
      const opts = options || {};
      const value = (locator || "").trim();
      if (!value) return null;
      const sameProject = Boolean(
        currentSession
        && tabHasRealProject(currentSession)
        && String(currentSession.locator || "").trim() === value
      );
      const prevSlug = slug;
      const prevProgram = program;
      const prevImports = sessionImportSlugs(currentSession);
      if (!sameProject && !opts.refresh) {
        resetTabState();
      }
      const inspected = await fetch(API.inspect + "?locator=" + encodeURIComponent(value), { cache: "no-store" }).then(function (res) { return res.json(); });
      if (!inspected.ok) {
        showToast(inspected.error || "Could not load that project.", "error");
        setDialogError(inspected.error || "Could not load that project.");
        return null;
      }
      const regSlug = String(inspected.slug || newSlug || "").trim();
      let registered = { ok: true, binary: { slug: regSlug } };
      if (!sameProject || !currentSession.projectSlug) {
        registered = await registerLocator(value, regSlug, { quiet: true });
        if (!registered.ok) {
          showToast(registered.error || "Could not register that project.", "error");
          setDialogError(registered.error || "Could not register that project.");
          return null;
        }
      }
      const projectSlug = (registered.binary && registered.binary.slug) || regSlug || (currentSession && currentSession.projectSlug) || "";
      const nextTitle = title || inspected.slug || (currentSession && currentSession.title) || "Project";
      const kind = inspected.kind || "ghidra-project";
      const programs = (inspected.programs || []).map(programName).filter(Boolean);
      const firstProgram = programs.length ? programs[0] : "";
      const keptImports = preservedImports(currentSession, projectSlug || "");
      const mergedImports = mergeImportSlugs(prevImports, keptImports, projectSlug || "");
      const nextProgram = sameProject && prevProgram ? prevProgram : firstProgram;
      let list = sessions.slice();
      let id = activeSession;
      if (!list.length || !id) {
        id = "s" + Date.now();
        list = [{
          id: id,
          title: nextTitle,
          kind: kind,
          locator: value,
          projectSlug: projectSlug || "",
          imports: mergedImports,
          program: nextProgram,
          created: Date.now()
        }];
      } else {
        list = list.map(function (item) {
          if (item.id !== id) return item;
          return Object.assign({}, item, {
            title: nextTitle,
            kind: kind,
            locator: value,
            projectSlug: projectSlug || "",
            imports: mergedImports,
            program: nextProgram
          });
        });
      }
      setDossier(inspected);
      setPreview(inspected);
      const nextSlug = sameProject && prevSlug ? prevSlug : (projectSlug || "");
      setSlug(nextSlug);
      setProgram(nextProgram);
      setSessions(list);
      setActiveSession(id);
      await putSessions(id, list);
      setIngestNote("Loaded " + nextTitle);
      closeDialog();
      return { ok: true, list: list, id: id, projectSlug: projectSlug || "", inspected: inspected };
    }

    function builtSharedUrl() {
      if (sharedUrl.trim()) return sharedUrl.trim();
      const host = sharedHost.trim() || "127.0.0.1";
      const port = sharedPort.trim() || "13100";
      const repo = sharedRepo.trim();
      const prog = sharedProgram.trim();
      if (!repo) return "";
      return "ghidra://" + host + ":" + port + "/" + repo + (prog ? "/" + prog.replace(/^\/+/, "") : "");
    }

    async function registerShared(ev) {
      if (ev) ev.preventDefault();
      const locator = builtSharedUrl();
      if (!locator) {
        showToast("Shared HTTP needs a repository name or a ghidra:// / http(s) URL.", "error");
        setDialogError("Shared HTTP needs a repository name or a ghidra:// / http(s) URL.");
        return;
      }
      await openLocator(locator, sharedRepo || sharedProgram || "shared");
    }

    async function newTab() {
      const id = "s" + Date.now();
      const item = {
        id: id,
        title: "Untitled",
        kind: "draft",
        locator: "",
        projectSlug: "",
        imports: [],
        program: "",
        created: Date.now()
      };
      resetTabState();
      await persistSessions(sessions.concat([item]), id);
    }

    async function closeTab(id) {
      const remain = sessions.filter(function (item) { return item.id !== id; });
      if (!remain.length) {
        const fresh = {
          id: "s" + Date.now(),
          title: "Untitled",
          kind: "draft",
          locator: "",
          projectSlug: "",
          imports: [],
          program: "",
          created: Date.now()
        };
        resetTabState();
        await persistSessions([fresh], fresh.id);
        return;
      }
      const next = id === activeSession ? remain[remain.length - 1].id : activeSession;
      await persistSessions(remain, next);
      if (id === activeSession) {
        const chosen = remain.find(function (item) { return item.id === next; });
        restoreTabSession(chosen);
      }
    }

    async function renameTab(id, title) {
      const name = (title || "").trim() || "Untitled";
      const list = sessions.map(function (item) {
        return item.id === id ? Object.assign({}, item, { title: name }) : item;
      });
      await persistSessions(list, activeSession);
      setEditingTab("");
    }

    async function createProject() {
      const res = await fetch(API.projects, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: (currentSession && currentSession.title) || "Project" })
      });
      const data = await res.json();
      if (!data.ok) {
        const err = data.error || "Could not create a local project.";
        setIngestNote(err);
        showToast(err, "error");
        return;
      }
      await openLocator(data.locator || data.gpr, data.slug);
    }

    function currentLocator() {
      return (dossier && dossier.locator) || (currentSession && currentSession.locator) || "";
    }

    /* Reload answers "did my change on disk land?" without losing the tab layout: it
       re-reads the store, the project dossier, the function list and every legacy panel,
       and keeps the current slug/program selection. */
    async function reloadProject() {
      setMenu("");
      setStatusError("");
      showToast("Reloading…");
      const locator = currentLocator();
      try {
        await loadBinaries();
        await loadActions();
        if (locator) await loadPreview(locator);
        await loadFuncs(slug, query);
        if (selected && selected.addr) await selectRow(selected);
        reloadIslands();
        showToast(locator ? "Reloaded " + locator : "Reloaded corpus store", "success");
      } catch (err) {
        showToast("Reload failed: " + String((err && err.message) || err), "error");
      }
    }

    async function saveProject() {
      const locator = currentLocator();
      const prevSlug = slug;
      const prevProgram = program;
      const res = await fetch(API.save, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ locator: locator })
      });
      const data = await res.json();
      if (!data.ok) {
        showToast(data.error || "Save failed.", "error");
        return data;
      }
      const nextLoc = data.locator || data.gpr || locator;
      const title = (currentSession && currentSession.title) || data.slug || "Project";
      setDossier(data);
      setPreview(data);
      const list = sessions.map(function (item) {
        if (item.id !== activeSession) return item;
        return Object.assign({}, item, {
          kind: data.kind || item.kind,
          locator: nextLoc || item.locator,
          projectSlug: item.projectSlug || data.slug || "",
          title: item.title || title
        });
      });
      await persistSessions(list, activeSession);
      if (prevSlug) setSlug(prevSlug);
      if (prevProgram) setProgram(prevProgram);
      showToast("Saved " + title, "success");
      setMenu("");
      return data;
    }

    function openSaveAsDialog() {
      setDialogError("");
      setSaveAsTarget("ghidra-project");
      setSaveAsName((currentSession && currentSession.title) || (dossier && dossier.slug) || "Project");
      setSaveAsDest("");
      setSaveAsUrl(sharedUrl || builtSharedUrl() || "");
      setDialog("save-as");
      setMenu("");
    }

    async function submitSaveAs(ev) {
      if (ev) ev.preventDefault();
      setDialogError("");
      if (!(saveAsName || "").trim()) {
        failDialog("Give the project a name before saving.");
        return null;
      }
      if (saveAsTarget === "shared-project" && !(saveAsUrl || "").trim()) {
        failDialog("A shared project needs a ghidra:// or http(s) server URL.");
        return null;
      }
      const res = await fetch(API.saveAs, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          locator: currentLocator(),
          target: saveAsTarget,
          name: saveAsName,
          dest: saveAsDest,
          url: saveAsUrl
        })
      });
      const data = await res.json();
      if (!data.ok) {
        failDialog(data.error || "Save As failed.");
        return data;
      }
      closeDialog();
      const next = data.locator || data.local_checkout || data.gpr;
      if (next && next !== currentLocator()) {
        const carryImports = sessionImportSlugs(currentSession);
        const opened = await openLocator(next, data.slug || saveAsName);
        if (opened && opened.ok && carryImports.length) {
          const list = opened.list.map(function (item) {
            if (item.id !== opened.id) return item;
            return Object.assign({}, item, {
              imports: mergeImportSlugs(sessionImportSlugs(item), carryImports, item.projectSlug || "")
            });
          });
          await persistSessions(list, opened.id);
        }
      } else if (next) {
        setDossier(data);
        setPreview(data);
      }
      showToast("Saved as " + kindTitle(data.kind || saveAsTarget), "success");
      return data;
    }

    function openProjectDialog(tab) {
      setOpenTab(tab === "remote" ? "remote" : "local");
      setDialogError("");
      setDialog("open");
      setMenu("");
      if (tab !== "remote") loadBrowse("");
    }

    /* A dialog reports its own failure next to the field that caused it; the toast alone
       leaves the operator staring at an unchanged form wondering what happened. */
    function failDialog(message) {
      setDialogError(String(message || ""));
      showToast(message, "error");
    }

    async function openPastedPath() {
      const value = (openPaste || "").trim();
      setDialogError("");
      if (!value) {
        failDialog("Paste a folder, .gpr, binary, or ghidra:// URL.");
        return;
      }
      if (/^(ghidra|http|https):\/\//i.test(value)) {
        await openLocator(value, value.split("/").pop() || "shared");
        return;
      }
      const inspected = await fetch(API.inspect + "?locator=" + encodeURIComponent(value), { cache: "no-store" }).then(function (res) { return res.json(); });
      if (inspected.ok && (inspected.kind === "shared-fs" || inspected.kind === "ghidra-project" || inspected.kind === "shared-project")) {
        await openLocator(value, inspected.slug || value);
        return;
      }
      if (!inspected.ok && inspected.error) {
        setDialogError(inspected.error);
      }
      await openBinaryPath(value);
    }

    /* Navigating closes the overflow menu the way a desktop menu closes on pick; the
       chosen window stays visible because CorpusNavBar promotes it into the tab strip. */
    function jumpTo(id) {
      setMenu("");
      setMoreOpen(false);
      if (id === "wb-sidebar") {
        const el = document.getElementById("wb-sidebar");
        if (el) el.scrollIntoView({ block: "nearest" });
        const first = el && el.querySelector("button, input");
        if (first) first.focus();
        return;
      }
      if (id === "wb-jobs") {
        setJobsDockOpen(true);
        setCenterTab("wb-jobs");
        return;
      }
      const tab = editorTabFor(id);
      setCenterTab(tab);
      scrollToSurface(id === "wb-inspect" ? "wb-inspect" : tab);
    }

    function jumpToCorpus(surfaceId) {
      setMoreOpen(false);
      setCenterTab(editorTabFor(surfaceId));
      scrollToSurface(surfaceId);
    }

    function askConfirm(opts) {
      setConfirmDialog({
        title: opts.title,
        message: opts.message || "",
        confirmLabel: opts.confirmLabel || "Confirm",
        danger: Boolean(opts.danger),
        onConfirm: function () {
          setConfirmDialog(null);
          if (opts.onConfirm) opts.onConfirm();
        }
      });
    }

    function closeConfirm() {
      setConfirmDialog(null);
    }

    function openActionStrip(actionId) {
      if (actionId) setLastActionId(actionId);
      setPendingActionId(actionId || "");
      setActionExpanded(false);
    }

    function openCtx(ev, items) {
      if (ev) {
        ev.preventDefault();
        ev.stopPropagation();
      }
      setMenu("");
      setCtxMenu({ x: ev.clientX, y: ev.clientY, items: items || [] });
    }

    function copyText(text, label) {
      const value = String(text || "");
      if (!value) {
        showToast("Nothing to copy.", "error");
        return;
      }
      const clip = window.navigator && window.navigator.clipboard;
      if (clip && clip.writeText) {
        clip.writeText(value).then(function () {
          showToast("Copied " + (label || "value"), "success");
        }).catch(function () {
          showToast("The browser refused clipboard access.", "error");
        });
        return;
      }
      showToast("This browser exposes no clipboard API.", "error");
    }

    /* Right-click menus are built from the thing that was clicked. A menu that offers the
       same File verbs everywhere teaches the operator that right-click is not worth using. */
    function importCtxItems(row) {
      const name = (row && row.slug) || "";
      return [
        { title: "Open in Functions", run: function () { selectImportBinary(row); } },
        { title: "Listing", id: "view.listing" },
        "—",
        { title: "Copy slug", run: function () { copyText(name, "slug"); } },
        { title: "Copy path", run: function () { copyText((row && (row.locator || row.repo)) || "", "path"); } },
        "—",
        { title: "Remove " + name, danger: true, accel: "Del", run: function () { removeSlug(name); } }
      ].map(decorateCommandItem);
    }

    function programCtxItems(name) {
      return [
        { title: "Select program", run: function () { selectProgram(name); } },
        { title: "Listing", id: "view.listing" },
        { title: "Call Graph", id: "view.graph" },
        "—",
        { title: "Copy program name", run: function () { copyText(name, "program name"); } }
      ].map(decorateCommandItem);
    }

    function projectCtxItems() {
      return [
        { id: "file.add-binaries" },
        { id: "file.reload" },
        "—",
        { id: "file.save" },
        { id: "file.save-as" },
        "—",
        { title: "Copy project path", run: function () { copyText(currentLocator(), "project path"); } },
        "—",
        { id: "file.close-tab", danger: true }
      ].map(decorateCommandItem);
    }

    function functionCtxItems(row) {
      function runTool(actionId) {
        if (row) selectRow(row);
        openActionStrip(actionId);
      }
      return [
        { title: "Listing", id: "view.listing" },
        { title: "Call Graph", id: "view.graph" },
        { title: "Inspector", id: "view.inspect" },
        "—",
        { title: "Decompile…", run: function () { runTool("mcp.decompile-function"); } },
        { title: "Add comment…", run: function () { runTool("mcp.manage-comments"); } },
        { title: "Create label…", run: function () { runTool("mcp.create-label"); } },
        { title: "Cross-references…", run: function () { runTool("mcp.get-references"); } },
        { title: "Data flow…", run: function () { runTool("mcp.analyze-data-flow"); } },
        { title: "Bookmark…", run: function () { runTool("mcp.manage-bookmarks"); } },
        { title: "Rename / manage function…", run: function () { runTool("mcp.manage-function"); } },
        { title: "Match function…", run: function () { runTool("mcp.match-function"); } },
        "—",
        { title: "Run last action", id: "run.last" },
        { title: "Run Cross-place", id: "run.cross-place" },
        "—",
        { title: "Copy address", run: function () { copyText(row && row.addr, "address"); } },
        { title: "Copy name", run: function () { copyText((row && row.name) || (row && row.addr), "name"); } }
      ].map(decorateCommandItem);
    }

    function runCommand(id, extra) {
      extra = extra || {};
      setCtxMenu(null);
      setMenu("");
      if (id === "file.new-project") { createProject(); showToast("New project"); return; }
      if (id === "file.new-tab") { newTab(); showToast("New tab"); return; }
      if (id === "file.open") { openProjectDialog(); showToast("Open…"); return; }
      if (id === "file.open-url") { openProjectDialog("remote"); showToast("Open from URL…"); return; }
      if (id === "file.save") { saveProject(); return; }
      if (id === "file.save-as") { openSaveAsDialog(); showToast("Save As…"); return; }
      if (id === "file.add-binaries") { triggerFileUpload(); showToast("Add binaries…"); return; }
      if (id === "file.reload") { reloadProject(); return; }
      if (id === "file.close-tab") {
        if (!currentSession) return;
        const dirty = currentSession.kind !== "draft" || currentSession.locator || sessionImportSlugs(currentSession).length;
        if (dirty) {
          askConfirm({
            title: "Close " + (currentSession.title || "tab") + "?",
            message: "This closes the project tab, not an editor buffer. File → Open reopens it. + only creates a draft.",
            confirmLabel: "Close tab",
            danger: true,
            onConfirm: function () { closeTab(currentSession.id); }
          });
          return;
        }
        closeTab(currentSession.id);
        showToast("Closed tab");
        return;
      }
      if (id === "file.remove-binary") {
        if (extra.slug) removeSlug(extra.slug);
        else if (slug && slug !== (currentSession && currentSession.projectSlug)) removeSlug(slug);
        return;
      }
      if (id === "edit.rename-tab") {
        if (currentSession) setEditingTab(currentSession.id);
        showToast("Rename tab");
        return;
      }
      /* Navigation is its own feedback: the tab highlights and the body changes.
         Toasting it as well buries the notifications that report real outcomes. */
      if (id === "view.palette") { setPaletteOpen(true); setPaletteQuery(""); return; }
      if (id === "view.jobs") { jumpTo("wb-jobs"); return; }
      if (id === "view.listing") { jumpTo("decompile"); return; }
      if (id === "view.browse") { jumpTo("wb-fnbrowse"); return; }
      if (id === "view.logical") { jumpTo("wb-logical"); return; }
      if (id === "view.inspect") { jumpTo("wb-inspect"); return; }
      if (id === "view.graph") { jumpTo("wb-graph"); return; }
      if (id === "view.overview") { jumpTo("wb-overview"); return; }
      if (id === "view.atlas") { jumpTo("wb-atlas"); return; }
      if (id === "view.pipeline") { jumpTo("wb-pipeline"); return; }
      if (id === "view.report") { jumpTo("wb-report"); return; }
      if (id === "view.cross-match") { jumpTo("wb-match"); return; }
      if (id === "view.recovery") { jumpTo("wb-recovery"); return; }
      if (id === "view.stabs") { jumpTo("wb-stabs"); return; }
      if (id === "view.knowledge") { jumpTo("wb-knowledge"); return; }
      if (id === "view.review") { jumpTo("wb-review"); return; }
      if (id === "view.corpus") { jumpTo("wb-corpus"); return; }
      if (id === "view.tools") { jumpTo("wb-tools"); return; }
      if (id === "view.explorer") { jumpTo("wb-sidebar"); return; }
      if (id === "view.density-compact") { setDensity("compact"); return; }
      if (id === "view.density-comfortable") { setDensity("comfortable"); return; }
      if (id === "view.jobs-rail") { setJobsRail(true); return; }
      if (id === "view.jobs-bottom") { setJobsRail(false); return; }
      if (id === "analyze.program") {
        const target = program || "";
        if (!target) { showToast("Select a program first", "error"); return; }
        startImportPipeline(target);
        showToast("analyze-program started on " + target);
        return;
      }
      if (id === "analyze.bsim-ingest") { openActionStrip("corpus.bsim-ingest"); showToast("BSim ingest — review and Run"); return; }
      if (id === "analyze.bsim-report") { openActionStrip("corpus.bsim-report"); showToast("BSim report — review and Run"); return; }
      if (id === "analyze.bsim-create") { openActionStrip("corpus.bsim-createdatabase"); showToast("Create BSim database — review and Run"); return; }
      if (id === "run.cross-place") { openActionStrip("corpus.cross-place"); showToast("Cross-place — review and Run"); return; }
      if (id === "run.last") {
        if (lastActionId) { openActionStrip(lastActionId); showToast("Last action " + lastActionId); }
        else showToast("No last action yet.", "error");
        return;
      }
      if (id === "help.access") { setDialog("access"); showToast("Keyboard & five ways"); return; }
      if (id === "help.classic-overview") { jumpTo("wb-overview"); showToast("Overview"); return; }
      showToast("Unknown command " + id, "error");
    }

    useEffect(function () {
      function typingTarget(el) {
        if (!el) return false;
        const tag = (el.tagName || "").toLowerCase();
        return tag === "input" || tag === "textarea" || tag === "select" || el.isContentEditable;
      }
      function onCmd(ev) {
        if (typingTarget(ev.target) && ev.key !== "Escape") return;
        const mod = ev.ctrlKey || ev.metaKey;
        const key = (ev.key || "").toLowerCase();
        if (ev.key === "Escape") {
          if (paletteOpen) { ev.preventDefault(); setPaletteOpen(false); return; }
          if (confirmDialog) { ev.preventDefault(); closeConfirm(); return; }
          if (ctxMenu) { ev.preventDefault(); setCtxMenu(null); return; }
          if (dialog) { ev.preventDefault(); closeDialog(); return; }
          if (menu) { ev.preventDefault(); setMenu(""); return; }
          if (moreOpen) { ev.preventDefault(); setMoreOpen(false); return; }
          return;
        }
        if (ev.key === "F2") { ev.preventDefault(); runCommand("edit.rename-tab"); return; }
        if (ev.key === "Delete") {
          if (slug && currentSession && slug !== currentSession.projectSlug) {
            ev.preventDefault();
            runCommand("file.remove-binary", { slug: slug });
          }
          return;
        }
        if (ev.key === "?" && ev.shiftKey && !mod) { ev.preventDefault(); runCommand("help.access"); return; }
        if (ev.altKey && !mod) {
          const altMap = {
            n: "file.new-project",
            t: "file.new-tab",
            w: "file.close-tab",
            r: "file.reload",
            f: "view.browse",
            l: "view.logical",
            j: "view.jobs",
            1: "view.listing",
            2: "view.graph",
            3: "view.overview",
            4: "view.atlas",
            5: "view.cross-match",
            6: "view.inspect",
            7: "view.tools"
          };
          const altCmd = altMap[key];
          if (altCmd) { ev.preventDefault(); runCommand(altCmd); }
          return;
        }
        if (!mod) return;
        if (key === "k") { return; }
        else if (key === "u" && ev.shiftKey) { ev.preventDefault(); runCommand("file.open-url"); }
        else if (key === "o") { ev.preventDefault(); runCommand("file.open"); }
        else if (key === "s" && ev.shiftKey) { ev.preventDefault(); runCommand("file.save-as"); }
        else if (key === "s") { ev.preventDefault(); runCommand("file.save"); }
        else if (key === "i") { ev.preventDefault(); runCommand("file.add-binaries"); }
        else if (key === "e" && ev.shiftKey) { ev.preventDefault(); runCommand("view.explorer"); }
        else if (key === "x" && ev.shiftKey) { ev.preventDefault(); runCommand("run.cross-place"); }
      }
      window.addEventListener("keydown", onCmd);
      return function () { window.removeEventListener("keydown", onCmd); };
    });

    async function selectJobInDock(jobId) {
      setSelectedJobId(jobId || "");
      setJobsDockOpen(true);
    }

    async function cancelJob(jobId) {
      if (!jobId) return;
      try {
        await fetch(API.jobs + "/" + encodeURIComponent(jobId) + "/cancel", { method: "POST" });
        showToast("Cancel requested for " + jobId, "success");
      } catch (_err) {
        showToast("Could not cancel job.", "error");
      }
    }

    async function executeAction(actionId, paramOverrides, options) {
      const opts = options || {};
      if (!actionId) return null;
      setLastActionId(actionId);
      const act = actions.find(function (item) { return item.id === actionId; });
      if (!act) {
        showToast("Unknown action " + actionId, "error");
        return null;
      }
      const params = paramOverrides || {};
      const checkedRows = rows.filter(function (row) { return checkedAddrs.indexOf(row.addr) >= 0; });
      const batchTargets = opts.batch === false
        ? []
        : (checkedRows.length > 1 && actionUsesAddr(act) ? checkedRows : []);
      const needsConfirm = !opts.skipConfirm && (
        opts.danger || act.danger || opts.mutating || act.mutating
      );
      if (needsConfirm) {
        askConfirm({
          title: batchTargets.length > 1
            ? "Run " + (act.title || actionId) + " on " + batchTargets.length + " functions?"
            : "Run " + (act.title || actionId) + "?",
          message: act.summary || "",
          danger: act.danger || opts.danger,
          onConfirm: function () {
            executeAction(actionId, paramOverrides, Object.assign({}, opts, { skipConfirm: true }));
          }
        });
        return null;
      }
      if (batchTargets.length > 1) {
        showToast("Starting " + (act.title || actionId) + " on " + batchTargets.length + " functions…", "success");
        let ok = 0;
        for (let i = 0; i < batchTargets.length; i += 1) {
          const row = batchTargets[i];
          const result = await executeAction(
            actionId,
            Object.assign({}, params, { addr: row.addr, name: row.name }),
            { skipConfirm: true, batch: false, quiet: true, targetRow: row }
          );
          if (result) ok += 1;
        }
        showToast("Queued " + ok + " of " + batchTargets.length + " — " + (act.title || actionId), ok ? "success" : "error");
        return ok;
      }
      const row = opts.targetRow;
      const ctx = {
        slug: toolContext.slug || "",
        program: toolContext.program || "",
        repo: toolContext.repo || "",
        addr: (row && row.addr) || params.addr || toolContext.addr || "",
        name: (row && row.name) || params.name || toolContext.name || "",
        db: toolContext.db || "",
        work_dir: toolContext.work_dir || "",
        kb: toolContext.kb || ""
      };
      if (!opts.quiet) showToast("Starting " + (act.title || actionId) + "…", "success");
      const body = Object.assign({ confirm: true, context: ctx }, params);
      const res = await fetch("/api/v1/actions/" + actionId.replace(".", "/"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        if (!opts.quiet) showToast(data.error || "Action failed", "error");
        reactJob(actionId, data);
        return null;
      }
      reactJob(actionId, data);
      pushRecentActionId(actionId);
      setRecentActionIds(readRecentActionIds());
      if (data.job && data.job.id) {
        setJobsDockOpen(true);
        setSelectedJobId(data.job.id);
        if (!opts.quiet) showToast("Job " + data.job.id + " — " + (act.title || actionId), "success");
      } else if (data.argv && !opts.quiet) {
        showToast("Dry run: " + data.argv.join(" "), "success");
      }
      if (String(actionId).indexOf("decompile") >= 0 || String(actionId).indexOf("rename") >= 0) {
        loadBinaries();
        loadFuncs();
        if (selected) selectRow(selected);
      }
      return data;
    }

    function startImportPipeline(programName) {
      const target = String(programName || "").trim();
      if (!target) return;
      setProgramProgress(function (prev) {
        const next = Object.assign({}, prev);
        next[target] = { pct: 4, tool: "mcp.analyze-program", status: "queued" };
        return next;
      });
      executeAction("mcp.analyze-program", { program: target }, { skipConfirm: true, quiet: true });
    }

    function chainAfterAnalyze(job) {
      if (!job || job.status !== "ok") return;
      const actionId = String(job.actionId || "");
      if (actionId !== "mcp.analyze-program" && actionId.indexOf("analyze-program") < 0) return;
      if (pipelineChainedRef.current[job.id]) return;
      pipelineChainedRef.current[job.id] = true;
      const prog = String((job.params && (job.params.program || job.params.binary)) || program || "").trim();
      executeAction("corpus.extract-stabs", {}, { skipConfirm: true, quiet: true });
      executeAction("corpus.bsim-ingest", {}, { skipConfirm: true, quiet: true });
      executeAction("corpus.cross-place", {}, { skipConfirm: true, quiet: true });
      if (prog) {
        setProgramProgress(function (prev) {
          const next = Object.assign({}, prev);
          next[prog] = { pct: 100, tool: "apply-names", status: "ok" };
          return next;
        });
        loadFuncs();
        loadBinaries();
      }
    }
    chainAfterAnalyzeRef.current = chainAfterAnalyze;

    function runFromActionStrip() {
      const act = actions.find(function (item) { return item.id === pendingActionId; });
      if (!act) return;
      const params = readActionParams(actionFormRef.current, act, toolContext);
      executeAction(pendingActionId, params, { danger: act.danger, mutating: act.mutating });
    }

    function onPaletteAction(actionId) {
      setPaletteOpen(false);
      setPaletteQuery("");
      openActionStrip(actionId);
    }

    function onPaletteSurface(surfaceId) {
      setPaletteOpen(false);
      setPaletteQuery("");
      if (MORE_SURFACE_IDS.has(surfaceId)) setMoreOpen(true);
      jumpTo(surfaceId);
    }

    function onPaletteJob(jobId) {
      setPaletteOpen(false);
      setPaletteQuery("");
      selectJobInDock(jobId);
    }

    async function openBinaryPath(filePath, preferredName) {
      const path = (filePath || "").trim();
      if (!path) return;
      const baseName = (preferredName || path.split(/[/\\]/).pop() || "binary").trim();
      const slugNameWanted = slugFromDiskPath(path, baseName);
      const res = await fetch(API.binaries, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          path: path,
          slug: slugNameWanted,
          role: role || "member",
          label: label || ""
        })
      });
      const data = await res.json();
      reactJob("corpus.add-binary", data);
      if (!data.ok || !data.binary) {
        const message = data.error || "Could not register binary";
        setIngestNote(message);
        showToast(message, "error");
        return null;
      }
      const slugName = data.binary.slug;
      let session = sessions.find(function (item) { return item.id === activeSession; }) || currentSession;
      if (tabHasRealProject(session)) {
        await importIntoTab(slugName);
        try {
          const sessRes = await fetch(API.sessions, { cache: "no-store" });
          const sessData = await sessRes.json();
          session = (sessData.sessions || []).find(function (item) { return item.id === activeSession; }) || session;
        } catch (_err) { /* ignore */ }
        setSlug(slugName);
        setProgram("");
        patchActiveSession({ program: "" });
        setSelected(null);
        setDetail(null);
        setIngestNote("Added " + baseName + " to " + ((session && session.title) || "project"));
        closeDialog();
      } else {
        const opened = await createTabProject(baseName);
        if (!opened || !opened.ok) {
          setSlug(slugName);
          setIngestNote("Registered " + baseName + " (project creation failed)");
          await loadBinaries();
          return data;
        }
        const list = opened.list.map(function (item) {
          if (item.id !== opened.id) return item;
          const imports = (item.imports || []).slice();
          if (imports.indexOf(slugName) < 0) imports.push(slugName);
          return Object.assign({}, item, { imports: imports });
        });
        await persistSessions(list, opened.id);
        setSlug(slugName);
        setProgram("");
        setIngestNote("Created project and added " + baseName);
        closeDialog();
      }
      await loadBinaries();
      const names = ((data.binary && data.binary.programs) || []).map(programName).filter(Boolean);
      const target = names[0] || baseName;
      if (target) {
        if (names[0]) selectProgram(names[0]);
        startImportPipeline(target);
      }
      return data;
    }

    async function selectImportBinary(row) {
      if (!row || !row.slug) return;
      if (tabHasRealProject(currentSession) && !importsContain(currentSession, row.slug)) {
        await importIntoTab(row.slug);
      }
      setSlug(row.slug);
      setProgram("");
      patchActiveSession({ program: "" });
      setSelected(null);
      setDetail(null);
    }

    async function uploadFiles(fileList) {
      const files = Array.from(fileList || []);
      const rels = files.map(function (file) { return file.webkitRelativePath || file.name; });
      const gprs = files.filter(function (file) { return /\.gpr$/i.test(file.name); });
      const looksShared = rels.some(function (rel) {
        return rel === "users" || rel.indexOf("~index.dat") >= 0 || /(^|\/)users$/.test(rel);
      });
      const looksRep = rels.some(function (rel) { return /\.rep(\/|$)/i.test(rel); });
      if (gprs.length || looksShared || looksRep) {
        const repRel = rels.find(function (rel) { return /\.rep(\/|$)/i.test(rel); }) || "";
        const dropName = (gprs[0] && gprs[0].name) || (repRel ? repRel.split("/")[0] : files[0].name);
        const form = new FormData();
        files.forEach(function (file) {
          form.append("file", file, file.name);
        });
        form.append("paths", JSON.stringify(rels));
        const stageRes = await fetch(API.stageDrop, { method: "POST", body: form });
        const stageData = await stageRes.json();
        if (!stageRes.ok || stageData.ok === false || !stageData.staging_id) {
          setIngestNote(stageData.error || "Could not stage dropped files.");
          return;
        }
        const res = await fetch(API.resolveDrop, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            name: dropName,
            relativePaths: rels,
            staging_id: stageData.staging_id
          })
        });
        const data = await res.json();
        if (data.ok && data.locator) {
          await openLocator(data.locator, data.slug);
          return;
        }
        if (data.candidates && data.candidates.length) {
          setIngestNote("Several matches. Pick one in the folder list.");
          return;
        }
        setIngestNote(data.error || "Could not resolve that drop to a project on disk.");
        return;
      }
      let tabReady = tabHasRealProject(currentSession);
      for (const file of files) {
        const body = new FormData();
        body.append("file", file, file.name);
        if (newSlug) body.append("slug", newSlug);
        body.append("role", role || "member");
        let session = sessions.find(function (item) { return item.id === activeSession; }) || currentSession;
        if (tabReady) {
          body.append("label", (session && (session.title || session.projectSlug)) || "import");
        } else if (label) {
          body.append("label", label);
        }
        const res = await fetch(API.binaries, { method: "POST", body: body });
        const data = await res.json();
        reactJob("corpus.add-binary", data);
        if (!data.ok) {
          setIngestNote(data.error || "upload failed");
          continue;
        }
        if (!data.binary) continue;
        const slugName = data.binary.slug;
        if (tabReady) {
          await importIntoTab(slugName);
          try {
            const sessRes = await fetch(API.sessions, { cache: "no-store" });
            const sessData = await sessRes.json();
            session = (sessData.sessions || []).find(function (item) { return item.id === activeSession; }) || session;
          } catch (_err) { /* ignore */ }
          if (session && session.projectSlug) setSlug(slugName);
          setIngestNote("Added " + file.name + " to " + ((session && session.title) || "project"));
        } else {
          const opened = await createTabProject(file.name);
          if (!opened || !opened.ok) {
            setSlug(slugName);
            setIngestNote("Registered " + file.name + " (project creation failed)");
            continue;
          }
          const list = opened.list.map(function (item) {
            if (item.id !== opened.id) return item;
            return Object.assign({}, item, {
              imports: mergeImportSlugs(sessionImportSlugs(item), [slugName], item.projectSlug || "")
            });
          });
          await persistSessions(list, opened.id);
          setSlug(slugName);
          setIngestNote("Created project and added " + file.name);
          tabReady = true;
        }
      }
      await loadBinaries();
    }

    async function removeSlug(target) {
      if (!target) return;
      askConfirm({
        title: "Remove " + target + "?",
        message: "Remove this binary from the corpus store. This cannot be undone from the dashboard.",
        danger: true,
        confirmLabel: "Remove",
        onConfirm: function () { removeSlugConfirmed(target); }
      });
    }

    async function removeSlugConfirmed(target) {
      const res = await fetch(API.binaries + "/" + encodeURIComponent(target), {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ confirm: true })
      });
      const data = await res.json();
      reactJob("corpus.remove-binary", data);
      if (currentSession && currentSession.projectSlug === target) {
        resetTabState();
        const cleared = sessions.map(function (item) {
          if (item.id !== activeSession) return item;
          return Object.assign({}, item, {
            kind: "draft",
            locator: "",
            projectSlug: "",
            imports: [],
            program: ""
          });
        });
        await persistSessions(cleared, activeSession);
      } else if (currentSession && importsContain(currentSession, target)) {
        const trimmed = sessions.map(function (item) {
          if (item.id !== activeSession) return item;
          return Object.assign({}, item, {
            imports: sessionImportSlugs(item).filter(function (slug) { return slug !== target; })
          });
        });
        await persistSessions(trimmed, activeSession);
      }
      if (slug === target) {
        setSlug(currentSession && currentSession.projectSlug ? currentSession.projectSlug : "");
        setSelected(null);
        setDetail(null);
      }
      await loadBinaries();
    }

    async function saveMeta(ev) {
      if (ev) ev.preventDefault();
      if (!slug) return;
      const res = await fetch(API.binaries + "/" + encodeURIComponent(slug), {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ role: editRole, label: editLabel })
      });
      reactJob("corpus.edit-binary", await res.json());
      await loadBinaries();
    }

    async function runQuickAction(spec) {
      if (!spec) return;
      if (spec.ui === "upload") {
        triggerFileUpload();
        return;
      }
      if (spec.ui === "import") {
        openProjectDialog();
        return;
      }
      if (spec.ui === "new-project") {
        createProject();
        return;
      }
      openActionStrip(spec.id);
      executeAction(spec.id, {}, { danger: spec.danger, mutating: spec.mutating });
    }

    async function shutdownServer() {
      askConfirm({
        title: "Shut down server?",
        message: "Stop the AgentDecompile HTTP server on this port.",
        danger: true,
        confirmLabel: "Shutdown",
        onConfirm: async function () {
          showToast("Shutting down server…", "success");
          try {
            await fetch(API.serverShutdown, { method: "POST" });
          } catch (_err) { /* connection will drop */ }
        }
      });
    }

    async function restartServer() {
      askConfirm({
        title: "Restart server?",
        message: "Restart the AgentDecompile HTTP server. Open tabs will reconnect when it is back.",
        confirmLabel: "Restart",
        onConfirm: async function () {
          showToast("Restarting server…", "success");
          try {
            await fetch(API.serverRestart, { method: "POST" });
          } catch (_err) { /* connection may drop while restarting */ }
          window.setTimeout(function () {
            window.location.reload();
          }, 2500);
        }
      });
    }

    function quickActionFlags() {
      return {
        needsFunction: !selected && checkedAddrs.length === 0,
        needsSlug: !slug,
        needsProject: !tabHasRealProject(currentSession)
      };
    }

    function quickBar(setName) {
      return html`<${QuickActions}
        items=${QUICK_ACTION_SETS[setName] || []}
        catalog=${actions}
        onPress=${runQuickAction}
        flags=${quickActionFlags()} />`;
    }

    function onSearch(value) {
      setQuery(value);
      setFuncOffset(0);
    }

    function onIngestDragOver(ev) {
      ev.preventDefault();
      ev.stopPropagation();
      ev.currentTarget.classList.add("on");
    }

    function onIngestDragLeave(ev) {
      ev.currentTarget.classList.remove("on");
    }

    function onDrop(ev) {
      ev.preventDefault();
      if (ev.currentTarget && ev.currentTarget.classList) ev.currentTarget.classList.remove("on");
      if (dropRef.current) dropRef.current.classList.remove("on");
      uploadFiles(ev.dataTransfer && ev.dataTransfer.files);
    }

    const projectLocator = (dossier && dossier.locator) || (currentSession && currentSession.locator) || "";
    const projectNames = (dossier && dossier.ok ? (dossier.programs || []) : []).map(programName).filter(Boolean);
    const tabImports = sessionImportSlugs(currentSession);
    const activeProjectSlug = (currentSession && currentSession.projectSlug) || slug;
    const projectRow = dossier && dossier.ok ? binaries.find(function (row) {
      return row.slug === activeProjectSlug
        || row.locator === projectLocator
        || row.repo === projectLocator
        || row.slug === dossier.slug;
    }) : null;
    const importItems = [];
    tabImports.forEach(function (name) {
      if (!name) return;
      if (projectRow && name === projectRow.slug) return;
      const row = binaries.find(function (item) { return item.slug === name; }) || { slug: name, kind: "binary" };
      importItems.push({
        key: "import-" + name,
        name: row.slug || name,
        kind: kindLabel(row),
        row: row
      });
    });
    let projectCard = null;
    if (dossier && dossier.ok) {
      projectCard = {
        key: "project-" + (projectLocator || dossier.slug || "project"),
        name: (currentSession && currentSession.title) || dossier.slug || "Project",
        kind: styleKind(dossier.kind),
        row: projectRow,
        programs: projectNames,
        imports: importItems
      };
    } else if (currentSession && currentSession.projectSlug) {
      const row = binaries.find(function (item) { return item.slug === currentSession.projectSlug; });
      projectCard = {
        key: "project-" + currentSession.projectSlug,
        name: currentSession.title || currentSession.projectSlug,
        kind: styleKind(currentSession.kind || (row && row.kind) || "draft"),
        row: row,
        programs: projectNames,
        imports: importItems
      };
    }

    const graphUrl = selected
      ? "/dashboard/function/" + encodeURIComponent(slug) + "/" + encodeURIComponent(selected.addr)
      : "";
    const panelUrl = function (id) { return API.panel + "?id=" + id + "&embed=1"; };
    /* One block of the retired browse page, mounted as its own window. */
    const blockUrl = function (block) {
      let url = "/dashboard/browse-block?block=" + encodeURIComponent(block);
      if (slug) url += "&binary=" + encodeURIComponent(slug);
      ["lq", "logical_q", "logical_after", "review_after", "q", "addr", "logical_id"].forEach(function (key) {
        const val = start.get(key);
        if (val) url += "&" + encodeURIComponent(key) + "=" + encodeURIComponent(val);
      });
      return url;
    };

    function openLogicalId(logicalId) {
      if (!logicalId) return;
      jumpToCorpus("wb-logical");
      showToast("Logical #" + logicalId + " — see Logical identities");
    }

    const toolContext = useMemo(function () {
      const tabSlugs = [];
      const seen = new Set();
      function addSlug(name) {
        if (!name || seen.has(name)) return;
        seen.add(name);
        tabSlugs.push(name);
      }
      if (currentSession && currentSession.projectSlug && slug === currentSession.projectSlug) {
        addSlug(currentSession.projectSlug);
      }
      sessionImportSlugs(currentSession).forEach(addSlug);
      if (slug) addSlug(slug);
      const tabRows = tabSlugs.map(function (name) {
        return binaries.find(function (row) { return row.slug === name; });
      }).filter(Boolean);
      const projectNames = (dossier && dossier.ok ? (dossier.programs || []) : []).map(programName).filter(Boolean);
      const activeRow = binaries.find(function (row) { return row.slug === slug; }) || tabRows[0] || {};
      return {
        slug: slug || (currentSession && currentSession.projectSlug) || "",
        program: program || "",
        repo: activeRow.repo || "",
        addr: selected && selected.addr ? selected.addr : "",
        name: selected && selected.name ? selected.name : "",
        db: envDefaults.db || "",
        work_dir: envDefaults.work_dir || "",
        kb: envDefaults.kb || "",
        recovered: recoveredRoot || "",
        tabSlugs: tabSlugs,
        tabRows: tabRows.length ? tabRows : binaries.slice(0, 32),
        allBinaries: binaries,
        programs: projectNames,
        functions: rows
      };
    }, [binaries, slug, program, selected, rows, currentSession, dossier, envDefaults, recoveredRoot]);

    const pendingAction = pendingActionId
      ? actions.find(function (item) { return item.id === pendingActionId; })
      : null;

    /* Every legacy panel gets at least Refresh, so no surface is a read-only dead end. */
    function panelActions(extras) {
      return html`<div className="wb-surface-actions">
        ${extras || null}
        <button type="button" className="wb-btn wb-btn-mini"
          onClick=${function () { reloadIslands(); showToast("Panel refreshed", "success"); }}>Refresh</button>
      </div>`;
    }

    function runActionButton(actionId, label) {
      const known = actions.some(function (item) { return item.id === actionId; });
      if (!known) return null;
      return html`<button type="button" className="wb-btn wb-btn-mini"
        onClick=${function () { openActionStrip(actionId); }}>${label}</button>`;
    }

    function renderEditorBody() {
      const tab = centerTab || "decompile";
      if (tab === "graph") {
        return html`<${Surface} id="wb-graph" title="Graph">
          ${graphUrl
            ? html`<${HtmlIsland} url=${graphUrl} refreshKey=${slug + ":" + (selected && selected.addr)} className="wb-graph-island" />`
            : html`<div className="wb-empty wb-empty-surface">
              <p>${program
                ? (program + " is a Ghidra program. Call Graph needs a corpus function — pick an Import, extract inventory, then select a row in Functions.")
                : "Select a function in Functions, or pick an Import that has inventory."}</p>
              <p className="wb-hint">Graph is empty until an address is selected. This is not a failed decompile.</p>
            </div>`}
        </${Surface}>`;
      }
      if (tab === "wb-overview") {
        return html`<${Surface} id="wb-overview" title="Overview" actions=${panelActions()}>
          <${TabRoster}
            programs=${projectNames}
            imports=${importItems}
            selectedSlug=${slug}
            selectedProgram=${program}
            onPickProgram=${function (name) {
              selectProgram(name);
              showToast("Program " + name);
            }}
            onPickImport=${function (row) {
              selectImportBinary(row);
              showToast("Import " + ((row && row.slug) || ""));
            }} />
          <p className="wb-hint">${sessionOverviewSlugs.length ? ("Corpus slugs: " + sessionOverviewSlugs.join(", ")) : "No corpus slugs in this tab."}</p>
          <${HtmlIsland} url=${overviewUrl} refreshKey=${sessionOverviewSlugs.join("|") + "|" + projectNames.join("|")} className="wb-island wb-overview-island" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-atlas") {
        return html`<${Surface} id="wb-atlas" title="Atlas" actions=${panelActions(
          html`<a className="wb-btn wb-btn-mini" href="/atlas" target="_blank" rel="noreferrer">Open full page</a>`
        )}>
          <${HtmlIsland} url="/atlas?embed=1" refreshKey="atlas" className="wb-island wb-atlas-island" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-report") {
        return html`<${Surface} id="wb-report" title="Report" actions=${panelActions(
          html`<a className="wb-btn wb-btn-mini" href="/report" target="_blank" rel="noreferrer">Open full page</a>`
        )}>
          <${HtmlIsland} url="/report?embed=1" refreshKey="report" className="wb-island wb-report" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-pipeline") {
        return html`<${Surface} id="wb-pipeline" title="Pipeline" actions=${panelActions()}>
          <${HtmlIsland} url=${panelUrl("steps")} refreshKey="steps" className="wb-island wb-pipeline-island" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-jobs") {
        return html`<${Surface} id="wb-jobs" title="Jobs">
          <ul id="action-jobs" className="wb-job-list">
            ${jobs.length ? jobs.map(function (job) {
              return html`<li key=${job.id}><code>${job.id}</code> ${job.actionId || ""} ${job.status}</li>`;
            }) : html`<li>no jobs</li>`}
          </ul>
        </${Surface}>`;
      }
      if (tab === "wb-match") {
        return html`<${Surface} id="wb-match" title="Cross-match" actions=${panelActions(
          html`<button type="button" id="wb-run-cross-place" className="wb-btn wb-btn-mini wb-btn-primary"
            onClick=${function () { openActionStrip("corpus.cross-place"); }}>Run Cross-place</button>`
        )}>
          <${HtmlIsland} url=${panelUrl("crossmatch")} refreshKey="crossmatch" className="wb-island wb-match-island" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-recovery") {
        return html`<${Surface} id="wb-recovery" title="Recovery" actions=${panelActions(
          runActionButton("corpus.recover", "Run recovery")
        )}>
          <${HtmlIsland} url=${panelUrl("recovery")} refreshKey="recovery" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-stabs") {
        return html`<${Surface} id="wb-stabs" title="STABS" actions=${panelActions(
          runActionButton("corpus.stabs-link", "Run STABS link")
        )}>
          <${HtmlIsland} url=${panelUrl("stabs")} refreshKey="stabs" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-knowledge") {
        return html`<${Surface} id="wb-knowledge" title="Knowledge" actions=${panelActions()}>
          <${HtmlIsland} url=${panelUrl("knowledge")} refreshKey="knowledge" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-roundtrip") {
        return html`<${Surface} id="wb-roundtrip" title="Roundtrip" actions=${panelActions()}>
          <${HtmlIsland} url=${panelUrl("roundtrip")} refreshKey="roundtrip" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-processes") {
        return html`<${Surface} id="wb-processes" title="Process log" actions=${panelActions()}>
          <${HtmlIsland} url=${panelUrl("processes")} refreshKey=${String(jobs.length)} compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-mission") {
        return html`<${Surface} id="wb-mission" title="Mission" actions=${panelActions()}>
          <${HtmlIsland} url=${panelUrl("directives")} refreshKey="directives" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-corpus") {
        return html`<${Surface} id="wb-corpus" title="Corpus" actions=${panelActions(
          html`<button type="button" className="wb-btn wb-btn-mini" data-cmd="file.add-binaries"
            onClick=${function () { runCommand("file.add-binaries"); }}>Add binaries…</button>`
        )}>
          <${HtmlIsland} url=${panelUrl("binaries")} refreshKey="binaries" compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-fnbrowse") {
        return html`<${Surface} id="wb-fnbrowse" title="Functions" actions=${html`<div className="wb-surface-actions">
          <${FuncPager} offset=${funcOffset} limit=${funcLimit} shown=${rows.length} total=${total}
            onOffset=${setFuncOffset} onLimit=${function (n) { setFuncLimit(n); setFuncOffset(0); }} />
          <button type="button" className="wb-btn wb-btn-mini"
            onClick=${function () { loadFuncs(slug, query); showToast("Function list reloaded", "success"); }}>Refresh</button>
        </div>`}>
          <div className="wb-fnb-head">
            <label className="wb-fnb-filter">
              <span className="sr-only">Find a function by name or address</span>
              <input id="wb-fnbrowse-q" type="search" placeholder="Find a function by name or address…"
                value=${query} onInput=${function (ev) { onSearch(ev.target.value); }} autocomplete="off" />
            </label>
            <span className="wb-hint">${slug
              ? (program ? slug + " · Ghidra program " + program : slug)
              : "No build selected — pick an Import in Explorer."}</span>
          </div>
          ${rows.length ? html`<table id="wb-fnbrowse-table" className="wb-fnb-table">
            <thead>
              <tr>
                <th scope="col">Address</th>
                <th scope="col">Name</th>
                <th scope="col">Size</th>
                <th scope="col">Logical</th>
                <th scope="col">Decompiled C</th>
                <th scope="col">Validated</th>
              </tr>
            </thead>
            <tbody>
              ${rows.map(function (row) {
                const on = selected && selected.addr === row.addr;
                return html`<tr key=${row.addr} className=${on ? "on" : ""}
                  onContextMenu=${function (ev) {
                    if (!on) selectRow(row);
                    openCtx(ev, functionCtxItems(row));
                  }}
                  onClick=${function () { selectRow(row); }}>
                  <td><code>${row.addr}</code></td>
                  <td>${row.name}</td>
                  <td className="wb-num">${row.size || ""}</td>
                  <td>${row.logicalId
                    ? html`<button type="button" className="wb-text-action"
                        onClick=${function (ev) { ev.stopPropagation(); openLogicalId(row.logicalId); }}
                        >#${row.logicalId}</button>`
                    : html`<span className="wb-hint">unbound</span>`}</td>
                  <td><span className=${"wb-flag st-" + (row.decomp || "none")}>${row.decomp || "none"}</span></td>
                  <td><span className=${"wb-flag st-" + (row.validate || "none")}>${row.validate || "none"}</span></td>
                </tr>`;
              })}
            </tbody>
          </table>` : html`<div className="wb-empty wb-empty-surface">
            <p>${funcNote || "Select a program in Explorer to list its functions."}</p>
            <p className="wb-empty-actions">
              <button type="button" className="wb-btn wb-btn-primary" data-cmd="analyze.bsim-ingest"
                onClick=${function () { runCommand("analyze.bsim-ingest"); }}>Ingest repository into BSim</button>
              <button type="button" className="wb-btn" data-cmd="analyze.bsim-report"
                onClick=${function () { runCommand("analyze.bsim-report"); }}>Report BSim</button>
            </p>
          </div>`}
          ${rows.length ? html`<${FuncPager} offset=${funcOffset} limit=${funcLimit} shown=${rows.length}
            total=${total} onOffset=${setFuncOffset}
            onLimit=${function (n) { setFuncLimit(n); setFuncOffset(0); }} />` : null}
        </${Surface}>`;
      }
      if (tab === "wb-logical") {
        return html`<${Surface} id="wb-logical" title="Logical identities" actions=${panelActions()}>
          <p className="wb-hint">The same function across builds. Click a row to open it in Functions.</p>
          <${HtmlIsland} url=${blockUrl("logical")} refreshKey=${"logical:" + slug} compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-review") {
        return html`<${Surface} id="wb-review" title="Review" actions=${panelActions()}>
          <p className="wb-hint">Match rows that still need a human. Real C and byte-accuracy stay separate.</p>
          <${HtmlIsland} url=${blockUrl("review")} refreshKey=${"review:" + slug} compact=${true} />
        </${Surface}>`;
      }
      if (tab === "wb-tools") {
        const needle = (commandFilter || "").trim().toLowerCase();
        const matches = actions.filter(function (item) {
          if (!needle) return true;
          return (item.id + " " + (item.title || "") + " " + (item.group || "") + " " + (item.summary || ""))
            .toLowerCase().indexOf(needle) >= 0;
        });
        const groups = [];
        const byGroup = {};
        matches.forEach(function (item) {
          const key = item.group || "Other";
          if (!byGroup[key]) { byGroup[key] = []; groups.push(key); }
          byGroup[key].push(item);
        });
        return html`<${Surface} id="wb-tools" title="Commands" actions=${html`<div className="wb-surface-actions">
          <a className="wb-btn wb-btn-mini" href="/docs" target="_blank" rel="noreferrer">HTTP API</a>
          <button type="button" className="wb-btn wb-btn-mini"
            onClick=${function () { setPaletteOpen(true); setPaletteQuery(""); }}>Palette ${accelLabel("mod+K")}</button>
        </div>`}>
          <label className="wb-cmd-filter">
            <span className="sr-only">Filter commands</span>
            <input type="search" id="wb-cmd-filter" placeholder=${"Filter " + actions.length + " commands…"}
              value=${commandFilter} onInput=${function (ev) { setCommandFilter(ev.target.value); }} />
          </label>
          <p className="wb-hint">${matches.length} of ${actions.length} commands. Click one to load it into the run strip with the current selection.</p>
          ${recentActionIds.length && !needle ? html`<section className="wb-cmd-group">
            <h3>Recent</h3>
            <ul className="wb-cmd-list">
              ${recentActionIds.map(function (id) {
                const item = actions.find(function (row) { return row.id === id; });
                if (!item) return null;
                return html`<li key=${"recent-" + id}>
                  <button type="button" className="wb-cmd-entry" onClick=${function () { openActionStrip(item.id); }}>
                    <span className="wb-cmd-title">${item.title || item.id}</span>
                    <code className="wb-cmd-id">${item.id}</code>
                  </button>
                </li>`;
              })}
            </ul>
          </section>` : null}
          ${groups.map(function (name) {
            return html`<section key=${name} className="wb-cmd-group">
              <h3>${name}</h3>
              <ul className="wb-cmd-list">
                ${byGroup[name].map(function (item) {
                  return html`<li key=${item.id}>
                    <button type="button" className=${"wb-cmd-entry" + (item.danger || item.mutating ? " danger" : "")}
                      data-action=${item.id}
                      onClick=${function () { openActionStrip(item.id); }}>
                      <span className="wb-cmd-title">${item.title || item.id}</span>
                      <code className="wb-cmd-id">${item.id}</code>
                      ${item.summary ? html`<span className="wb-cmd-summary">${item.summary}</span>` : null}
                      ${item.danger || item.mutating ? html`<span className="wb-cmd-flag">writes</span>` : null}
                    </button>
                  </li>`;
                })}
              </ul>
            </section>`;
          })}
          ${!matches.length ? html`<p className="wb-empty">No command matches “${commandFilter}”.</p>` : null}
        </${Surface}>`;
      }
      const hasProject = dossier && dossier.ok;
      if (!hasProject && !selected) {
        return html`<section id="wb-inspect" className="wb-surface wb-listing">
          <div id="wb-ingest" className="wb-listing-empty wb-ingest-drop"
            onDragOver=${onIngestDragOver} onDragLeave=${onIngestDragLeave} onDrop=${onDrop}
            onClick=${openProjectDialog}>
            <p>Drop a binary or project here.</p>
            <p className="wb-hint">File → Open</p>
          </div>
        </section>`;
      }
      return html`<${Surface} id="wb-inspect" title="Listing">
        <div id="wb-inspect-body">
          ${selected ? html`<div>
            <h3>${selected.name} <code>${selected.addr}</code></h3>
            <p className="wb-hint">logical ${selected.logicalId || "unbound"}</p>
            <div className="wb-fn-tools" role="toolbar" aria-label="Function tools">
              <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { openActionStrip("mcp.decompile-function"); }}>Decompile</button>
              <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { openActionStrip("mcp.manage-comments"); }}>Comment</button>
              <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { openActionStrip("mcp.create-label"); }}>Label</button>
              <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { openActionStrip("mcp.get-references"); }}>Xrefs</button>
              <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { openActionStrip("mcp.analyze-data-flow"); }}>Data flow</button>
              <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { openActionStrip("mcp.manage-bookmarks"); }}>Bookmark</button>
              <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { openActionStrip("mcp.manage-function"); }}>Rename</button>
              <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { openActionStrip("mcp.match-function"); }}>Match</button>
            </div>
            ${(detail && detail.siblings && detail.siblings.length) ? html`<ul className="wb-siblings">
              ${detail.siblings.map(function (sib) {
                return html`<li key=${sib.slug + sib.addr}>
                  <button type="button" className="wb-text-action"
                    onClick=${function () { setSlug(sib.slug); }}>${sib.slug} ${sib.addr}</button>
                </li>`;
              })}
            </ul>` : null}
            <pre className="wb-preview">${(detail && detail.preview) || "No recovered C on disk."}</pre>
          </div>` : html`<div className="wb-empty wb-empty-surface">
            <p>${program
              ? ("Listing " + program + ". Pick a function, or ingest the repository into BSim so the function list fills.")
              : (hasProject
                ? "Pick a program in Explorer. Functions and listing come from that program — same as IDA or Ghidra."
                : "File → Open a Ghidra repository, then pick a program.")}</p>
            <p className="wb-empty-actions">
              <button type="button" className="wb-btn wb-btn-primary" data-cmd="analyze.bsim-ingest"
                onClick=${function () { runCommand("analyze.bsim-ingest"); }}>Ingest repository into BSim</button>
              <button type="button" className="wb-btn" data-cmd="view.browse"
                onClick=${function () { runCommand("view.browse"); }}>Functions</button>
            </p>
          </div>`}
          <div id="wb-reaction" className="wb-reaction">
            ${reaction && (selected || String(reaction.id || "").indexOf("decompile") >= 0) ? html`<p><strong>${reaction.id}</strong> ${formatJobSummary(reaction.data)}</p>
              ${reaction.data && reaction.data.job && reaction.data.job.id
                ? html`<button type="button" className="wb-text-action"
                    onClick=${function () { selectJobInDock(reaction.data.job.id); }}>View log in dock</button>`
                : null}
              <details className="wb-reaction-raw">
                <summary>Raw response</summary>
                <pre className="wb-preview">${JSON.stringify(reaction.data, null, 2).slice(0, 4000)}</pre>
              </details>`
              : null}
          </div>
        </div>
      </${Surface}>`;
    }

    return html`<div className="wb">
      <a className="skip-link" href="#wb-functions">Skip to functions</a>
      <div className="wb-chrome">
      <header className="wb-toolbar">
        <div className="wb-brand">
          <span className="wb-mark" aria-hidden="true">AD</span>
          <strong>AgentDecompile</strong>
        </div>
        <label className="wb-search">
          <span className="sr-only">Filter functions in the open binary</span>
          <input id="wb-q" type="search" placeholder="Filter functions…"
            value=${query} onInput=${function (ev) { onSearch(ev.target.value); }} autocomplete="off" />
        </label>
        <p className="wb-status-line">
          <button type="button" className="wb-server-btn" data-cmd="view.palette"
            onClick=${function () { setPaletteOpen(true); setPaletteQuery(""); }}
            title=${"Command palette (" + accelLabel("mod+K") + ")"}>${accelLabel("mod+K")}</button>
          <span id="job-pulse">${running.length ? running.length + " running" : (jobs[0] ? jobs[0].status : "idle")}</span>
        </p>
      </header>
      <nav id="wb-menubar" className="wb-menubar" aria-label="Application">
        ${[
          ["file", "File", [
            ["New Project…", "file.new-project"],
            ["New Tab", "file.new-tab"],
            ["Open…", "file.open"],
            ["Open from URL…", "file.open-url"],
            ["Add binaries…", "file.add-binaries"],
            ["—"],
            ["Reload from disk", "file.reload"],
            ["Save", "file.save"],
            ["Save As…", "file.save-as"],
            ["—"],
            ["Close Tab", "file.close-tab"]
          ]],
          ["edit", "Edit", [
            ["Rename Tab", "edit.rename-tab"]
          ]],
          ["view", "View", [
            ["Command palette", "view.palette"],
            ["Explorer", "view.explorer"],
            ["—"],
            ["Listing", "view.listing"],
            ["Functions", "view.browse"],
            ["Logical identities", "view.logical"],
            ["Call Graph", "view.graph"],
            ["Inspector", "view.inspect"],
            ["—"],
            ["Overview", "view.overview"],
            ["Pipeline", "view.pipeline"],
            ["Atlas", "view.atlas"],
            ["Jobs", "view.jobs"],
            ["—"],
            ["Cross-match", "view.cross-match"],
            ["Run Cross-place", "run.cross-place"],
            ["Recovery", "view.recovery"],
            ["STABS", "view.stabs"],
            ["Knowledge", "view.knowledge"],
            ["Review", "view.review"],
            ["Report", "view.report"],
            ["Corpus table", "view.corpus"],
            ["Commands", "view.tools"],
            ["—"],
            ["Compact density", "view.density-compact"],
            ["Comfortable density", "view.density-comfortable"],
            ["Jobs dock on side (wide screens)", "view.jobs-rail"],
            ["Jobs dock on bottom", "view.jobs-bottom"]
          ]],
          ["analyze", "Analyze", [
            ["Analyze program", "analyze.program"],
            ["Ingest repository into BSim", "analyze.bsim-ingest"],
            ["Report BSim database", "analyze.bsim-report"],
            ["Create BSim database", "analyze.bsim-create"]
          ]],
          ["server", "Server", [
            ["Restart Server", null, restartServer],
            ["Shutdown Server", null, shutdownServer]
          ]],
          ["help", "Help", [
            ["Keyboard & five ways…", "help.access"],
            ["Swagger / all commands", null, function () { window.location.href = "/docs"; }],
            ["Full corpus overview", null, function () { window.location.href = "/dashboard/overview-corpus"; }],
            ["Classic overview (legacy)", "help.classic-overview"]
          ]]
        ].map(function (entry) {
          const id = entry[0];
          const label = entry[1];
          const items = entry[2];
          return html`<div key=${id} className=${"wb-menu" + (menu === id ? " on" : "")}
            onMouseEnter=${function () { if (menu) setMenu(id); }}>
            <button type="button" className="wb-menu-btn" aria-haspopup="true" aria-expanded=${menu === id}
              onClick=${function () { setMenu(menu === id ? "" : id); }}>${label}</button>
            ${menu === id ? html`<ul className="wb-menu-list">${items.map(function (item, index) {
              if (item[0] === "—") return html`<li key=${id + "-s" + index} className="wb-menu-sep" />`;
              const cmdId = item[1];
              const accel = (cmdId && COMMAND_BY_ID[cmdId] && accelLabel(COMMAND_BY_ID[cmdId].accel))
                || COMMAND_ACCEL[item[0]] || "";
              return html`<li key=${id + "-" + item[0]}>
                <button type="button" className="wb-menu-item" data-cmd=${cmdId || ""}
                  onClick=${function () {
                    setMenu("");
                    if (cmdId) runCommand(cmdId);
                    else if (item[2]) item[2]();
                  }}>
                  <span>${item[0]}</span>
                  ${accel ? html`<span className="wb-accel">${accel}</span>` : null}
                </button>
              </li>`;
            })}</ul>` : null}
          </div>`;
        })}
      </nav>
      <div id="wb-sessions" className="wb-sessions" role="tablist" aria-label="Open projects"
        onContextMenu=${function (ev) {
          openCtx(ev, [
            { id: "file.new-tab" },
            { id: "file.new-project" },
            "—",
            { id: "file.open" },
            { id: "file.open-url" }
          ].map(decorateCommandItem));
        }}>
        ${sessions.map(function (item) {
          const on = item.id === activeSession;
          return html`<div key=${item.id} className=${"wb-tab kind-" + styleKind(item.kind) + (on ? " on" : "")} role="tab" aria-selected=${on}
            onContextMenu=${function (ev) {
              if (item.id !== activeSession) {
                setActiveSession(item.id);
                persistSessions(sessions, item.id);
                restoreTabSession(item);
              }
              openCtx(ev, [
                { title: "Rename “" + (item.title || "tab") + "”", run: function () { setEditingTab(item.id); }, accel: "F2" },
                { id: "file.reload" },
                "—",
                { id: "file.save" },
                { id: "file.save-as" },
                "—",
                { title: "Copy project path", run: function () { copyText(item.locator || "", "project path"); } },
                "—",
                { title: "Close “" + (item.title || "tab") + "”", danger: true, accel: accelLabel("alt+W"),
                  run: function () { runCommand("file.close-tab"); } }
              ].map(decorateCommandItem));
            }}>
            <span className=${"wb-tab-chip kind-" + styleKind(item.kind)} title=${kindTitle(item.kind)}>${styleKind(item.kind)}</span>
            ${editingTab === item.id
              ? html`<input className="wb-tab-rename" value=${item.title} autofocus
                  onBlur=${function (ev) { renameTab(item.id, ev.target.value); }}
                  onKeyDown=${function (ev) { if (ev.key === "Enter") renameTab(item.id, ev.target.value); }} />`
              : html`<button type="button" className="wb-tab-name" title="Double-click to rename"
                  onClick=${function () {
                    if (item.id === activeSession) return;
                    setActiveSession(item.id);
                    persistSessions(sessions, item.id);
                    restoreTabSession(item);
                  }}
                  onDblClick=${function () { setEditingTab(item.id); }}>${item.title}</button>`}
            <button type="button" className="wb-tab-close" aria-label=${"Close " + item.title}
              onClick=${function () {
                const dirty = item.kind !== "draft" || item.locator || sessionImportSlugs(item).length;
                if (dirty) {
                  askConfirm({
                    title: "Close " + (item.title || "tab") + "?",
                    message: "This closes the project tab, not an editor buffer. File → Open reopens it.",
                    confirmLabel: "Close tab",
                    danger: true,
                    onConfirm: function () { closeTab(item.id); }
                  });
                  return;
                }
                closeTab(item.id);
              }}>×</button>
          </div>`;
        })}
        <button type="button" id="wb-tab-new" className="wb-tab-new" data-cmd="file.new-tab"
          onClick=${function () { runCommand("file.new-tab"); }}
          title=${"New tab (" + accelLabel("alt+T") + ")"}>+</button>
      </div>
      ${pendingAction ? html`<${ActionStrip}
        action=${pendingAction}
        ctx=${toolContext}
        expanded=${actionExpanded}
        danger=${pendingAction.danger || pendingAction.mutating}
        checkedCount=${checkedAddrs.length}
        formRef=${actionFormRef}
        onToggleExpand=${function () { setActionExpanded(function (v) { return !v; }); }}
        onRun=${runFromActionStrip}
        onClose=${function () { setPendingActionId(""); setActionExpanded(false); }} />` : null}
      <${JobLiveRegion} text=${jobLiveText} />
      </div>
      <${CommandPalette}
        open=${paletteOpen}
        query=${paletteQuery}
        onQuery=${setPaletteQuery}
        actions=${actions}
        surfaces=${SURFACES}
        jobs=${jobs}
        recentActionIds=${recentActionIds}
        commands=${WORKBENCH_COMMANDS}
        onPickAction=${onPaletteAction}
        onPickSurface=${onPaletteSurface}
        onPickJob=${onPaletteJob}
        onPickCommand=${function (id) { setPaletteOpen(false); setPaletteQuery(""); runCommand(id); }}
        onClose=${function () { setPaletteOpen(false); setPaletteQuery(""); }} />
      <${ContextMenu} menu=${ctxMenu} onClose=${function () { setCtxMenu(null); }}
        onPick=${function (item) {
          setCtxMenu(null);
          if (typeof item.run === "function") item.run();
          else runCommand(item.id, item.extra);
        }} />
      <${ConfirmDialog}
        open=${Boolean(confirmDialog)}
        title=${confirmDialog && confirmDialog.title}
        message=${confirmDialog && confirmDialog.message}
        confirmLabel=${confirmDialog && confirmDialog.confirmLabel}
        danger=${confirmDialog && confirmDialog.danger}
        onConfirm=${confirmDialog && confirmDialog.onConfirm}
        onCancel=${closeConfirm} />
      <main id="app">
      <input id="wb-bin-file-global" type="file" multiple hidden ref=${fileRef}
        onChange=${function (ev) { if (ev.target.files && ev.target.files.length) uploadFiles(ev.target.files); }} />
      <input id="wb-bin-folder-global" type="file" webkitdirectory="true" hidden ref=${folderRef}
        onChange=${function (ev) { if (ev.target.files && ev.target.files.length) uploadFiles(ev.target.files); }} />
      ${toast ? html`<div className=${"wb-toast" + (toastKind ? " kind-" + toastKind : "")} role="status">${toast}</div>` : null}

      <${Modal} open=${dialog === "open"} title="Open Project" onClose=${closeDialog} error=${dialogError} footer=${html`
        <button type="button" className="wb-btn" onClick=${closeDialog}>Cancel</button>
        <button type="button" className="wb-btn wb-btn-primary" id="wb-open-paste-go" onClick=${openPastedPath}>Open path</button>
      `}>
        <label className="wb-open-paste">Path or URL
          <input id="wb-open-paste" value=${openPaste} placeholder="/home/…/repos · Name.gpr · ghidra://host:port/repo · /path/to/binary"
            onInput=${function (ev) { setOpenPaste(ev.target.value); }}
            onKeyDown=${function (ev) { if (ev.key === "Enter") { ev.preventDefault(); openPastedPath(); } }} />
        </label>
        <div className="wb-dialog-tabs">
          <button type="button" className=${openTab === "local" ? "on" : ""} onClick=${function () { setOpenTab("local"); }}>This computer</button>
          <button type="button" className=${openTab === "remote" ? "on" : ""} onClick=${function () { setOpenTab("remote"); }}>Remote URL</button>
        </div>
        ${openTab === "local" ? html`<div>
          <div id="wb-drop" className="wb-drop wb-drop-compact" tabindex="0" ref=${dropRef}
            onClick=${triggerFileUpload}
            onDragOver=${function (ev) { ev.preventDefault(); ev.currentTarget.classList.add("on"); }}
            onDragLeave=${function (ev) { ev.currentTarget.classList.remove("on"); }}
            onDrop=${onDrop}>
            Drop a .gpr, .rep folder, repos tree, or PE/ELF
          </div>
          <p className="wb-dialog-actions">
            <button type="button" className="wb-btn" onClick=${triggerFolderUpload}>Choose folder…</button>
            <button type="button" className="wb-btn wb-btn-primary" onClick=${createProject}>New empty project</button>
          </p>
          <div id="wb-browse" className="wb-browse">
            <p className="wb-browse-path">
              ${browse.parent ? html`<button type="button" className="wb-text-action" onClick=${function () { loadBrowse(browse.parent); }}>Up</button>` : null}
              <code>${browse.path || "roots"}</code>
            </p>
            <ul className="wb-browse-list">
              ${(browse.entries || []).map(function (entry) {
                return html`<li key=${entry.path} className=${"kind-" + styleKind(entry.kind)}>
                  <button type="button" className="wb-browse-item" data-kind=${entry.kind}
                    onClick=${function () {
                      if (entry.kind === "binary") {
                        openBinaryPath(entry.path, entry.name);
                      } else if (entry.kind === "gpr" || entry.kind === "project-dir" || entry.kind === "shared-fs") {
                        openLocator(entry.path, entry.name);
                      } else {
                        loadBrowse(entry.path);
                      }
                    }}>
                    <strong>${entry.name}</strong>
                    <span>${kindTitle(entry.kind)}${entry.programs && entry.programs.length ? " · " + entry.programs.length + " programs" : ""}</span>
                  </button>
                </li>`;
              })}
            </ul>
          </div>
        </div>` : html`<form id="wb-shared-form" className="wb-bin-form" onSubmit=${registerShared}>
          <label>URL
            <input id="wb-shared-url" placeholder="ghidra://127.0.0.1:13100/Repo/Game.exe"
              value=${sharedUrl} onInput=${function (ev) { setSharedUrl(ev.target.value); }} />
          </label>
          <p className="wb-hint">Or build from host, port, and repository:</p>
          <label>Host<input id="wb-shared-host" value=${sharedHost} onInput=${function (ev) { setSharedHost(ev.target.value); }} /></label>
          <label>Port<input id="wb-shared-port" value=${sharedPort} onInput=${function (ev) { setSharedPort(ev.target.value); }} /></label>
          <label>Repository<input id="wb-shared-repo" value=${sharedRepo} onInput=${function (ev) { setSharedRepo(ev.target.value); }} /></label>
          <label>Program<input id="wb-shared-program" value=${sharedProgram} onInput=${function (ev) { setSharedProgram(ev.target.value); }} /></label>
          <p className="wb-hint"><code>${builtSharedUrl() || "ghidra://host:port/repository"}</code></p>
          <button type="submit" id="wb-shared-add" className="wb-btn wb-btn-primary">Open</button>
        </form>`}
      </${Modal}>

      <${Modal} open=${dialog === "save-as"} title="Save As" onClose=${closeDialog} error=${dialogError}
        footer=${html`
          <button type="button" className="wb-btn" onClick=${closeDialog}>Cancel</button>
          <button type="submit" form="wb-save-as-form" className="wb-btn wb-btn-primary">Save</button>
        `}>
        <form id="wb-save-as-form" onSubmit=${submitSaveAs}>
          <label>Project name
            <input value=${saveAsName} onInput=${function (ev) { setSaveAsName(ev.target.value); }} />
          </label>
          <label>Format
            <select value=${saveAsTarget} onChange=${function (ev) { setSaveAsTarget(ev.target.value); }}>
              <option value="ghidra-project">Local Ghidra project (.gpr)</option>
              <option value="shared-fs">Shared server folder (filesystem layout)</option>
              <option value="shared-project">HTTP / ghidra:// link with local checkout</option>
            </select>
          </label>
          ${saveAsTarget === "shared-project" ? html`<label>Server URL
            <input id="wb-save-as-url" value=${saveAsUrl} placeholder="ghidra://host:13100/repo"
              onInput=${function (ev) { setSaveAsUrl(ev.target.value); }} />
          </label>` : html`<label>Folder <span className="wb-hint">optional</span>
            <input value=${saveAsDest} placeholder="defaults to work directory"
              onInput=${function (ev) { setSaveAsDest(ev.target.value); }} />
          </label>`}
          <p className="wb-hint">Save writes project metadata on disk. Ghidra program databases are not copied unless you already have a local .gpr tree.</p>
        </form>
      </${Modal}>

      <${Modal} open=${dialog === "access"} title="Keyboard & five ways" onClose=${closeDialog}
        footer=${html`<button type="button" className="wb-btn wb-btn-primary" onClick=${closeDialog}>Close</button>`}>
        <p className="wb-hint">Every workbench verb is reachable five ways: menubar, ⌘K palette, right-click context menu, shortcut, and an in-place button.</p>
        <table className="wb-access-table">
          <thead><tr><th>Command</th><th>Menu</th><th>Palette</th><th>Context</th><th>Key</th></tr></thead>
          <tbody>
            ${WORKBENCH_COMMANDS.map(function (cmd) {
              return html`<tr key=${cmd.id}>
                <td>${cmd.title}</td>
                <td>${cmd.group}</td>
                <td>${accelLabel("mod+K")}</td>
                <td>Right-click</td>
                <td><code>${accelLabel(cmd.accel) || "—"}</code></td>
              </tr>`;
            })}
          </tbody>
        </table>
      </${Modal}>

      <div className="wb-app-shell">
        <aside id="wb-sidebar" className="wb-sidebar"
          onContextMenu=${function (ev) {
            const items = [
              { id: "file.open", title: "Open…" },
              { id: "file.add-binaries", title: "Add binaries…" },
              "—",
              { id: "file.save", title: "Save" },
              { id: "file.save-as", title: "Save As…" },
              "—",
              { id: "file.reload", title: "Reload" }
            ].map(decorateCommandItem);
            openCtx(ev, items);
          }}>
          <div id="wb-sources" className="wb-sidebar-section">
            <header className="wb-sidebar-head">
              <h3>Explorer</h3>
            </header>
            <ul id="wb-binary-list" className="wb-source-tree">
              ${projectCard ? html`<li key=${projectCard.key}
                className=${((activeProjectSlug && slug === activeProjectSlug && !program && !(projectCard.imports || []).some(function (item) { return item.row.slug === slug; })) ? "on " : "") + "kind-" + projectCard.kind + " wb-source-project"}>
                <button type="button" className="wb-bin" data-slug=${(projectCard.row && projectCard.row.slug) || activeProjectSlug || projectCard.name}
                  onContextMenu=${function (ev) { openCtx(ev, projectCtxItems()); }}
                  onClick=${function () {
                    if (activeProjectSlug) {
                      setSlug(activeProjectSlug);
                      setProgram("");
                      patchActiveSession({ program: "" });
                      setSelected(null);
                      setDetail(null);
                    }
                  }}>
                  ${projectCard.name}
                </button>
                ${((projectCard.programs || []).length || (projectCard.imports || []).length) ? html`<ul className="wb-programs">
                  ${(projectCard.imports || []).length ? html`<li className="wb-import-head">Imports · corpus store</li>` : null}
                  ${(projectCard.imports || []).map(function (item) {
                    const row = item.row || {};
                    return html`<li key=${item.key} className=${"wb-import" + (slug === row.slug && !program ? " on" : "")}
                      onContextMenu=${function (ev) { openCtx(ev, importCtxItems(row)); }}>
                      <button type="button" className="wb-text-action"
                        onClick=${function (ev) {
                          ev.stopPropagation();
                          selectImportBinary(row);
                        }}>${item.name}</button>
                      <button type="button" className="wb-text-action wb-remove"
                        onClick=${function (ev) {
                          ev.stopPropagation();
                          removeSlug(row.slug);
                        }}>Remove</button>
                    </li>`;
                  })}
                  ${(projectCard.programs || []).length ? html`<li className="wb-program-head">Programs · Ghidra project</li>` : null}
                  ${(projectCard.programs || []).map(function (name) {
                    const meter = programProgress[name] || null;
                    const live = meter && meter.status && meter.status !== "ok";
                    return html`<li key=${"prog-" + name} className=${"wb-program" + (program === name && slug === activeProjectSlug ? " on" : "") + (live ? " live" : "")}
                      onContextMenu=${function (ev) { openCtx(ev, programCtxItems(name)); }}>
                      <button type="button" className="wb-text-action"
                        onClick=${function (ev) {
                          ev.stopPropagation();
                          selectProgram(name);
                          if (activeProjectSlug) setSlug(activeProjectSlug);
                          setSelected(null);
                          setDetail(null);
                        }}>${name}</button>
                      ${meter ? html`<span className="wb-prog-pct" title=${meter.tool || ""}>${meter.pct}%</span>` : null}
                      ${meter && live ? html`<span className="wb-prog-meter" aria-hidden="true"><i style=${{ transform: "scaleX(" + (Number(meter.pct) / 100) + ")" }}></i></span>` : null}
                    </li>`;
                  })}
                </ul>` : null}
              </li>` : null}
              ${!projectCard && importItems.length ? importItems.map(function (item) {
                const row = item.row || {};
                return html`<li key=${item.key} className=${(slug === row.slug ? "on " : "") + "kind-" + item.kind + " wb-source-import"}>
                  <button type="button" className="wb-bin" data-slug=${row.slug}
                    onClick=${function () { selectImportBinary(row); }}>${item.name}</button>
                  <button type="button" className="wb-text-action wb-remove"
                    onClick=${function () { removeSlug(row.slug); }}>Remove</button>
                </li>`;
              }) : null}
              ${!projectCard && !importItems.length ? html`<li className="wb-empty">File → Open to load a project.</li>` : null}
            </ul>
          </div>
          <div id="wb-functions" className="wb-sidebar-section">
            <h3>Functions ${total ? "(" + total + ")" : ""} ${checkedAddrs.length ? html`<span className="wb-sel-chip">${checkedAddrs.length} selected <button type="button" className="wb-sel-clear" aria-label="Clear function selection" onClick=${function () { setCheckedAddrs([]); setCheckAnchor(""); }}>×</button></span>` : null}</h3>
            <span id="wb-func-meta" className="sr-only">${total || 0} functions${checkedAddrs.length ? ", " + checkedAddrs.length + " selected" : ""}</span>
            ${total > rows.length || funcOffset ? html`<${FuncPager} compact=${true}
              offset=${funcOffset} limit=${funcLimit} shown=${rows.length} total=${total}
              onOffset=${setFuncOffset} onLimit=${setFuncLimit} />` : null}
            <div id="wb-func-window" className="wb-func-window" tabindex="0"
              onContextMenu=${function (ev) {
                openCtx(ev, [
                  { title: checkedAddrs.length
                      ? "Clear " + checkedAddrs.length + " selected"
                      : "Nothing selected",
                    danger: Boolean(checkedAddrs.length),
                    run: function () { setCheckedAddrs([]); setCheckAnchor(""); } },
                  "—",
                  { id: "run.last" },
                  { id: "run.cross-place" },
                  "—",
                  { id: "view.listing" },
                  { id: "view.graph" }
                ].map(decorateCommandItem));
              }}>
              ${rows.map(function (row) {
                const on = selected && selected.addr === row.addr ? " on" : "";
                const checked = checkedAddrs.indexOf(row.addr) >= 0;
                return html`<div key=${row.addr} className=${"wb-func-row" + on + (checked ? " checked" : "")}
                  onContextMenu=${function (ev) {
                    if (!selected || selected.addr !== row.addr) selectRow(row);
                    openCtx(ev, functionCtxItems(row));
                  }}
                  onClick=${function (ev) { onFuncRowClick(ev, row); }}>
                  <input type="checkbox" className="wb-func-check" checked=${checked}
                    aria-label=${"Select " + (row.name || row.addr)}
                    onClick=${function (ev) { onFuncCheck(ev, row); }}
                    onChange=${function () { /* controlled by onClick */ }} />
                  <code>${row.addr}</code><span>${row.name}</span>
                </div>`;
              })}
              ${!rows.length ? html`<p className="wb-hint">${funcNote || "Select a program to list functions."}</p>` : null}
            </div>
            <p className="wb-sidebar-foot">
              <button type="button" className="wb-text-action" data-cmd="view.browse"
                onClick=${function () { runCommand("view.browse"); }}>Browse all functions</button>
            </p>
          </div>
        </aside>

      <div className="wb-editor"
        onContextMenu=${function (ev) {
          openCtx(ev, [
            { title: "Refresh this panel", run: function () { reloadIslands(); showToast("Panels refreshed", "success"); } },
            "—",
            { id: "view.palette" },
            { id: "view.cross-match" },
            { id: "run.cross-place" },
            "—",
            { id: "file.open" },
            { id: "file.add-binaries" }
          ].map(decorateCommandItem));
        }}>
        <${CorpusNavBar} active=${centerTab} moreOpen=${moreOpen}
          onMoreToggle=${setMoreOpen} onJump=${jumpToCorpus} />
        ${dossier && dossier.ok ? html`<div id="wb-project-bar" className="wb-editor-meta">
          <span className=${"wb-kind wb-kind-" + styleKind(dossier.kind)}>${kindTitle(dossier.kind)}</span>
          <code className="wb-project-path">${dossier.locator || ""}</code>
          <span className="wb-hint">${dossier.program_count != null ? dossier.program_count + " programs" : ""}${tabImports.length ? " · " + tabImports.length + " import(s)" : ""}</span>
        </div>` : null}
        <div className="wb-editor-body" onDragOver=${onIngestDragOver} onDragLeave=${onIngestDragLeave} onDrop=${onDrop}>
          ${renderEditorBody()}
        </div>
      </div>
      </div>
        <input id="wb-bin-slug" type="hidden" value=${newSlug} />
        <input id="wb-bin-role" type="hidden" value=${role} />
        <input id="wb-bin-label" type="hidden" value=${label} />
      </main>

      <footer className="wb-status" id="wb-status">
        <span id="wb-status-source">${(currentSession && currentSession.title) || "No project"}</span>
        <span id="wb-status-kind">${current.kind || (currentSession && kindTitle(currentSession.kind)) || ""}</span>
        <span id="wb-status-program">${program
          ? "Ghidra program: " + program
          : (slug
            ? ((currentSession && slug === currentSession.projectSlug)
              ? "Project root: " + slug + " — pick an Import or a Program"
              : "Corpus import: " + slug)
            : "No source selected")}</span>
        <span id="wb-status-selection">${selected
          ? "fn " + (selected.name || selected.addr) + (checkedAddrs.length ? " · " + checkedAddrs.length + " checked" : "")
          : (total ? total + " fn in store" + (checkedAddrs.length ? " · " + checkedAddrs.length + " checked" : "") : "no functions")}</span>
        ${statusError
          ? html`<span id="wb-status-error" className="wb-status-error" role="alert">${statusError}
              <button type="button" className="wb-status-dismiss" aria-label="Dismiss error"
                onClick=${function () { setStatusError(""); }}>×</button></span>`
          : html`<span id="wb-last-action" className="wb-hint">${lastNote}</span>`}
        <span className="wb-hint">A finished job is not a match.</span>
        <a className="wb-link" href="/dashboard/overview-corpus">Full corpus overview</a>
      </footer>
      <${JobsDock}
        jobs=${jobs}
        expanded=${jobsDockOpen}
        pinned=${running.length > 0}
        selectedId=${selectedJobId}
        jobDetail=${jobDetail}
        onToggle=${function () { setJobsDockOpen(function (v) { return !v; }); }}
        onSelectJob=${selectJobInDock}
        onCancel=${cancelJob} />
    </div>`;
  }

  const root = document.getElementById("wb-root");
  if (root && window.ReactDOM) {
    ReactDOM.createRoot(root).render(e(App));
  }
})();
