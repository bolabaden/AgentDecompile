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
    ensureProgram: "/dashboard/api/workbench/ensure-program",
    workspace: "/dashboard/api/workbench/workspace",
    programs: "/dashboard/api/workbench/programs",
    matchStatus: "/dashboard/api/workbench/match-status",
    matchDecide: "/dashboard/api/workbench/match-decide",
    recoverStatus: "/dashboard/api/workbench/recover-status",
    corpusStatus: "/dashboard/api/workbench/corpus-status",
    ghidraDefaults: "/dashboard/api/workbench/ghidra-defaults",
    artifacts: "/dashboard/artifact",
    evidence: "/dashboard/evidence/database",
    context: "/dashboard/api/workbench/context",
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
    { id: "wb-graph", title: "Call trees", keys: ["graph", "call"] },
    { id: "wb-jobs", title: "Jobs", keys: ["job", "pulse"] },
    { id: "wb-atlas", title: "Atlas", keys: ["atlas", "map", "score", "prompt"] },
    { id: "wb-report", title: "Report", keys: ["report"] },
    { id: "wb-fnbrowse", title: "Functions", keys: ["function", "func", "addr", "browse", "page"] },
    { id: "wb-review", title: "Review", keys: ["review"] },
    { id: "wb-logical", title: "Logical identities", keys: ["logical", "identity", "sibling"] },
    { id: "wb-artifacts", title: "Artifacts", keys: ["artifact"] },
    { id: "wb-pipeline", title: "Pipeline", keys: ["pipeline", "steps"] },
    { id: "wb-match", title: "Match", keys: ["match", "cross"] },
    { id: "wb-recovery", title: "Recover", keys: ["recovery", "recover", "dump"] },
    { id: "wb-stabs", title: "STABS", keys: ["stabs", "donor"] },
    { id: "wb-knowledge", title: "Knowledge", keys: ["knowledge"] },
    { id: "wb-roundtrip", title: "Roundtrip", keys: ["roundtrip", "rebuild"] },
    { id: "wb-processes", title: "Process log", keys: ["process", "log"] },
    { id: "wb-mission", title: "Mission", keys: ["mission", "directive"] },
    { id: "wb-corpus", title: "Corpus table", keys: ["corpus"] },
    { id: "wb-tools", title: "Commands", keys: ["mcp", "cli", "tool", "command", "swagger"] }
  ];

  /* Analyze / Match / Recover are the methodology. Atlas, Pipeline, Corpus
     table and the rest stay in More — they are not a second row of chrome. */
  const EDITOR_PRIMARY = [
    { id: "decompile", title: "Listing" },
    { id: "wb-fnbrowse", title: "Functions" },
    { id: "graph", title: "Call trees" },
    { id: "wb-match", title: "Match" },
    { id: "wb-recovery", title: "Recover" }
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

  function humanError(raw) {
    const text = String(raw || "").trim();
    if (!text) return "";
    if (text.charAt(0) === "{") {
      try {
        const obj = JSON.parse(text);
        return String(obj.error || obj.message || text).slice(0, 280);
      } catch (_err) {
        return text.slice(0, 280);
      }
    }
    return text.slice(0, 280);
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
    if (kind === "packed-program") return "gzf";
    if (kind === "shared-fs") return "shared-fs";
    if (kind === "shared-project" || kind === "shared-http") return "ghidra-server";
    if (kind === "draft") return "draft";
    return "bin";
  }

  function styleKind(kind) {
    if (kind === "ghidra-project" || kind === "gpr") return "gpr";
    if (kind === "packed-program" || kind === "gzf") return "gzf";
    if (kind === "shared-fs") return "shared-fs";
    if (kind === "shared-project" || kind === "shared-http" || kind === "ghidra-server") return "ghidra-server";
    if (kind === "draft") return "draft";
    return "bin";
  }

  function kindTitle(kind) {
    if (kind === "ghidra-project" || kind === "gpr" || kind === "project-dir") return "Local Ghidra project";
    if (kind === "packed-program" || kind === "gzf") return "Packed Ghidra program";
    if (kind === "dir") return "Folder";
    if (kind === "shared-fs") return "On-disk Ghidra Server tree";
    if (kind === "shared-project" || kind === "shared-http" || kind === "ghidra-server") return "Ghidra Server";
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

  function wireStepActions(host) {
    if (!host || host.dataset.stepActionsWired) return;
    host.dataset.stepActionsWired = "1";
    host.addEventListener("click", function (ev) {
      const link = ev.target.closest("a.step-run[data-action-id]");
      if (!link || !host.contains(link)) return;
      ev.preventDefault();
      if (link.classList.contains("disabled") || link.getAttribute("aria-disabled") === "true") return;
      const actionId = link.getAttribute("data-action-id");
      if (!actionId) return;
      const params = {};
      const slug = link.getAttribute("data-action-slug");
      const program = link.getAttribute("data-action-program");
      const src = link.getAttribute("data-action-src");
      const dst = link.getAttribute("data-action-dst");
      if (slug) {
        params.slug = slug;
        params.id = slug;
      }
      if (program) params.program = program;
      if (src) params.src = src;
      if (dst) params.dst = dst;
      if (slug && !params.db) {
        const uiEnv = window.AgentDecompileUI;
        if (uiEnv && typeof uiEnv.getEnvDefaults === "function") {
          const env = uiEnv.getEnvDefaults();
          if (env && env.db) params.db = env.db;
        }
      }
      const ui = window.AgentDecompileUI;
      if (ui && typeof ui.runCatalogAction === "function") {
        ui.runCatalogAction(actionId, params);
        return;
      }
      if (window.AgentDecompileActions && window.AgentDecompileActions.openForm) {
        window.AgentDecompileActions.openForm(actionId);
      }
    });
  }

  function wireMatchDecide(host) {
    if (!host || host.dataset.matchDecideWired) return;
    host.dataset.matchDecideWired = "1";
    host.addEventListener("click", function (ev) {
      const link = ev.target.closest("a.wb-match-decide[data-match-id][data-decision]");
      if (!link || !host.contains(link)) return;
      ev.preventDefault();
      if (link.dataset.busy === "1") return;
      const matchId = link.getAttribute("data-match-id");
      const decision = link.getAttribute("data-decision");
      if (!matchId || !decision) return;
      link.dataset.busy = "1";
      fetch(API.matchDecide, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ match_id: Number(matchId), decision: decision })
      }).then(function (res) {
        return res.json().then(function (data) { return { ok: res.ok, data: data }; });
      }).then(function (payload) {
        link.dataset.busy = "0";
        const ui = window.AgentDecompileUI || {};
        if (payload.ok && payload.data && payload.data.ok) {
          const msg = (decision === "accept" ? "Accepted" : "Rejected")
            + " match #" + matchId + " → " + payload.data.status;
          if (typeof ui.showToast === "function") ui.showToast(msg, "info");
          reloadIslands();
          return;
        }
        const err = (payload.data && payload.data.error) || "Could not update match.";
        if (typeof ui.showToast === "function") ui.showToast(err, "error");
      }).catch(function (err) {
        link.dataset.busy = "0";
        const ui = window.AgentDecompileUI || {};
        if (typeof ui.showToast === "function") {
          ui.showToast(String(err.message || err), "error");
        }
      });
    });
  }

  function reviewPageMatchIds() {
    const host = document.querySelector("#wb-review .wb-legacy");
    if (!host) return [];
    const ids = [];
    const seen = {};
    host.querySelectorAll("table tbody tr").forEach(function (tr) {
      let id = 0;
      const span = tr.querySelector("td:first-child [data-match-id]");
      if (span) {
        id = Number(span.getAttribute("data-match-id"));
      } else {
        const link = tr.querySelector("a.wb-match-decide[data-match-id]");
        if (link) id = Number(link.getAttribute("data-match-id"));
      }
      if (id && !seen[id]) {
        seen[id] = 1;
        ids.push(id);
      }
    });
    return ids;
  }

  function batchReviewPage(decision) {
    const matchIds = reviewPageMatchIds();
    const ui = window.AgentDecompileUI || {};
    if (!matchIds.length) {
      if (typeof ui.showToast === "function") ui.showToast("No review rows on this page.", "error");
      return;
    }
    fetch(API.matchDecideBatch, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ match_ids: matchIds, decision: decision })
    }).then(function (res) {
      return res.json().then(function (data) { return { ok: res.ok, data: data }; });
    }).then(function (payload) {
      if (payload.ok && payload.data && payload.data.ok) {
        const d = payload.data;
        const verb = decision === "accept" ? "Accepted" : "Rejected";
        const msg = verb + " " + d.updated + " match" + (d.updated === 1 ? "" : "es")
          + (d.skipped ? " (" + d.skipped + " skipped)" : "");
        if (typeof ui.showToast === "function") ui.showToast(msg, "info");
        reloadIslands();
        return;
      }
      const err = (payload.data && payload.data.error) || "Could not update matches.";
      if (typeof ui.showToast === "function") ui.showToast(err, "error");
    }).catch(function (err) {
      if (typeof ui.showToast === "function") {
        ui.showToast(String(err.message || err), "error");
      }
    });
  }

  function TabRoster({ programs, imports, selectedSlug, selectedProgram, onPickProgram, onPickImport }) {
    const programList = programs || [];
    const importList = imports || [];
    if (!programList.length && !importList.length) {
      return html`<div className="wb-tab-roster wb-empty">Nothing in this tab yet. File → Open, then Add to project…</div>`;
    }
    return html`<div className="wb-tab-roster" id="wb-tab-roster">
      <p className="wb-hint">This list is the Ghidra project. Add and Remove change it.</p>
      ${!programList.length && importList.length ? html`<table className="wb-roster-table">
        <caption className="wb-kicker">Binaries</caption>
        <thead><tr><th>Name</th><th>Kind</th></tr></thead>
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
      </table>` : null}
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

  function CallGraphView({ graph, onPick }) {
    const data = graph || {};
    const center = data.center || null;
    const callers = data.callers || [];
    const callees = data.callees || [];
    const neighbors = data.neighbors || [];
    if (!center && !callers.length && !callees.length && !neighbors.length) {
      return html`<div id="wb-callgraph" className="wb-callgraph wb-callgraph-empty">
        <p>No graph yet. Pick a program.</p>
      </div>`;
    }
    function nodeBtn(node, extra) {
      if (!node) return null;
      return html`<button type="button" className=${"wb-cg-node " + (extra || "")}
        data-addr=${node.addr}
        title=${(node.kind || "") + " " + (node.addr || "")}
        onClick=${function () { if (onPick) onPick(node); }}>
        <code>${node.addr}</code>
        <span>${node.name}</span>
        ${node.kind ? html`<i>${node.kind}</i>` : null}
      </button>`;
    }
    return html`<div id="wb-callgraph" className="wb-callgraph">
      <div className="wb-cg-col wb-cg-callers">
        <h3>Callers ${callers.length ? "· " + callers.length : ""}</h3>
        ${callers.length ? callers.map(function (node) { return nodeBtn(node, "in"); })
          : html`<p class="wb-hint">No incoming refs at this entry.</p>`}
      </div>
      <div className="wb-cg-col wb-cg-center">
        <h3>This function</h3>
        ${nodeBtn(center, "on")}
      </div>
      <div className="wb-cg-col wb-cg-callees">
        <h3>Callees ${callees.length ? "· " + callees.length : ""}</h3>
        ${callees.length ? callees.map(function (node) { return nodeBtn(node, "out"); })
          : html`<p class="wb-hint">No outgoing refs at the entry.</p>`}
      </div>
      ${neighbors.length ? html`<div className="wb-cg-neighbors">
        <h3>Nearby</h3>
        ${neighbors.map(function (node) { return nodeBtn(node, "near"); })}
      </div>` : null}
    </div>`;
  }

  function fmtCount(n) {
    if (n == null || n === "") return "—";
    return String(n);
  }

  function fmtByteExact(n) {
    if (n == null || n === "" || n === "unmeasured") return "unmeasured";
    return String(n);
  }

  function stepStateClass(state) {
    const key = String(state || "unmeasured").replace(/\s+/g, "-");
    return "wb-step st-" + key;
  }

  function atlasHref(status) {
    const raw = status && status.atlas && status.atlas.decomp;
    if (raw) {
      try {
        const u = new URL(raw, window.location.href);
        u.hostname = window.location.hostname;
        return u.toString();
      } catch (_err) {
        return raw;
      }
    }
    return "http://" + window.location.hostname + ":5173/";
  }

  function CorpusHeadline({ headline, claim }) {
    const h = headline || {};
    return html`<section className="wb-corpus-hero" id="wb-corpus-hero">
      <p className="wb-kicker">Readable C and byte identity stay separate</p>
      <div className="wb-corpus-pair">
        <div>
          <p className="wb-hero-n">${fmtCount(h.real_c)} <span class="of">logical functions with real C</span></p>
          <p className="wb-hint">${fmtCount(h.placed_concrete)} concrete instances · ${fmtCount(h.unplaced_real_c)} without a logical id</p>
        </div>
        <div>
          <p className="wb-hero-n">${fmtByteExact(h.byte_exact)} <span class="of">byte-exact receipts</span></p>
          <p className="wb-hint">Not added to real C. A compile is not a match.</p>
        </div>
      </div>
      ${h.queued != null ? html`<p className="wb-hint">Queue still holds ${fmtCount(h.queued)} logical functions.</p>` : null}
      <p className="wb-claim">${claim || "This is a live view. It is not completion."}</p>
    </section>`;
  }

  function HealthStrip({ probes, atlasUrl }) {
    const list = probes || [];
    return html`<div className="wb-health" id="wb-health">
      ${list.map(function (p, i) {
        const text = (p && p.text) || "probe";
        const st = (p && p.state) || "unmeasured";
        const ok = st === "done" || st === "up";
        return html`<span key=${i} className=${"wb-health-chip" + (ok ? "" : " is-down")}>${text}</span>`;
      })}
      ${atlasUrl ? html`<a className="wb-health-chip" href=${atlasUrl} target="_blank" rel="noreferrer">Atlas :5173</a>` : null}
    </div>`;
  }

  function AtlasReact({ onToast }) {
    const [data, setData] = useState(null);
    const [err, setErr] = useState("");
    const [picked, setPicked] = useState(null);
    useEffect(function () {
      let gone = false;
      fetch("/atlas/api/loadProject", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })
        .then(function (res) { return res.json().then(function (body) { return { ok: res.ok, body: body }; }); })
        .then(function (pack) {
          if (gone) return;
          if (!pack.ok || pack.body.error) {
            setErr(pack.body.error || "Atlas project is not loaded.");
            setData(null);
            return;
          }
          setErr("");
          setData(pack.body);
        })
        .catch(function (e) { if (!gone) setErr(String(e && e.message || e)); });
      return function () { gone = true; };
    }, []);
    const fns = ((data && data.data && data.data.functions) || []).slice(0, 80);
    return html`<div className="wb-atlas-react">
      <p className="wb-hint">${data && data.platform ? ("Platform " + data.platform) : "In-tree Atlas API. Decomp Atlas on :5173 stays a separate app."}</p>
      ${err ? html`<p className="wb-hint">${err}</p>` : null}
      <table className="wb-fnb-table">
        <thead><tr><th>Function</th><th>C module</th><th>Calls</th></tr></thead>
        <tbody>
          ${fns.length ? fns.map(function (fn) {
            return html`<tr key=${fn.id || fn.name} className=${picked && picked.id === fn.id ? "on" : ""}
              onClick=${function () { setPicked(fn); if (onToast) onToast(fn.name || fn.id); }}>
              <td><code>${fn.name || fn.id}</code></td>
              <td>${fn.cModulePath || ""}</td>
              <td>${(fn.callsFunctions || []).length}</td>
            </tr>`;
          }) : html`<tr><td colspan="3">No Atlas index on this server yet.</td></tr>`}
        </tbody>
      </table>
      ${picked ? html`<pre className="wb-job-log">${(picked.cCode || picked.asmCode || "").slice(0, 4000)}</pre>` : null}
    </div>`;
  }

  function ReportReact({ report }) {
    const r = report || {};
    return html`<div className="wb-report-react">
      <div className="wb-corpus-pair">
        <p className="wb-hero-n">${fmtCount(r.logical)} <span class="of">logical recovered</span></p>
        <p className="wb-hero-n">${fmtCount(r.artifacts)} <span class="of">artifacts</span></p>
      </div>
      <p className="wb-hint">Unplaced ${fmtCount(r.unplaced)} · unbound ${fmtCount(r.unbound)}. Real C only.</p>
      <table className="wb-fnb-table">
        <thead><tr><th>Build</th><th>Artifacts</th><th>Logical</th><th>Concrete</th></tr></thead>
        <tbody>
          ${(r.by_build || []).map(function (b) {
            return html`<tr key=${b.slug}>
              <td><code>${b.slug}</code></td>
              <td>${fmtCount(b.artifacts)}</td>
              <td>${fmtCount(b.logical)}</td>
              <td>${fmtCount(b.concrete)}</td>
            </tr>`;
          })}
        </tbody>
      </table>
      <table className="wb-fnb-table">
        <thead><tr><th>Function</th><th>Build</th><th>Bytes</th><th>Convention</th><th>Logical</th></tr></thead>
        <tbody>
          ${(r.functions || []).map(function (fn, i) {
            return html`<tr key=${i}>
              <td><code>${fn.name || ""}</code></td>
              <td>${fn.slug || ""}</td>
              <td>${fmtCount(fn.size)}</td>
              <td>${fn.convention || ""}</td>
              <td>${fn.logical_id != null ? fn.logical_id : "—"}</td>
            </tr>`;
          })}
        </tbody>
      </table>
    </div>`;
  }

  function MissionReact({ mission }) {
    const m = mission || {};
    if (!m.ok) return html`<p className="wb-hint">${m.error || "No mission contract on disk."}</p>`;
    return html`<article className="wb-mission-react">
      <p className="wb-kicker">${m.id} · ${m.status}</p>
      <h3>${m.title || "Mission"}</h3>
      <p>${m.objective || ""}</p>
      <h4>Acceptance</h4>
      <ol>${(m.acceptance || []).map(function (item, i) { return html`<li key=${i}>${item}</li>`; })}</ol>
      <h4>Evidence paths</h4>
      <ul>${(m.evidence || []).map(function (item, i) { return html`<li key=${i}><code>${item}</code></li>`; })}</ul>
    </article>`;
  }

  function ReviewReact({ review, onDecide }) {
    const r = review || {};
    const statuses = r.by_status || {};
    return html`<div className="wb-review-react">
      <p className="wb-hint">${Object.keys(statuses).map(function (k) { return k + " " + statuses[k]; }).join(" · ") || "No match table."}</p>
      <table className="wb-fnb-table">
        <thead><tr><th>Score</th><th>Source</th><th>Dest</th><th></th></tr></thead>
        <tbody>
          ${(r.rows || []).length ? (r.rows || []).map(function (row, i) {
            return html`<tr key=${i}>
              <td>${fmtCount(row.score)}</td>
              <td><code>${row.src_name || row.src_addr}</code></td>
              <td><code>${row.dst_name || row.dst_addr}</code></td>
              <td>
                <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { if (onDecide) onDecide(row, "accept"); }}>Accept</button>
                <button type="button" className="wb-btn wb-btn-mini" onClick=${function () { if (onDecide) onDecide(row, "reject"); }}>Reject</button>
              </td>
            </tr>`;
          }) : html`<tr><td colspan="4">No review-tier matches queued.</td></tr>`}
        </tbody>
      </table>
    </div>`;
  }

  function StepLadder({ steps, title, onRun }) {
    const list = steps || [];
    if (!list.length) return html`<p className="wb-hint">No ladder facts yet.</p>`;
    return html`<section className="wb-ladder">
      ${title ? html`<h3 className="wb-ladder-title">${title}</h3>` : null}
      <ol className="wb-ladder-list">
        ${list.map(function (step) {
          const st = step.state || "unmeasured";
          const unattempted = (st === "not started" || st === "unmeasured") && !step.done;
          const count = unattempted
            ? "not attempted"
            : (fmtCount(step.done) + " / " + fmtCount(step.total) + (step.unit ? " " + step.unit : ""));
          return html`<li key=${step.key || step.title} className=${stepStateClass(st)}>
            <div className="wb-step-head">
              <span className="wb-step-no">${step.label || ""}</span>
              <span className="wb-step-name">${step.title || step.key}</span>
              <span className="wb-step-state">${st}</span>
              <span className="wb-step-count">${count}</span>
              ${step.action_id && onRun ? html`<button type="button" className="wb-btn wb-btn-mini"
                disabled=${!step.action_enabled}
                onClick=${function () { onRun(step); }}>Run</button>` : null}
            </div>
            <p className="wb-hint">${step.why || ""}</p>
            ${step.next ? html`<p className="wb-hint">Next: ${step.next}</p>` : null}
          </li>`;
        })}
      </ol>
    </section>`;
  }

  function BinaryCompareTable({ binaries, onOpen }) {
    const rows = binaries || [];
    if (!rows.length) return html`<p className="wb-hint">No non-DRM builds in the corpus snapshot.</p>`;
    return html`<table className="wb-fnb-table wb-compare-table">
      <thead><tr>
        <th>Build</th><th>Game</th><th>Functions</th><th>Bound</th><th>Real C</th><th>Named</th>
      </tr></thead>
      <tbody>
        ${rows.map(function (b) {
          return html`<tr key=${b.slug} onClick=${function () { if (onOpen) onOpen(b); }}>
            <td><code>${b.slug}</code></td>
            <td>${b.game || ""} ${b.platform || ""}</td>
            <td>${fmtCount(b.func_count)}</td>
            <td>${fmtCount(b.bound)}</td>
            <td>${fmtCount(b.real_c)}</td>
            <td>${fmtCount(b.named_count)}</td>
          </tr>`;
        })}
      </tbody>
    </table>`;
  }

  function ProgramHero({ overview }) {
    if (!overview) return null;
    const blocks = overview.memory || [];
    const named = Number(overview.namedCount || 0);
    const total = Number(overview.functionCount || 0);
    const pct = total ? Math.round((named / total) * 100) : 0;
    return html`<div id="wb-program-hero" className="wb-program-hero">
      <p className="wb-hero-n">${total || 0} <span class="of">functions</span>
        <span class="st">${named} named · ${pct}%</span></p>
      <p className="wb-hint">${overview.program || ""} ${overview.path || ""} · ${overview.language || ""} · base ${overview.imageBase || ""}</p>
      ${total ? html`<div className="wb-bar" aria-hidden="true"><i style=${{ width: pct + "%" }}></i></div>` : null}
      ${blocks.length ? html`<ul className="wb-mem">
        ${blocks.map(function (block) {
          return html`<li key=${block.name + block.start}><code>${block.start}</code> ${block.name} · ${block.length}</li>`;
        })}
      </ul>` : null}
    </div>`;
  }

  const BSIM_HONEST = {
    missing_datadir: "No BSim datadir on disk.",
    not_a_datadir: "The BSim path is not a directory.",
    no_postgres: "Datadir has no PostgreSQL cluster.",
    no_bsim_database: "Datadir has no BSim database.",
    empty_database: "BSim database exists but holds 0 executables.",
    populated: "BSim holds executables.",
    database_unreachable: "BSim did not answer."
  };

  function repoForSlug(slugName, binaries) {
    const row = (binaries || []).find(function (item) { return item.slug === slugName; });
    return (row && row.repo) || "";
  }

  function workDirPath(workDir) {
    return String(workDir || "").replace(/\/$/, "");
  }

  function hasCorpusContext(ctx) {
    return Boolean((ctx && ctx.slug) || (ctx && ctx.program));
  }

  function matchPairParams(ctx, binaries, siblings) {
    const srcSlug = (ctx && ctx.slug) || "";
    const src = repoForSlug(srcSlug, binaries) || (ctx && ctx.repo) || (ctx && ctx.program) || "";
    let dst = "";
    if (siblings && siblings.length) {
      for (let i = 0; i < siblings.length; i += 1) {
        const sib = siblings[i];
        if (!sib || !sib.slug || sib.slug === srcSlug) continue;
        const hit = repoForSlug(sib.slug, binaries);
        if (hit) {
          dst = hit;
          break;
        }
      }
    }
    if (!dst && ctx && ctx.tabRows && ctx.tabRows.length) {
      const donor = ctx.tabRows.find(function (row) { return row.role === "donor"; });
      const other = ctx.tabRows.find(function (row) {
        return row.slug && row.slug !== srcSlug;
      });
      if (donor && donor.slug && donor.slug !== srcSlug) {
        dst = repoForSlug(donor.slug, binaries) || donor.repo || "";
      } else if (other) {
        dst = repoForSlug(other.slug, binaries) || other.repo || "";
      }
    }
    if (!dst && binaries.length > 1 && srcSlug) {
      const other = binaries.find(function (row) { return row.slug && row.slug !== srcSlug; });
      if (other) dst = other.repo || "";
    }
    return { src: src, dst: dst, ok: Boolean(src && dst) };
  }

  function identityActionParams(actionId, ctx, binaries, siblings) {
    const work = workDirPath(ctx && ctx.work_dir);
    const slugName = (ctx && ctx.slug) || "";
    const programName = (ctx && ctx.program) || (ctx && ctx.repo) || slugName || "";
    const base = { program: programName, slug: slugName };
    if (actionId === "corpus.match-pair") {
      return Object.assign(base, matchPairParams(ctx, binaries, siblings));
    }
    if (actionId === "corpus.apply-stabs") {
      const out = Object.assign({}, base);
      if (work && slugName) out.manifest = work + "/extract/stabs/" + slugName + ".manifest.jsonl";
      const row = (binaries || []).find(function (item) { return item.slug === slugName; });
      if (row && row.id) out["binary-id"] = row.id;
      return out;
    }
    if (actionId === "corpus.logical-build") return base;
    if (actionId === "corpus.merge-parts") {
      const out = Object.assign({}, base);
      if (work) out["parts-dir"] = work + "/parts";
      return out;
    }
    if (actionId === "corpus.propagate-corpus" || actionId === "corpus.propagate-source") return base;
    return base;
  }

  function catalogParamsFor(actionId, overrides) {
    const extra = overrides || {};
    const ui = window.AgentDecompileUI || {};
    const ctx = typeof ui.getToolContext === "function" ? ui.getToolContext() : {};
    const env = typeof ui.getEnvDefaults === "function" ? ui.getEnvDefaults() : {};
    const binaries = typeof ui.getBinaries === "function" ? ui.getBinaries() : [];
    const siblings = typeof ui.getSiblings === "function" ? ui.getSiblings() : [];
    const slug = extra.slug || extra.id || ctx.slug || "";
    const mergedCtx = Object.assign({}, ctx, {
      slug: slug || ctx.slug || "",
      program: extra.program || ctx.program || "",
      db: ctx.db || env.db || "",
      work_dir: ctx.work_dir || env.work_dir || "",
      kb: ctx.kb || env.kb || ""
    });
    const base = identityActionParams(actionId, mergedCtx, binaries, siblings);
    const out = Object.assign({}, base, extra);
    if (slug && !out.db && (mergedCtx.db || env.db)) out.db = mergedCtx.db || env.db;
    if (slug && !out.slug) out.slug = slug;
    if (slug && !out.id) out.id = slug;
    return out;
  }

  function MatchWorkbench({
    program, selected, detail, bsim,
    onRefresh, onRunMatch, onRunMatchFunction,
    onApplyStabs, onLogicalBuild, onMergeParts, onPropagate,
    onRunCrossPlace, onExtractStabs, onPickSibling,
    canMatchPair, canMatchFunction, canIdentity
  }) {
    const state = (bsim && bsim.state) || "";
    const siblings = (detail && detail.siblings) || [];
    let line = BSIM_HONEST[state] || (bsim && bsim.summary) || "Checking BSim…";
    if (state === "populated") {
      line = "BSim holds " + ((bsim && bsim.executables) || 0) + " executables.";
    }
    return html`<div className="wb-re-pane" id="wb-match-pane">
      <p className="wb-hint">${program ? ("Program " + program) : "Pick a program in Explorer."}
        ${selected ? (" · " + ((selected.name || selected.addr) + " " + (selected.addr || ""))) : ""}</p>
      <div id="wb-match-bsim" className=${"wb-bsim-state st-" + (state || "unknown")}>
        <strong>BSim</strong>
        <p>${line}</p>
        ${bsim && bsim.datadir ? html`<p className="wb-hint"><code>${bsim.datadir}</code></p>` : null}
      </div>
      <div className="wb-fn-tools" role="toolbar" aria-label="Match">
        <button type="button" id="wb-match-run" className="wb-btn wb-btn-primary"
          disabled=${canMatchPair === false}
          onClick=${onRunMatch}>Run match</button>
        <button type="button" id="wb-match-fn" className="wb-btn"
          disabled=${canMatchFunction === false}
          onClick=${onRunMatchFunction}>Match function</button>
        <button type="button" id="wb-match-apply-stabs" className="wb-btn wb-btn-mini"
          disabled=${canIdentity === false}
          onClick=${onApplyStabs}>Apply STABS</button>
        <button type="button" id="wb-match-logical-build" className="wb-btn wb-btn-mini"
          disabled=${canIdentity === false}
          onClick=${onLogicalBuild}>Logical build</button>
        <button type="button" id="wb-match-merge-parts" className="wb-btn wb-btn-mini"
          disabled=${canIdentity === false}
          onClick=${onMergeParts}>Merge parts</button>
        <button type="button" id="wb-match-propagate" className="wb-btn wb-btn-mini"
          disabled=${canIdentity === false}
          onClick=${onPropagate}>Propagate</button>
        <button type="button" id="wb-match-cross" className="wb-btn"
          onClick=${onRunCrossPlace}>Run cross-place</button>
        <button type="button" className="wb-btn" onClick=${onRefresh}>Refresh</button>
      </div>
      <section className="wb-stabs-detail">
        <h3>STABS</h3>
        <p className="wb-hint">Donor symbols for this program, if a STABS file exists.</p>
        <button type="button" id="wb-match-stabs" className="wb-btn wb-btn-mini" onClick=${onExtractStabs}>Extract STABS</button>
      </section>
      ${siblings.length ? html`<section>
        <h3>Siblings</h3>
        <ul className="wb-siblings">
          ${siblings.map(function (sib) {
            return html`<li key=${(sib.slug || "") + (sib.addr || "")}>
              <button type="button" className="wb-text-action"
                onClick=${function () { if (onPickSibling) onPickSibling(sib); }}>${sib.slug || sib.program || ""} ${sib.addr || ""} ${sib.name || ""}</button>
            </li>`;
          })}
        </ul>
      </section>` : html`<p className="wb-hint">No sibling matches for this function yet.</p>`}
    </div>`;
  }

  function RepoStatus({ dossier, user }) {
    if (!dossier || !dossier.ok) {
      return html`<p id="wb-repo-status" className="wb-repo-row wb-repo-empty">No active project</p>`;
    }
    const kind = dossier.kind || "";
    if (kind === "shared-project") {
      const host = dossier.host || "";
      const port = Number(dossier.port || 0);
      const portBit = (port && port !== 13100) ? (":" + port) : "";
      const repo = dossier.repository || "";
      const who = dossier.user || user || "";
      return html`<p id="wb-repo-status" className=${"wb-repo-row" + (dossier.reachable ? " on" : " off")}>
        <span>Project Repository: ${repo || "—"}</span>
        <span>${dossier.reachable
          ? ("Reachable at " + host + portBit)
          : ("Disconnected from " + (host || "Ghidra Server"))}</span>
        ${who ? html`<span>User ${who}</span>` : null}
        ${dossier.mirror_available ? html`<span>Local copy bound for listing</span>` : null}
      </p>`;
    }
    if (kind === "shared-fs") {
      return html`<p id="wb-repo-status" className="wb-repo-row">On-disk Ghidra Server tree. No live RMI session.</p>`;
    }
    if (kind === "packed-program") {
      return html`<p id="wb-repo-status" className="wb-repo-row">Packed Ghidra program ${dossier.slug || ""}</p>`;
    }
    if (kind === "ghidra-project") {
      return html`<p id="wb-repo-status" className="wb-repo-row">Local project ${dossier.slug || ""}</p>`;
    }
    return html`<p id="wb-repo-status" className="wb-repo-row">${kindTitle(kind)}</p>`;
  }

  function ArtifactsReact({ path, onOpen }) {
    const [data, setData] = useState(null);
    const [note, setNote] = useState("");
    useEffect(function () {
      const url = API.artifacts + (path ? "?p=" + encodeURIComponent(path) : "");
      fetch(url, { cache: "no-store" }).then(function (res) { return res.json(); }).then(function (body) {
        setData(body);
        setNote("");
      }).catch(function (err) {
        setNote(String(err && err.message || err));
      });
    }, [path]);
    if (note) return html`<p className="wb-dialog-error">${note}</p>`;
    if (!data) return html`<p className="wb-hint">Reading artifacts…</p>`;
    if (!data.ok) return html`<p className="wb-hint">${data.error || "No artifacts."}</p>`;
    if (data.kind === "dir") {
      return html`<div className="wb-artifacts">
        <p className="wb-hint"><code>${data.path || "."}</code></p>
        ${data.parent != null && data.parent !== "" ? html`<button type="button" className="wb-text-action"
          onClick=${function () { if (onOpen) onOpen(data.parent); }}>Up</button>` : null}
        <ul className="wb-artifact-list">
          ${(data.entries || []).map(function (entry) {
            return html`<li key=${entry.path}>
              <button type="button" className="wb-text-action"
                onClick=${function () { if (onOpen) onOpen(entry.path); }}>
                ${entry.name}${entry.dir ? "/" : ""}
              </button>
              ${entry.size != null ? html`<span className="wb-hint">${formatBytes(entry.size)}</span>` : null}
            </li>`;
          })}
        </ul>
      </div>`;
    }
    return html`<div className="wb-artifacts">
      ${data.parent != null ? html`<button type="button" className="wb-text-action"
        onClick=${function () { if (onOpen) onOpen(data.parent); }}>Up</button>` : null}
      <p className="wb-hint"><code>${data.path || ""}</code></p>
      ${data.binary
        ? html`<p className="wb-hint">Binary file. Not shown as text.</p>`
        : html`<pre className="wb-preview">${data.text || ""}</pre>`}
    </div>`;
  }

  function EvidenceReact() {
    const [data, setData] = useState(null);
    useEffect(function () {
      fetch(API.evidence, { cache: "no-store" }).then(function (res) { return res.json(); }).then(setData)
        .catch(function () { setData({ ok: false, error: "Could not read database evidence." }); });
    }, []);
    if (!data) return html`<p className="wb-hint">Reading the corpus database…</p>`;
    if (!data.ok) return html`<p className="wb-hint">${data.error || "Database evidence is unset."}</p>`;
    return html`<div className="wb-evidence">
      <p className="wb-hint"><code>${data.path || ""}</code> ${data.size_mb != null ? data.size_mb + " MB" : ""}</p>
      <table className="wb-fnb-table">
        <thead><tr><th>Name</th><th>Type</th></tr></thead>
        <tbody>
          ${(data.objects || []).map(function (row) {
            return html`<tr key=${row.type + row.name}><td><code>${row.name}</code></td><td>${row.type}</td></tr>`;
          })}
        </tbody>
      </table>
    </div>`;
  }

  function RecoverWorkbench({ program, selected, recover, recoveredRoot, onRefresh, onDump, onOneShot, onExportC, onDecompile, onGhidraBulk, onCrossPlace, onIngest }) {
    const state = (recover && recover.state) || "";
    const files = (recover && recover.files) || [];
    const summary = (recover && recover.summary)
      || (recoveredRoot ? "A recovered source directory is set." : "No recovered source yet.");
    return html`<div className="wb-re-pane" id="wb-recover-pane">
      <p className="wb-hint">${program ? ("Program " + program) : "Pick a program in Explorer."}
        ${selected ? (" · " + (selected.name || selected.addr)) : ""}</p>
      <div id="wb-recover-status" className=${"wb-bsim-state st-" + (state || "none")}>
        <strong>Source</strong>
        <p>${summary}</p>
        ${recover && recover.path ? html`<p className="wb-hint"><code>${recover.path}</code></p>` : null}
      </div>
      <div className="wb-fn-tools" role="toolbar" aria-label="Recover">
        <button type="button" id="wb-recover-run" className="wb-btn wb-btn-primary"
          onClick=${onGhidraBulk}>Ghidra bulk</button>
        <button type="button" className="wb-btn" onClick=${onCrossPlace}>Cross-place</button>
        <button type="button" id="wb-recover-export" className="wb-btn"
          onClick=${onExportC}>Export C</button>
        <button type="button" className="wb-btn" onClick=${onIngest}>Ingest recovered</button>
        <button type="button" className="wb-btn" onClick=${onDecompile}>Decompile function</button>
        <button type="button" className="wb-btn" onClick=${onRefresh}>Refresh</button>
      </div>
      ${((recover && recover.leftoverCount) || 0) > 0 ? html`<div className="wb-fn-tools" role="toolbar" aria-label="Leftover">
        <button type="button" className="wb-btn" onClick=${onDump}>Dump leftover</button>
        <button type="button" className="wb-btn" onClick=${onOneShot}>One-shot leftover</button>
      </div>` : html`<p className="wb-hint">Leftover dump stays off until a leftover set exists.</p>`}
      ${files.length ? html`<ul className="wb-recover-files">
        ${files.map(function (name) {
          return html`<li key=${name}><code>${name}</code></li>`;
        })}
      </ul>` : html`<p className="wb-hint">Run Ghidra bulk to write compiling C.</p>`}
    </div>`;
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
                + " is not on this process. Open the full HTTP app, or stay on Overview.</p>";
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
          wireStepActions(ref.current);
          wireMatchDecide(ref.current);
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
    return html`<div ref=${ref} className=${className || "wb-island"}><p className="wb-hint">Loading panel…</p></div>`;
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
    { id: "decompile", label: "Listing" },
    { id: "graph", label: "Call trees" }
  ];

  const QUICK_ACTION_SETS = {
    home: [
      { id: "corpus.ghidra-bulk", label: "Ghidra bulk", mutating: true },
      { id: "corpus.cross-place", label: "Cross-place" },
      { id: "mcp.status", label: "Status" },
      { id: "mcp.list-functions", label: "List functions" }
    ],
    atlas: [
      { id: "corpus.genproject", label: "Genproject" },
      { id: "mcp.decompile-function", label: "Decompile", needsFunction: true },
      { id: "mcp.get-function", label: "Get function", needsFunction: true }
    ],
    functions: [
      { id: "mcp.list-functions", label: "List functions" },
      { id: "mcp.search-symbols", label: "Search symbols" },
      { id: "corpus.logical-build", label: "Logical build", needsProject: true }
    ],
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
      { id: "corpus.run", label: "Run pipeline", danger: true },
      { id: "corpus.extract-stabs", label: "1 Extract", needsProject: true },
      { id: "corpus.match-pair", label: "2 Match", needsProject: true, mutating: true },
      { id: "corpus.calibrate-global", label: "3 Calibrate global", mutating: true },
      { id: "corpus.workspace", label: "4 Link floor", mutating: true },
      { id: "corpus.ghidra-bulk", label: "5 Ghidra bulk", mutating: true },
      { id: "corpus.cross-place", label: "6 Cross-place" },
      { id: "corpus.genproject", label: "7 Leftover" },
      { id: "corpus.objdiff-check", label: "8 Objdiff audit", mutating: true }
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
    "wb-jobs", "wb-stabs", "wb-knowledge",
    "wb-roundtrip", "wb-processes", "wb-mission", "wb-corpus", "wb-review",
    "wb-logical", "wb-artifacts", "wb-evidence", "wb-tools"
  ]);


  const CORPUS_NAV = [
    { id: "wb-overview", title: "Overview", more: true },
    { id: "wb-atlas", title: "Atlas", more: true },
    { id: "wb-report", title: "Report", more: true },
    { id: "wb-pipeline", title: "Pipeline", more: true },
    { id: "wb-stabs", title: "STABS", more: true },
    { id: "wb-knowledge", title: "Knowledge", more: true },
    { id: "wb-logical", title: "Logical identities", more: true },
    { id: "wb-artifacts", title: "Artifacts", more: true },
    { id: "wb-evidence", title: "Database", more: true },
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
    if (id === "match" || id === "cross-match" || id === "crossmatch") return "wb-match";
    if (id === "recover" || id === "recovery") return "wb-recovery";
    if (id === "artifact" || id === "artifacts") return "wb-artifacts";
    if (id === "evidence" || id === "wb-evidence") return "wb-evidence";
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
    const aliases = {
      decompile: "wb-inspect",
      inspect: "wb-inspect",
      graph: "wb-graph"
    };
    const node = document.getElementById(aliases[surfaceId] || surfaceId);
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

  function actionTitle(id, catalog) {
    const key = String(id || "");
    if (!key) return "";
    const known = {
      "corpus.add-binary": "Opened project",
      "corpus.remove-binary": "Removed program",
      "corpus.edit-binary": "Edited program",
      "corpus.extract-stabs": "Extract STABS",
      "corpus.bsim-ingest": "BSim ingest",
      "corpus.bsim-report": "BSim report",
      "corpus.cross-place": "Cross-place",
      "corpus.match-pair": "Match pair",
      "corpus.apply-stabs": "Apply STABS",
      "corpus.logical-build": "Logical build",
      "corpus.merge-parts": "Merge parts",
      "corpus.propagate-source": "Propagate source",
      "corpus.export-c": "Export C",
      "mcp.analyze-program": "Analyze program",
      "mcp.match-function": "Match function",
      "mcp.decompile-function": "Decompile",
      "reconstruct.one-shot": "Dump source"
    };
    if (known[key]) return known[key];
    const act = (catalog || []).find(function (item) { return item.id === key; });
    if (act && act.title) return act.title;
    return key.split(".").pop().replace(/-/g, " ");
  }

  function formatJobSummary(data, catalog) {
    if (!data) return "";
    if (data.job) {
      const job = data.job;
      const title = actionTitle(job.actionId, catalog);
      return "Job " + job.id + " — " + (job.status || "started")
        + (title ? " (" + title + ")" : "");
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
    { id: "file.checkin", title: "Check in to Ghidra server", group: "File" },
    { id: "file.open-program", title: "Open selected program in Ghidra", group: "File" },
    { id: "file.add-binaries", title: "Add to project…", accel: "mod+I", group: "File" },
    { id: "file.remove-binary", title: "Remove from project", accel: "Del", group: "File" },
    { id: "file.reload", title: "Reload from disk", accel: "alt+R", group: "File" },
    { id: "file.close-tab", title: "Close Tab", accel: "alt+W", group: "File" },
    { id: "edit.rename-tab", title: "Rename Tab", accel: "F2", group: "Edit" },
    { id: "view.palette", title: "Command palette", accel: "mod+K", group: "View" },
    { id: "view.explorer", title: "Explorer", accel: "mod+shift+E", group: "View" },
    { id: "view.listing", title: "Listing", accel: "alt+1", group: "View" },
    { id: "view.browse", title: "Functions", accel: "alt+F", group: "View" },
    { id: "view.graph", title: "Call trees", accel: "alt+2", group: "View" },
    { id: "view.artifacts", title: "Artifacts", group: "View" },
    { id: "view.evidence", title: "Database evidence", group: "View" },
    { id: "view.logical", title: "Logical identities", accel: "alt+L", group: "View" },
    { id: "view.overview", title: "Overview", accel: "alt+3", group: "View" },
    { id: "view.atlas", title: "Atlas", accel: "alt+4", group: "View" },
    { id: "view.cross-match", title: "Match", accel: "alt+5", group: "View" },
    { id: "view.inspect", title: "Inspector", accel: "alt+6", group: "View" },
    { id: "view.tools", title: "Commands", accel: "alt+7", group: "View" },
    { id: "view.jobs", title: "Jobs", accel: "alt+J", group: "View" },
    { id: "view.pipeline", title: "Pipeline", group: "View" },
    { id: "view.report", title: "Report", group: "View" },
    { id: "view.recovery", title: "Recover", group: "View" },
    { id: "view.stabs", title: "STABS", group: "View" },
    { id: "view.knowledge", title: "Knowledge", group: "View" },
    { id: "view.review", title: "Review", group: "View" },
    { id: "view.corpus", title: "Corpus table", group: "View" },
    { id: "view.density-compact", title: "Use compact layout", group: "View" },
    { id: "view.density-comfortable", title: "Use roomy layout", group: "View" },
    { id: "view.jobs-rail", title: "Dock jobs on the side", group: "View" },
    { id: "view.jobs-bottom", title: "Dock jobs at the bottom", group: "View" },
    { id: "analyze.program", title: "Analyze program", accel: "mod+shift+A", group: "Analyze" },
    { id: "analyze.bsim-ingest", title: "Ingest repository into BSim", accel: "mod+shift+B", group: "Analyze" },
    { id: "analyze.bsim-report", title: "Report BSim database", group: "Analyze" },
    { id: "analyze.bsim-create", title: "Create BSim database", group: "Analyze" },
    { id: "run.cross-place", title: "Run Cross-place", accel: "mod+shift+X", group: "Run" },
    { id: "run.last", title: "Run last action", accel: "Enter", group: "Run" },
    { id: "help.access", title: "Shortcuts and menus…", accel: "shift+?", group: "Help" },
    { id: "help.overview", title: "Overview", group: "Help" }
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

  function SplitHandle({ axis, label, onDrag }) {
    return html`<div className=${"wb-split wb-split-" + axis} role="separator"
      aria-orientation=${axis === "x" ? "vertical" : "horizontal"}
      aria-label=${label}
      onMouseDown=${onDrag}></div>`;
  }

  function beginResize(ev, startPx, setter, key, axis, min, max, invert) {
    ev.preventDefault();
    const origin = axis === "x" ? ev.clientX : ev.clientY;
    document.body.classList.add(axis === "x" ? "wb-resizing-x" : "wb-resizing-y");
    function move(e) {
      const delta = (axis === "x" ? e.clientX : e.clientY) - origin;
      const next = Math.round(Math.min(max, Math.max(min, startPx + (invert ? -delta : delta))));
      setter(next);
      writeUiPref(key, String(next));
    }
    function up() {
      document.removeEventListener("mousemove", move);
      document.removeEventListener("mouseup", up);
      document.body.classList.remove("wb-resizing-x", "wb-resizing-y");
    }
    document.addEventListener("mousemove", move);
    document.addEventListener("mouseup", up);
  }

  function LogDock({
    entries, tab, onTab, open, onToggle, selectedId, onSelect,
    jobs, selectedJobId, jobDetail, onSelectJob, onCancel, actions, height, onResize
  }) {
    const list = jobs || [];
    const running = list.filter(function (job) { return job.status === "running" || job.status === "queued"; });
    const detail = jobDetail || null;
    const logText = detail && detail.log ? String(detail.log).slice(-12000) : "";
    const rows = (entries || []).slice().reverse();
    return html`<aside id="wb-log-dock" className=${"wb-log-dock" + (open ? " open" : "")}
      style=${open ? { height: height + "px" } : undefined}>
      <${SplitHandle} axis="y" label="Resize log"
        onDrag=${onResize} />
      <header className="wb-log-dock-head">
        <button type="button" className=${"wb-log-tab" + (tab === "log" ? " on" : "")}
          onClick=${function () { onTab("log"); if (!open) onToggle(true); }}>Log</button>
        <button type="button" className=${"wb-log-tab" + (tab === "jobs" ? " on" : "")}
          onClick=${function () { onTab("jobs"); if (!open) onToggle(true); }}>
          Jobs${running.length ? " · " + running.length + " running" : ""}
        </button>
        <span className="wb-hint">A finished job is not a match.</span>
        <button type="button" className="wb-log-toggle" onClick=${function () { onToggle(!open); }}>
          ${open ? "Hide" : "Show"}
        </button>
      </header>
      ${open ? html`<div className="wb-log-body">
        ${tab === "log" ? html`<ul className="wb-log-list" id="wb-log-list">
          ${rows.length ? rows.map(function (item) {
            const on = item.id === selectedId;
            const preview = item.text.length > 140 && !on ? item.text.slice(0, 137) + "…" : item.text;
            return html`<li key=${item.id} className=${"wb-log-item kind-" + (item.kind || "info") + (on ? " on" : "")}>
              <button type="button" className="wb-log-row" onClick=${function () { onSelect(on ? "" : item.id); }}>
                <span className="wb-log-kind">${item.kind || "note"}</span>
                <span className="wb-log-text">${preview}</span>
              </button>
            </li>`;
          }) : html`<li className="wb-hint">No log lines yet.</li>`}
        </ul>` : html`<div className="wb-jobs-dock-body">
          <ul className="wb-job-list">
            ${list.length ? list.map(function (job) {
              const on = job.id === selectedJobId;
              const live = job.status === "running" || job.status === "queued";
              return html`<li key=${job.id} className=${on ? "on" : ""}>
                <button type="button" className="wb-job-row" onClick=${function () { onSelectJob(job.id); }}>
                  <code>${job.id}</code>
                  <span>${actionTitle(job.actionId, actions)}</span>
                  <span className=${"st-" + (job.status || "unknown")}>${job.status}</span>
                </button>
                ${live ? html`<button type="button" className="wb-btn danger wb-job-cancel"
                  onClick=${function (ev) { ev.stopPropagation(); onCancel(job.id); }}>Cancel</button>` : null}
              </li>`;
            }) : html`<li className="wb-hint">No jobs yet.</li>`}
          </ul>
          ${selectedJobId && logText ? html`<pre className="wb-job-log">${logText}</pre>`
            : selectedJobId ? html`<p className="wb-hint">Loading log…</p>` : null}
        </div>`}
      </div>` : null}
    </aside>`;
  }

  const LIST_LIMITS = ["all", 10, 20, 50, 100, 200];

  function FuncPager({ limit, shown, total, onLimit, compact }) {
    const clipped = limit !== "all" && shown && total && shown < total;
    return html`<div className=${"wb-pager" + (compact ? " wb-pager-compact" : "")}>
      <span className="wb-pager-count">${clipped ? shown + " of " + total : (total || shown || 0) + " functions"}</span>
      <label className="wb-pager-size">
        <span className="sr-only">How many functions to show</span>
        <select value=${String(limit)} onChange=${function (ev) { onLimit(ev.target.value); }}>
          ${LIST_LIMITS.map(function (size) {
            return html`<option key=${String(size)} value=${String(size)}>${size === "all" ? "All" : size}</option>`;
          })}
        </select>
      </label>
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
    const [overview, setOverview] = useState(null);
    const [corpusStatus, setCorpusStatus] = useState(null);
    const [graph, setGraph] = useState(null);
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
    const [sharedUser, setSharedUser] = useState("");
    const [artifactPath, setArtifactPath] = useState(start.get("p") || "");
    const [ingestNote, setIngestNote] = useState("");
    const [logEntries, setLogEntries] = useState([]);
    const [openLogId, setOpenLogId] = useState("");
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
    const [addPath, setAddPath] = useState("");
    const [editRole, setEditRole] = useState("member");
    const [editLabel, setEditLabel] = useState("");
    const [probes, setProbes] = useState([]);
    const [centerTab, setCenterTab] = useState(function () { return bootWindow(); });
    const [bottomTab, setBottomTab] = useState("pipeline");
    const [dropCandidates, setDropCandidates] = useState([]);
    const [treeExpanded, setTreeExpanded] = useState(true);
    const [envDefaults, setEnvDefaults] = useState({ db: "", work_dir: "", kb: "", mcp_url: "" });
    const [recoveredRoot, setRecoveredRoot] = useState("");
    const [bsimStatus, setBsimStatus] = useState(null);
    const [recoverInfo, setRecoverInfo] = useState(null);
    const [paletteOpen, setPaletteOpen] = useState(false);
    const [paletteQuery, setPaletteQuery] = useState("");
    const [commandFilter, setCommandFilter] = useState("");
    const [funcOffset, setFuncOffset] = useState(0);
    const [funcLimit, setFuncLimit] = useState("all");
    const DEFAULT_FUNCTION_ACTION = "mcp.decompile-function";
    const [pendingActionId, setPendingActionId] = useState("");
    const [lastActionId, setLastActionId] = useState(DEFAULT_FUNCTION_ACTION);
    const [actionExpanded, setActionExpanded] = useState(false);
    const [confirmDialog, setConfirmDialog] = useState(null);
    const [logOpen, setLogOpen] = useState(true);
    const [logTab, setLogTab] = useState("log");
    const [selectedJobId, setSelectedJobId] = useState("");
    const [jobDetail, setJobDetail] = useState(null);
    const [sideW, setSideW] = useState(function () { return Number(readUiPref("wb-side-w", "360")) || 360; });
    const [explorerH, setExplorerH] = useState(function () { return Number(readUiPref("wb-explorer-h", "240")) || 240; });
    const [logH, setLogH] = useState(function () { return Number(readUiPref("wb-log-h", "180")) || 180; });
    const [moreOpen, setMoreOpen] = useState(false);
    const [density, setDensity] = useState(function () { return readUiPref("wb-density", "compact"); });
    const [jobsRail, setJobsRail] = useState(function () { return readUiPref("wb-jobs-rail", "0") === "1"; });
    const [recentActionIds, setRecentActionIds] = useState(readRecentActionIds);
    const [checkedAddrs, setCheckedAddrs] = useState([]);
    const [checkAnchor, setCheckAnchor] = useState("");
    const [jobLiveText, setJobLiveText] = useState("");
    const jobsSnapshotRef = useRef([]);
    const pipelineChainedRef = useRef({});
    const ensureSeqRef = useRef(0);
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

    const loadCorpusStatus = useCallback(async function () {
      try {
        const res = await fetch(API.corpusStatus, { cache: "no-store" });
        const data = await res.json();
        setCorpusStatus(data);
      } catch (err) {
        setCorpusStatus({ ok: false, error: String(err && err.message || err) });
      }
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
      const loc = (typeof currentLocator === "function" ? currentLocator() : "") || "";
      const url = API.functions + "?slug=" + encodeURIComponent(useSlug)
        + "&q=" + encodeURIComponent(nextQuery !== undefined ? nextQuery : query)
        + "&offset=" + Math.max(0, funcOffset) + "&limit=" + funcLimit
        + (program ? "&program=" + encodeURIComponent(program) : "")
        + (loc ? "&locator=" + encodeURIComponent(loc) : "");
      const res = await fetch(url, { cache: "no-store" });
      const data = await res.json();
      if (seq !== funcSeqRef.current) return;
      setRows(data.results || []);
      setTotal(data.total || 0);
      if (!data.ok && data.error) setFuncNote(humanError(data.error));
      else if (!(data.results || []).length) {
        setFuncNote(humanError(data.error) || (program
          ? (program + " has no functions yet. Analyze → Analyze program.")
          : (funcOffset ? "Past the end of this build. Go back a page." : "Pick a program in Explorer.")));
      } else setFuncNote("");
    }, [slug, query, program, funcOffset, funcLimit]);

    const applyWorkspace = useCallback(function (data, row) {
      if (!data || !data.ok) {
        if (data && data.error) {
          setDetail(function (prev) {
            return {
              name: (row && row.name) || (prev && prev.name) || "",
              addr: (row && row.addr) || (prev && prev.addr) || "",
              preview: "// Could not open listing\n// " + humanError(data.error)
            };
          });
        }
        return data;
      }
      if (data.overview) setOverview(data.overview);
      if (data.graph) setGraph(data.graph);
      const listing = data.listing || data;
      if (listing && (listing.preview || listing.name || listing.addr || data.decompile || listing.decompile)) {
        setDetail(Object.assign({}, listing, data.decompile ? { decompile: data.decompile } : {}));
      }
      const pick = data.selected || row;
      if (pick && pick.addr) {
        setSelected(pick);
        setContext(pick);
      }
      return data;
    }, [setContext]);

    const loadWorkspace = useCallback(async function (name, row, locatorHint) {
      const loc = locatorHint || (typeof currentLocator === "function" ? currentLocator() : "") || "";
      const prog = name || program || "";
      if (!loc || !prog) return null;
      const sameProgram = !program || !name || program === name;
      const addr = (row && row.addr) || (sameProgram && selected && selected.addr) || "";
      const url = API.workspace
        + "?locator=" + encodeURIComponent(loc)
        + "&program=" + encodeURIComponent(prog)
        + "&slug=" + encodeURIComponent(slug || "")
        + (addr ? "&addr=" + encodeURIComponent(addr) : "");
      const data = await fetch(url, { cache: "no-store" }).then(function (res) { return res.json(); });
      return applyWorkspace(data, row);
    }, [program, slug, selected, applyWorkspace]);

    const selectRow = useCallback(async function (row) {
      setSelected(row);
      setContext(row);
      const loc = (typeof currentLocator === "function" ? currentLocator() : "") || "";
      if (loc && program) {
        const ws = await loadWorkspace(program, row);
        if (ws && ws.ok) return;
      }
      const res = await fetch(
        API.detail + "?slug=" + encodeURIComponent(slug)
          + "&addr=" + encodeURIComponent(row.addr)
          + (loc ? "&locator=" + encodeURIComponent(loc) : "")
          + (program ? "&program=" + encodeURIComponent(program) : ""),
        { cache: "no-store" }
      );
      const data = await res.json();
      setDetail(data);
      if (data.graph) setGraph(data.graph);
      if (data.overview) setOverview(data.overview);
    }, [slug, program, setContext, loadWorkspace]);

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

    const loadContext = useCallback(async function () {
      try {
        const res = await fetch(API.context, { cache: "no-store" });
        const data = await res.json();
        if (data.defaults) setEnvDefaults(data.defaults);
      } catch (_err) { /* optional */ }
    }, []);

    const loadActions = useCallback(async function () {
      const res = await fetch(API.actions, { cache: "no-store" });
      const data = await res.json();
      const list = data.actions || [];
      setActions(list);
      if (data.context && data.context.defaults) setEnvDefaults(data.context.defaults);
    }, []);

    const loadMatchStatus = useCallback(async function () {
      try {
        const res = await fetch(API.matchStatus, { cache: "no-store" });
        const data = await res.json();
        setBsimStatus(data);
        return data;
      } catch (_err) {
        setBsimStatus({ ok: true, state: "database_unreachable", summary: "Could not read BSim status." });
        return null;
      }
    }, []);

    const loadRecoverStatus = useCallback(async function () {
      try {
        const url = API.recoverStatus
          + "?program=" + encodeURIComponent(program || "")
          + "&slug=" + encodeURIComponent(slug || "");
        const res = await fetch(url, { cache: "no-store" });
        const data = await res.json();
        setRecoverInfo(data);
        if (data.path) setRecoveredRoot(data.path);
        return data;
      } catch (_err) {
        setRecoverInfo({ ok: true, state: "none", summary: "Could not read recovered source." });
        return null;
      }
    }, [program, slug]);

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

    function showToast(message, kind) {
      const text = String(message || "");
      if (!text) return;
      const tone = kind || "info";
      const entry = {
        id: "log-" + Date.now() + "-" + Math.random().toString(16).slice(2, 8),
        at: Date.now(),
        kind: tone,
        text: text
      };
      setLogEntries(function (prev) {
        const next = prev.concat(entry);
        return next.length > 200 ? next.slice(-200) : next;
      });
      setLogTab("log");
      setLogOpen(true);
      if (tone === "error") setOpenLogId(entry.id);
      setIngestNote(text);
      window.clearTimeout(showToast._errTimer);
      if (tone === "error") {
        setStatusError(text);
        showToast._errTimer = window.setTimeout(function () { setStatusError(""); }, 20000);
      } else {
        setStatusError("");
        setLastNote(text);
      }
    }

    function openLogJobs() {
      setLogTab("jobs");
      setLogOpen(true);
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
      const loc = currentLocator();
      if (picked && loc) {
        loadWorkspace(picked, null, loc);
        ensureGhidraProgram(picked, { locator: loc, quiet: true });
      }
    }

    async function ensureGhidraProgram(name, options) {
      const opts = options || {};
      const target = String(name || program || "").trim();
      const locator = opts.locator || currentLocator();
      if (!target || !locator) return null;
      ensureSeqRef.current += 1;
      const seq = ensureSeqRef.current;
      setProgramProgress(function (prev) {
        const next = Object.assign({}, prev);
        next[target] = { pct: 12, tool: "open", status: "running" };
        return next;
      });
      if (!opts.quiet) showToast("Opening " + target + "…");
      try {
        const res = await fetch(API.ensureProgram, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ locator: locator, program: target })
        });
        const data = await res.json();
        if (seq !== ensureSeqRef.current) return data;
        if (data.results && data.results.length) {
          setRows(data.results);
          setTotal(data.total || data.results.length);
          setFuncNote("");
          const first = data.results[0];
          setSelected(first);
          setOverview(function (prev) {
            if (prev && prev.program === target && prev.functionCount) return prev;
            return {
              program: target,
              functionCount: data.total || data.results.length,
              namedCount: data.named || 0,
              path: data.program_path || target
            };
          });
          setDetail(function (prev) {
            if (prev && prev.preview && String(prev.preview).indexOf("Opening ") !== 0) return prev;
            return {
              name: first.name,
              addr: first.addr,
              preview: "// " + target + "\n// " + (data.total || data.results.length)
                + " functions from the Ghidra project\n" + (first.name || "") + "  @ " + (first.addr || "")
            };
          });
          setProgramProgress(function (prev) {
            const next = Object.assign({}, prev);
            next[target] = { pct: 70, tool: "workspace", status: "running" };
            return next;
          });
          await loadWorkspace(target, first, locator);
          setProgramProgress(function (prev) {
            const next = Object.assign({}, prev);
            next[target] = { pct: 100, tool: "list-functions", status: "ok" };
            return next;
          });
          if (!opts.quiet) showToast(target + " — " + (data.total || data.results.length) + " functions", "success");
          return data;
        }
        setProgramProgress(function (prev) {
          const next = Object.assign({}, prev);
          next[target] = { pct: 40, tool: "list-functions", status: data.next === "analyze-program" ? "ok" : "failed" };
          return next;
        });
        await loadFuncs();
        if (data.error && !opts.quiet) showToast(data.error, data.next === "analyze-program" ? "" : "error");
        return data;
      } catch (err) {
        setProgramProgress(function (prev) {
          const next = Object.assign({}, prev);
          next[target] = { pct: 0, tool: "open", status: "failed" };
          return next;
        });
        if (!opts.quiet) showToast("Could not open " + target + " in Ghidra.", "error");
        return null;
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
      const programNames = [];
      const seenPrograms = new Set();
      function addProgram(name) {
        if (!name || seenPrograms.has(name)) return;
        seenPrograms.add(name);
        programNames.push(name);
      }
      if (currentSession && currentSession.program) addProgram(currentSession.program);
      ((dossier && dossier.ok ? (dossier.programs || []) : []).map(programName).filter(Boolean)).forEach(addProgram);
      programNames.forEach(function (name) {
        url += "&program=" + encodeURIComponent(name);
      });
      return url;
    }, [sessionOverviewSlugs, dossier, currentSession]);

    useEffect(function () {
      window.AgentDecompileUI = {
        announce: function (msg) {
          const pulse = document.getElementById("job-pulse");
          if (pulse) pulse.title = msg;
        }
      };
      window.KotorXidUI = window.AgentDecompileUI;
      loadBinaries();
      loadCorpusStatus();
      loadContext();
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
        if (data.user) setSharedUser(String(data.user));
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
          runCommand("file.close-tab");
        } else if (key === "i") {
          ev.preventDefault();
          runCommand("file.add-binaries");
        } else if (key === "j") {
          ev.preventDefault();
          runCommand("view.jobs");
        } else if (key === "a" && ev.shiftKey) {
          ev.preventDefault();
          runCommand("analyze.program");
        } else if (key === "b" && ev.shiftKey) {
          ev.preventDefault();
          runCommand("analyze.bsim-ingest");
        }
      }
      window.addEventListener("keydown", onKey);
      return function () {
        window.clearInterval(probeTimer);
        window.removeEventListener("keydown", onKey);
      };
    }, [loadBinaries, loadContext, loadActions, loadBrowse, loadPreview]);

    useEffect(function () {
      if (!dossier || !dossier.ok || program) return;
      const names = (dossier.programs || []).map(programName).filter(Boolean);
      if (names.length === 1) setProgram(names[0]);
    }, [dossier, program]);

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

    useEffect(function () {
      if (centerTab === "wb-match") loadMatchStatus();
      if (centerTab === "wb-recovery") loadRecoverStatus();
    }, [centerTab, loadMatchStatus, loadRecoverStatus]);

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
      if (running.length) openLogJobs();
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
            showToast(note, /failed|cancelled/.test(note) ? "error" : "info");
          }
          setJobs(list);
          const nextProgress = {};
          list.forEach(function (job) {
            chainAfterAnalyzeRef.current(job);
            const params = job.params || {};
            const key = String(params.program || params.programPath || params.binary || params.name || "").trim();
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
      list = list.filter(function (item) {
        if (item.id === id) return true;
        return tabHasRealProject(item) || sessionImportSlugs(item).length;
      });
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
      if (nextProgram) ensureGhidraProgram(nextProgram, { quiet: true, locator: value });
      return { ok: true, list: list, id: id, projectSlug: projectSlug || "", inspected: inspected };
    }

    function builtSharedUrl() {
      if (sharedUrl.trim()) return sharedUrl.trim();
      const host = sharedHost.trim() || "127.0.0.1";
      const portNum = parseInt(sharedPort.trim() || "13100", 10);
      const repo = sharedRepo.trim();
      const prog = sharedProgram.trim();
      if (!repo) return "";
      const portBit = (!portNum || portNum === 13100) ? "" : (":" + portNum);
      return "ghidra://" + host + portBit + "/" + repo + (prog ? "/" + prog.replace(/^\/+/, "") : "");
    }

    async function registerShared(ev) {
      if (ev) ev.preventDefault();
      const locator = builtSharedUrl();
      if (!locator) {
        showToast("Enter a repository name or a ghidra:// URL.", "error");
        setDialogError("Enter a repository name or a ghidra:// URL.");
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
      const locator = currentLocator();
      if (!locator) {
        showToast("This tab has no project to reload.");
        return;
      }
      showToast("Reloading…");
      try {
        await loadBinaries();
        await loadActions();
        await loadPreview(locator);
        await loadFuncs(slug, query);
        if (selected && selected.addr) await selectRow(selected);
        reloadIslands();
        showToast(locator ? "Reloaded " + locator : "This tab has no project to reload.", locator ? "success" : "");
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
        failDialog("A shared project needs a ghidra:// server URL.");
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
      const next = saveAsTarget === "shared-project"
        ? (data.http_locator || data.locator || data.local_checkout || data.gpr)
        : (data.locator || data.local_checkout || data.gpr);
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
        openLogJobs();
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
        { title: "Copy name", run: function () { copyText(name, "name"); } },
        { title: "Copy path", run: function () { copyText((row && (row.locator || row.repo)) || "", "path"); } },
        "—",
        { title: "Remove " + name, danger: true, accel: "Del", run: function () { removeSlug(name); } }
      ].map(decorateCommandItem);
    }

    function programCtxItems(name) {
      return [
        { title: "Select program", run: function () { selectProgram(name); } },
        { title: "Open in Ghidra", run: function () { setProgram(name); ensureGhidraProgram(name, { locator: currentLocator() }); } },
        { title: "Analyze program", run: function () { setProgram(name); startImportPipeline(name); } },
        { title: "Listing", id: "view.listing" },
        { title: "Match", id: "view.cross-match" },
        { title: "Recover", id: "view.recovery" },
        { title: "Call Graph", id: "view.graph" },
        "—",
        { title: "Check in", id: "file.checkin" },
        "—",
        { title: "Copy program name", run: function () { copyText(name, "program name"); } },
        "—",
        { title: "Remove from project", danger: true, accel: "Del", run: function () { removeProgramFromProject(name); } }
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
      function runTool(actionId, extras) {
        if (row) selectRow(row);
        executeAction(actionId, extras || { addr: row && row.addr, name: row && row.name }, { skipConfirm: true });
      }
      return [
        { title: "Listing", id: "view.listing" },
        { title: "Call Graph", id: "view.graph" },
        { title: "Match", id: "view.cross-match" },
        { title: "Recover", id: "view.recovery" },
        { title: "Inspector", id: "view.inspect" },
        "—",
        { title: "Decompile", run: function () { runTool("mcp.decompile-function"); } },
        { title: "Add comment…", run: function () { if (row) selectRow(row); openActionStrip("mcp.manage-comments"); } },
        { title: "Create label…", run: function () { if (row) selectRow(row); openActionStrip("mcp.create-label"); } },
        { title: "Cross-references", run: function () { runTool("mcp.get-references"); } },
        { title: "Data flow", run: function () { runTool("mcp.analyze-data-flow"); } },
        { title: "Bookmark…", run: function () { if (row) selectRow(row); openActionStrip("mcp.manage-bookmarks"); } },
        { title: "Rename / manage function…", run: function () { if (row) selectRow(row); openActionStrip("mcp.manage-function"); } },
        { title: "Match function", run: function () { runTool("mcp.match-function"); } },
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
      if (id === "file.checkin") {
        const kind = (dossier && dossier.kind) || (currentSession && currentSession.kind) || "";
        const loc = currentLocator();
        const isServer = kind === "shared-project" || String(loc).indexOf("ghidra://") === 0;
        if (!isServer) {
          showToast("Check in needs a Ghidra Server project, not a local .gpr.", "error");
          return;
        }
        if (!program) {
          showToast("Select a program to check in.", "error");
          return;
        }
        if (dossier && dossier.reachable === false && !dossier.mirror_available) {
          showToast("Lost connection to Ghidra Server.", "error");
          return;
        }
        const programPath = (dossier && dossier.program_paths && dossier.program_paths[program]) || program;
        executeAction("mcp.checkin-program", { program: programPath }, { skipConfirm: true });
        showToast("Check in queued");
        return;
      }
      if (id === "file.open-program") {
        if (!program) { showToast("Select a program first", "error"); return; }
        ensureGhidraProgram(program, { locator: currentLocator() });
        return;
      }
      if (id === "file.add-binaries") { openAddToProjectDialog(); return; }
      if (id === "file.reload") { reloadProject(); return; }
      if (id === "file.close-tab") {
        if (!currentSession) return;
        const dirty = currentSession.kind !== "draft" || currentSession.locator || sessionImportSlugs(currentSession).length;
        if (dirty) {
          askConfirm({
            title: "Close " + (currentSession.title || "tab") + "?",
            message: "This closes the project tab. File → Open reopens it. New tab only creates a draft.",
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
        if (program) { removeProgramFromProject(program); return; }
        if (extra.program) { removeProgramFromProject(extra.program); return; }
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
      if (id === "view.artifacts") { jumpTo("wb-artifacts"); return; }
      if (id === "view.evidence") { jumpTo("wb-evidence"); return; }
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
      if (id === "analyze.bsim-ingest") {
        executeAction("corpus.bsim-ingest", {}, { skipConfirm: true });
        showToast("BSim ingest started");
        return;
      }
      if (id === "analyze.bsim-report") {
        executeAction("corpus.bsim-report", catalogParamsFor("corpus.bsim-report", {}), { skipConfirm: true });
        showToast("BSim report started");
        return;
      }
      if (id === "analyze.bsim-create") {
        executeAction("corpus.bsim-createdatabase", {}, { skipConfirm: true });
        showToast("Create BSim database started");
        return;
      }
      if (id === "run.cross-place") {
        jumpTo("wb-match");
        executeAction("corpus.cross-place", {}, { skipConfirm: true });
        return;
      }
      if (id === "run.last") {
        if (lastActionId) { openActionStrip(lastActionId); showToast("Last action " + lastActionId); }
        else showToast("No last action yet.", "error");
        return;
      }
      if (id === "help.access") { setDialog("access"); showToast("Shortcuts and menus"); return; }
      if (id === "help.overview") { jumpTo("wb-overview"); return; }
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
        else if (key === "a" && ev.shiftKey) { ev.preventDefault(); runCommand("analyze.program"); }
        else if (key === "b" && ev.shiftKey) { ev.preventDefault(); runCommand("analyze.bsim-ingest"); }
        else if (key === "w") { ev.preventDefault(); runCommand("file.close-tab"); }
      }
      window.addEventListener("keydown", onCmd);
      return function () { window.removeEventListener("keydown", onCmd); };
    });

    async function selectJobInDock(jobId) {
      setSelectedJobId(jobId || "");
      openLogJobs();
    }

    async function cancelJob(jobId) {
      if (!jobId) return;
      try {
        await fetch(API.jobs + "/" + encodeURIComponent(jobId) + "/cancel", { method: "POST" });
        showToast("Cancel requested for " + jobId, "info");
      } catch (_err) {
        showToast("Could not cancel job.", "error");
      }
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
        showToast("Starting " + (act.title || actionId) + " on " + batchTargets.length + " functions…", "info");
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
        showToast("Queued " + ok + " of " + batchTargets.length + " — " + (act.title || actionId), ok ? "info" : "error");
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
      if (!opts.quiet) showToast("Starting " + (act.title || actionId) + "…", "info");
      const body = Object.assign({ confirm: true, context: ctx }, params);
      const res = await fetch("/api/v1/actions/" + actionId.replace(/\./g, "/"), {
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
        openLogJobs();
        setSelectedJobId(data.job.id);
        if (!opts.quiet) showToast("Job " + data.job.id + " — " + (act.title || actionId), "info");
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

    useEffect(function () {
      window.AgentDecompileUI = Object.assign(window.AgentDecompileUI || {}, {
        getToolContext: function () { return toolContext; },
        getEnvDefaults: function () { return envDefaults; },
        getBinaries: function () { return binaries; },
        getSiblings: function () { return (detail && detail.siblings) || []; },
        runCatalogAction: function (actionId, params) {
          if (!actionId) return null;
          openActionStrip(actionId);
          const filled = catalogParamsFor(actionId, params && Object.keys(params).length ? params : {});
          return executeAction(actionId, filled, {});
        },
        showToast: showToast
      });
      window.KotorXidUI = window.AgentDecompileUI;
    }, [toolContext, envDefaults, binaries, detail]);

    function programAlreadyAnalyzed(data) {
      if (!data) return false;
      if (data.analysisComplete === true) return true;
      if (data.results && data.results.length) return true;
      if ((data.total || 0) > 0 && data.source === "ghidra-store") return true;
      return false;
    }

    function startImportPipeline(programName, opts) {
      const target = String(programName || "").trim();
      if (!target) return;
      const force = !!(opts && opts.force);
      setProgramProgress(function (prev) {
        const next = Object.assign({}, prev);
        next[target] = { pct: 4, tool: "open", status: "queued" };
        return next;
      });
      Promise.resolve(ensureGhidraProgram(target, { quiet: true, locator: currentLocator() })).then(function (data) {
        if (!force && programAlreadyAnalyzed(data)) {
          setProgramProgress(function (prev) {
            const next = Object.assign({}, prev);
            next[target] = { pct: 100, tool: "list-functions", status: "ok" };
            return next;
          });
          return;
        }
        executeAction("mcp.analyze-program", {
          program: target,
          locator: currentLocator()
        }, { skipConfirm: true, quiet: true });
      });
    }

    function chainAfterAnalyze(job) {
      if (!job || job.status !== "ok") return;
      const actionId = String(job.actionId || "");
      if (actionId !== "mcp.analyze-program" && actionId.indexOf("analyze-program") < 0) return;
      if (pipelineChainedRef.current[job.id]) return;
      pipelineChainedRef.current[job.id] = true;
      const prog = String((job.params && (job.params.program || job.params.programPath || job.params.binary)) || program || "").trim();
      const loc = currentLocator();
      const after = { program: prog, locator: loc };
      executeAction("corpus.extract-stabs", after, { skipConfirm: true, quiet: true });
      executeAction("corpus.bsim-ingest", after, { skipConfirm: true, quiet: true });
      if (prog) {
        setProgramProgress(function (prev) {
          const next = Object.assign({}, prev);
          next[prog] = { pct: 70, tool: "extract-stabs", status: "running" };
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

    async function applyProjectInspect(inspected) {
      if (inspected && inspected.ok) {
        setDossier(inspected);
        setPreview(inspected);
      }
      return inspected;
    }

    function openAddToProjectDialog() {
      setDialogError("");
      setAddPath("");
      setDialog("add-binary");
      setMenu("");
      showToast(currentLocator() ? "Add a binary into this project" : "Add creates a project, then imports into it");
    }

    async function submitAddToProject(ev) {
      if (ev) ev.preventDefault();
      const field = document.getElementById("wb-add-path");
      const path = ((addPath || "").trim() || (field && field.value) || "").trim();
      if (!path) {
        failDialog("Paste a binary path, or choose a file.");
        return null;
      }
      const data = await importPathIntoProject(path, path.split(/[/\\]/).pop() || "binary");
      if (data && data.ok) closeDialog();
      return data;
    }

    async function importPathIntoProject(filePath, preferredName, sourceProgram) {
      const path = (filePath || "").trim();
      if (!path) return null;
      const baseName = (preferredName || path.split(/[/\\]/).pop() || "binary").trim();
      let locator = currentLocator();
      if (!locator) {
        const opened = await createTabProject(baseName);
        if (!opened || !opened.ok) {
          showToast("Open a project first, then add binaries into it.", "error");
          return null;
        }
        locator = (opened.inspected && opened.inspected.locator) || currentLocator();
      }
      if (!locator) {
        showToast("The project tab has no locator yet.", "error");
        return null;
      }
      showToast("Importing " + baseName + " into the project…");
      const res = await fetch(API.programs, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          locator: locator,
          path: path,
          program: sourceProgram || "",
          name: baseName,
          analyze: false
        })
      });
      const data = await res.json();
      if (!data.ok) {
        const message = data.error || "Could not import into the project.";
        setIngestNote(message);
        showToast(message, "error");
        return data;
      }
      if (data.inspect) await applyProjectInspect(data.inspect);
      else await loadPreview(locator);
      const prog = data.program || baseName;
      if (currentSession && currentSession.projectSlug) setSlug(currentSession.projectSlug);
      if (prog) {
        setProgram(prog);
        patchActiveSession({ program: prog });
        setSelected(null);
        setDetail(null);
      }
      closeDialog();
      setIngestNote("Imported " + prog + " into the project");
      showToast("Imported " + prog + " into the project", "success");
      if (prog) startImportPipeline(prog);
      return data;
    }

    async function removeProgramFromProject(name) {
      const target = (name || program || "").trim();
      const locator = currentLocator();
      if (!target || !locator) {
        showToast("Select a program in this project first.", "error");
        return;
      }
      askConfirm({
        title: "Remove " + target + " from the project?",
        message: "This deletes the program from the open Ghidra project.",
        danger: true,
        confirmLabel: "Remove from project",
        onConfirm: function () { removeProgramConfirmed(locator, target); }
      });
    }

    async function removeProgramConfirmed(locator, target) {
      const res = await fetch(API.programs, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ locator: locator, program: target, confirm: true })
      });
      const data = await res.json();
      if (!data.ok) {
        showToast(data.error || "Could not remove that program.", "error");
        return;
      }
      if (data.inspect) await applyProjectInspect(data.inspect);
      else await loadPreview(locator);
      if (program === target) {
        const next = ((data.inspect && data.inspect.programs) || []).map(programName).filter(Boolean)[0] || "";
        setProgram(next);
        patchActiveSession({ program: next });
        setSelected(null);
        setDetail(null);
        setRows([]);
        setTotal(0);
        if (next) ensureGhidraProgram(next, { quiet: true, locator: locator });
      }
      showToast("Removed " + target + " from the project", "success");
    }

    async function openBinaryPath(filePath, preferredName) {
      const path = (filePath || "").trim();
      if (!path) return;
      const baseName = (preferredName || path.split(/[/\\]/).pop() || "binary").trim();
      return importPathIntoProject(path, baseName);
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
      if (dialog === "add-binary") closeDialog();
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
      for (const file of files) {
        const body = new FormData();
        body.append("file", file, file.name);
        body.append("role", role || "member");
        const res = await fetch(API.binaries, { method: "POST", body: body });
        const data = await res.json();
        if (!data.ok || !data.binary) {
          setIngestNote(data.error || "upload failed");
          showToast(data.error || "Could not stage " + file.name, "error");
          continue;
        }
        const staged = data.binary.locator || data.binary.repo || "";
        if (!staged) {
          showToast("Upload landed but has no path to import.", "error");
          continue;
        }
        await importPathIntoProject(staged, file.name);
      }
    }

    async function removeSlug(target) {
      if (!target) return;
      askConfirm({
        title: "Remove " + target + "?",
        message: "Remove this leftover corpus row. Prefer Remove on a program in the open project.",
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
      if (!spec.id) return;
      openActionStrip(spec.id);
      const act = actions.find(function (item) { return item.id === spec.id; });
      const mutating = spec.mutating || (act && act.mutating);
      const danger = spec.danger || (act && act.danger);
      executeAction(
        spec.id,
        catalogParamsFor(spec.id, {}),
        { skipConfirm: !mutating && !danger, danger: danger, mutating: mutating }
      );
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
        message: "Restart the AgentDecompile HTTP server. Open tabs reconnect when it is back.",
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

    function runActionButtonRun(actionId, label, options) {
      const known = actions.some(function (item) { return item.id === actionId; });
      if (!known) return null;
      return html`<button type="button" className="wb-btn wb-btn-mini"
        onClick=${function () {
          executeAction(actionId, catalogParamsFor(actionId, options), { skipConfirm: true });
        }}>${label}</button>`;
    }

    function runLadderStep(step) {
      if (!step || !step.action_id) return;
      executeAction(step.action_id, {
        slug: step.action_slug || slug || "",
        program: step.action_program || program || ""
      }, { skipConfirm: !step.action_enabled, quiet: false });
    }

    function renderEditorBody() {
      const tab = centerTab || "decompile";
      if (tab === "graph") {
        return html`<${Surface} id="wb-graph" title="Call trees">
          <p className="wb-hint">Incoming and outgoing calls for this function. This is not Ghidra Function Graph.</p>
          <${CallGraphView} graph=${graph} onPick=${function (node) {
            const hit = rows.find(function (row) { return row.addr === node.addr; });
            selectRow(hit || node);
          }} />
        </${Surface}>`;
      }
      if (tab === "wb-overview") {
        const ladder = (corpusStatus && corpusStatus.ladder) || {};
        return html`<${Surface} id="wb-overview" title="Overview" actions=${panelActions(
          html`<button type="button" className="wb-btn wb-btn-mini" onClick=${function () { loadCorpusStatus(); }}>Refresh facts</button>`
        )}>
          ${quickBar("home")}
          ${quickBar("project")}
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
          <${HealthStrip} probes=${corpusStatus && corpusStatus.probes} atlasUrl=${atlasHref(corpusStatus)} />
          <${CorpusHeadline} headline=${corpusStatus && corpusStatus.headline} claim=${corpusStatus && corpusStatus.claimBoundary} />
          <${StepLadder} title="Corpus ladder" steps=${ladder.corpus_steps} onRun=${runLadderStep} />
          <${BinaryCompareTable} binaries=${ladder.binaries} onOpen=${function (b) {
            if (b && b.slug) { setSlug(b.slug); setCenterTab("wb-pipeline"); }
          }} />
        </${Surface}>`;
      }
      if (tab === "wb-atlas") {
        return html`<${Surface} id="wb-atlas" title="Atlas" actions=${panelActions(
          runActionButton("corpus.export-atlas-db", "Export atlas DB"),
          html`<a className="wb-btn wb-btn-mini" href=${atlasHref(corpusStatus)} target="_blank" rel="noreferrer">Decomp Atlas :5173</a>`
        )}>
          ${quickBar("atlas")}
          <${AtlasReact} onToast=${function (name) { showToast(name || "Atlas function"); }} />
        </${Surface}>`;
      }
      if (tab === "wb-report") {
        return html`<${Surface} id="wb-report" title="Report" actions=${panelActions(
          runActionButton("corpus.coverage-report", "Coverage report"),
          runActionButton("corpus.export-run-report", "Export run report"),
          html`<button type="button" className="wb-btn wb-btn-mini" onClick=${function () { loadCorpusStatus(); }}>Refresh facts</button>`
        )}>
          ${quickBar("report")}
          <${ReportReact} report=${corpusStatus && corpusStatus.report} />
        </${Surface}>`;
      }
      if (tab === "wb-pipeline") {
        const ladder = (corpusStatus && corpusStatus.ladder) || {};
        const active = (ladder.binaries || []).find(function (b) { return b.slug === slug; }) || (ladder.binaries || [])[0];
        return html`<${Surface} id="wb-pipeline" title="Pipeline" actions=${panelActions(
          runActionButton("corpus.run", "Run pipeline"),
          runActionButton("corpus.stages", "Stages"),
          html`<button type="button" className="wb-btn wb-btn-mini" onClick=${function () { loadCorpusStatus(); }}>Refresh facts</button>`
        )}>
          ${quickBar("pipeline")}
          <${StepLadder} title="Corpus" steps=${ladder.corpus_steps} onRun=${runLadderStep} />
          ${active ? html`<${StepLadder} title=${"Build " + active.slug} steps=${active.steps} onRun=${runLadderStep} />` : null}
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
        const siblings = (detail && detail.siblings) || [];
        const pair = matchPairParams(toolContext, binaries, siblings);
        const canPair = pair.ok;
        const canFn = Boolean(selected && selected.addr && program);
        const canId = hasCorpusContext(toolContext);
        const matchRunReady = canId ? canPair : canFn;
        function runIdentity(actionId) {
          if (!canId) {
            showToast("Pick a program or corpus binary in Explorer first", "error");
            return;
          }
          if (actionId === "corpus.apply-stabs" && !toolContext.slug) {
            showToast("Pick a corpus binary slug for STABS apply", "error");
            return;
          }
          if (actionId === "corpus.match-pair") {
            if (!pair.src) {
              showToast("No repo path for the active binary", "error");
              return;
            }
            if (!pair.dst) {
              showToast("Need a second binary for pair match", "error");
              return;
            }
          }
          executeAction(
            actionId,
            identityActionParams(actionId, toolContext, binaries, siblings),
            { skipConfirm: true }
          );
        }
        return html`<${Surface} id="wb-match" title="Match" actions=${panelActions(
          runActionButtonRun("corpus.bsim-ingest", "BSim ingest"),
          runActionButtonRun("corpus.bsim-report", "BSim report"),
          runActionButton("corpus.bsim-createdatabase", "Create BSim DB")
        )}>
          <${MatchWorkbench}
            program=${program}
            selected=${selected}
            detail=${detail}
            bsim=${bsimStatus}
            canMatchPair=${matchRunReady}
            canMatchFunction=${canFn}
            canIdentity=${canId}
            onRefresh=${function () { loadMatchStatus(); showToast("BSim status refreshed"); }}
            onRunMatch=${function () {
              if (canId) {
                runIdentity("corpus.match-pair");
                return;
              }
              if (!canFn) {
                showToast("Select a function first", "error");
                return;
              }
              executeAction("mcp.match-function", {
                addr: selected.addr,
                name: selected.name || "",
                program: program || ""
              }, { skipConfirm: true });
            }}
            onRunMatchFunction=${function () {
              if (!canFn) {
                showToast("Select a function first", "error");
                return;
              }
              executeAction("mcp.match-function", {
                addr: selected.addr,
                name: selected.name || "",
                program: program || ""
              }, { skipConfirm: true });
            }}
            onApplyStabs=${function () { runIdentity("corpus.apply-stabs"); }}
            onLogicalBuild=${function () { runIdentity("corpus.logical-build"); }}
            onMergeParts=${function () { runIdentity("corpus.merge-parts"); }}
            onPropagate=${function () { runIdentity("corpus.propagate-source"); }}
            onRunCrossPlace=${function () {
              executeAction("corpus.cross-place", { program: program || "", slug: slug || "" }, { skipConfirm: true });
            }}
            onExtractStabs=${function () {
              executeAction("corpus.extract-stabs", { program: program || "", slug: slug || "" }, { skipConfirm: true });
            }}
            onPickSibling=${function (sib) {
              if (sib && sib.slug) setSlug(sib.slug);
            }} />
          <${BinaryCompareTable} binaries=${(corpusStatus && corpusStatus.ladder && corpusStatus.ladder.binaries) || []}
            onOpen=${function (b) { if (b && b.slug) setSlug(b.slug); }} />
        </${Surface}>`;
      }
      if (tab === "wb-recovery") {
        return html`<${Surface} id="wb-recovery" title="Recover" actions=${panelActions(
          runActionButtonRun("corpus.genproject", "Genproject"),
          runActionButtonRun("recover.inspect", "Inspect recover")
        )}>
          <${RecoverWorkbench}
            program=${program}
            selected=${selected}
            recover=${recoverInfo}
            recoveredRoot=${recoveredRoot}
            onRefresh=${function () { loadRecoverStatus(); showToast("Recovery status refreshed"); }}
            onDump=${function () {
              if (!((recoverInfo && recoverInfo.leftoverCount) || 0)) {
                showToast("No leftover functions. Ghidra bulk is the recover path.", "error");
                return;
              }
              executeAction("corpus.genproject", {
                program: program || "",
                "leftover-only": true
              }, { skipConfirm: true });
            }}
            onOneShot=${function () {
              if (!((recoverInfo && recoverInfo.leftoverCount) || 0)) {
                showToast("No leftover functions. Ghidra bulk is the recover path.", "error");
                return;
              }
              executeAction("reconstruct.one-shot", {
                program: program || ""
              }, { skipConfirm: true });
            }}
            onGhidraBulk=${function () {
              executeAction("corpus.ghidra-bulk", { program: program || "" }, { skipConfirm: true });
            }}
            onCrossPlace=${function () {
              executeAction("corpus.cross-place", { program: program || "" }, { skipConfirm: true });
            }}
            onIngest=${function () {
              executeAction("corpus.ingest-recovered", {}, { skipConfirm: true });
            }}
            onExportC=${function () {
              const loc = (typeof currentLocator === "function" ? currentLocator() : "") || "";
              const work = envDefaults.work_dir || "";
              if (!work) {
                showToast("Set AGENT_DECOMPILE_CORPUS_WORK_DIR on the server", "error");
                return;
              }
              const dest = work.replace(/\/?$/, "/") + "export-c";
              executeAction("corpus.export-c", {
                "repo-path": loc,
                "out-dir": dest,
                program: program || ""
              }, { skipConfirm: true });
            }}
            onDecompile=${function () {
              if (!selected || !selected.addr) {
                showToast("Select a function first", "error");
                return;
              }
              if (selected.decomp === "c") {
                showToast("This logical function already has real C. Ghidra bulk skips it.", "error");
                return;
              }
              executeAction("mcp.decompile-function", {
                addr: selected.addr,
                name: selected.name || "",
                program: program || ""
              }, { skipConfirm: true });
            }} />
        </${Surface}>`;
      }
      if (tab === "wb-stabs") {
        const bins = (corpusStatus && corpusStatus.ladder && corpusStatus.ladder.binaries) || [];
        return html`<${Surface} id="wb-stabs" title="STABS" actions=${panelActions(
          runActionButton("corpus.extract-stabs", "Extract STABS"),
          runActionButton("corpus.stabs-manifest", "STABS manifest")
        )}>
          ${quickBar("stabs")}
          <p className="wb-hint">Named counts come from the live corpus snapshot. Extract STABS writes the index the ladder reads.</p>
          <${BinaryCompareTable} binaries=${bins} onOpen=${function (b) { if (b && b.slug) setSlug(b.slug); }} />
        </${Surface}>`;
      }
      if (tab === "wb-knowledge") {
        const steps = ((corpusStatus && corpusStatus.ladder && corpusStatus.ladder.corpus_steps) || []).filter(function (s) {
          return s.key === "calibrate-global" || s.key === "identify";
        });
        return html`<${Surface} id="wb-knowledge" title="Knowledge" actions=${panelActions(
          runActionButton("corpus.bsim-ingest", "BSim ingest"),
          runActionButton("corpus.bsim-report", "BSim report")
        )}>
          <${StepLadder} title="Identity and knowledge merge" steps=${steps} onRun=${runLadderStep} />
        </${Surface}>`;
      }
      if (tab === "wb-roundtrip") {
        const steps = ((corpusStatus && corpusStatus.ladder && corpusStatus.ladder.corpus_steps) || []).filter(function (s) {
          return s.key === "leftover-recover" || s.key === "verify-byte-accuracy" || s.key === "apply-cross-build";
        });
        return html`<${Surface} id="wb-roundtrip" title="Roundtrip" actions=${panelActions(
          runActionButton("reconstruct.run", "Reconstruct run"),
          runActionButton("corpus.verify-legacy-recovered", "Verify legacy"),
          runActionButton("corpus.external-bridge", "External bridge")
        )}>
          <${CorpusHeadline} headline=${corpusStatus && corpusStatus.headline} claim="Compile and byte-accuracy stay separate columns." />
          <${StepLadder} title="Compile and verify" steps=${steps} onRun=${runLadderStep} />
        </${Surface}>`;
      }
      if (tab === "wb-processes") {
        return html`<${Surface} id="wb-processes" title="Process log" actions=${panelActions(
          runActionButton("mcp.status", "MCP status"),
          runActionButton("corpus.run", "Run pipeline")
        )}>
          <${HealthStrip} probes=${corpusStatus && corpusStatus.probes} atlasUrl=${atlasHref(corpusStatus)} />
          <ul id="action-jobs" className="wb-job-list">
            ${jobs.length ? jobs.map(function (job) {
              return html`<li key=${job.id}><code>${job.id}</code> ${job.actionId || ""} ${job.status}</li>`;
            }) : html`<li>No catalog jobs in this session.</li>`}
          </ul>
        </${Surface}>`;
      }
      if (tab === "wb-mission") {
        return html`<${Surface} id="wb-mission" title="Mission" actions=${panelActions(
          html`<button type="button" className="wb-btn wb-btn-mini" onClick=${function () { loadCorpusStatus(); }}>Refresh</button>`
        )}>
          <${MissionReact} mission=${corpusStatus && corpusStatus.mission} />
        </${Surface}>`;
      }
      if (tab === "wb-corpus") {
        return html`<${Surface} id="wb-corpus" title="Corpus" actions=${panelActions(
          runActionButton("corpus.init", "Init corpus"),
          runActionButton("corpus.program-inventory", "Program inventory"),
          runActionButton("corpus.add-binary", "Add binary"),
          runActionButton("corpus.remove-binary", "Remove binary"),
          html`<button type="button" className="wb-btn wb-btn-mini" data-cmd="file.add-binaries"
            onClick=${function () { runCommand("file.add-binaries"); }}>Add to project…</button>`
        )}>
          <${BinaryCompareTable} binaries=${(corpusStatus && corpusStatus.ladder && corpusStatus.ladder.binaries) || []}
            onOpen=${function (b) { if (b && b.slug) { setSlug(b.slug); setCenterTab("wb-pipeline"); } }} />
        </${Surface}>`;
      }
      if (tab === "wb-fnbrowse") {
        return html`<${Surface} id="wb-fnbrowse" title="Functions" actions=${html`<div className="wb-surface-actions">
          <${FuncPager} limit=${funcLimit} shown=${rows.length} total=${total}
            onLimit=${function (n) { setFuncLimit(n); setFuncOffset(0); }} />
          <button type="button" className="wb-btn wb-btn-mini"
            onClick=${function () { loadFuncs(slug, query); showToast("Function list reloaded", "success"); }}>Refresh</button>
        </div>`}>
          ${quickBar("function")}
          ${quickBar("functions")}
          <div className="wb-fnb-head">
            <label className="wb-fnb-filter">
              <span className="sr-only">Find a function by name or address</span>
              <input id="wb-fnbrowse-q" type="search" placeholder="Find a function by name or address…"
                value=${query} onInput=${function (ev) { onSearch(ev.target.value); }} autocomplete="off" />
            </label>
            <span className="wb-hint">${program
              ? "Ghidra program " + program
              : (slug ? slug : "Pick a program in Explorer.")}</span>
          </div>
          ${rows.length ? html`<table id="wb-fnbrowse-table" className="wb-fnb-table">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Location</th>
                <th scope="col">Function Signature</th>
                <th scope="col">Function Size</th>
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
                  onClick=${function () { selectRow(row); }}
                  onDoubleClick=${function () { selectRow(row); jumpTo("decompile"); }}>
                  <td>${row.name}</td>
                  <td><code>${row.addr}</code></td>
                  <td className="wb-sig">${row.signature || "—"}</td>
                  <td className="wb-num">${row.size || ""}</td>
                </tr>`;
              })}
            </tbody>
          </table>` : html`<div className="wb-empty wb-empty-surface">
            <p>${funcNote || "Select a program in Explorer to list its functions."}</p>
            <p className="wb-empty-actions">
              <button type="button" className="wb-btn wb-btn-primary" data-cmd="analyze.program"
                onClick=${function () { runCommand("analyze.program"); }}>Analyze program</button>
              <button type="button" className="wb-btn" data-cmd="file.open-program"
                onClick=${function () { runCommand("file.open-program"); }}>Open in Ghidra</button>
              <button type="button" className="wb-btn" data-cmd="analyze.bsim-ingest"
                onClick=${function () { runCommand("analyze.bsim-ingest"); }}>Ingest into BSim</button>
            </p>
          </div>`}
          ${rows.length ? html`<${FuncPager} limit=${funcLimit} shown=${rows.length}
            total=${total}
            onLimit=${function (n) { setFuncLimit(n); setFuncOffset(0); }} />` : null}
        </${Surface}>`;
      }
      if (tab === "wb-artifacts") {
        return html`<${Surface} id="wb-artifacts" title="Artifacts" actions=${panelActions()}>
          <${ArtifactsReact} path=${artifactPath} onOpen=${setArtifactPath} />
        </${Surface}>`;
      }
      if (tab === "wb-evidence") {
        return html`<${Surface} id="wb-evidence" title="Database" actions=${panelActions()}>
          <${EvidenceReact} />
        </${Surface}>`;
      }
      if (tab === "wb-logical") {
        return html`<${Surface} id="wb-logical" title="Logical identities" actions=${panelActions(
          runActionButton("corpus.logical-build", "Logical build"),
          runActionButton("corpus.propagate-source", "Propagate source"),
          runActionButton("corpus.cross-place", "Cross-place")
        )}>
          <p className="wb-hint">Same function across builds. Bound vs real C is the identity picture.</p>
          <${BinaryCompareTable} binaries=${(corpusStatus && corpusStatus.ladder && corpusStatus.ladder.binaries) || []}
            onOpen=${function (b) { if (b && b.slug) setSlug(b.slug); }} />
        </${Surface}>`;
      }
      if (tab === "wb-review") {
        return html`<${Surface} id="wb-review" title="Review" actions=${panelActions(
          runActionButton("corpus.reclassify-matches", "Reclassify"),
          runActionButton("corpus.match-pair", "Re-run match"),
          runActionButton("corpus.evaluate-pair", "Evaluate pair"),
          html`<button type="button" className="wb-btn wb-btn-mini"
            onClick=${function () { batchReviewPage("accept"); }}>Accept page</button>`,
          html`<button type="button" className="wb-btn wb-btn-mini"
            onClick=${function () { batchReviewPage("reject"); }}>Reject page</button>`
        )}>
          <p className="wb-hint">Review-tier match rows ranked by score. Accept or reject from the row or the toolbar.</p>
          <${ReviewReact} review=${corpusStatus && corpusStatus.review} onDecide=${function (row, decision) {
            if (!row) return;
            fetch(API.matchDecide, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                decision: decision,
                src_addr: row.src_addr,
                dst_addr: row.dst_addr,
                src_binary_id: row.src_binary_id,
                dst_binary_id: row.dst_binary_id
              })
            }).then(function (res) { return res.json(); }).then(function (data) {
              showToast((decision === "accept" ? "Accepted" : "Rejected") + " match", "info");
              loadCorpusStatus();
              if (!data || data.ok === false) showToast((data && data.error) || "Decide failed", "error");
            }).catch(function (e) { showToast(String(e && e.message || e), "error"); });
          }} />
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
          <p className="wb-hint">${matches.length} of ${actions.length} commands. Click a command to load it.</p>
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
      const decompileText = (detail && detail.decompile && detail.decompile.text) || "";
      const listingTitle = (selected && selected.name) || program || "Listing";
      return html`<${Surface} id="wb-inspect" title=${"Listing: " + (program || "—")}>
        <div id="wb-inspect-body" className=${"wb-workspace-split" + (decompileText ? "" : " wb-listing-only")}>
          <div className="wb-listing-pane">
          ${overview || selected || program ? html`<div>
            <h3>Listing ${listingTitle} ${(selected && selected.addr) ? html`<code>${selected.addr}</code>` : null}</h3>
            <p className="wb-hint">${(detail && detail.path) || (overview && overview.path) || ""}</p>
            <div className="wb-fn-tools" role="toolbar" aria-label="Listing tools">
              <button type="button" id="wb-analyze" className="wb-btn wb-btn-mini wb-btn-primary" data-cmd="analyze.program"
                onClick=${function () {
                  if (!program) { showToast("Select a program first", "error"); return; }
                  startImportPipeline(program);
                  showToast("analyze-program started on " + program);
                }}>Analyze</button>
              <button type="button" id="wb-listing-decompile" className="wb-btn wb-btn-mini"
                onClick=${function () {
                  if (!selected || !selected.addr) { showToast("Select a function first", "error"); return; }
                  executeAction("mcp.decompile-function", {
                    addr: selected.addr, name: selected.name || "", program: program || ""
                  }, { skipConfirm: true });
                }}>Decompile</button>
              <button type="button" id="wb-listing-match" className="wb-btn wb-btn-mini"
                onClick=${function () { jumpTo("wb-match"); }}>Match</button>
              <button type="button" id="wb-listing-recover" className="wb-btn wb-btn-mini"
                onClick=${function () { jumpTo("wb-recovery"); }}>Recover</button>
              <button type="button" id="wb-listing-fields" className="wb-btn wb-btn-mini"
                onClick=${function () { openActionStrip(selected ? "mcp.manage-function" : "mcp.decompile-function"); }}>Fields…</button>
            </div>
            ${(detail && detail.siblings && detail.siblings.length) ? html`<ul className="wb-siblings">
              ${detail.siblings.map(function (sib) {
                return html`<li key=${sib.slug + sib.addr}>
                  <button type="button" className="wb-text-action"
                    onClick=${function () { setSlug(sib.slug); }}>${sib.slug} ${sib.addr}</button>
                </li>`;
              })}
            </ul>` : null}
            <pre className="wb-preview" id="wb-listing-preview">${(detail && detail.preview) || (program
              ? ("Reading " + program + " from the Ghidra project on disk…")
              : "Pick a program in Explorer.")}</pre>
          </div>` : html`<div className="wb-empty wb-empty-surface">
            <p>${hasProject
              ? "Pick a program in Explorer. Listing comes from that program."
              : "File → Open a Ghidra repository, then pick a program."}</p>
          </div>`}
          </div>
          ${decompileText ? html`<div className="wb-decompile-pane">
            <h3>Decompile: ${(selected && selected.name) || "function"}</h3>
            <p className="wb-hint">${(detail.decompile && detail.decompile.source === "recovered")
              ? "Recovered C for this function."
              : "Decompiler pane."}</p>
            <pre className="wb-preview" id="wb-decompile-preview">${decompileText}</pre>
          </div>` : null}
          <div id="wb-reaction" className="wb-reaction">
            ${reaction && /analyze|decompile|match-function|export-c|one-shot|recover/.test(String(reaction.id || ""))
              && String(reaction.id || "").indexOf("add-binary") < 0
              ? html`<p><strong>${actionTitle(reaction.id, actions)}</strong> ${formatJobSummary(reaction.data, actions)}</p>
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
          <span id="job-pulse">${running.length ? running.length + " running" : "idle"}</span>
        </p>
      </header>
      <${RepoStatus} dossier=${dossier} user=${sharedUser} />
      <nav id="wb-menubar" className="wb-menubar" aria-label="Application">
        ${[
          ["file", "File", [
            ["New Project…", "file.new-project"],
            ["New Tab", "file.new-tab"],
            ["Open…", "file.open"],
            ["Open from URL…", "file.open-url"],
            ["Add to project…", "file.add-binaries"],
            ["—"],
            ["Reload from disk", "file.reload"],
            ["Save", "file.save"],
            ["Save As…", "file.save-as"],
            ["Check in to Ghidra server", "file.checkin"],
            ["Open selected program in Ghidra", "file.open-program"],
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
            ["Call trees", "view.graph"],
            ["Match", "view.cross-match"],
            ["Recover", "view.recovery"],
            ["Artifacts", "view.artifacts"],
            ["Database", "view.evidence"],
            ["Inspector", "view.inspect"],
            ["—"],
            ["Overview", "view.overview"],
            ["Pipeline", "view.pipeline"],
            ["Atlas", "view.atlas"],
            ["Jobs", "view.jobs"],
            ["—"],
            ["Run Cross-place", "run.cross-place"],
            ["STABS", "view.stabs"],
            ["Knowledge", "view.knowledge"],
            ["Logical identities", "view.logical"],
            ["Review", "view.review"],
            ["Report", "view.report"],
            ["Corpus table", "view.corpus"],
            ["Commands", "view.tools"],
            ["—"],
            ["Use compact layout", "view.density-compact"],
            ["Use roomy layout", "view.density-comfortable"],
            ["Dock jobs on the side", "view.jobs-rail"],
            ["Dock jobs at the bottom", "view.jobs-bottom"]
          ]],
          ["analyze", "Analyze", [
            ["Analyze program", "analyze.program"],
            ["Ingest repository into BSim", "analyze.bsim-ingest"],
            ["Report BSim database", "analyze.bsim-report"],
            ["Create BSim database", "analyze.bsim-create"]
          ]],
          ["server", "Server", [
            ["Restart server", null, restartServer],
            ["Shut down server", null, shutdownServer]
          ]],
          ["help", "Help", [
            ["Shortcuts and menus…", "help.access"],
            ["Open all commands", null, function () { window.location.href = "/docs"; }],
            ["Overview", "help.overview"]
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
                    message: "This closes the project tab. File → Open reopens it.",
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
      <${Modal} open=${dialog === "open"} title="Open project" onClose=${closeDialog} error=${dialogError} footer=${html`
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
          <button type="button" className=${openTab === "remote" ? "on" : ""} onClick=${function () { setOpenTab("remote"); }}>Ghidra Server</button>
        </div>
        ${openTab === "local" ? html`<div>
          <div id="wb-drop" className="wb-drop wb-drop-compact" tabindex="0" ref=${dropRef}
            onClick=${triggerFileUpload}
            onDragOver=${function (ev) { ev.preventDefault(); ev.currentTarget.classList.add("on"); }}
            onDragLeave=${function (ev) { ev.currentTarget.classList.remove("on"); }}
            onDrop=${onDrop}>
            Drop a .gpr, repos folder, or binary
          </div>
          <p className="wb-dialog-actions">
            <button type="button" className="wb-btn" onClick=${triggerFolderUpload}>Choose folder…</button>
            <button type="button" className="wb-btn wb-btn-primary" onClick=${createProject}>Create empty project</button>
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
                      if (entry.kind === "binary" || entry.kind === "packed-program") {
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
            <input id="wb-shared-url" placeholder="ghidra://127.0.0.1/Repo/Game.exe"
              value=${sharedUrl} onInput=${function (ev) { setSharedUrl(ev.target.value); }} />
          </label>
          <p className="wb-hint">Ghidra Server uses RMI. The user is not part of the URL.</p>
          <label>Server Name<input id="wb-shared-host" value=${sharedHost} onInput=${function (ev) { setSharedHost(ev.target.value); }} /></label>
          <label>Port Number<input id="wb-shared-port" value=${sharedPort} onInput=${function (ev) { setSharedPort(ev.target.value); }} /></label>
          <label>Repository Name<input id="wb-shared-repo" value=${sharedRepo} onInput=${function (ev) { setSharedRepo(ev.target.value); }} /></label>
          <label>User<input id="wb-shared-user" value=${sharedUser} onInput=${function (ev) { setSharedUser(ev.target.value); }} /></label>
          <label>Program<input id="wb-shared-program" value=${sharedProgram} onInput=${function (ev) { setSharedProgram(ev.target.value); }} /></label>
          <p className="wb-hint"><code>${builtSharedUrl() || "ghidra://host/repository"}</code></p>
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
              <option value="shared-project">Ghidra Server (ghidra://) with local checkout</option>
            </select>
          </label>
          ${saveAsTarget === "shared-project" ? html`<label>Server URL
            <input id="wb-save-as-url" value=${saveAsUrl} placeholder="ghidra://host/repo"
              onInput=${function (ev) { setSaveAsUrl(ev.target.value); }} />
          </label>` : html`<label>Folder <span className="wb-hint">optional</span>
            <input value=${saveAsDest} placeholder="defaults to work directory"
              onInput=${function (ev) { setSaveAsDest(ev.target.value); }} />
          </label>`}
          <p className="wb-hint">Save writes project metadata on disk. Ghidra databases are not copied.</p>
        </form>
      </${Modal}>

      <${Modal} open=${dialog === "add-binary"} title="Add binary to this project" onClose=${closeDialog} error=${dialogError}
        footer=${html`
          <button type="button" className="wb-btn" onClick=${closeDialog}>Cancel</button>
          <button type="button" className="wb-btn" onClick=${triggerFileUpload}>Choose file…</button>
          <button type="submit" form="wb-add-binary-form" className="wb-btn wb-btn-primary">Add to project</button>
        `}>
        <form id="wb-add-binary-form" onSubmit=${submitAddToProject}>
          <p className="wb-hint">${currentLocator()
            ? "The file is imported into the open Ghidra project."
            : "This tab has no project yet. Add creates one, then imports the binary."}</p>
          <label>Binary path
            <input id="wb-add-path" value=${addPath} placeholder="/path/to/game.exe"
              onInput=${function (ev) { setAddPath(ev.target.value); }}
              onKeyDown=${function (ev) { if (ev.key === "Enter") { ev.preventDefault(); submitAddToProject(ev); } }} />
          </label>
        </form>
      </${Modal}>

      <${Modal} open=${dialog === "access"} title="Shortcuts and menus" onClose=${closeDialog}
        footer=${html`<button type="button" className="wb-btn wb-btn-primary" onClick=${closeDialog}>Close</button>`}>
        <p className="wb-hint">Use the menu, the command palette, a right-click, a shortcut, or a button.</p>
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

      <div className="wb-app-shell" style=${{ "--wb-side-w": sideW + "px" }}>
        <aside id="wb-sidebar" className="wb-sidebar" style=${{ width: sideW + "px", flexBasis: sideW + "px" }}
          onContextMenu=${function (ev) {
            const items = [
              { id: "file.open", title: "Open…" },
              { id: "file.add-binaries", title: "Add to project…" },
              "—",
              { id: "file.save", title: "Save" },
              { id: "file.save-as", title: "Save As…" },
              "—",
              { id: "file.reload", title: "Reload" }
            ].map(decorateCommandItem);
            openCtx(ev, items);
          }}>
          <div id="wb-sources" className="wb-sidebar-section" style=${{ flex: "0 0 " + explorerH + "px", height: explorerH + "px" }}>
            <header className="wb-sidebar-head">
              <h3>Explorer</h3>
              <button type="button" className="wb-text-action" data-cmd="file.add-binaries"
                title="Import a binary into this Ghidra project"
                onClick=${function () { runCommand("file.add-binaries"); }}>Add to project</button>
            </header>
            <ul id="wb-binary-list" className="wb-source-tree">
              ${projectCard ? html`<li key=${projectCard.key}
                className=${((activeProjectSlug && slug === activeProjectSlug && !program) ? "on " : "") + "kind-" + projectCard.kind + " wb-source-project"}>
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
                ${((projectCard.programs || []).length) ? html`<ul className="wb-programs">
                  ${(projectCard.programs || []).map(function (name) {
                    const meter = programProgress[name] || null;
                    const live = meter && (meter.status === "queued" || meter.status === "running");
                    return html`<li key=${"prog-" + name} className=${"wb-program" + (program === name && slug === activeProjectSlug ? " on" : "") + (live ? " live" : "")}
                      onContextMenu=${function (ev) { openCtx(ev, programCtxItems(name)); }}>
                      <button type="button" className="wb-text-action"
                        title=${name}
                        onClick=${function (ev) {
                          ev.stopPropagation();
                          selectProgram(name);
                          if (activeProjectSlug) setSlug(activeProjectSlug);
                          setSelected(null);
                          setDetail(null);
                        }}
                        onDoubleClick=${function (ev) {
                          ev.stopPropagation();
                          selectProgram(name);
                          if (activeProjectSlug) setSlug(activeProjectSlug);
                          ensureGhidraProgram(name, { locator: currentLocator() });
                          jumpTo("decompile");
                        }}>${name}</button>
                      <button type="button" className="wb-text-action wb-remove"
                        title=${"Remove " + name + " from this project"}
                        onClick=${function (ev) {
                          ev.stopPropagation();
                          removeProgramFromProject(name);
                        }}>Remove</button>
                      ${live ? html`<span className="wb-prog-pct" title=${meter.tool || ""}>${meter.pct}%</span>` : null}
                      ${live ? html`<span className="wb-prog-meter" aria-hidden="true"><i style=${{ transform: "scaleX(" + (Number(meter.pct) / 100) + ")" }}></i></span>` : null}
                    </li>`;
                  })}
                </ul>` : html`<ul className="wb-programs">
                  <li className="wb-empty">Add binaries into this project.</li>
                </ul>`}
              </li>` : null}
              ${!projectCard ? html`<li className="wb-empty">This tab is the project. File → Open a .gpr, a repos folder, or a ghidra:// URL.</li>` : null}
            </ul>
          </div>
          <${SplitHandle} axis="y" label="Resize explorer"
            onDrag=${function (ev) { beginResize(ev, explorerH, setExplorerH, "wb-explorer-h", "y", 80, 720, false); }} />
          <div id="wb-functions" className="wb-sidebar-section">
            <h3>Functions ${total ? "(" + total + ")" : ""} ${checkedAddrs.length ? html`<span className="wb-sel-chip">${checkedAddrs.length} selected <button type="button" className="wb-sel-clear" aria-label="Clear function selection" onClick=${function () { setCheckedAddrs([]); setCheckAnchor(""); }}>×</button></span>` : null}</h3>
            <span id="wb-func-meta" className="sr-only">${total || 0} functions${checkedAddrs.length ? ", " + checkedAddrs.length + " selected" : ""}</span>
            ${html`<${FuncPager} compact=${true}
              limit=${funcLimit} shown=${rows.length} total=${total}
              onLimit=${function (n) { setFuncLimit(n); setFuncOffset(0); }} />`}
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
                  <code title=${row.addr}>${row.addr}</code><span title=${row.name || ""}>${row.name}</span>
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
        <${SplitHandle} axis="x" label="Resize explorer"
          onDrag=${function (ev) { beginResize(ev, sideW, setSideW, "wb-side-w", "x", 180, 900, false); }} />

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
          <span className="wb-hint">${[
            dossier.program_count != null ? dossier.program_count + " programs" : "",
            overview && overview.functionCount ? overview.functionCount + " functions" : ""
          ].filter(Boolean).join(" · ")}</span>
        </div>` : null}
        <div className="wb-editor-body" onDragOver=${onIngestDragOver} onDragLeave=${onIngestDragLeave} onDrop=${onDrop}>
          ${renderEditorBody()}
        </div>
      </div>
      </div>
      <${LogDock}
        entries=${logEntries}
        tab=${logTab}
        onTab=${setLogTab}
        open=${logOpen}
        onToggle=${setLogOpen}
        selectedId=${openLogId}
        onSelect=${setOpenLogId}
        jobs=${jobs}
        selectedJobId=${selectedJobId}
        jobDetail=${jobDetail}
        onSelectJob=${selectJobInDock}
        onCancel=${cancelJob}
        actions=${actions}
        height=${logH}
        onResize=${function (ev) { beginResize(ev, logH, setLogH, "wb-log-h", "y", 72, 640, true); }} />
        <input id="wb-bin-slug" type="hidden" value=${newSlug} />
        <input id="wb-bin-role" type="hidden" value=${role} />
        <input id="wb-bin-label" type="hidden" value=${label} />
      </main>

      <footer className="wb-status" id="wb-status">
        <span id="wb-status-source">${(currentSession && currentSession.title) || "No project"}</span>
        <span id="wb-status-program">${program || "No program"}</span>
        <span id="wb-status-selection">${selected
          ? ((selected.name || selected.addr) + " " + (selected.addr || ""))
          : (total ? total + " functions" : "No function")}</span>
        <span id="job-status">${running.length ? running.length + " running" : "idle"}</span>
        ${statusError
          ? html`<span id="wb-status-error" className="wb-status-error" role="alert">${statusError}
              <button type="button" className="wb-status-dismiss" aria-label="Dismiss error"
                onClick=${function () { setStatusError(""); }}>×</button></span>`
          : html`<span id="wb-last-action" className="wb-hint">${lastNote}</span>`}
      </footer>
    </div>`;
  }

  const root = document.getElementById("wb-root");
  if (root && window.ReactDOM) {
    ReactDOM.createRoot(root).render(e(App));
  }
})();
