import {UnifiedActivity} from './UnifiedActivity';
import { useCallback, useEffect, useRef, useState } from "react";
import {
  API,
  emptySelection,
  normalizeSelection,
  functionKey,
  query,
  request,
  recordedSelection,
  type ActionRequest,
  type Data,
  type Notify,
  type Selection,
} from "./contracts";
import {
  ErrorLine,
  jump as jumpTo,
  readPref,
  ResizeBar,
  savePref,
  useData,
  usePref,
} from "./ui";
import { WorkbenchSurfaces, EvidenceInspector } from "./Surfaces";
import { Commands, ActionRunner } from "./Actions";
import { PreparationActivity } from "./PreparationActivity";
import { CodeBrowser } from "./CodeBrowser";
import { GuideWorkflows } from "./GuideWorkflows";
import { useLibraryTransfer } from "./BinaryLibrary";
import { PersistentExplorer } from "./PersistentExplorer";
import { ProjectDialog } from "./ProjectDialog";
import { SourceDownload } from "./SourceDownload";
import "./actions.css";
const sectionNames: Record<string,string> = {
  overview: "Project overview", preparation: "Preparation status", listing: "Source and assembly",
  "code-browser": "Browse program data", guide: "Reversing workflows", graph: "Call relationships",
  logical: "Equivalent functions", review: "Review evidence", pipeline: "Pipeline progress",
  knowledge: "Shared names and types", types: "Types and debug information", recovery: "Recover and verify source",
  exports: "Exports and reports", context: "Assemble context", commands: "All commands",
};
const workspaceNavigation = [
  { id: "compare-builds", label: "Compare builds" },
  { id: "inspect-work", label: "Inspect" },
  { id: "recover-verify", label: "Recover & verify" },
];
function jump(id: string) {
  let parent = document.getElementById(id)?.parentElement;
  while (parent) { if (parent instanceof HTMLDetailsElement) parent.open = true; parent = parent.parentElement; }
  jumpTo(id);
}
function route(): Selection {
  const q = new URLSearchParams(location.search);
  return normalizeSelection({
    ...emptySelection,
    slug: q.get("binary") || q.get("slug") || "",
    program: q.get("program") || "",
    addr: q.get("addr") || "",
    logicalId: q.get("logical_id") || "",
    locator: q.get("locator") || "",
  });
}
function fromSession(s: Data): Selection {
  return normalizeSelection({
    ...emptySelection,
    ...s.selection,
    locator: s.selection?.locator ?? s.locator ?? "",
    slug: s.selection?.slug || s.projectSlug || "",
    program: s.selection?.program || s.program || "",
  });
}
function BatchTarget({
  batchId,
  index,
  row,
}: {
  batchId: string;
  index: number;
  row: Data;
}) {
  const [open, setOpen] = useState(false);
  const data = useData(
    open ? `/api/v1/batches/${batchId}/targets/${index}` : null,
  );
  return (
    <details onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary>Parameters and result</summary>
      <ErrorLine error={data.error} />
      <pre>{JSON.stringify(data.data.target || row, null, 2)}</pre>
    </details>
  );
}
export function App() {
  const [selection, setSelection] = useState<Selection>(() => route());
  const selectionRef = useRef(selection);
  selectionRef.current = selection;
  const [sessions, setSessions] = useState<Data[]>([]);
  const sessionsRef = useRef<Data[]>([]);
  sessionsRef.current = sessions;
  const [active, setActive] = useState("");
  const [ready, setReady] = useState(false);
  const preparedContexts = useRef(new Set<string>());
  const revisionRef = useRef(0);
  const [revision, setRevision] = useState(0);
  const refresh = useCallback(() => setRevision((x) => x + 1), []);
  const [events, setEvents] = usePref<Data[]>("activity", []);
  const notify: Notify = useCallback(
    (message, level = "info", details = {}) =>
      setEvents((old) =>
        [
          ...old,
          {
            id: crypto.randomUUID(),
            at: Date.now(),
            message,
            level,
            ...details,
          },
        ].slice(-500),
      ),
    [setEvents],
  );
  const [layout, setLayout] = usePref("layout", {
    explorer: 320,
    dock: 200,
    inspector: 300,
    tree: 200,
    showExplorer: true,
    showInspector: false,
    showDock: true,
  });
  const [density, setDensity] = usePref("density", "compact");
  const [dialog, setDialog] = useState<
    "open" | "create" | "copy" | "connection" | "import" | null
  >(null);
  const [action, setAction] = useState<ActionRequest | null>(null);
  const [checked, setChecked] = useState<Record<string, Selection>>({});
  const [filter, setFilter] = useState(() => readPref("filter", ""));
  const [offset, setOffset] = useState(0);
  const [recordFilter, setRecordFilter] = usePref("record-filter", "all");
  const navigationRef = useRef({ filter, recordFilter, offset, scroll: 0 });
  navigationRef.current = {
    filter,
    recordFilter,
    offset,
    scroll: document.querySelector("main")?.scrollTop || 0,
  };
  const [palette, setPalette] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [menu, setMenu] = useState("");
  const [context, setContext] = useState<{
    x: number;
    y: number;
    target: Selection;
    kind: string;
  } | null>(null);
  const [jobs, setJobs] = useState<Data[]>([]);
  const [batches, setBatches] = useState<Data[]>([]);
  const [jobId, setJobId] = useState("");
  const [dockTab, setDockTab] = usePref("dock-tab", "logs");
  const [connection, setConnection] = useState("Connecting");
  const jobsSnapshot = useRef<Record<string, string>>({});
  const pollRef = useRef(false);
  const saveRef = useRef(Promise.resolve());
  const [sessionError, setSessionError] = useState("");
  const binaries = useData(API + "/binaries", revision);
  const libraryTransfer = useLibraryTransfer(binaries.data.binaries || [], notify);
  const catalog = useData("/dashboard/api/actions");
  const activateContext = useCallback((next: Selection) => {
    const found = sessionsRef.current.find(s => next.locator
      ? s.locator === next.locator
      : !s.locator && s.selection?.slug === next.slug);
    if (found) { if(found.hidden){sessionsRef.current=sessionsRef.current.map(s=>s.id===found.id?{...s,hidden:false}:s);setSessions(sessionsRef.current);}setActive(found.id); return; }
    if (!next.locator && !next.slug) { setActive(""); return; }
    const session = { id: crypto.randomUUID(),
      title: next.locator.split("/").pop() || next.program || next.slug,
      locator: next.locator, projectSlug: next.slug,
      imports: next.slug ? [next.slug] : [], selection: next };
    sessionsRef.current = [...sessionsRef.current, session];
    setSessions(sessionsRef.current);
    setActive(session.id);
  }, []);
  const select = useCallback((patch: Partial<Selection>) => {
    const prior = selectionRef.current;
    const next = { ...prior, ...patch };
    if (
      (patch.slug !== undefined && patch.slug !== prior.slug) ||
      (patch.program !== undefined && patch.program !== prior.program) ||
      (patch.locator !== undefined && patch.locator !== prior.locator)
    ) {
      next.addr = patch.addr || "";
      next.logicalId = patch.logicalId || "";
      setOffset(0);
      setChecked({});
    }
    const priorState = {
      ...navigationRef.current,
      scroll: document.querySelector("main")?.scrollTop || 0,
    };
    history.replaceState(priorState, "", location.href);
    selectionRef.current = next;
    activateContext(next);
    setSelection(next);
    history.pushState(
      {
        ...priorState,
        offset:
          next.slug !== prior.slug || next.program !== prior.program
            ? 0
            : priorState.offset,
      },
      "",
      location.pathname + "?mode=workbench&" + query(next),
    );
  }, []);
  async function projectVisibility(record:Data,hidden:boolean) {
    const locator=String(record.locator||'');
    let next=sessionsRef.current.map(session=>session.locator===locator?{...session,hidden}:session);
    if(!next.some(session=>session.locator===locator))next.push({...record,id:record.id||crypto.randomUUID(),locator,hidden});
    let nextActive=active;
    if(hidden&&selectionRef.current.locator===locator){
      let fallback=next.find(session=>!session.hidden&&session.locator!==locator);
      if(!fallback){fallback={id:crypto.randomUUID(),title:'Untitled',locator:'',imports:[],selection:emptySelection};next.push(fallback);}
      nextActive=fallback.id;setActive(nextActive);
      const nextSelection=fromSession(fallback);selectionRef.current=nextSelection;setSelection(nextSelection);setChecked({});setOffset(0);
      history.replaceState(null,'',location.pathname+'?mode=workbench&'+query(nextSelection));
    }
    sessionsRef.current=next;setSessions(next);
    const operation=saveRef.current.catch(()=>{}).then(async()=>{const response=await request(API+'/sessions',{method:'PUT',body:JSON.stringify({active:nextActive,sessions:next,revision:revisionRef.current})});revisionRef.current=response.revision||revisionRef.current;});
    saveRef.current=operation.catch(()=>{});
    await operation;notify(hidden?'Project removed from workspace. Files and background work remain available.':'Project restored to workspace.','info',{target:locator});
  }
  const onAction = useCallback(
    (id: string, params: Data = {}, targets?: Selection[]) =>
      setAction({ id, params, targets: targets || Object.values(checked) }),
    [checked],
  );
  const openSelection = useCallback(
    (patch: Partial<Selection>) => {
      const next = normalizeSelection(patch);
      const found = sessionsRef.current.find(
        (s) => s.locator === next.locator && next.locator,
      );
      const id = found?.id || crypto.randomUUID();
      if (!found) {
        const list = [
          ...sessionsRef.current,
          {
            id,
            title: next.locator.split("/").pop() || next.slug || "Project",
            locator: next.locator,
            projectSlug: next.slug,
            imports: next.slug ? [next.slug] : [],
            selection: next,
          },
        ];
        sessionsRef.current = list;
        setSessions(list);
      }
      setActive(id);
      select(next);
      refresh();

    },
    [sessions, select, refresh, notify],
  );
  useEffect(() => {
    let dead = false;
    request(API + "/sessions")
      .then((data) => {
        if (dead) return;
        revisionRef.current = data.revision || 0;
        const list: Data[] = data.sessions || [];
        const explicit = route();
        const linked = Boolean(explicit.slug || explicit.locator || explicit.program);
        let current = linked
          ? list.find(s => explicit.locator ? s.locator === explicit.locator : (explicit.slug ? s.projectSlug === explicit.slug : s.program === explicit.program))
          : list.find(s => s.id === data.active) || list[0];
        if (linked && !current) {
          current = {id: crypto.randomUUID(), title: explicit.locator.split("/").pop() || explicit.program || explicit.slug,
            locator: explicit.locator, program: explicit.program, projectSlug: explicit.slug,
            selection: explicit, imports: explicit.slug ? [explicit.slug] : []};
          list.push(current);
        }
        setSessions(list);
        setActive(current?.id || "");
        if (!linked && current) setSelection(fromSession(current));
        setReady(true);
      })
      .catch((e) => {
        if (!dead) {
          setSessionError(e.message);
          setReady(true);
        }
      });
    return () => {
      dead = true;
    };
  }, []);
  useEffect(() => {
    if (!ready || (!selection.locator && !selection.slug)) return;
    const context = {locator: selection.locator, program: selection.program, slug: selection.slug};
    const key = JSON.stringify(context);
    if (preparedContexts.current.has(key)) return;
    preparedContexts.current.add(key);
    request(API + "/prepare", {method: "POST", body: JSON.stringify(context)})
      .then(result => notify("Project preparation accepted", "info", {target: context.locator || context.slug, preparationId: result.run?.id}))
      .catch(error => {preparedContexts.current.delete(key);notify("Project preparation could not start: " + error.message, "error");});
  }, [ready, selection.locator, selection.program, selection.slug, notify]);
  useEffect(() => {
    if (!ready) return;
    savePref("filter", filter);
  }, [ready, filter]);
  useEffect(() => {
    if (!ready || !active) return;
    setSessions((old) =>
      old.map((s) =>
        s.id === active && (!s.locator || s.locator === selection.locator)
          ? {
              ...s,
              locator: selection.locator || s.locator,
              program: selection.program,
              selection,
              imports: Array.from(
                new Set([...(s.imports || []), selection.slug].filter(Boolean)),
              ),
            }
          : s,
      ),
    );
  }, [selection, active, ready]);
  useEffect(() => {
    if (!ready) return;
    const timer = setTimeout(() => {
      const payload = { active, sessions };
      saveRef.current = saveRef.current.then(async () => {
        try {
          const result = await request(API + "/sessions", {
            method: "PUT",
            body: JSON.stringify({ ...payload, revision: revisionRef.current }),
          });
          revisionRef.current = result.revision || revisionRef.current;
          setSessionError("");
          if (result.merged || !payload.sessions.length) {
            setSessions((old) => {
              const remote: Data[] = result.sessions || [];
              const ids = new Set(old.map((s) => s.id));
              const next = [
                ...old.map((s) => {
                  const saved = remote.find((r) => r.id === s.id);
                  return saved
                    ? {
                        ...saved,
                        ...s,
                        imports: Array.from(
                          new Set([
                            ...(saved.imports || []),
                            ...(s.imports || []),
                          ]),
                        ),
                      }
                    : s;
                }),
                ...remote.filter((s) => !ids.has(s.id)),
              ];
              return JSON.stringify(next) === JSON.stringify(old) ? old : next;
            });
            if (!payload.sessions.length && result.active)
              setActive(result.active);
          }
        } catch (e) {
          setSessionError(String(e));
        }
      });
    }, 350);
    return () => clearTimeout(timer);
  }, [sessions, active, ready]);
  useEffect(() => {
    const pop = (event: PopStateEvent) => {
      const next = route();
      if (
        next.slug !== selectionRef.current.slug ||
        next.program !== selectionRef.current.program ||
        next.locator !== selectionRef.current.locator
      )
        setChecked({});
      selectionRef.current = next;
      activateContext(next);
      setSelection(next);
      if (event.state) {
        setFilter(event.state.filter || "");
        setRecordFilter(event.state.recordFilter || "all");
        setOffset(event.state.offset || 0);
        requestAnimationFrame(() => {
          const main = document.querySelector("main");
          if (main) main.scrollTop = event.state.scroll || 0;
        });
      }
    };
    window.addEventListener("popstate", pop);
    return () => window.removeEventListener("popstate", pop);
  }, []);
  useEffect(() => {
    if (!ready) return;
    const params = new URLSearchParams(location.search);
    let id =
      params.get("window") ||
      params.get("focus") ||
      params.get("tool") ||
      location.hash.slice(1);
    id = id.replace(/^wb-/, "");
    const aliases: Data = {
      fnbrowse: "listing",
      functions: "listing",
      corpus: "overview",
      match: "knowledge",
      stabs: "types",
      report: "exports",
      recover: "recovery",
    };
    if (id) setTimeout(() => jump(aliases[id] || id), 300);
  }, [ready]);
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      if (pollRef.current) return;
      pollRef.current = true;
      try {
        const [response, batchResponse] = await Promise.all([
          request("/dashboard/api/jobs"),
          request("/api/v1/batches"),
        ]);
        if (stopped) return;
        const list = response.jobs || [];
        setJobs(list);
        setBatches(batchResponse.batches || []);
        setConnection("Connected");
        for (const job of list) {
          const prior = jobsSnapshot.current[job.id];
          if (prior !== job.status) {
            notify(
              `${job.title || job.actionId}: ${job.status}`,
              job.status === "failed" ? "error" : "info",
              {
                jobId: job.id,
                action: job.actionId,
                target: job.params?.program || job.params?.slug,
                status: job.status,
              },
            );
            if (!["running", "queued", "cancelling"].includes(job.status)) {
              const current = selectionRef.current;
              if (
                !job.params?.slug ||
                job.params.slug === current.slug ||
                job.params.program === current.program
              )
                refresh();
            }
          }
          jobsSnapshot.current[job.id] = job.status;
        }
      } catch {
        if (!stopped) setConnection("Disconnected · retrying");
      } finally {
        pollRef.current = false;
        if (!stopped) timer = setTimeout(poll, document.hidden ? 10000 : 2000);
      }
    }
    poll();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [notify, refresh]);
  useEffect(() => {
    function keyboard(e: KeyboardEvent) {
      const typing = (e.target as HTMLElement).matches(
        "input,textarea,select,[contenteditable=true]",
      );
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((x) => !x);
        return;
      }
      if (e.key === "Escape") {
        setPalette(false);
        setMenu("");
        setContext(null);
        return;
      }
      if (typing || dialog || action || palette) return;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        save();
      }
    }
    window.addEventListener("keydown", keyboard);
    return () => window.removeEventListener("keydown", keyboard);
  }, [dialog, action, palette, selection]);
  function toggle(row: Data) {
    const target = {
      ...selection,
      addr: String(row.addr),
      logicalId: String(row.logicalId || ""),
    };
    const key = functionKey(target);
    setChecked((old) => {
      const next = { ...old };
      if (next[key]) delete next[key];
      else next[key] = target;
      return next;
    });
  }
  async function save() {
    const snapshot = { active, sessions: sessionsRef.current };
    saveRef.current = saveRef.current.then(async () => {
      try {
        const result = await request(API + "/sessions", {
          method: "PUT",
          body: JSON.stringify({ ...snapshot, revision: revisionRef.current }),
        });
        revisionRef.current = result.revision || revisionRef.current;
        setSessionError("");
        notify("Workspace saved.", "info", {
          target: selection.locator || selection.slug,
          result: { revision: result.revision },
        });
      } catch (e) {
        setSessionError(String(e));
        notify(String(e), "error");
      }
    });
    await saveRef.current;
  }
  function selectedSession(id: string) {
    setActive(id);
    const s = sessions.find((s) => s.id === id);
    if (s) select(fromSession(s));
  }
  const onBrowseFunctions = (scope: {
    slugs: string[];
    program?: string;
    locator?: string;
    filter: string;
  }) => {
    select({
      slug: scope.slugs[0] || "",
      program: scope.program || "",
      locator: scope.locator || "",
      addr: "",
      logicalId: "",
    });
    setRecordFilter(scope.filter);
    setFilter("");
    setOffset(0);
  };
  const surfaceProps = {
    selection,
    onSelect: select,
    onAction,
    notify,
    revision,
    onBrowseFunctions,
  };
  const batchCount = Object.keys(checked).length;
  return (
    <div
      className={"app " + density}
      style={
        {
          "--explorer": layout.showExplorer ? layout.explorer + "px" : "0px",
          "--inspector": layout.showInspector ? layout.inspector + "px" : "0px",
          "--dock": layout.showDock ? layout.dock + "px" : "28px",
        } as React.CSSProperties
      }
    >
      <a className="skip-link" href="#function-list">
        Skip to functions
      </a>
      <header className="chrome">
        <strong className="brand">AgentDecompile</strong>
        <span className="divider" />
        {["File", "View", "Analyze"].map((name) => (
          <div className="menu" key={name}>
            <button
              aria-expanded={menu === name}
              onClick={() => setMenu(menu === name ? "" : name)}
            >
              {name}
            </button>
            {menu === name && (
              <div className="popup">
                {name === "File" ? (
                  <>
                    {(
                      [
                        "open",
                        "create",
                        "import",
                        "copy",
                        "connection",
                      ] as const
                    ).map((mode) => (
                      <button
                        key={mode}
                        onClick={() => {
                          setDialog(mode);
                          setMenu("");
                        }}
                      >
                        {
                          {
                            open: "Open project…",
                            create: "Create project…",
                            import: "Import binaries…",
                            copy: "Copy project…",
                            connection: "Save connection…",
                          }[mode]
                        }
                      </button>
                    ))}
                    <button
                      onClick={() => {
                        save();
                        setMenu("");
                      }}
                    >
                      Save workspace <kbd>Ctrl S</kbd>
                    </button>
                  </>
                ) : name === "View" ? (
                  <>
                    <button
                      onClick={() =>
                        setDensity(density === "compact" ? "roomy" : "compact")
                      }
                    >
                      Use {density === "compact" ? "roomy" : "compact"} layout
                    </button>
                    {(
                      ["showExplorer", "showInspector", "showDock"] as const
                    ).map((key) => (
                      <button
                        key={key}
                        onClick={() =>
                          setLayout((x) => ({ ...x, [key]: !x[key] }))
                        }
                      >
                        {layout[key] ? "Hide" : "Show"} {{showExplorer:"project explorer",showInspector:"evidence inspector",showDock:"Activity dock"}[key]}
                      </button>
                    ))}
                    <button
                      onClick={() => {
                        setLayout({
                          explorer: 320,
                          dock: 200,
                          inspector: 300,
                          tree: 200,
                          showExplorer: true,
                          showInspector: false,
                          showDock: true,
                        });
                        Object.keys(localStorage)
                          .filter((k) => k.startsWith("ad.react.height."))
                          .forEach((k) => localStorage.removeItem(k));
                        location.reload();
                      }}
                    >
                      Reset layout
                    </button>
                  </>
                ) : (
                  <>
                    {[
                      {id:"mcp.decompile-function",label:"Decompile selected function",enabled:Boolean(selection.addr)},
                      {id:"corpus.bsim-report",label:"Review cross-build matches",enabled:Boolean(selection.slug||selection.locator)},
                      {id:"corpus.bsim-ingest",label:"Index project for matching",enabled:Boolean(selection.locator||selection.slug)},
                      {id:"corpus.ghidra-bulk",label:"Generate compiling C",enabled:Boolean(selection.slug)},
                      {id:"corpus.cross-place",label:"Share source with related builds",enabled:Boolean(selection.slug)},
                      {id:"corpus.objdiff-check",label:"Verify compiled bytes",enabled:Boolean(selection.slug)},
                    ].map(({id,label,enabled})=><button key={id} disabled={!enabled} onClick={()=>{onAction(id);setMenu("");}}>{label}</button>)}
                    <hr />
                    <button onClick={()=>{setPalette(true);setMenu("");}}>Find another command…</button>
                  </>
                )}
              </div>
            )}
          </div>
        ))}
        <button onClick={() => setPalette(true)}>
          Commands <kbd>Ctrl K</kbd>
        </button>
        <span className="muted connection">{connection}</span>
      </header>
      <div
        className="project-tabs"
        role="tablist"
        aria-label="Project sessions"
      >
        {sessions.filter(s=>!s.hidden).map((s) => (
          <div
            className={"session " + (active === s.id ? "selected" : "")}
            {...libraryTransfer.dropProps(s.locator)}
            key={s.id}
          >
            <button
              role="tab"
              aria-selected={active === s.id}
              onClick={() => selectedSession(s.id)}
              onDoubleClick={() => {
                const title = window.prompt("Project tab name", s.title);
                if (title)
                  setSessions((old) =>
                    old.map((x) => (x.id === s.id ? { ...x, title } : x)),
                  );
              }}
            >
              {s.title || "Project"}
            </button>
            <button
              aria-label={"Close " + s.title}
              onClick={() => {
                setSessions((old) => old.filter((x) => x.id !== s.id));
                if (s.id === active) {
                  const other = sessions.find((x) => x.id !== s.id);
                  setActive(other?.id || "");
                  select(other ? fromSession(other) : emptySelection);
                }
              }}
            >
              ×
            </button>
          </div>
        ))}
        <button
          aria-label="Open another project"
          onClick={() => setDialog("open")}
        >
          ＋
        </button>
        <span className="project-path" title={selection.locator}>
          {selection.locator || "Open a project or import binaries"}
        </span>
      </div>
      {sessionError && (
        <div className="error">
          Session state: {sessionError}{" "}
          <button onClick={() => setSessions([...sessions])}>Retry save</button>
        </div>
      )}
      {libraryTransfer.confirmation}
      <div className="work-area">
        <aside className="explorer" hidden={!layout.showExplorer}>
          <PersistentExplorer onProjectVisibility={projectVisibility} notify={notify} libraryLoading={binaries.loading} libraryError={binaries.error} builds={binaries.data.binaries || []} projects={sessions} unresolved={binaries.data.unresolvedBinaries || []}
            selection={selection} onSelect={select} onAdd={libraryTransfer.stage} dropProps={libraryTransfer.dropProps} revision={revision} recordFilter={recordFilter} onRecordFilterChange={setRecordFilter} functionQuery={filter} onFunctionQueryChange={setFilter}
            onImport={()=>setDialog("import")} onCreate={()=>setDialog("create")}
            checkedFunctions={row=>Boolean(checked[functionKey({...selection,addr:row.addr})])}
            onCheckFunction={(row,shift,range)=>{
              if(shift && range?.length){setChecked(old=>{const next={...old};for(const item of range){const target={...selection,addr:item.addr,logicalId:String(item.logicalId||"")};next[functionKey(target)]=target;}return next;});}
              else toggle(row);
            }}
            onFunctionContextMenu={(event,row)=>{event.preventDefault();setContext({x:event.clientX,y:event.clientY,target:{...selection,addr:row.addr,logicalId:String(row.logicalId||"")},kind:"function"});}}
            functionToolbar={batchCount>0?<div className="checked-info">{batchCount} functions checked <button onClick={()=>setChecked({})}>Clear</button><button onClick={()=>setPalette(true)}>Run command on {batchCount}</button></div>:undefined}
          />
        </aside>
        {layout.showExplorer && (
          <ResizeBar
            axis="x"
            label="Resize explorer"
            onResize={(d) =>
              setLayout((x) => ({
                ...x,
                explorer: Math.max(240, Math.min(560, x.explorer + d)),
              }))
            }
          />
        )}
        <main>
          <nav className="section-index" aria-label="Workspace sections">
            {workspaceNavigation.map(({id,label})=><button key={id} onClick={()=>jump(id)}>{label}</button>)}
            {selection.slug && <SourceDownload selection={selection} notify={notify} />}
          </nav>
          <WorkbenchSurfaces {...surfaceProps} inspectTools={<CodeBrowser {...surfaceProps} />} preparationTools={<PreparationActivity {...surfaceProps} />} />
          <details className="workspace-reference"><summary>Reversing workflows</summary><section id="guide">
            <GuideWorkflows {...surfaceProps} />
          </section>
          </details><details className="workspace-reference"><summary>All commands</summary><section id="commands" tabIndex={-1}>
            <Commands {...surfaceProps} />
          </section></details>
        </main>
        {layout.showInspector && (
          <>
            <ResizeBar
              axis="x"
              label="Resize evidence inspector"
              onResize={(d) =>
                setLayout((x) => ({
                  ...x,
                  inspector: Math.max(220, Math.min(600, x.inspector - d)),
                }))
              }
            />
            <aside className="inspector">
              <header>
                <h2>Evidence inspector</h2>
                <button
                  aria-label="Hide evidence inspector"
                  onClick={() =>
                    setLayout((x) => ({ ...x, showInspector: false }))
                  }
                >
                  ×
                </button>
              </header>
              <EvidenceInspector {...surfaceProps} />
            </aside>
          </>
        )}
      </div>
      <ResizeBar
        axis="y"
        label="Resize Activity dock"
        onResize={(d) =>
          setLayout((x) => ({
            ...x,
            showDock: true,
            dock: Math.max(100, Math.min(650, x.dock - d)),
          }))
        }
      />
      <section className="activity" aria-label="Activity dock"><UnifiedActivity jobs={jobs} events={events} batches={batches} expanded={layout.showDock} onToggle={()=>setLayout(x=>({...x,showDock:!x.showDock}))} notify={notify} onRetry={job=>setAction({id:job.actionId,params:job.params,targets:[recordedSelection(job,selection)]})} onRetryBatch={batch=>setAction({id:batch.action,params:batch.results[0]?.params,targets:batch.results.filter((row:Data)=>row.status!=='ok').map((row:Data)=>row.context)})}/></section>
      <footer>
        <span>
          {selection.program || selection.slug || "No program selected"}
        </span>
        <code>{selection.addr}</code>
        <span>{connection}</span>
      </footer>
      <div className="sr-only" aria-live="polite">
        {events.at(-1)?.message}
      </div>
      {palette && (
        <div className="modal-backdrop" onClick={() => setPalette(false)}>
          <div
            className="palette"
            role="dialog"
            aria-modal="true"
            aria-label="Command palette"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Tab") {
                const items = Array.from(
                  e.currentTarget.querySelectorAll<HTMLElement>(
                    "input,button:not(:disabled)",
                  ),
                );
                const first = items[0],
                  last = items.at(-1);
                if (e.shiftKey && document.activeElement === first) {
                  e.preventDefault();
                  last?.focus();
                } else if (!e.shiftKey && document.activeElement === last) {
                  e.preventDefault();
                  first?.focus();
                }
              }
            }}
          >
            <input
              autoFocus
              aria-label="Search commands and sections"
              value={paletteQuery}
              onChange={(e) => setPaletteQuery(e.target.value)}
              placeholder="Find an action or section…"
            />
            <button onClick={() => setPalette(false)}>Close</button>
            <div className="palette-results">
              {Object.keys(sectionNames)
                .filter((id) => (id+" "+sectionNames[id]).toLowerCase().includes(paletteQuery.toLowerCase()))
                .map((id) => (
                  <button
                    key={id}
                    onClick={() => {
                      setPalette(false);
                      jump(id);
                    }}
                  >
                    Go to {sectionNames[id]}
                  </button>
                ))}
              {(catalog.data.actions || [])
                .filter((a: Data) =>
                  (a.id + " " + a.title)
                    .toLowerCase()
                    .includes(paletteQuery.toLowerCase()),
                )
                .slice(0, 60)
                .map((a: Data) => (
                  <button
                    key={a.id}
                    onClick={() => {
                      setPalette(false);
                      onAction(a.id);
                    }}
                  >
                    {a.title} <code>{a.id}</code>
                  </button>
                ))}
              <button
                onClick={() => {
                  setPalette(false);
                  jump("commands");
                }}
              >
                Browse all commands
              </button>
            </div>
          </div>
        </div>
      )}
      {context && (
        <div className="context-catcher" onClick={() => setContext(null)}>
          <div
            className="popup context-popup"
            style={{
              left: Math.min(context.x, innerWidth - 240),
              top: Math.min(context.y, innerHeight - 180),
            }}
          >
            {[
              "mcp.decompile-function",
              "mcp.rename-function",
              "mcp.get-references",
            ].map((id) => (
              <button
                key={id}
                onClick={() => {
                  setAction({
                    id,
                    params: { addr: context.target.addr },
                    targets: [context.target],
                  });
                  setContext(null);
                }}
              >
                {id.split(".").pop()}
              </button>
            ))}
            <button
              onClick={() =>
                navigator.clipboard
                  .writeText(context.target.addr)
                  .then(() => notify("Address copied"))
              }
            >
              Copy address
            </button>
          </div>
        </div>
      )}
      <ActionRunner
        request={action}
        selection={selection}
        onClose={() => setAction(null)}
        notify={notify}
        onSubmitted={() => refresh()}
      />
      <ProjectDialog
        mode={dialog}
        selection={selection}
        onClose={() => setDialog(null)}
        onSelect={openSelection}
        notify={notify}
        onRefresh={refresh}
      />
    </div>
  );
}
