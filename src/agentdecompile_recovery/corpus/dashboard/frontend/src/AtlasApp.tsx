import {UnifiedActivity} from './UnifiedActivity';
import {SourceDownload} from './SourceDownload';
import {SourceEditor,sourceWitness,sourceExtent,useFunctionEvidence} from './SourceEditor';
import { useCallback, useEffect, useRef, useState } from "react";
import {
  API,
  emptySelection,
  normalizeSelection,
  query,
  request,
  recordedSelection,
  type Data,
  type Selection,
  type ActionRequest,
} from "./contracts";
import { Commands, ActionRunner, DialogFrame } from "./Actions";
import { ProjectDialog } from "./ProjectDialog";
import { RecordView, ResizeBar, useData, usePref } from "./ui";
import "./atlas.css";
import { GuideWorkflows } from "./GuideWorkflows";
import { CodeBrowser } from "./CodeBrowser";
import { BinaryEvidenceWorkspace, RecoveryWorkspace } from "./Surfaces";
import { useLibraryTransfer } from "./BinaryLibrary";
import { AtlasAnalysis } from "./AtlasAnalysis";
import { PersistentExplorer } from "./PersistentExplorer";
import { PreparationProgress, selectPreparation } from "./PreparationActivity";
const number = (value: unknown) =>
  typeof value === "number" ? value.toLocaleString() : "—";
const title = (s: Partial<Selection>) =>
  (s.program || s.locator || s.slug || "Project").split("/").pop();
const isActiveStage = (stage?: Data) =>
  Boolean(stage && ["queued", "running", "waiting", "cancelling"].includes(String(stage.status)));
const measuredStage = (stage?: Data) => {
  const progress = stage?.workProgress || stage || {};
  return Number.isFinite(progress.total) && progress.total > 0 &&
    Number.isFinite(progress.completed) && progress.completed >= 0 && progress.completed <= progress.total
    ? progress as Data : undefined;
};
function RecoveryBrief({run, related}: {run?: Data; related: Data[]}) {
  const stages: Data[] = run?.stages || [];
  const current = stages.find(stage => ["running", "waiting", "cancelling"].includes(String(stage.status))) ||
    stages.find(stage => stage.status === "queued");
  const next = stages.find(stage => stage !== current && stage.status === "queued");
  const matching = stages.find(stage => stage.key === "matching");
  const byteAudit = stages.find(stage => stage.key === "verify-byte-accuracy");
  const progress = measuredStage(current);
  const auditStatus = String(byteAudit?.status || "queued");
  const auditLabel = auditStatus === "completed" ? "Byte audit completed — review its receipt" :
    auditStatus === "running" ? "Byte audit running" :
    auditStatus === "blocked" || auditStatus === "failed" ? "Byte audit blocked" :
    "Byte audit queued";
  const auditDetail = auditStatus === "completed"
    ? "A completion record exists. Byte identity is established only by an accepted comparison receipt."
    : auditStatus === "blocked" || auditStatus === "failed"
      ? String(byteAudit?.reason || byteAudit?.error || "A required compiler, comparison input, or receipt is unavailable.")
      : "It will compile the recovered source, compare the result with original bytes, and store an independent comparison receipt.";
  const matchingProgress = measuredStage(matching);
  return <>
    <section className="atlas-recovery-brief" aria-label="Live recovery status">
      <header>
        <div><span>LIVE RECOVERY</span><strong>{run ? "Workflow state from the active coordinator" : "Waiting for a workflow record"}</strong></div>
        <span className={`atlas-stage-badge state-${String(current?.status || run?.status || "unknown")}`}>{current?.status || run?.status || "waiting"}</span>
      </header>
      <div className="atlas-recovery-grid">
        <article>
          <span>NOW</span>
          <strong>{current?.title || "Checking project state"}</strong>
          {current?.currentProgram || run?.currentProgram ? <code>{current?.currentProgram || run?.currentProgram}</code> : <small>{current?.reason || "The coordinator will reuse recorded analysis before scheduling new work."}</small>}
          {progress ? <><progress value={progress.completed} max={progress.total} aria-label={`${current?.title}: ${progress.completed} of ${progress.total}`} /><small>{progress.completed} / {progress.total} {progress.unit || "items"}{progress.currentTarget ? ` · ${progress.currentTarget}` : ""}</small></> : isActiveStage(current) ? <><progress aria-label={`${current?.title || "Current stage"}: activity in progress`} /><small>{current?.reason || "Work is active; this operation does not expose a completed/total count yet."}</small></> : <small>{current?.reason || "No work has been admitted for this selection."}</small>}
        </article>
        <article>
          <span>RELATIONSHIPS</span>
          <strong>{matching?.status === "completed" ? `${related.length} related build${related.length === 1 ? "" : "s"} available` : matching?.status === "running" ? "Cross-matching in progress" : "Cross-matching queued"}</strong>
          {matchingProgress ? <><progress value={matchingProgress.completed} max={matchingProgress.total} aria-label={`Cross-matching: ${matchingProgress.completed} of ${matchingProgress.total}`} /><small>{matchingProgress.completed} / {matchingProgress.total} {matchingProgress.unit || "comparisons"}</small></> : <small>{matching?.reason || "Function facts and stable identities are collected before related builds are compared."}</small>}
        </article>
        <article className={`atlas-byte-gate state-${auditStatus}`}>
          <span>BYTE PROOF GATE</span>
          <strong>{auditLabel}</strong>
          <small>{auditDetail}</small>
        </article>
      </div>
      {next && <footer>Next: <strong>{next.title}</strong>{next.reason ? ` · ${next.reason}` : ""}</footer>}
    </section>
  </>;
}
function ActivityJob({
  summary,
  notify,
  onRetry,
  selected=false,
  visible=true,
}: {
  onRetry: (job:Data)=>void;
  selected?:boolean;
  visible?:boolean;
  summary: Data;
  notify: (message: string, level?: string) => void;
}) {
  const [expanded, setExpanded] = useState(selected),
    [job, setJob] = useState<Data>(summary),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false);
  useEffect(()=>{if(selected)setExpanded(true);},[selected]);
  useEffect(() => {
    if (!expanded||!visible) return;
    setLoading(true);
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const controller = new AbortController();
    async function poll() {
      try {
        const result = await request(
          "/dashboard/api/jobs/" + encodeURIComponent(summary.id),
          { signal: controller.signal },
        );
        if (!alive) return;
        setJob(result.job);
        setLoading(false);
        setError("");
        if (["queued", "running", "cancelling"].includes(result.job.status))
          timer = setTimeout(poll, 1500);
      } catch (e) {
        if (alive) {
          setLoading(false);
          setError(e instanceof Error ? e.message : String(e));
          if (["queued", "running", "cancelling"].includes(summary.status))
            timer = setTimeout(poll, 3000);
        }
      }
    }
    void poll();
    return () => {
      alive = false;
      controller.abort();
      clearTimeout(timer);
    };
  }, [expanded, visible, summary.id, summary.status]);
  return (
    <details open={expanded} onToggle={(e) => setExpanded(e.currentTarget.open)}>
      <summary>
        {summary.title || summary.actionId} · {summary.status}
      </summary>
      {expanded && (
        <>
          <p>
            {job.params?.programPath ||
              job.params?.program ||
              job.params?.slug ||
              "Target not recorded"}{" "}
            · Job {summary.id}
          </p>
          {error && <p role="alert">{error}</p>}
          {["failed", "cancelled", "interrupted"].includes(job.status) && <button onClick={()=>onRetry(job)}>Retry with recorded parameters</button>}
          {["queued", "running", "cancelling"].includes(job.status) && (
            <button
              disabled={job.status === "cancelling"}
              onClick={() =>
                request(
                  "/dashboard/api/jobs/" +
                    encodeURIComponent(summary.id) +
                    "/cancel",
                  { method: "POST" },
                )
                  .then(() => {
                    setJob((j) => ({ ...j, status: "cancelling" }));
                    notify(
                      "Cancellation requested. Completed changes are not rolled back.",
                    );
                  })
                  .catch((e) => notify(e.message, "error"))
              }
            >
              Request cancellation
            </button>
          )}
          <pre>
            {loading && !Object.hasOwn(job, "log")
              ? "Loading job output…"
              : job.log || job.error || "No output recorded."}
          </pre>
          <details>
            <summary>Parameters and result metadata</summary>
            <RecordView
              value={{
                params: job.params,
                result: job.result,
                returncode: job.returncode,
              }}
            />
          </details>
        </>
      )}
    </details>
  );
}
function atlasUrl(selection?: Selection) {
  const params = new URLSearchParams(selection ? query(selection) : "");
  const mode = new URLSearchParams(location.search).get("mode");
  if (mode) params.set("mode", mode);
  return location.pathname + (params.size ? "?" + params.toString() : "");
}
export function AtlasApp() {
  const [selection, setSelection] = usePref<Selection>("atlas.selection",emptySelection),
    [loaded, setLoaded] = useState(false),
    [view, setView] = useState("overview"),
    [search, setSearch] = useState(""),
    [offset, setOffset] = useState(0),
    [revision, setRevision] = useState(0);
  const [explorerWidth,setExplorerWidth]=usePref("atlas.explorer-width",320);
  const [dialog, setDialog] = useState<
      "open" | "create" | "copy" | "connection" | "import" | null
    >(null),
    [runs, setRuns] = useState<Data[]>([]),
    [jobs, setJobs] = useState<Data[]>([]),
    [batches,setBatches]=useState<Data[]>([]),
    [connection, setConnection] = useState("Connecting"),
    [prepareError, setPrepareError] = useState("");
  const [preparationFeedError,setPreparationFeedError]=useState("");
  const [lastPreparationAt,setLastPreparationAt]=useState(0);
  const [messages,setMessages]=usePref<Data[]>('atlas.activity',[]);
  const [activityOpen,setActivityOpen]=usePref('atlas.dock-open',true);
  const [dockHeight,setDockHeight]=usePref('atlas.dock-height',220);
  const [dockTab,setDockTab]=usePref('atlas.dock-tab','logs');
  const [seenAt,setSeenAt]=usePref('atlas.activity-seen',0);
  const [selectedJob,setSelectedJob]=useState('');
  const jobStatuses=useRef<Record<string,string>>({});
  const [recordFilter, setRecordFilter] = useState("all");
  const [toolsOpen, setToolsOpen] = useState(false),
    [action, setAction] = useState<ActionRequest | null>(null);
  const pendingJobs = useRef(new Set<string>());
  const openKey = useRef("");
  const mounted = useRef(true);
  const prepared = useRef(new Set<string>());
  const notify = useCallback(
    (message: string, level = "info", metadata:Data={}) =>
      setMessages((old) =>
        [...old, { ...metadata,id:crypto.randomUUID(),message,level,at:Date.now() }].slice(-500),
      ),
    [],
  );
  const refresh = useCallback(() => setRevision((v) => v + 1), []);
  const binaries = useData(API + "/binaries", revision),
    sessions = useData(API + "/sessions", revision);
  const detailResponse = useFunctionEvidence(
    loaded && selection.addr ? API + "/function?" + query(selection) : null,
    revision,
  );
  const detail = detailResponse.data.listing
    ? {
        ...detailResponse.data,
        ...detailResponse.data.listing,
        function: detailResponse.data.selected,
      }
    : detailResponse.data;
  const open = useCallback(
    (patch: Partial<Selection>) => {
      const next = normalizeSelection(patch);
      openKey.current = JSON.stringify([next.locator, next.program, next.slug]);
      setSelection(next);
      setLoaded(true);
      setView(next.addr?"functions":"overview");
      setOffset(0);
      setSearch("");
      setRecordFilter("all");
      setPrepareError("");
      history.replaceState(null, "", atlasUrl(next));
      if (next.locator)
        request(API + "/sessions")
          .then((data) => {
            const list: Data[] = data.sessions || [];
            const existing = list.find((s) => s.locator === next.locator);
            const id = existing?.id || crypto.randomUUID();
            const item = {
              ...existing,
              hidden: false,
              id,
              title: existing?.title || title(next),
              locator: next.locator,
              program: next.program,
              projectSlug: existing?.projectSlug || next.slug,
              selection: next,
              imports: Array.from(
                new Set(
                  [...(existing?.imports || []), next.slug].filter(Boolean),
                ),
              ),
            };
            return request(API + "/sessions", {
              method: "PUT",
              body: JSON.stringify({
                revision: data.revision,
                active: id,
                sessions: [...list.filter((s) => s.id !== id), item],
              }),
            });
          })
          .then(refresh)
          .catch((e) =>
            notify(
              "Project opened, but recent-project state could not be saved: " +
                e.message,
              "error",
            ),
          );
      const key = JSON.stringify([next.locator, next.program, next.slug]);
      if (!prepared.current.has(key)) {
        prepared.current.add(key);
        request(API + "/prepare", {
          method: "POST",
          body: JSON.stringify(next),
        })
          .then(() => refresh())
          .catch((e) => {
            prepared.current.delete(key);
            if (mounted.current && openKey.current === key)
              setPrepareError(e.message);
          });
      }
    },
    [refresh, notify],
  );
  useEffect(() => {
    mounted.current = true;
    const q = new URLSearchParams(location.search);
    if (q.get("slug") || q.get("program") || q.get("locator"))
      open({
        slug: q.get("slug") || "",
        program: q.get("program") || "",
        locator: q.get("locator") || "",
        addr: q.get("addr") || "",
        logicalId: q.get("logical_id") || "",
      });
    else if(selection.slug||selection.program||selection.locator) open(selection);
    return () => {
      mounted.current = false;
    };
  }, [open]);
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    let signature = "";
    async function poll() {
      try {
        const [preparationsResult, jobsResult] = await Promise.allSettled([
          request(API + "/preparations", {signal: AbortSignal.timeout(8000)}).then(data=>{
            if(!stopped){setRuns(data.runs||[]);setLastPreparationAt(Date.now());setPreparationFeedError("");}
            return data;
          }),
          request("/dashboard/api/jobs", {signal: AbortSignal.timeout(8000)}).then(data=>{
            if(!stopped)setJobs(data.jobs||[]);
            return data;
          }),
          request('/api/v1/batches',{signal:AbortSignal.timeout(8000)}).then(data=>{if(!stopped)setBatches(data.batches||[]);return data;}),
        ]);
        if (stopped) return;
        const p=preparationsResult.status==='fulfilled'?preparationsResult.value:null;
        const j=jobsResult.status==='fulfilled'?jobsResult.value:null;
        if(!p)setPreparationFeedError("Preparation updates unavailable. Showing the last received state.");
        for (const job of j?.jobs || []) {
          const previous=jobStatuses.current[job.id];
          if((previous&&previous!==job.status)||(!previous&&pendingJobs.current.has(job.id)&&!['queued','running','cancelling'].includes(job.status)))notify(`${job.title||job.actionId}: ${job.status}`,job.status==='failed'?'error':'info',{jobId:job.id,status:job.status,action:job.actionId,target:job.params?.programPath||job.params?.program||job.params?.slug});
          jobStatuses.current[job.id]=job.status;
          if (
            pendingJobs.current.has(job.id) &&
            !["queued", "running", "cancelling"].includes(job.status)
          ) {
            pendingJobs.current.delete(job.id);
            refresh();
          }
        }
        setConnection(p&&j?"Live":p?"Job updates unavailable":j?"Preparation updates unavailable":"Reconnecting");
        const next = JSON.stringify(
          (p?.runs || []).map((r: Data) => [
            r.id,
            r.status,
            (r.stages || []).map((s: Data) => [s.key, s.status, s.completed, s.total]),
          ]),
        );
        if (p && signature && signature !== next) refresh();
        if(p)signature = next;
      } catch {
        if (!stopped) setConnection("Reconnecting");
      } finally {
        if (!stopped) timer = setTimeout(poll, document.hidden ? 8000 : 2000);
      }
    }
    poll();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [refresh,notify]);
  useEffect(() => {
    document.querySelector(".atlas-shell")?.scrollTo({ top: 0 });
  }, [view, loaded]);
  const builds: Data[] = binaries.data.binaries || [];
  const libraryTransfer = useLibraryTransfer(builds, notify);
  const build = builds.find((b) => b.slug === selection.slug);
  const related = build ? builds.filter((b) => b.game === build.game) : [];
  const matchedRun = selectPreparation(runs, selection);
  const run: Data | undefined = matchedRun ? {...matchedRun, stages:(matchedRun.stages||[]).map((stage:Data)=>{
    const job=jobs.find((item)=>item.id===stage.jobId);
    return job?{...stage,jobStatus:job.status,currentAction:job.title||job.actionId,currentProgram:job.params?.programPath||job.params?.program||stage.currentProgram,startedAt:job.startedAt||stage.startedAt}:stage;
  })}:undefined;
  const source = sourceWitness(detail);
  const graph = detail.graph || {};
  const selectedName =
    detail.function?.name || detail.selected?.name || selection.addr;
  const selectContext = (patch: Partial<Selection>) => {
    const changed = (patch.slug !== undefined && patch.slug !== selection.slug) ||
      (patch.program !== undefined && patch.program !== selection.program) ||
      (patch.locator !== undefined && patch.locator !== selection.locator);
    const next = normalizeSelection({...selection,...(changed ? {addr:'',logicalId:''}:{}),...patch});
    if (changed) {setOffset(0);setSearch('');}
    const url=atlasUrl(next);
    if(url!==location.pathname+location.search){
      const scroll=document.querySelector('.atlas-shell')?.scrollTop||0;
      history.replaceState({...history.state,atlas:{view,search,offset,recordFilter,scroll}},'',location.href);
      history.pushState({atlas:{view,search:changed?'':search,offset:changed?0:offset,recordFilter,scroll}},'',url);
    }
    setSelection(next);
  };
  useEffect(()=>{
    const restore=(event:PopStateEvent)=>{
      const params=new URLSearchParams(location.search);
      const next=normalizeSelection({slug:params.get('slug')||'',program:params.get('program')||'',locator:params.get('locator')||'',addr:params.get('addr')||'',logicalId:params.get('logical_id')||''});
      setSelection(next);setLoaded(Boolean(next.slug||next.program||next.locator));
      const saved=event.state?.atlas;
      if(saved){setView(saved.view||'overview');setSearch(saved.search||'');setOffset(saved.offset||0);setRecordFilter(saved.recordFilter||'all');requestAnimationFrame(()=>document.querySelector('.atlas-shell')?.scrollTo({top:saved.scroll||0}));}
      // Navigation restores context only. Previously admitted work keeps running.
    };
    window.addEventListener('popstate',restore);return()=>window.removeEventListener('popstate',restore);
  },[]);
  async function projectVisibility(record:Data,hidden:boolean) {
    const snapshot=await request(API+'/sessions');
    const items:Data[]=snapshot.sessions||[];
    const next=items.map(item=>item.locator===record.locator?{...item,hidden}:item);
    if(!next.some(item=>item.locator===record.locator))next.push({...record,id:record.id||crypto.randomUUID(),hidden});
    let nextActive=snapshot.active;
    if(hidden&&items.find(item=>item.id===snapshot.active)?.locator===record.locator){let fallback=next.find(item=>!item.hidden);if(!fallback){fallback={id:crypto.randomUUID(),title:'Untitled',locator:'',imports:[],selection:emptySelection};next.push(fallback);}nextActive=fallback.id;}
    await request(API+'/sessions',{method:'PUT',body:JSON.stringify({revision:snapshot.revision,active:nextActive,sessions:next})});
    if(hidden&&selection.locator===record.locator){setSelection(emptySelection);setLoaded(false);history.replaceState(null,'',atlasUrl());}
    refresh();notify(hidden?'Project removed from workspace. Files and background work remain available.':'Project restored to workspace.','info',{target:record.locator});
  }
  const submitted = (data: Data) => {
    if (data.job?.id) pendingJobs.current.add(data.job.id);
    refresh();
  };
  const surfaceProps = {
    selection,
    onSelect: selectContext,
    onInspectSource: () => setView("functions"),
    onAction: (id: string, params: Data = {}, targets?: Selection[]) =>
      setAction({ id, params, targets: targets || [{ ...selection }] }),
    notify,
    revision,
    onBrowseFunctions: (scope: {
      slugs: string[];
      program?: string;
      locator?: string;
      filter: "all" | "named" | "bound" | "real-c";
    }) => {
      setSelection({
        ...emptySelection,
        slug: scope.slugs[0] || "",
        program: scope.program || "",
        locator: scope.locator || "",
      });
      setSearch("");
      setOffset(0);
      setRecordFilter(scope.filter);
      setView("functions");
    },
  };
  const [editorSurface,setEditorSurface]=usePref('atlas.editor-surface','source');
  const activeStage=run?.stages?.find((stage:Data)=>['running','waiting','cancelling'].includes(stage.status));
  const workflowSummary=activeStage?.title||run?.stages?.find((stage:Data)=>stage.status==='blocked')?.reason||run?.status||'Reading workflow…';
  async function saveWorkspace(){try{const snapshot=await request(API+'/sessions');const existing=(snapshot.sessions||[]).find((item:Data)=>item.locator===selection.locator&&(selection.locator||item.selection?.slug===selection.slug));const record={...(existing||{id:crypto.randomUUID(),title:title(selection),locator:selection.locator}),selection,program:selection.program,hidden:false,imports:[...new Set([...(existing?.imports||[]),selection.slug].filter(Boolean))]};await request(API+'/sessions',{method:'PUT',body:JSON.stringify({revision:snapshot.revision,active:record.id,sessions:[...(snapshot.sessions||[]).filter((item:Data)=>item.id!==record.id),record]})});notify('Workspace saved. Project selection and imports retained.','info',{target:selection.locator||selection.slug});refresh();}catch(error){notify(String(error),'error');}}
  const goHome = () => {
    setLoaded(false);
    history.replaceState(null, "", atlasUrl());
  };
  return (
    <div className="atlas-app">
      <div className="atlas-explorer-column" style={{width:Math.max(240,Math.min(560,explorerWidth)),height:`calc(100dvh - ${activityOpen?Math.max(120,dockHeight):36}px)`}}>
        <PersistentExplorer onProjectVisibility={projectVisibility} notify={notify} libraryLoading={binaries.loading} libraryError={binaries.error} builds={builds} projects={sessions.data.sessions||[]} unresolved={binaries.data.unresolvedBinaries||[]} selection={selection} onSelect={patch=>{if(patch.slug!==undefined||patch.locator!==undefined)open({...selection,...patch});else{selectContext(patch);setView("functions");setLoaded(true);}}} onAdd={libraryTransfer.stage} dropProps={libraryTransfer.dropProps} revision={revision} recordFilter={recordFilter} onRecordFilterChange={setRecordFilter} onImport={()=>setDialog("import")} onCreate={()=>setDialog("create")}/>
        <ResizeBar axis="x" label="Resize binary explorer" onResize={delta=>setExplorerWidth(w=>Math.max(240,Math.min(560,w+delta)))}/>
      </div>
      <div className="atlas-shell" style={{height:`calc(100dvh - ${activityOpen?Math.max(120,dockHeight):36}px)`,overflow:'auto',paddingBottom:16}}>
        {libraryTransfer.confirmation}
        <header className="atlas-top atlas-context-toolbar">
          <strong className="atlas-wordmark" title="AgentDecompile">AD<span> / </span></strong>
          <select aria-label="Workspace view" value={loaded?view:'home'} onChange={event=>{if(event.target.value==='home')goHome();else setView(event.target.value);}}><option value="home">Workspace</option>{loaded&&<><option value="overview">Compare builds</option><option value="functions">Inspect function</option><option value="browser">Program data</option><option value="recovery">Recover & verify</option></>}</select>
          <span className="atlas-current-context" title={selection.locator||selection.program||selection.slug}>{loaded?title(selection):'Choose a project in the explorer'}</span>
          <span className="atlas-connection" title={'Backend '+connection}>{connection}</span>
          <button onClick={()=>setToolsOpen(true)} aria-label="Tools and workspace commands">Tools</button>
        </header>
        {!loaded ? (
          <main className="atlas-landing atlas-workspace-empty"><h1>Workspace</h1><p>Select a project or binary in the explorer. Its existing analysis and recorded evidence stay available while missing work progresses.</p><p>Use <strong>＋ Project</strong> or <strong>Add binaries</strong> above the tree to bring in more files. Drag checked binaries onto a project to link them.</p>{binaries.error&&<p role="alert">{binaries.error}</p>}</main>
        ) : (
          <main className={"atlas-work atlas-view-"+view}>
            <div className="atlas-work-context"><span className="atlas-context-platform">{build?.platform||'Project evidence'}</span><button className="atlas-workflow-summary" onClick={()=>setView('recovery')} title={workflowSummary}>{workflowSummary}</button>{(selection.slug||selection.program)&&<SourceDownload selection={selection} notify={notify}/>}</div>
            {prepareError && (
              <div className="atlas-error" role="alert">
                Preparation admission: {prepareError}
                <span>Accepted work keeps running. Admission and dependency details appear in the activity feed.</span>
              </div>
            )}

            {view === "browser" ? (
              <div className="atlas-native-browser">
                <CodeBrowser {...surfaceProps} /><BinaryEvidenceWorkspace {...surfaceProps}/>
              </div>
            ) : view === "recovery" ? (
              <div className="atlas-native-evidence">
                <RecoveryWorkspace props={surfaceProps} liveRun={run} />
              </div>
            ) : view === "overview" ? (
              <>
                {(selection.slug||selection.program)&&<AtlasAnalysis {...surfaceProps}/>}
                <details className="atlas-workflow-details"><summary>Workflow stages and prerequisites</summary>
                  <PreparationProgress run={run} selection={selection} notify={notify} error={preparationFeedError} loading={!lastPreparationAt&&!preparationFeedError} lastConnectedAt={lastPreparationAt} />
                </details>
                <RecoveryBrief run={run} related={related} />
              </>
            ) : (
              <div className="atlas-function-layout">
                <section className="atlas-function-detail">
                  {!selection.addr ? (
                    <div className="atlas-function-empty">
                      <span>ƒ</span>
                      <h2>Select a function</h2>
                      <p>
                        Inspect source, relationships, and the evidence behind
                        its identity.
                      </p>
                    </div>
                  ) : (
                    <>
                      <header className="atlas-function-heading"><code>{selection.addr}</code><h1 title={selectedName}>{selectedName}</h1><select aria-label="Editor evidence surface" value={editorSurface} onChange={event=>setEditorSurface(event.target.value)}><option value="source">Source</option><option value="assembly">Assembly</option><option value="compare">Source + assembly</option></select></header>
                      {detailResponse.error && (
                        <p role="alert">{detailResponse.error}</p>
                      )}
                      {detailResponse.loading && (
                        <p role="status">Loading evidence…</p>
                      )}
                      <div className={"atlas-code-grid editor-surface-"+editorSurface}>
                        <article className="atlas-source-pane" hidden={editorSurface==='assembly'}>
                          <SourceEditor selection={selection} value={source} loading={detailResponse.loading} extent={sourceExtent(detail)}/>
                        </article>
                        <article className="atlas-assembly-pane" hidden={editorSurface==='source'}>
                          <SourceEditor selection={selection} value={detail.assembly?.text||detail.disassembly?.text||''} kind="assembly" loading={detailResponse.loading}/>
                        </article>
                      </div>
                      <details className="atlas-related-details"><summary>Callers and callees</summary><div className="atlas-relationships">
                        {[
                          ["Callers", graph.callers || detail.callers || []],
                          ["Callees", graph.callees || detail.callees || []],
                        ].map(([label, rows]) => (
                          <article key={String(label)}>
                            <h3>{String(label)}</h3>
                            {(rows as Data[]).map((r: Data, i: number) => (
                              <button
                                key={i}
                                onClick={() =>
                                  setSelection((s) => ({
                                    ...s,
                                    addr: String(r.addr || r.address),
                                    logicalId: "",
                                  }))
                                }
                              >
                                <code>{r.addr || r.address}</code>
                                {r.name || "Unnamed"}
                              </button>
                            ))}
                            {!(rows as Data[]).length && (
                              <p>No recorded edges.</p>
                            )}
                          </article>
                        ))}
                      </div>
                      </details>
                      {(graph.callersTruncated || graph.calleesTruncated) && (
                        <p>Additional edges were omitted by the server.</p>
                      )}
                      <details>
                        <summary>Cross-build identity and provenance</summary>
                        <RecordView
                          value={
                            detail.siblings ||
                            detail.bindings ||
                            detail.provenance
                          }
                        />
                      </details>
                      <p className="atlas-proof-note">
                        No byte-verification claim is inferred from source text,
                        names, or job completion.
                      </p>
                    </>
                  )}
                </section>
              </div>
            )}
          </main>
        )}

      </div>
      <section className={'atlas-activity-dock '+(activityOpen?'expanded':'collapsed')} style={{height:activityOpen?Math.max(120,dockHeight):36}} aria-label="Activity dock">
        {activityOpen&&<ResizeBar axis="y" label="Resize activity dock" onResize={delta=>setDockHeight(h=>Math.max(120,Math.min(window.innerHeight*.65,h-delta)))}/>}
        <UnifiedActivity jobs={jobs} events={messages} batches={batches} expanded={activityOpen} onToggle={()=>setActivityOpen(v=>!v)} notify={notify} onRetry={job=>setAction({id:job.actionId,params:job.params,targets:[recordedSelection(job,selection)]})} onRetryBatch={batch=>setAction({id:batch.action,params:batch.results[0]?.params,targets:batch.results.filter((row:Data)=>row.status!=='ok').map((row:Data)=>row.context)})}/>
      </section>
      <ActionRunner
        request={action}
        selection={selection}
        onClose={() => setAction(null)}
        notify={notify}
        onSubmitted={submitted}
      />
      {toolsOpen && (
        <DialogFrame
          title="Tools for this context"
          onClose={() => setToolsOpen(false)}
        >
          <div className="atlas-tools">
            <div className="atlas-workspace-commands"><button onClick={()=>{setToolsOpen(false);setDialog('open');}}>Open existing project</button><button onClick={()=>{setToolsOpen(false);setDialog('create');}}>Create project</button><button onClick={()=>{setToolsOpen(false);setDialog('import');}}>Add binaries</button><button onClick={()=>void saveWorkspace()}>Save workspace</button><button disabled={!selection.locator} onClick={()=>{setToolsOpen(false);setDialog('copy');}}>Copy project…</button><button onClick={()=>{setToolsOpen(false);setDialog('connection');}}>Save connection…</button><a href="/dashboard?mode=workbench">Advanced workbench ↗</a></div>
            <GuideWorkflows
              selection={selection}
              onSelect={(patch) => setSelection((s) => ({ ...s, ...patch }))}
              onAction={(id, params, targets) => {
                setAction({ id, params, targets });
                setToolsOpen(false);
              }}
              notify={notify}
              revision={revision}
            />
            <details>
              <summary>All catalogue actions</summary>
              <Commands
                selection={selection}
                onSelect={(patch) => setSelection((s) => ({ ...s, ...patch }))}
                onAction={(id, params, targets) => {
                  setAction({ id, params, targets });
                  setToolsOpen(false);
                }}
                notify={notify}
                revision={revision}
              />
            </details>
          </div>
        </DialogFrame>
      )}
      <ProjectDialog
        mode={dialog}
        selection={selection}
        onClose={() => setDialog(null)}
        onSelect={open}
        notify={notify}
        onRefresh={refresh}
      />
    </div>
  );
}
