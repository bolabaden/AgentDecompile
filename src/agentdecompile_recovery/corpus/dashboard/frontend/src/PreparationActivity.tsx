import { useEffect, useState } from "react";
import { API, request, type Data, type SurfaceProps, type Selection, type Notify } from "./contracts";
import { ErrorLine, Section } from "./ui";
import "./preparation.css";
const active = (status: string) => ["queued", "running", "waiting", "cancelling"].includes(status);
function ProgressMessage({message}: {message: unknown}) {
  const text = String(message || "");
  if (text.length <= 220 && !text.includes("\n")) return <>{text}</>;
  const firstLine = text.split("\n")[0];
  return <details><summary>{firstLine.slice(0, 180)}{firstLine.length > 180 ? "…" : ""} · Details</summary><pre>{text}</pre></details>;
}
export function selectPreparation(runs: Data[], selection: Selection): Data | undefined {
  const applicable = runs.filter(run => selection.locator ? run.locator === selection.locator && (!selection.program || !run.program || run.program === selection.program || run.programs?.includes(selection.program)) : Boolean(selection.slug) && run.slug === selection.slug);
  return applicable.sort((a, b) => Number(active(b.status)) - Number(active(a.status)) || Number(b.updatedAt || 0) - Number(a.updatedAt || 0))[0];
}
function WorkflowControls({run,selection,notify}:{run:Data;selection:Selection;notify:Notify}) {
  const [busy,setBusy]=useState(''),[error,setError]=useState(''),[hours,setHours]=useState(24),[budgetMode,setBudgetMode]=useState('unlimited');
  useEffect(()=>{setBudgetMode(run.budgetSeconds==null?'unlimited':'finite');if(typeof run.budgetSeconds==='number')setHours(Math.max(1,Math.ceil(run.budgetSeconds/3600)));},[run.id]);
  async function control(operation:string){
    if(busy)return;setBusy(operation);setError('');
    try {const result=await request('/dashboard/api/jobs',{method:'POST',body:JSON.stringify({action:'workbench.workflow-control',params:{preparation_id:run.id,operation,...(operation==='budget'?{seconds:budgetMode==='unlimited'?null:Math.round(hours*3600)}:{})},context:selection,confirm:true})});notify(`${operation==='budget'?'Budget change':operation==='pause'?'Pause':operation==='resume'?'Resume':'Stop'} requested`, 'info',{jobId:result.job?.id,target:run.locator||run.slug});}
    catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy('');}
  }
  return <div className="workflow-controls">{active(run.status)&&<><button disabled={Boolean(busy)} onClick={()=>void control('pause')}>Pause workflow</button><button disabled={Boolean(busy)} onClick={()=>void control('stop')}>Stop workflow</button></>}{run.status==='paused'&&(!run.deadline||run.deadline>Date.now()/1000)&&<button disabled={Boolean(busy)} onClick={()=>void control('resume')}>Resume workflow</button>}<details><summary>Execution budget · {run.deadline==null?'Unlimited':'Limited'}</summary><p>Unlimited work has no wall-clock deadline. Per-function attempt limits and prerequisite checks still apply. A budget is not an estimate of completion.</p>{run.deadline!=null?<p>{Math.max(0,Math.ceil((run.deadline-Date.now()/1000)/60))} minutes remaining</p>:<p>No execution deadline</p>}<label>Budget <select aria-label="Workflow execution budget" value={budgetMode} onChange={e=>setBudgetMode(e.target.value)}><option value="unlimited">Unlimited</option><option value="finite">Time allowance</option></select></label>{budgetMode==='finite'&&<label>Hours from now <input aria-label="Workflow execution budget hours" type="number" min={1} max={168} value={hours} onChange={e=>setHours(Number(e.target.value))}/></label>}<button disabled={Boolean(busy)||(budgetMode==='finite'&&(!Number.isFinite(hours)||hours<1||hours>168))} onClick={()=>void control('budget')}>{budgetMode==='unlimited'?'Use unlimited budget':'Set time allowance'}</button></details>{busy&&<span role="status">Submitting {busy}…</span>}<ErrorLine error={error}/></div>;
}
export function PreparationProgress({ run, selection, notify, error = "", loading = false, lastConnectedAt, now = Date.now(), compact = false }: {
  run?: Data; selection: Selection; notify: Notify; error?: string; loading?: boolean; lastConnectedAt?: number; now?: number; compact?: boolean;
}) {
  const stages: Data[] = run?.stages || [];
  const current = active(run?.status) ? stages.find(stage => stage.status === "running" || stage.status === "waiting" || stage.status === "cancelling") || stages.find(stage => stage.status === "queued") : undefined;
  const recent = run?.events?.at(-1);
  const work=current?.workProgress;
  const workMeasured=Number.isFinite(work?.total)&&work.total>0&&Number.isFinite(work?.completed)&&work.completed>=0&&work.completed<=work.total;
  const stale = Boolean(error) || Boolean(lastConnectedAt && now - lastConnectedAt > 10000);
  const currentJob = run?.currentJob;
  const startedAt = currentJob?.startedAt || currentJob?.started_at || current?.startedAt;
  const elapsed = startedAt ? Math.max(0, Math.floor((now - Number(startedAt) * 1000) / 1000)) : null;
  const program = current?.currentProgram || currentJob?.params?.programPath || currentJob?.params?.program || run?.program;
  const action = current?.currentAction || currentJob?.title || currentJob?.actionId;
  const actionName = String(action || "").replace(/^mcp\./, "").replace(/[-_]/g, " ");
  const operation = /execute script/i.test(actionName) ? ({analysis: "Check existing analysis", facts: "Index functions and relationships", bsim: "Build similarity signatures"} as Record<string,string>)[current?.key] || actionName : /analyze program/i.test(actionName) ? "Analyze binary" : /match pair/i.test(actionName) ? "Compare related builds" : actionName;
  const state = currentJob?.status || current?.jobStatus || run?.status;
  const updated = run?.updatedAt ? new Date(run.updatedAt * 1000) : null;
  return <div className={`preparation-progress${compact ? " preparation-compact" : ""}`} aria-busy={loading}>
    <div className="preparation-status" role="status" aria-live="polite">
      <strong>{run ? ({queued: "Preparation queued", running: "Preparing project", completed: "Preparation completed", partial: "Preparation needs attention", cancelling: "Stopping preparation"}[run.status as string] || `Preparation ${run.status}`) : loading ? "Checking preparation status…" : selection.locator || selection.slug ? "No preparation job reported for this selection" : "Open a project to prepare its binaries"}</strong>
      <span>{stale ? "Connection lost · retrying; showing last received state" : run ? "Connected" : ""}</span>
    </div>
    {run && <>
      <p className="preparation-scope">{run.program ? `Program · ${run.program}` : `Project-wide · ${run.locator || selection.locator}`}</p>
      <div className="preparation-current">
        <span>{state === "queued" ? "Waiting for a worker" : state === "cancelling" ? "Waiting for accepted work to stop" : current?.title || "Recorded result"}</span>
        {program && <code title={program}>{program}</code>}
        {operation && <span title={actionName}>{operation}</span>}
        <span>{run.programs?.length ?? 0} programs</span>
        {elapsed !== null && active(state) && <span>Current job {elapsed}s elapsed</span>}
      </div>
      {workMeasured&&<div className="preparation-live-work" role="status"><strong>{current?.title}: {work.completed} / {work.total} {work.unit||'items'}</strong><progress value={work.completed} max={work.total} aria-label={`${current?.title}: ${work.completed} of ${work.total} ${work.unit||'items'}`}/>{work.currentTarget&&<code>{work.currentTarget}</code>}</div>}
      {!compact && <ol className="preparation-rail" aria-label="Preparation stages">
        {stages.map(stage => {
          const stepProgress=stage.workProgress||stage;
          const measured = Number.isFinite(stepProgress.total) && stepProgress.total > 0 && Number.isFinite(stepProgress.completed) && stepProgress.completed >= 0 && stepProgress.completed <= stepProgress.total;
          return <li key={stage.key} data-state={stage.status} aria-current={stage === current ? "step" : undefined}>
            <div><strong>{stage.title}</strong><span>{stage.status}</span></div>
            {measured ? <progress max={stepProgress.total} value={stepProgress.completed} aria-label={`${stage.title}: ${stepProgress.completed} of ${stepProgress.total}`} /> : active(stage.status) && stage.status !== "queued" ? <progress aria-label={`${stage.title}: progress not yet measured`} /> : <div className="preparation-track" />}
            <small>{measured ? `${stepProgress.completed} / ${stepProgress.total} ${stepProgress.unit||'completed'}` : stage.total === 0 ? "No applicable items" : stage.status === "queued" ? "Waiting for preceding work" : "Awaiting a measured counter from the active operation"}</small>
            {stage.nextFallback&&<small>{stage.nextFallback}{stage.retryAt?` · next attempt ${new Date(stage.retryAt*1000).toLocaleTimeString()}`:''}{stage.attempts?` · attempt ${stage.attempts}`:''}</small>}
            {stage.reason && <div className="preparation-reason"><ProgressMessage message={stage.reason} /></div>}
          </li>;
        })}
      </ol>}
      {run.admissionPending&&<p role="status">Waiting for a project worker. Work starts automatically when one becomes available.</p>}
      {run.status==='paused'&&<p>Workflow paused. Accepted native operations may finish before the pause takes effect.</p>}
      {(run.error || run.reason) && <p className="error">{run.error || run.reason}</p>}
      {recent && <div className="preparation-latest"><time>{new Date(recent.at * 1000).toLocaleTimeString()}</time> <ProgressMessage message={recent.message} /></div>}
      <div className="preparation-footer">
        {updated && <time dateTime={updated.toISOString()}>Last change {updated.toLocaleTimeString()}{active(run.status) ? ` · ${Math.max(0, Math.floor((now - updated.getTime()) / 1000))}s ago` : ""}</time>}
        {lastConnectedAt ? <span>Last received {Math.max(0, Math.floor((now - lastConnectedAt) / 1000))}s ago</span> : null}
        <span>Stage completion is not byte verification.</span>
        <WorkflowControls run={run} selection={selection} notify={notify}/>
      </div>
      {!compact && <details className="preparation-events"><summary>Activity history ({run.events?.length || 0})</summary><ol>{(run.events || []).map((event: Data, index: number) => <li key={`${event.at}:${index}`}><time>{new Date(event.at * 1000).toLocaleTimeString()}</time><div><ProgressMessage message={event.message} /></div></li>)}</ol></details>}
    </>}
    <ErrorLine error={error} />
  </div>;
}
export function PreparationActivity({ selection, notify }: SurfaceProps) {
  const [runs, setRuns] = useState<Data[]>([]), [error, setError] = useState(""), [loading, setLoading] = useState(true), [lastConnectedAt, setLastConnectedAt] = useState(0), [now, setNow] = useState(Date.now());
  useEffect(() => {
    let alive = true, timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const data = await request(API + "/preparations", {signal: AbortSignal.timeout(8000)});
        if (alive) { setRuns(data.runs || []); setLastConnectedAt(Date.now()); setError(""); }
      } catch (e) { if (alive) setError(String(e)); }
      finally { if (alive) { setLoading(false); setNow(Date.now()); timer = setTimeout(poll, 2000); } }
    }
    void poll();
    return () => { alive = false; clearTimeout(timer); };
  }, []);
  const run = selectPreparation(runs, selection);
  const [childJob, setChildJob] = useState<Data | undefined>();
  const childId = run?.stages?.find((stage: Data) => stage.status === "running")?.jobId;
  useEffect(() => {
    let alive = true, timer: ReturnType<typeof setTimeout>;
    setChildJob(undefined);
    if (!childId) return;
    async function pollJob() {
      try { const data = await request(`/dashboard/api/jobs/${encodeURIComponent(childId)}`); if (alive) setChildJob(data.job); }
      catch { /* Preparation state remains useful when a child job is unavailable. */ }
      finally { if (alive) timer = setTimeout(pollJob, 2000); }
    }
    void pollJob();
    return () => { alive = false; clearTimeout(timer); };
  }, [childId]);
  const displayed = run && childJob?.id === childId ? {...run, currentJob: childJob} : run;
  return <Section id="preparation" title="Prepare the project"><PreparationProgress run={displayed} selection={selection} notify={notify} error={error} loading={loading} lastConnectedAt={lastConnectedAt} now={now} /></Section>;
}
