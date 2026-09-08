import {useEffect,useState} from 'react';
import {API,request,type Data,type Notify} from './contracts';
import {DialogFrame} from './Actions';
import {useData} from './ui';

export function ExplorerProjectActions({record,locator,onClose,notify}:{record:Data;locator:string;onClose:()=>void;notify?:Notify}) {
  const [revision,setRevision]=useState(0),[busy,setBusy]=useState(''),[error,setError]=useState(''),[stopConfirm,setStopConfirm]=useState(false),[budgetHours,setBudgetHours]=useState('24'),[budgetMode,setBudgetMode]=useState('unlimited');
  const data=useData(API+'/preparations',revision);
  useEffect(()=>{const timer=setInterval(()=>setRevision(n=>n+1),3000);return()=>clearInterval(timer);},[]);
  const candidates=(data.data.runs||[]).filter((run:Data)=>!run.supersededBy&&(locator?run.locator===locator:run.slug===record.slug));
  const canonical=(run:Data)=>run.scope==='project'||Boolean(run.locator&&!run.program&&!run.slug);
  const run:Data|undefined=candidates.sort((a:Data,b:Data)=>Number(canonical(b))-Number(canonical(a))||Number(['queued','running','paused'].includes(b.status))-Number(['queued','running','paused'].includes(a.status))||Number(b.updatedAt||b.createdAt||0)-Number(a.updatedAt||a.createdAt||0))[0];
  const currentStage=(run?.stages||[]).find((stage:Data)=>stage.key===run?.currentStage);
  const blocker=(run?.stages||[]).find((stage:Data)=>['blocked','failed','partial','interrupted'].includes(stage.status)&&stage.reason);
  useEffect(()=>{if(run)setBudgetMode(run.budgetSeconds==null?'unlimited':'finite');},[run?.id]);
  const priority=typeof run?.queuePriority==='number'?run.queuePriority:50;
  const budgetExpired=run?.status==='budget-stop'||Boolean(run?.deadline&&Number(run.deadline)<=Date.now()/1000);
  const budgetSeconds=Math.round(Number(budgetHours)*3600);
  const budgetValid=Number.isFinite(budgetSeconds)&&budgetSeconds>=1&&budgetSeconds<=604800;
  async function control(operation:string,value?:number|null) {
    if(!run||busy)return;setBusy(operation);setError('');
    try{
      const response=await request('/dashboard/api/jobs',{method:'POST',body:JSON.stringify({action:'workbench.workflow-control',params:{preparation_id:run.id,operation,...(operation==='priority'?{priority:value}:operation==='budget'?{seconds:value}:{})},context:{locator,slug:record.slug||'',program:''},confirm:true})});
      notify?.(`${operation==='priority'?'Queue priority change':operation==='budget'?'Execution budget change':operation==='stop'?'Workflow stop':operation==='pause'?'Workflow pause':'Workflow resume'} requested`,'info',{jobId:response.job?.id,target:locator||record.slug});setRevision(n=>n+1);setStopConfirm(false);
    }catch(failure){setError(String(failure));}finally{setBusy('');}
  }
  return <DialogFrame title={'Workflow · '+(record.title||record.label||record.slug||locator.split('/').pop())} onClose={onClose}>
    <p className="project-action-target">{locator||record.slug}</p>
    {data.loading&&!run?<p role="status">Reading the project’s current workflow…</p>:!run?<p>No admitted workflow is recorded for this project. Opening or adding a binary admits missing work automatically.</p>:<>
      <dl className="project-queue-facts"><div><dt>Current status</dt><dd>{run.status}</dd></div><div><dt>Current operation</dt><dd>{currentStage?.title||String(run.currentStage||'Not recorded').replaceAll('-',' ')}{currentStage?.status?' · '+currentStage.status:''}</dd></div><div><dt>Waiting queue position</dt><dd>{run.queuePosition!=null?'#'+run.queuePosition:run.admissionPending||run.status==='queued'?'Waiting; position unavailable':'Not waiting for admission'}</dd></div><div><dt>Priority</dt><dd>{priority} / 100</dd></div></dl>
      {blocker&&<p className="project-workflow-requirement"><strong>Next requirement:</strong> {blocker.reason}</p>}
      <p>{run.priorityReason||'Higher priority receives the next available worker first. Equal priorities keep their arrival order.'}</p>
      <p>Changes affect waiting work. An accepted native operation keeps running until it finishes or drains.</p>
      <div className="project-queue-controls"><button disabled={Boolean(busy)||priority>=100} onClick={()=>void control('priority',Math.min(100,priority+25))}>Move earlier in queue</button><button disabled={Boolean(busy)||priority<=0} onClick={()=>void control('priority',Math.max(0,priority-25))}>Move later in queue</button><button disabled={Boolean(busy)||priority===50} onClick={()=>void control('priority',50)}>Normal priority</button></div>
      <div className="project-queue-controls">{['running','queued'].includes(run.status)&&<button disabled={Boolean(busy)} onClick={()=>void control('pause')}>Pause after current operation</button>}{!budgetExpired&&['paused','partial','cancelled'].includes(run.status)&&<button disabled={Boolean(busy)} onClick={()=>void control('resume')}>Resume workflow</button>}{['running','queued','paused'].includes(run.status)&&<button disabled={Boolean(busy)} onClick={()=>setStopConfirm(true)}>Stop workflow…</button>}</div>
      <details open={budgetExpired||undefined}><summary>Execution budget · {run.deadline==null?'Unlimited':'Limited'}</summary><p>{budgetExpired?'The execution budget has expired. Choose unlimited work or a new allowance to continue.':'Unlimited work has no wall-clock deadline. Per-function attempt limits and prerequisite checks still apply.'} This is separate from the completion estimate.</p><label>Budget <select aria-label="Project execution budget" value={budgetMode} onChange={event=>setBudgetMode(event.target.value)}><option value="unlimited">Unlimited</option><option value="finite">Time allowance</option></select></label>{budgetMode==='finite'&&<label>Hours from now <input type="number" min="0.001" max="168" step="1" value={budgetHours} onChange={event=>setBudgetHours(event.target.value)}/></label>}<button disabled={Boolean(busy)||(budgetMode==='finite'&&!budgetValid)} onClick={()=>void control('budget',budgetMode==='unlimited'?null:budgetSeconds)}>{budgetMode==='unlimited'?'Use unlimited budget':'Set time allowance'}</button></details>
      {stopConfirm&&<div className="project-stop-confirm"><p>Stop this project’s workflow? Its accepted operation must drain before stopping. Completed analysis and files remain available.</p><button disabled={Boolean(busy)} onClick={()=>void control('stop')}>Stop this workflow</button><button onClick={()=>setStopConfirm(false)}>Keep working</button></div>}
      {busy&&<p role="status">Submitting {busy==='priority'?'priority change':busy}…</p>}
    </>}
    {(error||data.error)&&<p role="alert">{error||data.error}</p>}
  </DialogFrame>;
}
