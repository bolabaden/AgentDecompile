import {useEffect,useRef,useState} from 'react';
import {request,type Data,type Notify,type Selection} from './contracts';
import {readPref,usePref} from './ui';
import './source-download.css';

const action='workbench.export-source-zip';
const receiptUrl=(value:unknown):value is string=>typeof value==='string'&&/^\/dashboard\/api\/workbench\/source-archives\/[a-f0-9]{32}\/download$/.test(value);
const activeStatuses=['queued','running','cancelling'];
async function readStatus(url:string,signal:AbortSignal):Promise<Data> {
  const response=await fetch(url,{signal,headers:{Accept:'application/json'}});
  if(response.status===404)return {missing:true};
  const data=await response.json();
  if(!response.ok||data.ok===false)throw new Error(data.error||`Export status request failed (${response.status}).`);
  return data;
}
/** A persisted fixed-target batch owns admission; the browser only observes it. */
export function SourceDownload({selection,notify}:{selection:Selection;notify:Notify}) {
  const key=JSON.stringify([selection.locator,selection.slug,selection.program]);
  const [exports,setExports]=usePref<Record<string,Data>>('source-exports',{});
  const entry=exports[key]||{};
  const [state,setState]=useState<{key:string;job:Data;error:string}>({key,job:{},error:''});
  const activeKey=useRef(key),mounted=useRef(true),autoDownload=useRef(''),starting=useRef(false);
  activeKey.current=key;
  useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;autoDownload.current='';};},[]);
  const job=state.key===key?state.job:{};
  const error=(state.key===key?state.error:'')||entry.error||'';
  // Write before POST, rather than relying on the later preference effect.
  function persist(targetKey:string,patch:Data,replace=false) {
    const stored=readPref<Record<string,Data>>('source-exports',{});
    const next={...stored,[targetKey]:{...(replace?{}:stored[targetKey]),...patch}};
    localStorage.setItem('ad.react.source-exports',JSON.stringify(next));
    if(mounted.current)setExports(next);
    return next[targetKey];
  }
  useEffect(()=>{
    if(entry.result||['blocked','failed'].includes(entry.phase)||(!entry.request&&!entry.batchId&&!entry.jobId))return;
    const controller=new AbortController();let timer:ReturnType<typeof setTimeout>,failures=0;
    const signal=()=>AbortSignal.any([controller.signal,AbortSignal.timeout(12000)]);
    const terminal=(reason:string,phase='blocked',current:Data={})=>{
      persist(key,{phase,error:reason});
      if(mounted.current)setState({key,job:current,error:reason});
    };
    const finish=(current:Data)=>{
      let result:Data;
      try {result=typeof current.log==='string'?JSON.parse(current.log):current.result||{};}catch{throw new Error('The export finished without a readable archive receipt. Inspect its output in Activity.');}
      if(result.ok!==true||!receiptUrl(result.downloadUrl))throw new Error('The export finished without a confirmed ZIP download. Inspect its output in Activity.');
      const deliver=Boolean(autoDownload.current&&autoDownload.current===entry.request?.key&&activeKey.current===key&&mounted.current);
      autoDownload.current='';
      persist(key,{phase:'finished',result,error:'',jobId:current.id||entry.jobId});
      if(deliver){
        notify('Binary source ZIP is ready','info',{batchId:entry.batchId,jobId:current.id,target:entry.request?.targets?.[0]?.slug,coverage:result.coverage});
        const link=document.createElement('a');link.href=result.downloadUrl;link.download='';link.click();
      }
    };
    const poll=async()=>{
      try {
        if(entry.request&&!entry.batchId){
          // Replaying this exact persisted key retrieves accepted work, even
          // when its original acknowledgement was lost during navigation.
          const response=await request('/api/v1/batches',{method:'POST',body:JSON.stringify(entry.request),signal:signal()});
          if(controller.signal.aborted)return;
          if(!response.batch?.id){terminal('The server did not confirm this export batch. Its saved submission key is retained; inspect Activity before creating other work.');return;}
          persist(key,{batchId:response.batch.id,phase:'acknowledged',error:''});
          if(autoDownload.current===entry.request.key)notify('Binary source export queued','info',{batchId:response.batch.id,target:entry.request.targets[0].slug});
          return;
        }
        let current:Data,batch:Data={};
        if(entry.batchId){
          const response=await readStatus(`/api/v1/batches/${encodeURIComponent(entry.batchId)}/targets/0`,signal());
          if(controller.signal.aborted)return;
          if(response.missing){terminal(`Export batch ${entry.batchId} is unavailable on this backend. Check the connection and reconcile its accepted work in Activity.`);return;}
          batch=response.batch||{};
          const target=response.target||{};
          if(batch.ownerUnavailable||['blocked','failed','cancelled','budget-stop','interrupted'].includes(batch.status)){
            terminal(batch.error||`Export batch ${batch.status}. Inspect batch ${entry.batchId} in Activity.`,batch.status==='blocked'||batch.status==='interrupted'?'blocked':'failed',target.result||{});return;
          }
          current=target.result||{};
          if(target.status!=='ok'&&target.jobId&&activeStatuses.includes(target.status)){
            const live=await readStatus('/dashboard/api/jobs/'+encodeURIComponent(target.jobId),signal());
            if(controller.signal.aborted)return;
            // The durable batch remains authoritative if this process cannot
            // expose a job owned by another still-running server.
            current=live.missing?{status:target.status,log:'Accepted job output is unavailable on this connection.'}:live.job||live;
          } else current={...current,status:target.status||current.status,error:target.error||current.error};
          if(target.jobId)current.id=target.jobId;
        } else {
          // Retain downloads admitted by an older dashboard without replaying
          // their non-idempotent job submission.
          const response=await readStatus('/dashboard/api/jobs/'+encodeURIComponent(entry.jobId),signal());
          if(controller.signal.aborted)return;
          if(response.missing){terminal(`Previously accepted export job ${entry.jobId} is unavailable. Reconcile it in Activity before submitting another export.`);return;}
          current=response.job||response;
        }
        if(controller.signal.aborted)return;
        setState({key,job:current,error:''});
        if(current.status==='ok'){
          try {finish(current);}catch(failure){terminal(String(failure),'blocked',current);}return;
        }
        if(!activeStatuses.includes(current.status)){
          const uncertain=!current.status||['interrupted','blocked'].includes(current.status);
          terminal(current.error||current.log||`Export ${current.status||'status unavailable'}. Inspect ${current.id||entry.batchId} in Activity.`,uncertain?'blocked':'failed',current);return;
        }
        failures=0;
      }catch(failure){
        if(controller.signal.aborted)return;
        failures+=1;
        setState(old=>({key,job:old.key===key?old.job:{},error:`Export connection unavailable. The saved submission remains unchanged. ${String(failure)}`}));
      }
      if(!controller.signal.aborted)timer=setTimeout(poll,Math.min(30000,2500*2**Math.min(failures,4)));
    };
    void poll();
    return()=>{controller.abort();clearTimeout(timer);};
  },[key,entry.request?.key,entry.batchId,entry.jobId,entry.phase,Boolean(entry.result)]);
  function start() {
    if(starting.current||!selection.slug)return;
    starting.current=true;
    const target={slug:selection.slug,program:selection.program,locator:selection.locator};
    const submission={key:crypto.randomUUID(),action,params:target,targets:[target],confirm:false};
    try {
      persist(key,{request:submission,phase:'submitting',error:''},true);
      autoDownload.current=submission.key;
      setState({key,job:{},error:''});
    }catch{setState({key,job:{},error:'Browser storage is unavailable. No export was submitted because its recovery key could not be saved.'});}
    finally{starting.current=false;}
  }
  const pending=Boolean((entry.request||entry.batchId||entry.jobId)&&!entry.result&&!['failed','blocked'].includes(entry.phase));
  const restoring=pending&&!entry.batchId&&Boolean(entry.request);
  const status=restoring?'Confirming saved export submission…':pending?job.status==='queued'?'Waiting for an export worker':job.status==='cancelling'?'Stopping export…':job.status?'Exporting binary source…':'Restoring accepted export…':'';
  const ready=entry.result&&receiptUrl(entry.result.downloadUrl);
  return <div className="source-download" aria-label="Download binary source">
    {ready?<><a className="source-download-link" href={entry.result.downloadUrl} download>Download source ZIP</a><button onClick={start}>Update ZIP</button><span>Includes an inventory and source coverage manifest.</span></>:<button onClick={start} disabled={!selection.slug||pending||entry.phase==='blocked'}>Download source ZIP</button>}
    {status&&<div role="status"><span>{status}</span><progress aria-label="Source export progress" max={100} value={job.status==='queued'?0:typeof job.progress==='number'?job.progress:undefined}/><small>Work continues if you leave this view.</small>{job.log&&job.status==='running'&&<span className="source-download-operation">{String(job.log).split('\n').filter(Boolean).at(-1)?.slice(0,240)}</span>}</div>}
    {error&&<p role="alert">{error}</p>}
    {entry.phase==='blocked'&&<button onClick={()=>{try{persist(key,{phase:entry.batchId||entry.jobId?'acknowledged':'submitting',error:''});}catch{setState({key,job,error:'Could not save the status-check request.'});}}}>Check accepted export status</button>}
    {entry.result?.coverage?.wholeProgramCWritten?<small>Whole-program C included. Per-function coverage remains unverified; see the manifest.</small>:entry.result?.partial&&<small>The ZIP contains partial source. Its manifest lists missing evidence.</small>}
    {entry.result?.generationTask?.error&&<small className="source-download-reason">Source generation: {String(entry.result.generationTask.error)}</small>}
  </div>;
}
