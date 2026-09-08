import {ExplorerProjectActions} from './ExplorerProjectActions';
import { createContext, useContext, useEffect, useMemo, useRef, useState, type DragEvent, type ReactNode, type MouseEvent } from 'react';
import { API, query, request, type Data, type Selection, type Notify } from './contracts';
import { DialogFrame } from './Actions';
import { ResizeBar, usePref } from './ui';
import { protectionLabel } from './BinaryLibrary';
import { useEntityActivity } from './activity';
import './explorer.css';
const binaryKey = (b:Data) => String(b.libraryId || (b.sha256 ? `sha256:${b.sha256}` : b.id || b.slug));
const mime = 'application/x-agentdecompile-binaries';
const label = (b:Data) => String(b.label || b.name || b.title || b.slug || b.locator?.split('/').pop() || 'Unnamed');
const normalizedAddress = (value:unknown) => String(value || '').toLowerCase().replace(/^0x0*/, '');

const ActivityClock=createContext({now:Date.now(),loading:false});

export function EntityActivityStrip({entity, fallback='Not queued'}:{entity?:Data;fallback?:string}) {
  const clock=useContext(ActivityClock);
  const reading=!entity&&clock.loading;
  const started=typeof entity?.startedAt==='number'?entity.startedAt:0;
  const elapsed=entity?.status==='running'&&started?Math.max(0,Math.floor(clock.now/1000-started)):null;
  const elapsedLabel=elapsed==null?'':elapsed>=3600?`${Math.floor(elapsed/3600)}h ${Math.floor(elapsed%3600/60)}m elapsed`:elapsed>=60?`${Math.floor(elapsed/60)}m ${elapsed%60}s elapsed`:`${elapsed}s elapsed`;
  const progress=entity?.progress;
  const measured=progress?.kind==='measured' && Number.isFinite(progress.total) && progress.total>0 && Number.isFinite(progress.completed);
  const active=entity?.status==='running' && progress?.kind==='indeterminate';
  const readable=(value:unknown)=>String(value||'').replace(/^mcp\./,'').replaceAll('_',' ').replaceAll('-',' ');
  const stage=readable(entity?.stage),action=readable(entity?.action);
  const operation=stage&&!['Not queued','unknown','execute script','Execute script'].includes(stage)?stage:action==='execute script'?'Run project operation':action||fallback;
  const current=reading?'Reading activity…':entity?.error || operation;
  const queue=entity?.queue?.position;
  return <div className={'entity-activity '+(active?'is-active':'')}>
    <span className="entity-operation" title={String(current)}>{queue!=null?`#${queue} · `:''}{String(current).replaceAll('_',' ')}</span>
    <span className="entity-eta" title={typeof entity?.eta?.basis==='string'?entity.eta.basis:JSON.stringify(entity?.eta?.basis || '')}>{elapsedLabel?elapsedLabel+' · ':''}{reading?'Estimate pending':entity?.eta?.label || 'ETA unavailable'}</span>
    {measured?<progress aria-label={String(current)} value={Math.max(0,Math.min(progress.total,progress.completed))} max={progress.total}/>:active?<progress aria-label={String(current)}/>:<span className="entity-idle-track"/>}
    {measured&&<span className="entity-count">{progress.completed.toLocaleString()} / {progress.total.toLocaleString()}</span>}
  </div>;
}
function EvidenceBadges({entity,record}:{entity?:Data;record:Data}) {
  const facets:Data[]=[...(entity?.facets || [])];
  {
    if((record.source==='USER_DEFINED'||record.nameSource==='human'||record.humanAuthored)&&!facets.some(f=>f.kind==='human'))facets.push({kind:'human',label:'Human name'});
    if(record.decomp==='asm'&&!facets.some(f=>f.kind==='substrate'))facets.push({kind:'substrate',label:'Assembly substrate'});
    if(record.decomp==='c'&&!facets.some(f=>f.kind==='source'))facets.push({kind:'source',label:'C witness'});
  }
  return facets.length?<span className="explorer-facets">{facets.map((f,i)=><span key={i} data-evidence={f.kind} title={f.source || f.label}>{f.label}</span>)}</span>:null;
}
type Node = {id:string;parent?:string;level:number;name:string;expanded?:boolean;record:Data;kind:'project'|'group'|'binary'|'function';locator?:string;entity?:Data;unresolved?:boolean};
function VirtualTree({nodes,label:treeLabel,selected,onChoose,onExpand,onCheck,checked,drag,dropProps,onEnd,scrollKey,onDetails,functionChecked,onFunctionContextMenu,onMenu}:{nodes:Node[];label:string;selected:(node:Node)=>boolean;onChoose:(node:Node)=>void;onExpand:(id:string)=>void;onCheck?:(node:Node,shift:boolean)=>void;checked?:Set<string>;drag?:(e:DragEvent,node:Node)=>void;dropProps?:(locator:string)=>Data;onEnd?:()=>void;scrollKey:string;onDetails?:(node:Node)=>void;functionChecked?:(row:Data)=>boolean;onFunctionContextMenu?:(event:MouseEvent,row:Data)=>void;onMenu?:(node:Node,x:number,y:number)=>void}) {
  const [positions,setPositions]=usePref<Record<string,number>>('explorer.scroll',{});
  const [top,setTop]=useState(positions[scrollKey]||0),[height,setHeight]=useState(300),[focus,setFocus]=useState('');
  const host=useRef<HTMLDivElement>(null);
  const restoredScroll=useRef('');
  const offsets=useMemo(()=>{let y=0;return nodes.map(n=>{const row={top:y,height:n.kind==='group'?30:n.kind==='function'?52:n.kind==='project'?66:78};y+=row.height;return row;});},[nodes]);
  const total=offsets.length?offsets.at(-1)!.top+offsets.at(-1)!.height:0;
  useEffect(()=>{const el=host.current;if(!el)return;const observer=new ResizeObserver(()=>setHeight(el.clientHeight));observer.observe(el);return()=>observer.disconnect();},[]);
  useEffect(()=>{if(host.current)host.current.scrollTop=positions[scrollKey]||0;setTop(positions[scrollKey]||0);setFocus('');restoredScroll.current='';},[scrollKey]);
  useEffect(()=>{if(total>0&&host.current&&restoredScroll.current!==scrollKey){host.current.scrollTop=positions[scrollKey]||0;restoredScroll.current=scrollKey;}},[total,scrollKey]);
  const visible=nodes.map((n,i)=>({n,i,...offsets[i]})).filter(r=>r.top+r.height>=top-150&&r.top<top+height+150);
  function focusNode(index:number){const n=nodes[index];if(!n)return;setFocus(n.id);const el=host.current,o=offsets[index];if(el&&o){if(o.top<el.scrollTop)el.scrollTop=o.top;else if(o.top+o.height>el.scrollTop+height)el.scrollTop=o.top+o.height-height;}}
  return <div ref={host} className="explorer-tree" role="tree" aria-label={treeLabel} tabIndex={0} aria-activedescendant={visible.some(r=>r.n.id===focus)?'tree-'+encodeURIComponent(focus):undefined} onScroll={e=>{const y=e.currentTarget.scrollTop;setTop(y);setPositions(old=>({...old,[scrollKey]:y}));if(y+height>=total-250)onEnd?.();}} onKeyDown={e=>{
    if((e.target as HTMLElement).matches('input,select,button'))return;
    const index=Math.max(0,nodes.findIndex(n=>n.id===focus)),n=nodes[index];
    if(!n)return;
    if(['ArrowDown','ArrowUp','Home','End'].includes(e.key)){e.preventDefault();focusNode(e.key==='Home'?0:e.key==='End'?nodes.length-1:index+(e.key==='ArrowDown'?1:-1));}
    if(e.key==='ArrowRight'){e.preventDefault();if(n.expanded===false)onExpand(n.id);else focusNode(index+1);}
    if(e.key==='ArrowLeft'){e.preventDefault();if(n.expanded)onExpand(n.id);else if(n.parent)focusNode(nodes.findIndex(x=>x.id===n.parent));}
    if((e.key==='ContextMenu'||(e.shiftKey&&e.key==='F10'))&&onMenu){e.preventDefault();const rect=document.getElementById('tree-'+encodeURIComponent(n.id))?.getBoundingClientRect();onMenu(n,rect?.left||10,rect?.bottom||80);}
    if(e.key==='Enter'){e.preventDefault();onChoose(n);}
    if(e.key===' '){e.preventDefault();if(onCheck&&(n.kind==='binary'||n.kind==='function')&&!n.unresolved)onCheck(n,e.shiftKey);else if(n.expanded!==undefined)onExpand(n.id);}
  }}><div className="explorer-tree-space" style={{height:total}}>{visible.map(({n,top:rowTop,height:rowHeight})=><div key={n.id} id={'tree-'+encodeURIComponent(n.id)} role="treeitem" aria-level={n.level} aria-expanded={n.expanded} aria-selected={selected(n)} data-status={n.entity?.status||'unknown'} data-stage={n.entity?.stage||'unknown'} className={'explorer-node '+n.kind+(selected(n)?' inspected':'')+(focus===n.id?' keyboard-focus':'')+(n.unresolved?' unresolved':'')} style={{top:rowTop,height:rowHeight,paddingLeft:8+(n.level-1)*12}} draggable={n.kind==='binary'&&!n.unresolved} onDragStart={e=>drag?.(e,n)} onContextMenu={e=>{if(n.kind==='function'&&onFunctionContextMenu)onFunctionContextMenu(e,n.record);else if(onMenu&&n.kind!=='group'){e.preventDefault();onMenu(n,e.clientX,e.clientY);}}} {...(n.kind==='project'&&dropProps?dropProps(n.locator||''):{})} onClick={e=>{setFocus(n.id);if((e.shiftKey||e.ctrlKey||e.metaKey)&&onCheck&&(n.kind==='binary'||n.kind==='function'))onCheck(n,e.shiftKey);else onChoose(n);}}>
    <div className="explorer-node-title">{n.expanded!==undefined?<button className="explorer-chevron" tabIndex={-1} aria-label={(n.expanded?'Collapse ':'Expand ')+n.name} onClick={e=>{e.stopPropagation();onExpand(n.id);}}>{n.expanded?'▾':'▸'}</button>:<span className={'explorer-marker '+n.kind}>●</span>}{(n.kind==='binary'||(n.kind==='function'&&functionChecked))&&!n.unresolved&&onCheck&&<input type="checkbox" aria-label={'Check '+n.name} checked={n.kind==='function'?Boolean(functionChecked?.(n.record)):checked?.has(binaryKey(n.record))||false} onChange={()=>{}} onClick={e=>{e.stopPropagation();onCheck(n,e.shiftKey);}}/>}{n.kind==='function'&&<code className="explorer-address">{n.record.addr}</code>}<span className="explorer-name" title={n.name}>{n.name}</span>{n.kind==='function'&&<EvidenceBadges entity={n.entity} record={n.record}/>} {n.kind!=='group'&&onDetails&&<button className="explorer-info" aria-label={'Activity details for '+n.name} onClick={e=>{e.stopPropagation();onDetails(n);}}>ⓘ</button>}{n.kind!=='group'&&onMenu&&<button className="explorer-info explorer-actions" aria-label={'Actions for '+n.name} onClick={e=>{e.stopPropagation();const rect=e.currentTarget.getBoundingClientRect();onMenu(n,rect.left,rect.bottom);}}>⋯</button>}{n.kind==='group'&&<span className="explorer-total">{n.record.count}</span>}</div>
    {n.kind!=='group'&&<><div className="explorer-row-meta">{n.kind==='binary'?`${n.record.platform||'Platform unknown'} · ${protectionLabel(n.record)}`:n.kind==='function'?<code>{n.record.addr}</code>:n.record.locator}</div><EvidenceBadges entity={n.entity} record={n.record}/><EntityActivityStrip entity={n.entity} fallback={n.unresolved?'Resolve source identity':n.kind==='binary'?'Analysis state unavailable':'Not queued'}/></>}
  </div>)}</div></div>;
}

export function PersistentExplorer({builds,projects,unresolved=[],selection,onSelect,onAdd,dropProps,revision=0,onImport,onCreate,checkedFunctions,onCheckFunction,onFunctionContextMenu,functionToolbar,recordFilter,onRecordFilterChange,functionQuery,onFunctionQueryChange,libraryLoading=false,libraryError="",onProjectVisibility,notify}:{builds:Data[];projects:Data[];unresolved?:Data[];selection:Selection;onSelect:(selection:Partial<Selection>)=>void;onAdd:(locator:string,ids:string[])=>void;dropProps:(locator:string)=>Data;revision?:number;onImport:()=>void;onCreate:()=>void;checkedFunctions?:(row:Data)=>boolean;onCheckFunction?:(row:Data,shift:boolean,range?:Data[])=>void;onFunctionContextMenu?:(event:MouseEvent,row:Data)=>void;functionToolbar?:ReactNode;recordFilter?:string;onRecordFilterChange?:(value:string)=>void;functionQuery?:string;onFunctionQueryChange?:(value:string)=>void;libraryLoading?:boolean;libraryError?:string;onProjectVisibility?:(record:Data,hidden:boolean)=>Promise<void>;notify?:Notify}) {
  const [expanded,setExpanded]=usePref<Record<string,boolean>>('explorer.expanded',{});
  const [fraction,setFraction]=usePref('explorer.split',45);
  const [search,setSearch]=usePref('explorer.binary-search','');
  const [functionSearches,setFunctionSearches]=usePref<Record<string,string>>('explorer.function-search',{});
  const context=JSON.stringify([selection.locator,selection.slug,selection.program]);
  const functionSearch=functionQuery??functionSearches[context]??'';
  const [checkedValues,setChecked]=usePref<string[]>('explorer.checked',[]);
  const checked=useMemo(()=>new Set(checkedValues),[checkedValues]);
  const anchor=useRef('');
  const functionAnchor=useRef('');
  const [rows,setRows]=useState<Data[]>([]),[total,setTotal]=useState(0),[loading,setLoading]=useState(false),[error,setError]=useState('');
  const [localFilter,setLocalFilter]=usePref('explorer.function-filter','all');
  const filterValue=recordFilter??localFilter;
  const [page,setPage]=useState(0),[hasMore,setHasMore]=useState(false);
  const [inspectedActivity,setInspectedActivity]=useState<Node|null>(null);
  const [destination,setDestination]=useState('');
  const [menu,setMenu]=useState<{node:Node;x:number;y:number}|null>(null),[workflow,setWorkflow]=useState<Node|null>(null),[showHidden,setShowHidden]=useState(false),[actionError,setActionError]=useState(''),[hiding,setHiding]=useState(false);
  const menuRef=useRef<HTMLDivElement>(null);
  useEffect(()=>{if(!menu)return;menuRef.current?.querySelector<HTMLButtonElement>('button')?.focus();const close=(event:PointerEvent)=>{if(!menuRef.current?.contains(event.target as globalThis.Node))setMenu(null);};window.addEventListener('pointerdown',close);return()=>window.removeEventListener('pointerdown',close);},[menu]);
  const [refreshToken,setRefreshToken]=useState(0);
  const loadingRef=useRef(false),latestRevision=useRef(revision),appliedRevision=useRef(revision);
  latestRevision.current=revision;
  useEffect(()=>{const timer=setInterval(()=>{if(!loadingRef.current&&latestRevision.current!==appliedRevision.current)setRefreshToken(n=>n+1);},5000);return()=>clearInterval(timer);},[]);
  const panel=useRef<HTMLDivElement>(null);
  const activity=useEntityActivity(selection.locator,selection.slug);
  const [activityNow,setActivityNow]=useState(Date.now());
  useEffect(()=>{const timer=setInterval(()=>setActivityNow(Date.now()),1000);return()=>clearInterval(timer);},[]);
  const entity=(kind:string,record:Data,locator?:string)=>activity.entities.find((a:Data)=>a.kind===kind&&(kind==='project'?a.locator===locator:kind==='function'?a.slug===selection.slug&&normalizedAddress(a.addr)===normalizedAddress(record.addr):a.slug===record.slug||a.aliasSlugs?.includes(record.slug)||(record.sha256&&a.sha256===record.sha256)));
  const binaries=useMemo(()=>builds.filter(b=>b.kind==='binary'),[builds]);
  const projectRows=useMemo(()=>{const map=new Map<string,Data>();for(const p of projects)if(p.locator)map.set(p.locator,p);for(const b of binaries)for(const p of b.projectBindings||[])if(p.locator&&!map.has(p.locator))map.set(p.locator,{...p,title:p.locator.split('/').pop()});if(selection.locator&&!map.has(selection.locator))map.set(selection.locator,{locator:selection.locator,title:selection.locator.split('/').pop()});return [...map.values()].filter(p=>!p.hidden);},[projects,binaries,selection.locator]);
  const open=(id:string)=>expanded[id]??(!projectRows.some(p=>'project:'+p.locator===id)||id==='project:'+selection.locator);
  const toggle=(id:string)=>setExpanded(old=>({...old,[id]:!open(id)}));
  const filter=(b:Data)=>`${label(b)} ${b.platform||''} ${b.sha256||''}`.toLowerCase().includes(search.toLowerCase());
  const binaryNodes:Node[]=[];
  function addBinaries(items:Data[],parent:string,level:number,locator:string,includeAll=false){
    const groups=new Map<string,Data[]>();
    for(const b of items.filter(b=>includeAll||filter(b))){const g=b.variant_group;const key=g?.status==='related'?String(g.id):g?.status==='insufficient'?`separate:${binaryKey(b)}`:'unmatched';groups.set(key,[...(groups.get(key)||[]),b]);}
    for(const [key,items] of groups){const id=parent+':'+key;const g=items[0]?.variant_group;binaryNodes.push({id,parent,level,name:key==='unmatched'?'Awaiting cross-match evidence':g?.label||'Separate variant group',kind:'group',record:{count:items.length},expanded:open(id)});if(!open(id))continue;
      const parentDigest=(b:Data)=>b.containerSha256||b.container?.sha256;
      const seen=new Set<string>();
      const append=(b:Data,parentId:string,depth:number)=>{if(seen.has(binaryKey(b)))return;seen.add(binaryKey(b));const nodeId=parentId+':'+binaryKey(b),binding=(b.projectBindings||[]).find((p:Data)=>p.locator===locator),children=items.filter(c=>parentDigest(c)&&parentDigest(c)===b.sha256);binaryNodes.push({id:nodeId,parent:parentId,level:depth,name:binding?.program?.replace(/^\//,'')||label(b),kind:'binary',locator,record:{...b,...(binding?{program:binding.program}: {})},entity:entity('binary',b,locator),...(children.length?{expanded:open(nodeId)}:{})});if(open(nodeId))for(const child of children)append(child,nodeId,depth+1);};
      for(const b of items)if(!parentDigest(b)||!items.some(p=>p.sha256===parentDigest(b)&&p!==b))append(b,id,level+1);
    }
  }
  for(const p of projectRows){const id='project:'+p.locator;const members=binaries.filter(b=>(b.projectBindings||[]).some((x:Data)=>x.locator===p.locator)||(b.imported&&b.locator===p.locator)||(p.imports||[]).includes(b.slug));if(search&&!label(p).toLowerCase().includes(search.toLowerCase())&&!members.some(filter))continue;binaryNodes.push({id,level:1,name:label(p),kind:'project',locator:p.locator,record:p,expanded:open(id),entity:entity('project',p,p.locator)});if(open(id))addBinaries(members,id,2,p.locator,Boolean(search&&label(p).toLowerCase().includes(search.toLowerCase())));}
  const unassigned=binaries.filter(b=>!projectRows.some(p=>(b.projectBindings||[]).some((x:Data)=>x.locator===p.locator)||(b.imported&&b.locator===p.locator)||(p.imports||[]).includes(b.slug)));
  if(unassigned.some(filter)){binaryNodes.push({id:'unassigned',level:1,name:'Unassigned binaries',kind:'group',record:{count:unassigned.filter(filter).length},expanded:open('unassigned')});if(open('unassigned'))addBinaries(unassigned,'unassigned',2,'');}
  if(unresolved.length){binaryNodes.push({id:'unresolved',level:1,name:'Resolve source identity',kind:'group',record:{count:unresolved.length},expanded:expanded.unresolved===true});if(expanded.unresolved===true)for(const b of unresolved.filter(filter))binaryNodes.push({id:'unresolved:'+binaryKey(b),parent:'unresolved',level:2,name:label(b),kind:'binary',record:b,unresolved:true});}
  const selectionRef=useRef(selection);selectionRef.current=selection;
  useEffect(()=>{setRows([]);setPage(0);setTotal(0);setError('');setHasMore(false);},[context,functionSearch,filterValue]);
  useEffect(()=>{
    if(!selection.slug&&!selection.program){loadingRef.current=false;setLoading(false);return;}
    const controller=new AbortController();setLoading(true);loadingRef.current=true;appliedRevision.current=latestRevision.current;
    const timer=setTimeout(()=>{request(API+'/functions?'+query(selectionRef.current,{q:functionSearch,filter:filterValue,offset:page*200,limit:200}),{signal:AbortSignal.any([controller.signal,AbortSignal.timeout(15000)])}).then(d=>{
      if(controller.signal.aborted)return;
      setRows(old=>page===0?d.results||[]:[...old.filter(r=>!(d.results||[]).some((n:Data)=>n.addr===r.addr)),...(d.results||[])]);setTotal(d.total||0);setHasMore(Boolean(d.hasMore));setError(d.error||'');setLoading(false);loadingRef.current=false;
    }).catch(e=>{if(!controller.signal.aborted){setError(e.message);setLoading(false);loadingRef.current=false;}});},functionSearch?180:0);
    return()=>{clearTimeout(timer);controller.abort();};
  },[context,functionSearch,filterValue,page,refreshToken]);
  const selectedBinary=binaries.find(b=>b.slug===selection.slug||b.aliasSlugs?.includes(selection.slug));
  const functionNodes:Node[]=[];
  const groups=new Map<string,Data[]>();
  for(const f of rows){const group=f.humanModule||f.userModule||f.compilationUnit||f.sourceFile||f.sourceUnit||f.module||f.namespace||'Unassigned';const members=groups.get(String(group));if(members)members.push(f);else groups.set(String(group),[f]);}
  for(const [name,items] of groups){const id='functions:'+context+':'+name;functionNodes.push({id,level:1,name,kind:'group',record:{count:items.length},expanded:open(id)});if(open(id))for(const f of items)functionNodes.push({id:id+':'+f.addr,parent:id,level:2,name:f.name||f.addr,kind:'function',record:{...f,sha256:selectedBinary?.sha256},entity:entity('function',f)});}
  function choose(n:Node){if(n.kind==='group'){toggle(n.id);return;}if(n.kind==='project')onSelect({locator:n.locator||'',slug:'',program:'',addr:'',logicalId:''});else if(n.kind==='binary')onSelect({slug:n.record.slug,program:n.record.program||'',locator:n.locator|| (n.record.imported?n.record.locator:''),addr:'',logicalId:''});else onSelect({addr:n.record.addr,logicalId:String(n.record.logicalId||'')});}
  function check(n:Node,shift:boolean){const id=binaryKey(n.record),ordered=binaryNodes.filter(n=>n.kind==='binary'&&!n.unresolved).map(n=>binaryKey(n.record)),a=ordered.indexOf(anchor.current),b=ordered.indexOf(id);setChecked(old=>{const next=new Set(old);if(shift&&a>=0)ordered.slice(Math.min(a,b),Math.max(a,b)+1).forEach(x=>next.add(x));else if(next.has(id))next.delete(id);else next.add(id);return [...next];});anchor.current=id;}
  const detailEntity=activity.entities.find(e=>e.id===inspectedActivity?.entity?.id)||inspectedActivity?.entity;
  const selectedIds=checkedValues.filter(id=>binaries.some(b=>binaryKey(b)===id));
  return <ActivityClock.Provider value={{now:activityNow,loading:!activity.revision}}><aside className="persistent-explorer" aria-label="Project and function explorer" ref={panel}>
    <section className="explorer-management" style={{flexBasis:`${Math.max(20,Math.min(75,fraction))}%`}}><header><strong>Projects &amp; binaries</strong><div><button onClick={onCreate} title="Create project">＋ Project</button><button onClick={onImport}>Add binaries</button></div></header><input aria-label="Search projects and binaries" placeholder="Find binary or SHA-256…" value={search} onChange={e=>setSearch(e.target.value)}/><div className="explorer-selection-tools"><button onClick={()=>setChecked([...new Set([...checkedValues,...binaryNodes.filter(n=>n.kind==='binary'&&!n.unresolved).map(n=>binaryKey(n.record))])])}>Select all visible</button>{selectedIds.length>0&&<><span>{selectedIds.length} checked{selectedIds.filter(id=>!binaryNodes.some(n=>n.kind==='binary'&&binaryKey(n.record)===id)).length?` · ${selectedIds.filter(id=>!binaryNodes.some(n=>n.kind==='binary'&&binaryKey(n.record)===id)).length} outside view`:''}</span><button onClick={()=>setChecked([])}>Clear</button><select aria-label="Add checked binaries to project" value={destination} onChange={e=>setDestination(e.target.value)}><option value="">Choose project…</option>{projectRows.map(p=><option key={p.locator} value={p.locator}>{label(p)}</option>)}</select><button disabled={!destination} onClick={()=>onAdd(destination,selectedIds)}>Add {selectedIds.length}</button></>}</div>
    <VirtualTree nodes={binaryNodes} label="Projects and binaries" onDetails={setInspectedActivity} onMenu={(node,x,y)=>{setActionError('');setMenu({node,x,y});}} selected={n=>n.kind==='project'?selection.locator===n.locator&&!selection.slug:n.kind==='binary'&&n.record.slug===selection.slug&&(n.locator||'')===(selection.locator||'')} onChoose={choose} onExpand={id=>id==='unresolved'?setExpanded(old=>({...old,unresolved:!old.unresolved})):toggle(id)} checked={checked} onCheck={check} dropProps={dropProps} scrollKey="binaries" drag={(e,n)=>{e.dataTransfer.setData(mime,JSON.stringify(checked.has(binaryKey(n.record))?selectedIds:[binaryKey(n.record)]));e.dataTransfer.effectAllowed='copy';}}/>
    {!binaryNodes.length&&<p className="explorer-empty" role="status">{libraryLoading?'Loading projects and binaries…':libraryError?'Binary library unavailable.':'Open a project or add binaries to begin.'}</p>}{libraryError&&<details className="explorer-error"><summary>Library connection details</summary>{libraryError}</details>}</section>
    <ResizeBar axis="y" label="Resize project and function trees" onResize={delta=>setFraction(old=>Math.max(20,Math.min(75,old+delta/(panel.current?.clientHeight||600)*100)))}/>
    <section className="explorer-functions" id="function-list" tabIndex={-1}><header><strong>Functions</strong><select aria-label="Filter function inventory" value={filterValue} onChange={e=>{setLocalFilter(e.target.value);onRecordFilterChange?.(e.target.value);}}><option value="all">All functions</option><option value="named">Named</option><option value="bound">Identity bound</option><option value="real-c">Assembly-free C</option></select><span>{total.toLocaleString()}</span></header><input aria-label="Search all functions in selected binary" placeholder="Function name or 0xaddress…" value={functionSearch} onChange={e=>{setFunctionSearches(old=>({...old,[context]:e.target.value}));onFunctionQueryChange?.(e.target.value);}}/><p className="explorer-context" title={selection.program||selection.slug}>{selection.program||selection.slug||'Select a binary above'}</p>
    {functionToolbar}<VirtualTree nodes={functionNodes} label="Functions by source unit" onDetails={setInspectedActivity} functionChecked={checkedFunctions} onCheck={onCheckFunction?(n,shift)=>{const ordered=functionNodes.filter(x=>x.kind==='function').map(x=>x.record),a=ordered.findIndex(x=>x.addr===functionAnchor.current),b=ordered.findIndex(x=>x.addr===n.record.addr);onCheckFunction(n.record,shift,shift&&a>=0?ordered.slice(Math.min(a,b),Math.max(a,b)+1):undefined);functionAnchor.current=n.record.addr;}:undefined} onFunctionContextMenu={onFunctionContextMenu} onMenu={(node,x,y)=>{setActionError('');setMenu({node,x,y});}} selected={n=>n.kind==='function'&&n.record.addr===selection.addr} onChoose={choose} onExpand={toggle} scrollKey={'functions:'+context+':'+filterValue+':'+functionSearch} onEnd={()=>{if(hasMore&&!loading)setPage(p=>p+1);}}/>
    <footer><span role="status">{loading?'Loading function inventory…':error?'Inventory unavailable':rows.length?`${rows.length.toLocaleString()} of ${total.toLocaleString()} loaded`:selection.slug||selection.program?'No functions recorded yet':'No binary selected'}</span>{hasMore&&<button disabled={loading} onClick={()=>setPage(p=>p+1)}>Load next 200</button>}</footer>{error&&<details className="explorer-error"><summary>Inventory details</summary>{error}</details>}</section>
    {onProjectVisibility&&projects.some(p=>p.hidden)&&<button className="explorer-hidden-projects" onClick={()=>setShowHidden(true)}>Removed projects ({projects.filter(p=>p.hidden).length})</button>}
    <div className="explorer-feed" title={activity.error||'Workspace activity feed'}>{activity.connection}{activity.error?' · Keeping last state':''}</div>
    {menu&&<div ref={menuRef} className="explorer-context-menu" role="menu" aria-label={menu.node.name+' actions'} style={{left:Math.max(4,Math.min(menu.x,window.innerWidth-270)),top:Math.max(4,Math.min(menu.y,window.innerHeight-280))}} onKeyDown={event=>{const buttons=Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)'));const at=buttons.indexOf(document.activeElement as HTMLButtonElement);if(event.key==='Escape'){event.preventDefault();setMenu(null);panel.current?.querySelector<HTMLElement>('[role=tree]')?.focus();}if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)){event.preventDefault();buttons[event.key==='Home'?0:event.key==='End'?buttons.length-1:(at+(event.key==='ArrowDown'?1:-1)+buttons.length)%buttons.length]?.focus();}}}>
      <strong>{menu.node.name}</strong><button role="menuitem" onClick={()=>{choose(menu.node);setMenu(null);}}>Open {menu.node.kind}</button><button role="menuitem" onClick={()=>{setInspectedActivity(menu.node);setMenu(null);}}>Activity and evidence</button>
      {['project','binary'].includes(menu.node.kind)&&<button role="menuitem" onClick={()=>{setWorkflow(menu.node);setMenu(null);}}>Workflow and queue priority…</button>}
      <button role="menuitem" onClick={()=>{void navigator.clipboard.writeText(menu.node.record.addr||menu.node.locator||menu.node.record.path||menu.node.record.slug||menu.node.name).catch(failure=>setActionError(String(failure)));setMenu(null);}}>Copy {menu.node.kind==='function'?'address':'path or identity'}</button>
      {menu.node.kind==='project'&&onProjectVisibility&&<button role="menuitem" disabled={hiding} onClick={()=>{setHiding(true);void onProjectVisibility(menu.node.record,true).then(()=>setMenu(null)).catch(failure=>setActionError(String(failure))).finally(()=>setHiding(false));}}>Remove project from workspace</button>}
      {menu.node.kind==='project'&&<small>Removing a project keeps its files and background work. Restore it from Removed projects.</small>}
      {actionError&&<p role="alert">{actionError}</p>}
    </div>}
    {workflow&&<ExplorerProjectActions record={workflow.record} locator={workflow.locator||''} notify={notify} onClose={()=>setWorkflow(null)}/>}
    {showHidden&&<DialogFrame title="Removed projects" onClose={()=>setShowHidden(false)}><p>These projects are hidden from this workspace. Their files and completed work remain available.</p>{projects.filter(p=>p.hidden).map(p=><div className="explorer-hidden-row" key={p.id||p.locator}><span>{label(p)}</span><button disabled={hiding} onClick={()=>{setHiding(true);void onProjectVisibility?.(p,false).catch(failure=>setActionError(String(failure))).finally(()=>setHiding(false));}}>Restore project</button><small>{p.locator}</small></div>)}{actionError&&<p role="alert">{actionError}</p>}</DialogFrame>}
    {inspectedActivity&&<DialogFrame title={inspectedActivity.name} onClose={()=>setInspectedActivity(null)}><p>Activity and evidence for this {inspectedActivity.kind}.</p><EntityActivityStrip entity={detailEntity}/><dl className="explorer-activity-details">{Object.entries({Target:detailEntity?.target||inspectedActivity.record.program||inspectedActivity.locator||inspectedActivity.record.addr,Status:detailEntity?.status||'Not queued',Stage:detailEntity?.stage||'Not recorded',Job:detailEntity?.jobId||'No job recorded',Attempts:detailEntity?.attempts??'Not recorded','Queue priority':detailEntity?.queue?.reason||'Not queued','Next fallback':detailEntity?.nextFallback||'None recorded',Dependencies:detailEntity?.dependencies?.join(', ')||'None recorded','ETA basis':detailEntity?.eta?.basis||'No comparable timing evidence','SHA-256':inspectedActivity.record.sha256||'Source identity not confirmed'}).map(([key,value])=><div key={key}><dt>{key}</dt><dd>{String(value)}</dd></div>)}</dl><EvidenceBadges entity={detailEntity} record={inspectedActivity.record}/><details><summary>Proof receipts</summary>{detailEntity?.proofReceipts?.length?detailEntity.proofReceipts.map((receipt:Data,i:number)=><p key={i}>{typeof receipt.href==='string'&&receipt.href.startsWith('/dashboard/artifact?')?<a href={receipt.href} target="_blank" rel="noreferrer">{receipt.label||'Recorded receipt'}</a>:receipt.label||'Receipt'}: {receipt.path}<br/>{receipt.freshnessLabel||'Freshness unknown'}{receipt.sourceExists===false?' Source unavailable.':''}</p>):<p>No proof receipt recorded. A finished job is not a match.</p>}</details></DialogFrame>}
  </aside></ActivityClock.Provider>;
}
