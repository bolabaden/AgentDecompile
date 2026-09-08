import {SourceEditor} from './SourceEditor';
import { useEffect, useRef, useState } from "react";
import { request, type Data, type SurfaceProps } from "./contracts";
import { ErrorLine, RecordView, Section } from "./ui";
import "./code-browser.css";
import { FunctionEditor } from "./FunctionEditor";

const accepted = new Map<string, Promise<string>>();
export function useTool(
  tool: string,
  params: Data,
  props: SurfaceProps,
  enabled: boolean,
) {
  const [state, setState] = useState<{
    data: Data;
    error: string;
    status: string;
    jobId: string;
    target?: string;
    context?: string;
  }>({ data: {}, error: "", status: "", jobId: "" });
  const key = JSON.stringify([
    tool,
    params,
    props.selection.locator,
    props.selection.program,
    props.selection.slug,
    props.revision,
  ]);
  useEffect(() => {
    if (!enabled) {
      setState({ data: {}, error: "", status: "", jobId: "" });
      return;
    }
    let alive = true,
      timer: ReturnType<typeof setTimeout>;
    setState((old) => ({ ...old, data: {}, error: "", status: "submitting" }));
    const context = { ...props.selection };
    let submission = accepted.get(key);
    if (!submission) {
      submission = request("/dashboard/api/jobs", {
        method: "POST",
        body: JSON.stringify({
          action: "mcp." + tool,
          params: { ...params, programPath: context.program },
          context,
          confirm: true,
        }),
      }).then((r) => r.job.id as string);
      accepted.set(key, submission);
      submission.catch(() => accepted.delete(key));
      if (accepted.size > 200) accepted.delete(accepted.keys().next().value!);
    }
    submission
      .then((id) => {
        async function poll() {
          try {
            const { job } = await request("/dashboard/api/jobs/" + id);
            if (!alive) return;
            if (["queued", "running", "cancelling"].includes(job.status)) {
              setState((old) => ({ ...old, status: job.status, jobId: id }));
              timer = setTimeout(poll, 750);
              return;
            }
            if (job.status !== "ok")
              throw new Error(job.error || job.log || job.status);
            const start = String(job.log).indexOf("{");
            let data: Data;
            try {
              data =
                start < 0
                  ? { output: job.log }
                  : JSON.parse(job.log.slice(start));
            } catch {
              throw new Error(
                "The job output is incomplete or truncated. Inspect its log in Activity; no partial JSON is presented as evidence.",
              );
            }
            setState({
              data,
              error: "",
              status: "loaded",
              jobId: id,
              target: context.addr,
              context: context.locator + "|" + context.program,
            });
          } catch (error) {
            accepted.delete(key);
            if (alive)
              setState((old) => ({
                ...old,
                error: String(error),
                status: "failed",
                jobId: id,
              }));
          }
        }
        if (alive) void poll();
      })
      .catch((error) => {
        if (alive)
          setState((old) => ({
            ...old,
            error: String(error),
            status: "failed",
          }));
      });
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [key, enabled]);
  return state;
}
const address = (row: Data) =>
  String(
    row.address || row.addr || row.fromAddress || row.from || row.start || "",
  );
function records(data: Data): Data[] {
  for (const key of [
    "results",
    "symbols",
    "references",
    "bookmarks",
    "blocks",
    "archives",
    "functions",
    "instructions",
    "uses",
    "vtables",
  ])
    if (Array.isArray(data[key])) return data[key];
  return [];
}
export function CodeBrowser(props: SurfaceProps) {
  const { selection, onSelect, onAction } = props;
  const browserRef = useRef<HTMLDivElement>(null);
  const [enabled, setEnabled] = useState(false),
    [pane, setPane] = useState("symbols"),
    [kind, setKind] = useState("symbols"),
    [search, setSearch] = useState(""),
    [query, setQuery] = useState(""),
    [offset, setOffset] = useState(0),
    [goto, setGoto] = useState(selection.addr),
    [typeName, setTypeName] = useState(""),
    [vtableAddress, setVtableAddress] = useState(""),
    [category, setCategory] = useState(""),
    [hidePointers, setHidePointers] = useState(true),
    [localRevision, setLocalRevision] = useState(0);
  const [lastFunction, setLastFunction] = useState<Data>({});
  const [functionFilters, setFunctionFilters] = useState<Data>({}),
    [draftFilters, setDraftFilters] = useState<Data>({});
  const [navigation, setNavigation] = useState<Data | null>(null),
    [navigationKind, setNavigationKind] = useState("instruction"),
    [direction, setDirection] = useState("to");
  const [symbolJump, setSymbolJump] = useState<Data | null>(null),
    [symbolError, setSymbolError] = useState("");
  const liveProps = { ...props, revision: localRevision };
  const contextKey = selection.locator + "|" + selection.program;
  const mutationsSeen = useRef(new Set<string>());
  useEffect(() => {
    if (!selection.program || !browserRef.current) return;
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) setEnabled(true);
    });
    observer.observe(browserRef.current);
    return () => observer.disconnect();
  }, [contextKey]);
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    request("/dashboard/api/jobs")
      .then(({ jobs }) => {
        let changed = false;
        for (const job of jobs || []) {
          const mode = String(job.params?.mode || "")
            .replace(/[_-]/g, "")
            .toLowerCase();
          const readModes = [
            "info",
            "list",
            "symbols",
            "classes",
            "namespaces",
            "imports",
            "exports",
            "search",
            "get",
            "archives",
            "finduses",
            "count",
            "categories",
            "blocks",
            "read",
            "dataat",
            "dataitems",
            "segments",
            "instruction",
            "navigate",
          ];
          const writes =
            /^mcp\.(manage-|apply-|rename-|create-|delete-|resolve-modification-conflict|execute-script)/.test(
              job.actionId || "",
            ) && !readModes.includes(mode);
          const target = job.params?.programPath || job.params?.program;
          if (
            job.status === "ok" &&
            writes &&
            (!target ||
              String(target).replace(/^\//, "") ===
                selection.program.replace(/^\//, "")) &&
            !mutationsSeen.current.has(job.id)
          ) {
            mutationsSeen.current.add(job.id);
            changed = true;
          }
        }
        if (alive && changed) setLocalRevision((r) => r + 1);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [props.revision, enabled, contextKey]);
  useEffect(() => {
    setLastFunction({});
    setOffset(0);
    setEnabled(false);
    setTypeName("");
    setVtableAddress("");
    setCategory("");
    setSearch("");
    setQuery("");
    setNavigation(null);
    setSymbolJump(null);
    setSymbolError("");
    setFunctionFilters({});
    setDraftFilters({});
  }, [contextKey]);
  useEffect(() => setGoto(selection.addr), [selection.addr]);
  const targets: Record<string, [string, Data]> = {
    functions: [
      "list-functions",
      { namePattern: query, offset, limit: 80, ...functionFilters },
    ],
    symbols: [
      "manage-symbols",
      { mode: kind, query, offset, limit: 80, filterDefaultNames: false },
    ],
    types: [
      "manage-data-types",
      { mode: "list", categoryPath: category, offset, limit: 80 },
    ],
    memory: ["inspect-memory", { mode: "blocks" }],
    bookmarks: [
      "manage-bookmarks",
      { mode: "search", query, offset, limit: 80 },
    ],
    references: [
      "get-references",
      { addressOrSymbol: selection.addr, mode: direction, offset, limit: 80 },
    ],
    uses: [
      "manage-data-types",
      { mode: "find_uses", name: typeName, offset, limit: 80 },
    ],
    vtables: ["analyze-vtables", { mode: "containing", offset, limit: 80 }],
  };
  const [tool, params] = targets[pane] || targets.symbols;
  const items = useTool(
    tool,
    params,
    liveProps,
    enabled && Boolean(selection.program),
  );
  const functionData = useTool(
    "get-function",
    { functionIdentifier: selection.addr },
    liveProps,
    enabled && Boolean(selection.program && selection.addr),
  );
  const symbolResult = useTool(
    "manage-symbols",
    {
      mode: "symbols",
      query: symbolJump?.token || "",
      filterDefaultNames: false,
      limit: 80,
    },
    liveProps,
    enabled && Boolean(symbolJump),
  );
  useEffect(() => {
    if (
      !symbolJump ||
      symbolResult.status !== "loaded" ||
      symbolResult.context !== contextKey ||
      symbolJump.context !== contextKey ||
      symbolJump.origin !== selection.addr
    )
      return;
    const matches = records(symbolResult.data).filter(
      (row) =>
        [row.name, row.symbol, row.qualifiedName].includes(symbolJump.token) &&
        address(row),
    );
    const addresses = [...new Set(matches.map(address))];
    if (addresses.length === 1) {
      onSelect({ addr: "0x" + addresses[0].replace(/^0x/, "") });
      setSymbolError("");
    } else {
      setSymbolError(
        addresses.length > 1
          ? `Several symbols are named ${symbolJump.token}. Choose the intended address in Symbols.`
          : `No exact symbol named ${symbolJump.token} was found. Local variables are not program addresses.`,
      );
      setPane("symbols");
      setKind("symbols");
      setQuery(symbolJump.token);
      setSearch(symbolJump.token);
      setOffset(0);
    }
    setSymbolJump(null);
  }, [symbolResult.data]);
  const navigationResult = useTool(
    "inspect-memory",
    { mode: "navigate", ...(navigation || {}) },
    liveProps,
    enabled && Boolean(navigation),
  );
  const instruction = useTool(
    "inspect-memory",
    { mode: "instruction", addressOrSymbol: selection.addr },
    liveProps,
    enabled && Boolean(selection.program && selection.addr),
  );
  useEffect(() => {
    if (
      navigationResult.status === "loaded" &&
      navigationResult.data.address &&
      navigation &&
      navigation.addressOrSymbol === selection.addr &&
      navigationResult.context === contextKey
    ) {
      onSelect({
        addr: "0x" + String(navigationResult.data.address).replace(/^0x/, ""),
      });
      setNavigation(null);
    }
  }, [navigationResult.data]);
  const typeData = useTool(
    "manage-data-types",
    { mode: "info", name: typeName },
    liveProps,
    enabled && Boolean(typeName && selection.program),
  );
  const vtableData = useTool(
    "analyze-vtables",
    { mode: "analyze", addressOrSymbol: vtableAddress },
    liveProps,
    enabled && Boolean(vtableAddress && selection.program),
  );
  useEffect(() => {
    if (
      functionData.status === "loaded" &&
      functionData.context === contextKey &&
      (functionData.data.address || functionData.data.disassembly)
    ) {
      const text = String(functionData.data.decompilation || "");
      if (
        functionData.data.address &&
        functionData.target === selection.addr &&
        !/^(?:0x)?[0-9a-f]+$/i.test(selection.addr)
      ) {
        onSelect({
          addr: "0x" + String(functionData.data.address).replace(/^0x/, ""),
        });
      }
      setLastFunction({
        ...functionData.data,
        decompilation: text.startsWith("[decompilation unavailable")
          ? ""
          : text,
        decompilationReason: text.startsWith("[decompilation unavailable")
          ? text
          : "",
        selectedAddress: String(
          functionData.data.address || functionData.target || "",
        ),
      });
    }
  }, [functionData.data, functionData.context, contextKey]);
  const functionRows = records(items.data).filter(
    (r) => !hidePointers || pane !== "types" || !String(r.name).includes("*"),
  );
  const instructions =
    lastFunction.disassembly?.instructions || lastFunction.disassembly || [];
  const navigate = (addr: string) => {
    if (addr)
      onSelect({ addr: /^[0-9a-f]+$/i.test(addr) ? "0x" + addr : addr });
  };
  const act = (id: string, params: Data = {}, addr = selection.addr) =>
    onAction("mcp." + id, params, [{ ...selection, addr }]);
  return (
    <Section id="code-browser" title="Browse the program">
      <div className="code-browser" ref={browserRef}>
        <div className="cb-toolbar">
          <span>
            {selection.program ||
              "Open a Ghidra program to inspect its live state."}
          </span>
          <button
            disabled={!selection.program}
            onClick={() => {
              setEnabled(true);
              if (enabled) setLocalRevision((r) => r + 1);
            }}
          >
            {enabled ? "Refresh program evidence" : "Connect code browser"}
          </button>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              navigate(goto);
            }}
          >
            <label>
              Address or symbol{" "}
              <input
                aria-label="Go to address or symbol"
                value={goto}
                onChange={(e) => setGoto(e.target.value)}
              />
            </label>
            <button disabled={!goto}>Go</button>
          </form>
        </div>
        <div className="cb-layout">
          <aside>
            <nav aria-label="Code browser tools">
              {[
                "functions",
                "symbols",
                "types",
                "memory",
                "bookmarks",
                "references",
                "uses",
                "vtables",
              ].map((p) => (
                <button
                  key={p}
                  aria-pressed={pane === p}
                  onClick={() => {
                    setPane(p);
                    setOffset(0);
                  }}
                >
                  {p}
                </button>
              ))}
            </nav>
            {pane === "references" && (
              <select
                aria-label="Reference direction"
                value={direction}
                onChange={(e) => {
                  setDirection(e.target.value);
                  setOffset(0);
                }}
              >
                <option value="to">References to selected address</option>
                <option value="from">References from selected address</option>
              </select>
            )}
            {pane === "symbols" && (
              <select
                aria-label="Symbol kind"
                value={kind}
                onChange={(e) => {
                  setKind(e.target.value);
                  setOffset(0);
                }}
              >
                {["symbols", "classes", "namespaces", "imports", "exports"].map(
                  (k) => (
                    <option key={k}>{k}</option>
                  ),
                )}
              </select>
            )}
            {["symbols", "bookmarks", "functions"].includes(pane) && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  setQuery(search);
                  setOffset(0);
                }}
              >
                <input
                  aria-label="Search code browser"
                  placeholder="Name or regular expression"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <button>Search</button>
                <button
                  type="button"
                  onClick={() => {
                    setSearch("");
                    setQuery("");
                    setOffset(0);
                  }}
                >
                  Clear
                </button>
              </form>
            )}
            {pane === "functions" && (
              <details>
                <summary>Filter function properties</summary>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    setFunctionFilters(draftFilters);
                    setOffset(0);
                  }}
                >
                  {[
                    ["callingConvention", "Calling convention"],
                    ["signaturePattern", "Signature expression"],
                    ["addressMin", "First address"],
                    ["addressMax", "Last address"],
                    ["minSize", "Minimum bytes"],
                    ["maxSize", "Maximum bytes"],
                  ].map(([k, label]) => (
                    <label key={k}>
                      {label}
                      <input
                        aria-label={label}
                        value={draftFilters[k] ?? ""}
                        onChange={(e) =>
                          setDraftFilters((d) => ({
                            ...d,
                            [k]: k.endsWith("Size")
                              ? e.target.value === ""
                                ? undefined
                                : Number(e.target.value)
                              : e.target.value,
                          }))
                        }
                      />
                    </label>
                  ))}
                  {[
                    ["inline", "Inline functions"],
                    ["undefinedParameters", "Undefined parameters"],
                  ].map(([k, label]) => (
                    <label key={k}>
                      {label}
                      <select
                        value={
                          draftFilters[k] === undefined
                            ? ""
                            : String(draftFilters[k])
                        }
                        onChange={(e) =>
                          setDraftFilters((d) => ({
                            ...d,
                            [k]:
                              e.target.value === ""
                                ? undefined
                                : e.target.value === "true",
                          }))
                        }
                      >
                        <option value="">Any</option>
                        <option value="true">Yes</option>
                        <option value="false">No</option>
                      </select>
                    </label>
                  ))}
                  <button>Apply function filters</button>
                  <button
                    type="button"
                    onClick={() => {
                      setDraftFilters({});
                      setFunctionFilters({});
                      setOffset(0);
                    }}
                  >
                    Clear function filters
                  </button>
                </form>
              </details>
            )}
            {pane === "types" && (
              <>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    setTypeName(search);
                  }}
                >
                  <input
                    aria-label="Find data type"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                  <button>Inspect type</button>
                </form>
                <label>
                  <input
                    type="checkbox"
                    checked={hidePointers}
                    onChange={(e) => setHidePointers(e.target.checked)}
                  />
                  Hide pointers on this page
                </label>
                <input
                  aria-label="Type category"
                  placeholder="Category path (all by default)"
                  value={category}
                  onChange={(e) => {
                    setCategory(e.target.value);
                    setOffset(0);
                  }}
                />
              </>
            )}
            <ErrorLine error={items.error} />
            <p role="status">
              {enabled ? items.status : "Connect to load live Ghidra evidence."}{" "}
              {items.jobId && <small>Job {items.jobId}</small>}
            </p>
            <div className="cb-records">
              {functionRows.map((r, i) => (
                <button
                  key={String(r.id || r.path || address(r)) + i}
                  disabled={
                    pane !== "types" &&
                    !address(r) &&
                    !["classes", "namespaces"].includes(kind)
                  }
                  onClick={() => {
                    if (pane === "types")
                      setTypeName(
                        String(
                          r.path && r.path !== "/"
                            ? r.path + "/" + r.name
                            : r.name,
                        ),
                      );
                    else if (address(r)) {
                      if (pane === "vtables") setVtableAddress(address(r));
                      navigate(address(r));
                    } else {
                      setKind("symbols");
                      setSearch(String(r.name || ""));
                      setQuery(String(r.name || ""));
                      setOffset(0);
                    }
                  }}
                >
                  <code>{address(r) || r.category || r.path || ""}</code>
                  <span>
                    {r.name ||
                      r.symbol ||
                      r.comment ||
                      r.type ||
                      r.label ||
                      "Reference"}
                    <small>
                      {r.namespace || r.permissions || r.signature || ""}
                    </small>
                  </span>
                </button>
              ))}
            </div>
            {!functionRows.length && items.status === "loaded" && (
              <p>No rows returned for this view.</p>
            )}
            <div className="cb-toolbar">
              <button
                disabled={!offset}
                onClick={() => setOffset(Math.max(0, offset - 80))}
              >
                Previous records
              </button>
              <span>
                {offset + 1}–{offset + functionRows.length}
              </span>
              <button
                disabled={records(items.data).length < 80}
                onClick={() => setOffset(offset + 80)}
              >
                Next records
              </button>
            </div>
            {pane === "bookmarks" && (
              <button
                disabled={!selection.addr}
                onClick={() => act("manage-bookmarks", { mode: "set" })}
              >
                Bookmark this address
              </button>
            )}
            <details>
              <summary>Response and provenance</summary>
              <RecordView value={items.data} />
            </details>
          </aside>
          <div className="cb-documents">
            <div className="cb-toolbar">
              <strong>{selection.addr || "Select an address"}</strong>
              <button
                disabled={!selection.addr}
                onClick={() =>
                  act("manage-function", { mode: "rename", newName: "" })
                }
              >
                Rename
              </button>
              <button
                disabled={!selection.addr}
                onClick={() =>
                  act("manage-function", {
                    mode: "set_prototype",
                    prototype: lastFunction.signature || "",
                  })
                }
              >
                Edit signature
              </button>
              <button
                disabled={!selection.addr}
                onClick={() =>
                  act("manage-data-types", {
                    mode: "apply",
                    dataTypeString: "",
                  })
                }
              >
                Define data
              </button>
              <button
                disabled={!selection.addr}
                onClick={() =>
                  act("manage-comments", { mode: "set", comment: "" })
                }
              >
                Comment
              </button>
            </div>
            <div className="cb-toolbar">
              <select
                aria-label="Navigate by"
                value={navigationKind}
                onChange={(e) => setNavigationKind(e.target.value)}
              >
                {["instruction", "function", "label", "undefined"].map((k) => (
                  <option key={k}>{k}</option>
                ))}
              </select>
              {["previous", "next"].map((d) => (
                <button
                  key={d}
                  disabled={!enabled || !selection.addr}
                  onClick={() =>
                    setNavigation({
                      addressOrSymbol: selection.addr,
                      kind: navigationKind,
                      direction: d,
                    })
                  }
                >
                  {d === "next" ? "Next location" : "Previous location"}
                </button>
              ))}
              <ErrorLine error={navigationResult.error} />
              {navigationResult.data.found === false && (
                <span>No further {navigationKind} was found.</span>
              )}
            </div>
            <details>
              <summary>Selected instruction operands</summary>
              <ErrorLine error={instruction.error} />
              <RecordView value={instruction.data} />
              {(instruction.data.flows || []).map((a: string) => (
                <button key={a} onClick={() => navigate(a)}>
                  Follow {a}
                </button>
              ))}
            </details>
            <div className="cb-evidence">
              <article>
                <h3>Listing · bytes and interpreted instructions</h3>
                <ErrorLine error={functionData.error} />
                <table>
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>Bytes</th>
                      <th>Instruction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(Array.isArray(instructions) ? instructions : []).map(
                      (r: Data, i: number) => (
                        <tr
                          key={i}
                          tabIndex={0}
                          aria-selected={
                            selection.addr.replace(/^0x/, "") ===
                            String(r.address).replace(/^0x/, "")
                          }
                          onClick={() => navigate(address(r))}
                          onDoubleClick={() =>
                            act("inspect-memory", {
                              mode: "instruction",
                              addressOrSymbol: address(r),
                            })
                          }
                          onKeyDown={(e) => {
                            if (e.key === "Enter") navigate(address(r));
                          }}
                        >
                          <td>
                            <code>{r.address}</code>
                          </td>
                          <td>
                            <code>{r.bytes}</code>
                          </td>
                          <td>
                            {r.mnemonic}{" "}
                            {Array.isArray(r.operands)
                              ? r.operands.join(", ")
                              : r.operands}
                          </td>
                        </tr>
                      ),
                    )}
                  </tbody>
                </table>
              </article>
              <article>
                <h3>Decompile · advisory witness</h3>
                <ErrorLine error={symbolError || symbolResult.error} />
                <p>
                  Function {lastFunction.name || "not selected"}{" "}
                  {lastFunction.selectedAddress || ""}
                </p>
                {lastFunction.selectedAddress &&
                  String(lastFunction.selectedAddress).replace(/^0x/, "") !==
                    selection.addr.replace(/^0x/, "") && (
                    <p>
                      Retaining this function while the selected address is
                      inspected.
                    </p>
                  )}
                <SourceEditor selection={{...selection,addr:lastFunction.selectedAddress||selection.addr}} value={lastFunction.decompilation||''} extent="Recorded decompilation witness · no byte-verification claim" onInspectSymbol={token=>{if(/^[A-Za-z_$][A-Za-z0-9_$:]*$/.test(token)){setSymbolError('');setSymbolJump({token,origin:selection.addr,context:contextKey});}}}/>

                <FunctionEditor
                  props={liveProps}
                  address={lastFunction.selectedAddress || ""}
                />
                <details>
                  <summary>Signature, storage and function properties</summary>
                  <RecordView
                    value={{
                      signature: lastFunction.signature,
                      metadata: lastFunction.metadata,
                      storage: lastFunction.storage,
                    }}
                  />
                  <button
                    disabled={!selection.addr}
                    onClick={() =>
                      act(
                        "manage-function",
                        { mode: "set_properties" },
                        lastFunction.selectedAddress,
                      )
                    }
                  >
                    Edit function properties
                  </button>
                  <button
                    disabled={!selection.addr}
                    onClick={() =>
                      act(
                        "manage-function",
                        { mode: "set_storage" },
                        lastFunction.selectedAddress,
                      )
                    }
                  >
                    Edit custom storage
                  </button>
                </details>
              </article>
            </div>
            {vtableAddress && (
              <article>
                <h3>Virtual function table: {vtableAddress}</h3>
                <p>
                  Observed pointers are analysis evidence. Class ownership and
                  inheritance may remain ambiguous.
                </p>
                <ErrorLine error={vtableData.error} />
                <table>
                  <thead>
                    <tr>
                      <th>Slot</th>
                      <th>Address</th>
                      <th>Function target</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(vtableData.data.entries || []).map((entry: Data) => (
                      <tr key={entry.index}>
                        <td>{entry.index}</td>
                        <td>
                          <code>{entry.address}</code>
                        </td>
                        <td>
                          <button
                            disabled={!entry.function}
                            onClick={() => navigate(entry.target)}
                          >
                            {entry.function || "Unresolved pointer"} ·{" "}
                            {entry.target}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </article>
            )}
            {typeName && (
              <article>
                <h3>Type: {typeName}</h3>
                <ErrorLine error={typeData.error} />
                <RecordView value={typeData.data} />
                <div className="cb-toolbar">
                  <button
                    onClick={() => {
                      setPane("uses");
                      setOffset(0);
                    }}
                  >
                    Find uses of type
                  </button>
                  <button
                    onClick={() =>
                      act("manage-structures", {
                        mode: "modify_field",
                        name: typeName,
                      })
                    }
                  >
                    Edit structure field
                  </button>
                  <button
                    onClick={() =>
                      act("manage-enums", { mode: "info", name: typeName })
                    }
                  >
                    Inspect enum
                  </button>
                </div>
              </article>
            )}
            <details>
              <summary>Script console</summary>
              <p>
                Scripts run in the selected program. Their output stays in the
                Activity log.
              </p>
              <button
                onClick={() =>
                  act("execute-script", {
                    code: "print(currentProgram.getName())",
                  })
                }
              >
                Open script editor
              </button>
            </details>
          </div>
        </div>
      </div>
    </Section>
  );
}
