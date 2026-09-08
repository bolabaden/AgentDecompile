import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  API,
  request as apiRequest,
  query,
  type ActionRequest,
  type Data,
  type Notify,
  type Selection,
  type SurfaceProps,
} from "./contracts";
import "./actions.css";
const RECENT = "agentdecompile.react.recent-actions";
function recents(): string[] {
  try {
    return JSON.parse(localStorage.getItem(RECENT) || "[]").slice(0, 8);
  } catch {
    return [];
  }
}
function remember(id: string) {
  try {
    localStorage.setItem(
      RECENT,
      JSON.stringify([id, ...recents().filter((x) => x !== id)].slice(0, 8)),
    );
  } catch {
    /* Storage may be disabled. */
  }
}
export function DialogFrame({
  title,
  onClose,
  children,
  busy = false,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  busy?: boolean;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    ref.current
      ?.querySelector<HTMLElement>("button,input,select,textarea")
      ?.focus();
    return () => previous?.focus();
  }, []);
  return (
    <div
      className="ad-dialog-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div
        ref={ref}
        className={"ad-dialog " + (footer ? "ad-dialog-fixed-footer" : "ad-dialog-scrollable")} 
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onKeyDown={(e) => {
          if (e.key === "Escape" && !busy) {
            e.stopPropagation();
            onClose();
          }
          if (e.key === "Tab") {
            const items = Array.from(
              ref.current?.querySelectorAll<HTMLElement>(
                'button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href],[tabindex="0"]',
              ) || [],
            ).filter((x) => x.getClientRects().length);
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
        <header>
          <h2>{title}</h2>
          <button onClick={onClose} disabled={busy} aria-label="Close dialog">
            ×
          </button>
        </header>
        {footer ? <><div className="ad-dialog-body" tabIndex={0}>{children}</div><footer>{footer}</footer></> : children}
      </div>
    </div>
  );
}
export function Commands({ onAction }: SurfaceProps) {
  const [actions, setActions] = useState<Data[]>([]),
    [filter, setFilter] = useState(""),
    [error, setError] = useState("");
  useEffect(() => {
    const c = new AbortController();
    apiRequest("/dashboard/api/actions", { signal: c.signal })
      .then((d) => setActions(d.actions || []))
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, []);
  const matches = actions.filter((a) =>
    `${a.id} ${a.title} ${a.summary}`
      .toLowerCase()
      .includes(filter.toLowerCase()),
  );
  const groups = [...new Set(matches.map((a) => String(a.group)))].sort();
  return (
    <div className="ad-commands">
      <label>
        Find commands{" "}
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by name or purpose"
        />
      </label>
      <p>
        {matches.length} of {actions.length} commands
      </p>
      {error && <p role="alert">{error}</p>}
      {!filter && recents().length > 0 && (
        <section>
          <h3>Recent actions</h3>
          {recents()
            .map((id) => actions.find((a) => a.id === id))
            .filter(Boolean)
            .map((a) => (
              <button key={a!.id} onClick={() => onAction(a!.id)}>
                {a!.title}
              </button>
            ))}
        </section>
      )}
      {groups.map((group) => (
        <section key={group}>
          <h3>{group}</h3>
          {matches
            .filter((a) => a.group === group)
            .map((a) => (
              <div className="ad-command-row" key={a.id}>
                <button onClick={() => onAction(a.id)}>{a.title}</button>
                <span>{a.summary || a.id}</span>
                {(a.mutating || a.danger) && <small>Changes state</small>}
              </div>
            ))}
        </section>
      ))}
    </div>
  );
}
export function parseField(field: Data, value: any): any {
  if (value === "" || value === undefined || value === null) {
    if (field.required) throw new Error(`${field.name} is required.`);
    return undefined;
  }
  if (field.kind === "bool") return value === true || value === "true";
  if (["int", "integer", "float", "number"].includes(field.kind)) {
    const number = Number(value);
    if (
      !Number.isFinite(number) ||
      (["int", "integer"].includes(field.kind) && !Number.isInteger(number))
    )
      throw new Error(
        `${field.name} needs ${field.kind === "float" || field.kind === "number" ? "a number" : "a whole number"}.`,
      );
    return number;
  }
  if (["json", "dict", "list", "array", "object"].includes(field.kind)) {
    try {
      const parsed = typeof value === "string" ? JSON.parse(value) : value;
      if (["list", "array"].includes(field.kind) && !Array.isArray(parsed))
        throw new Error();
      if (
        ["dict", "object"].includes(field.kind) &&
        (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      )
        throw new Error();
      return parsed;
    } catch {
      throw new Error(
        `${field.name} needs valid ${field.kind === "json" ? "JSON" : field.kind + " JSON"}.`,
      );
    }
  }
  return value;
}
function selectionContext(
  selection: Selection,
  defaults: Data,
  binaries: Data[],
): Data {
  const row = binaries.find((b) => b.slug === selection.slug) || {};
  return {
    ...defaults,
    ...selection,
    logical_id: selection.logicalId,
    repo: selection.locator || row.repo || "",
    program: selection.program || row.program || "",
  };
}
export function ActionRunner({
  request,
  selection,
  onClose,
  notify,
  onSubmitted,
}: {
  request: ActionRequest | null;
  selection: Selection;
  onClose: () => void;
  notify: Notify;
  onSubmitted: (data: Data) => void;
}) {
  const [action, setAction] = useState<Data | null>(null),
    [values, setValues] = useState<Data>({}),
    [context, setContext] = useState<Data>({});
  const submission = useRef({ signature: "", key: "" });
  const [targets, setTargets] = useState<Data[]>([]),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [advanced, setAdvanced] = useState(false),
    [confirm, setConfirm] = useState(false),
    [preview, setPreview] = useState<Data | null>(null);
  useEffect(() => {
    if (!request) return;
    const c = new AbortController();
    setAction(null);
    setError("");
    setConfirm(false);
    setPreview(null);
    setAdvanced(false);
    const frozen = (
      request.targets?.length ? request.targets : [selection]
    ).map((s) => ({ ...s }));
    setContext(frozen[0]);
    setTargets(frozen);
    Promise.all([
      apiRequest("/dashboard/api/actions", { signal: c.signal }),
      apiRequest(`${API}/context?${query(frozen[0])}`, { signal: c.signal }),
    ])
      .then(([catalog, ctx]) => {
        const found = (catalog.actions || []).find(
          (a: Data) => a.id === request.id,
        );
        if (!found) throw new Error(`Action ${request.id} is unavailable.`);
        const defaults = { ...catalog.context?.defaults, ...ctx.defaults };
        const binaries = catalog.context?.binaries || [];
        const contexts = frozen.map((s) =>
          selectionContext(s, defaults, binaries),
        );
        setTargets(contexts);
        setContext(contexts[0]);
        const initial: Data = {};
        (found.fields || []).forEach((field: Data) => {
          const value =
            Object.entries(request.params || {}).find(
              ([key]) =>
                key.replace(/[_-]/g, "").toLowerCase() ===
                String(field.name).replace(/[_-]/g, "").toLowerCase(),
            )?.[1] ??
            (field.from_context
              ? contexts[0][field.from_context]
              : undefined) ??
            field.default ??
            "";
          initial[field.name] =
            typeof value === "object" ? JSON.stringify(value, null, 2) : value;
        });
        setValues(initial);
        setAction(found);
      })
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, [request]);
  if (!request) return null;
  const fields: Data[] = action?.fields || [];
  const usesAddr = fields.some(
    (f) =>
      f.from_context === "addr" ||
      ["addr", "address", "functionIdentifier", "addressOrSymbol"].includes(
        f.name,
      ),
  );
  const batch = usesAddr && targets.length > 1;
  async function submit(dryRun = false) {
    if (!action || busy) return;
    try {
      const params: Data = {};
      fields.forEach((f) => {
        if (
          batch &&
          (f.from_context === "addr" ||
            [
              "addr",
              "address",
              "functionIdentifier",
              "addressOrSymbol",
            ].includes(f.name))
        )
          return;
        const clearProperty =
          action.id === "mcp.manage-function" &&
          String(values.mode).replace(/[_-]/g, "").toLowerCase() ===
            "setproperties" &&
          ["namespace", "callfixup", "thunktarget"].includes(
            String(f.name).replace(/[_-]/g, "").toLowerCase(),
          ) &&
          Object.keys(request?.params || {}).some(
            (key) =>
              key.replace(/[_-]/g, "").toLowerCase() ===
              String(f.name).replace(/[_-]/g, "").toLowerCase(),
          );
        const parsed =
          clearProperty && values[f.name] === ""
            ? ""
            : parseField(f, values[f.name]);
        if (parsed !== undefined) params[f.name] = parsed;
      });
      if (!dryRun && (action.mutating || action.danger) && !confirm) {
        setConfirm(true);
        setError("");
        return;
      }
      setBusy(true);
      setError("");
      const payload = {
        action: action.id,
        params,
        context,
        confirm: Boolean(confirm || dryRun),
        dryRun,
      };
      const signature = JSON.stringify({ ...payload, targets });
      if (submission.current.signature !== signature)
        submission.current = { signature, key: crypto.randomUUID() };
      const result = await apiRequest(
        batch ? "/api/v1/batches" : "/dashboard/api/jobs",
        {
          method: "POST",
          body: JSON.stringify(
            batch
              ? { ...payload, targets, key: submission.current.key }
              : payload,
          ),
        },
      );
      if (dryRun) {
        setPreview(result);
        return;
      }
      remember(action.id);
      notify(
        batch
          ? `Queued ${targets.length} targets for ${action.title}.`
          : `Queued ${action.title}.`,
        "info",
        {
          jobId: result.job?.id,
          batchId: result.batch?.id,
          action: action.id,
          target: context.program || context.slug,
        },
      );
      onSubmitted(result);
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <DialogFrame
      title={action?.title || request.id}
      onClose={onClose}
      busy={busy}
    >
      <div className="ad-dialog-body">
        <p>{action?.summary}</p>
        <p className="ad-target">
          Target:{" "}
          {context.program || context.slug || context.locator || "No selection"}
          {batch
            ? ` · ${targets.length} functions`
            : context.addr
              ? ` · ${context.addr}`
              : ""}
        </p>
        {batch && (
          <details>
            <summary>Review frozen targets</summary>
            <ul>
              {targets.map((t, i) => (
                <li key={i}>
                  {t.program || t.slug} · {t.addr}
                </li>
              ))}
            </ul>
          </details>
        )}
        {!action && !error && <p role="status">Loading action fields…</p>}
        {fields
          .filter(
            (f) =>
              advanced ||
              f.required ||
              Object.keys(request.params || {}).some(
                (key) =>
                  key.replace(/[_-]/g, "").toLowerCase() ===
                  String(f.name).replace(/[_-]/g, "").toLowerCase(),
              ),
          )
          .map((f) => (
            <label className="ad-field" key={f.name}>
              {f.name}
              {f.required ? " *" : ""}
              {f.kind === "bool" ? (
                <select
                  value={values[f.name] === "" ? "" : String(values[f.name])}
                  disabled={busy || confirm}
                  onChange={(e) =>
                    setValues({ ...values, [f.name]: e.target.value })
                  }
                >
                  <option value="">Use default</option>
                  <option value="true">Yes</option>
                  <option value="false">No</option>
                </select>
              ) : f.choices?.length ? (
                <select
                  value={values[f.name] ?? ""}
                  disabled={busy || confirm}
                  onChange={(e) =>
                    setValues({ ...values, [f.name]: e.target.value })
                  }
                >
                  <option value="">Use default</option>
                  {f.choices.map((choice: any) => (
                    <option key={String(choice)} value={choice}>
                      {String(choice)}
                    </option>
                  ))}
                </select>
              ) : ["code", "comment", "prototype"].includes(f.name) ||
                ["json", "dict", "list", "array", "object"].includes(f.kind) ? (
                <textarea
                  value={values[f.name] ?? ""}
                  disabled={busy || confirm}
                  onChange={(e) =>
                    setValues({ ...values, [f.name]: e.target.value })
                  }
                />
              ) : (
                <input
                  value={values[f.name] ?? ""}
                  disabled={
                    busy || confirm || (batch && f.from_context === "addr")
                  }
                  onChange={(e) =>
                    setValues({ ...values, [f.name]: e.target.value })
                  }
                />
              )}
              {f.help && <small>{f.help}</small>}
            </label>
          ))}
        <button onClick={() => setAdvanced(!advanced)}>
          {advanced ? "Hide optional fields" : "Edit optional fields"}
        </button>
        {confirm && (
          <p role="alert">
            This action changes{" "}
            {batch
              ? `${targets.length} selected functions`
              : context.program || context.slug || "the selected target"}
            . Review the fields and targets above before confirming.
          </p>
        )}
        {error && (
          <p className="ad-error" role="alert">
            {error}
          </p>
        )}
        {preview && (
          <section>
            <h3>Dry run</h3>
            <p>
              {preview.summary ||
                preview.message ||
                "Request validated. No job was started."}
            </p>
            {preview.argv && <pre>{preview.argv.join(" ")}</pre>}
            <details>
              <summary>Inspect response</summary>
              <pre>{JSON.stringify(preview, null, 2)}</pre>
            </details>
          </section>
        )}
      </div>
      <footer>
        <button onClick={onClose} disabled={busy}>
          Cancel
        </button>
        {confirm && (
          <button onClick={() => setConfirm(false)} disabled={busy}>
            Edit fields
          </button>
        )}
        <button onClick={() => submit(true)} disabled={!action || busy}>
          Preview parameters
        </button>
        <button
          className={action?.danger ? "danger" : "primary"}
          disabled={!action || busy}
          onClick={() => submit()}
        >
          {busy
            ? "Submitting…"
            : confirm
              ? "Confirm run"
              : batch
                ? `Run ${targets.length}`
                : action?.mutating || action?.danger
                  ? "Review changes"
                  : "Run action"}
        </button>
      </footer>
    </DialogFrame>
  );
}
