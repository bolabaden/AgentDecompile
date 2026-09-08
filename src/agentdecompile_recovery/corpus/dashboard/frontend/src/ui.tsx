import { useEffect, useRef, useState, type ReactNode } from "react";
import { request, type Data } from "./contracts";
export function readPref<T>(key: string, fallback: T): T {
  try {
    return (
      JSON.parse(localStorage.getItem("ad.react." + key) || "null") ?? fallback
    );
  } catch {
    return fallback;
  }
}
export function savePref(key: string, value: unknown) {
  try {
    localStorage.setItem("ad.react." + key, JSON.stringify(value));
  } catch {
    /* private browsing or quota */
  }
}
export function usePref<T>(key: string, fallback: T) {
  const [value, setValue] = useState<T>(() => readPref(key, fallback));
  useEffect(() => savePref(key, value), [key, value]);
  return [value, setValue] as const;
}
export function useData(url: string | null, revision = 0) {
  const [state, setState] = useState<{
    key: string|null; data: Data; error: string; loading: boolean;
  }>({ key:null,data: {}, error: "", loading: false });
  const previousUrl = useRef<string | null>(null);
  const latestRevision = useRef(revision);
  const requestedRevision = useRef(revision);
  const [refresh, setRefresh] = useState(0);
  latestRevision.current = revision;
  useEffect(() => {
    requestedRevision.current = latestRevision.current;
    if (!url) {
      previousUrl.current = null;
      setState({ key:null,data: {}, error: "", loading: false });
      return;
    }
    const controller = new AbortController();
    const same = previousUrl.current === url;
    previousUrl.current = url;
    setState(s => ({ key:url,data: same ? s.data : {}, error: "", loading: true }));
    request(url, { signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]) })
      .then(data => {
        if (!controller.signal.aborted) setState({ key:url,data, error: "", loading: false });
      })
      .catch(error => {
        if (!controller.signal.aborted) setState(s => ({ ...s,
          error: error.name === "TimeoutError" ? "The data request timed out. Saved content is retained." : String(error.message),
          loading: false,
        }));
      });
    return () => controller.abort();
  }, [url, refresh]);
  // Live jobs can change faster than an inventory request completes. Finish
  // the current read, then coalesce those revisions into one fresh read.
  useEffect(() => {
    if (url && !state.loading && requestedRevision.current !== revision) {
      requestedRevision.current = revision;
      setRefresh(value => value + 1);
    }
  }, [url, revision, state.loading]);
  return state.key===url?state:{key:url,data:{},error:"",loading:Boolean(url)};
}
export function ResizeBar({
  axis,
  onResize,
  label,
}: {
  axis: "x" | "y";
  onResize: (delta: number) => void;
  label: string;
}) {
  return (
    <div
      className={"resize-bar " + axis}
      role="separator"
      aria-label={label}
      aria-orientation={axis === "x" ? "vertical" : "horizontal"}
      tabIndex={0}
      onKeyDown={(e) => {
        if (
          ["ArrowLeft", "ArrowUp", "ArrowRight", "ArrowDown"].includes(e.key)
        ) {
          e.preventDefault();
          onResize(e.key === "ArrowLeft" || e.key === "ArrowUp" ? -16 : 16);
        }
      }}
      onPointerDown={(e) => {
        e.preventDefault();
        const element = e.currentTarget;
        let previous = axis === "x" ? e.clientX : e.clientY;
        element.setPointerCapture(e.pointerId);
        const move = (ev: PointerEvent) => {
          const next = axis === "x" ? ev.clientX : ev.clientY;
          onResize(next - previous);
          previous = next;
        };
        const end = () => {
          element.removeEventListener("pointermove", move);
          element.removeEventListener("pointerup", end);
          element.removeEventListener("pointercancel", end);
        };
        element.addEventListener("pointermove", move);
        element.addEventListener("pointerup", end);
        element.addEventListener("pointercancel", end);
      }}
    />
  );
}
export function Section({
  id,
  title,
  children,
  actions,
}: {
  id: string;
  title: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  const ref = useRef<HTMLElement>(null);
  const [height, setHeight] = usePref<number | null>("height." + id, null);
  return (
    <section
      id={id}
      ref={ref}
      className="widget"
      tabIndex={-1}
      style={height ? { height } : undefined}
    >
      <header>
        <h2>{title}</h2>
        <div className="actions">{actions}</div>
      </header>
      <div className="widget-body">{children}</div>
      <ResizeBar
        axis="y"
        label={"Resize " + title}
        onResize={(delta) =>
          setHeight(Math.max(120, (ref.current?.offsetHeight || 240) + delta))
        }
      />
    </section>
  );
}
export function ErrorLine({ error }: { error: string }) {
  return error ? (
    <p role="alert" className="error">
      {error}
    </p>
  ) : null;
}
export function RecordView({ value }: { value: unknown }) {
  if (value === null || value === undefined)
    return <span className="muted">Not recorded</span>;
  if (Array.isArray(value))
    return value.length ? (
      <div className="records">
        {value.slice(0, 100).map((row, i) => (
          <div className="record" key={i}>
            <RecordView value={row} />
          </div>
        ))}
        {value.length > 100 && <p>Showing 100 of {value.length} records.</p>}
      </div>
    ) : (
      <span className="muted">No records</span>
    );
  if (typeof value === "object")
    return (
      <dl className="facts">
        {Object.entries(value as Data)
          .filter(
            ([key]) =>
              !["html", "script", "stdout", "stderr", "raw"].includes(key),
          )
          .map(([key, item]) => (
            <div key={key}>
              <dt>{key.replaceAll("_", " ")}</dt>
              <dd>
                {typeof item === "object" ? (
                  <details>
                    <summary>
                      {Array.isArray(item)
                        ? `${item.length} records`
                        : key.replaceAll("_", " ")}
                    </summary>
                    <RecordView value={item} />
                  </details>
                ) : (
                  String(item ?? "Not recorded")
                )}
              </dd>
            </div>
          ))}
      </dl>
    );
  return <span>{String(value)}</span>;
}
export function jump(id: string) {
  const target = document.getElementById(id);
  target?.scrollIntoView({ block: "start" });
  target?.focus({ preventScroll: true });
}
