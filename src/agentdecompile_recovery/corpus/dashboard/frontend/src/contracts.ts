export type Data = Record<string, any>;
export interface Selection {
  slug: string;
  program: string;
  addr: string;
  logicalId: string;
  locator: string;
}
export const emptySelection: Selection = {
  slug: "",
  program: "",
  addr: "",
  logicalId: "",
  locator: "",
};
/** Older project links put the project database path in the program field. */
export function normalizeSelection(value: Partial<Selection>): Selection {
  const selection = { ...emptySelection, ...value };
  if (!selection.locator && /^(?:\/|[A-Za-z]:[\\/]).*\.(?:gpr|rep)\/?$/i.test(selection.program)) {
    return { ...emptySelection, locator: selection.program };
  }
  return selection;
}
export type Notify = (
  message: string,
  level?: "info" | "error" | "warning",
  details?: Data,
) => void;
export interface ActionRequest {
  id: string;
  params?: Data;
  targets?: Selection[];
}
export type OnAction = (
  id: string,
  params?: Data,
  targets?: Selection[],
) => void;
export interface SurfaceProps {
  selection: Selection;
  onSelect: (patch: Partial<Selection>) => void;
  onAction: OnAction;
  onInspectSource?: () => void;
  notify: Notify;
  revision: number;
  onBrowseFunctions?: (scope: {
    slugs: string[];
    program?: string;
    locator?: string;
    filter: "all" | "named" | "bound" | "real-c";
  }) => void;
}
export const API = "/dashboard/api/workbench";
export async function request<T = Data>(
  url: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      ...(init.body instanceof FormData
        ? {}
        : { "Content-Type": "application/json" }),
      ...init.headers,
    },
  });
  const data = await response.json();
  if (!response.ok || data.ok === false) {
    const detail = Array.isArray(data.detail)
      ? data.detail
          .map((item: Data) => `${(item.loc || []).join(".")}: ${item.msg}`)
          .join("; ")
      : data.detail;
    throw new Error(
      data.error ||
        detail ||
        (data.errors || []).join("; ") ||
        `Request failed (${response.status})`,
    );
  }
  return data as T;
}
export function query(
  selection: Partial<Selection>,
  extras: Data = {},
): string {
  const params = new URLSearchParams();
  Object.entries({ ...selection, ...extras }).forEach(([key, value]) => {
    if (value !== "" && value !== undefined && value !== null)
      params.set(key === "logicalId" ? "logical_id" : key, String(value));
  });
  return params.toString();
}
export function functionKey(selection: Selection): string {
  return [
    selection.locator,
    selection.slug,
    selection.program,
    selection.addr,
  ].join("\u001f");
}

export function recordedSelection(job: Data, fallback: Selection): Selection {
  const p = job.params || {};
  const program = p.programPath || p.program || fallback.program;
  const same = program === fallback.program && (!p.locator || p.locator === fallback.locator);
  return {locator: p.locator || (same ? fallback.locator : ""), program,
    slug: p.slug || (same ? fallback.slug : ""),
    addr: p.functionIdentifier || p.addressOrSymbol || p.address_or_symbol || p.address || p.addr || "",
    logicalId: String(p.logical_id || "")};
}
