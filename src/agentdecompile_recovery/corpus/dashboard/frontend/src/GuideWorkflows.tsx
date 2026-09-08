import { useState } from "react";
import { type Data, type SurfaceProps } from "./contracts";
import { useData } from "./ui";
import "./guide.css";
type Task = {
  id: string;
  label: string;
  params?: Data;
  target: "project" | "program" | "address";
  requirement?: string;
  requireFields?: string[];
};
type Chapter = {
  title: string;
  guide: string;
  description: string;
  tasks: Task[];
  note?: string;
};
const chapters: Chapter[] = [
  {
    title: "Orient to the project",
    guide: "2–3 · Projects and code browser",
    description:
      "Start with the open programs and their current context. Reuse existing analysis before requesting more work.",
    tasks: [
      {
        id: "mcp.list-project-files",
        label: "Inspect project contents",
        target: "project",
      },
      {
        id: "mcp.get-current-program",
        label: "Inspect active program",
        target: "program",
      },
    ],
  },
  {
    title: "Find symbols and types",
    guide: "4–5 · Symbol tree and data type manager",
    description:
      "Search names, imports, exports, and type archives to find the structure already known about this program.",
    tasks: [
      {
        id: "mcp.search-symbols",
        label: "Search symbols",
        target: "program",
        params: { query: "" },
        requirement: "Enter a symbol or class name.",
      },
      {
        id: "mcp.manage-data-types",
        label: "Find uses of a type",
        target: "program",
        params: { mode: "find_uses", name: "", discoverTypes: false },
        requireFields: ["discoverTypes"],
        requirement:
          "Enter the exact type name. Expensive decompiler discovery is off by default.",
      },
      { id: "mcp.list-imports", label: "Browse imports", target: "program" },
      { id: "mcp.list-exports", label: "Browse exports", target: "program" },
      {
        id: "mcp.manage-data-types",
        label: "Browse type archives",
        target: "program",
        params: { mode: "archives" },
      },
      {
        id: "mcp.manage-data-types",
        label: "Inspect a type",
        target: "program",
        params: { mode: "info", dataTypeString: "" },
        requirement: "Enter the exact type name.",
      },
    ],
  },
  {
    title: "Read bytes and reconstructed code",
    guide: "6–7 · Listing and decompile view",
    description:
      "Use the machine-code evidence to check the decompiler’s interpretation. Source text remains advisory.",
    tasks: [
      {
        id: "mcp.inspect-memory",
        label: "Inspect instruction operands",
        target: "address",
        params: { mode: "instruction" },
        requireFields: ["direction", "kind"],
      },
      {
        id: "mcp.inspect-memory",
        label: "Navigate to the next instruction",
        target: "address",
        params: { mode: "navigate", direction: "next", kind: "instruction" },
        requireFields: ["direction", "kind"],
      },
      {
        id: "mcp.read-bytes",
        label: "Read target bytes",
        target: "address",
        params: { length: 64 },
      },
      {
        id: "mcp.get-function",
        label: "Inspect function evidence",
        target: "address",
      },
      {
        id: "mcp.decompile-function",
        label: "Decompile with assembly",
        target: "address",
        params: { includeDisassembly: true, includeComments: true },
      },
      {
        id: "mcp.decompile-function",
        label: "Inspect unreachable code",
        target: "address",
        params: { showUnreachable: true, includeDisassembly: true },
        requireFields: ["showUnreachable"],
      },
      {
        id: "mcp.apply-data-type",
        label: "Define data at this address",
        target: "address",
        params: { dataTypeString: "" },
        requirement: "Supply a type justified by the bytes and references.",
      },
      {
        id: "mcp.manage-function",
        label: "Rename a function",
        target: "address",
        params: { mode: "rename", newName: "" },
        requirement:
          "Enter a meaningful name; preserve stronger existing names.",
      },
    ],
  },
  {
    title: "Trace relationships and keep notes",
    guide: "8 · Call trees, memory map, and bookmarks",
    description:
      "Follow references to understand how code and data are used. Record the address and the reason for an interpretation.",
    tasks: [
      {
        id: "mcp.get-references",
        label: "Inspect references",
        target: "address",
      },
      {
        id: "mcp.get-call-graph",
        label: "Trace the call graph",
        target: "address",
      },
      {
        id: "mcp.inspect-memory",
        label: "Browse memory blocks",
        target: "program",
        params: { mode: "blocks" },
      },
      {
        id: "mcp.manage-bookmarks",
        label: "Inspect address bookmarks",
        target: "address",
        params: { mode: "get" },
      },
      {
        id: "mcp.manage-bookmarks",
        label: "Bookmark this address",
        target: "address",
        params: { mode: "set", type: "Note", category: "", comment: "" },
        requirement: "Record why this address matters.",
      },
      {
        id: "mcp.manage-comments",
        label: "Review comments",
        target: "address",
        params: { mode: "get" },
      },
    ],
  },
  {
    title: "Check function signatures and ABI",
    guide: "9–11 · Functions, conventions, and return storage",
    description:
      "Compare parameter use, stack cleanup, and return-register use at both sides of a call before editing the signature.",
    tasks: [
      {
        id: "mcp.get-function",
        label: "Inspect the selected function",
        target: "address",
      },
      {
        id: "mcp.manage-function",
        label: "Inspect function properties",
        target: "address",
        params: { mode: "info" },
        requireFields: ["customStorage"],
      },
      {
        id: "mcp.manage-function",
        label: "Edit function properties",
        target: "address",
        params: { mode: "set_properties" },
        requireFields: ["namespace"],
        requirement: "Review namespace, thunk target, and function flags.",
      },
      {
        id: "mcp.manage-function",
        label: "Edit explicit return storage",
        target: "address",
        params: { mode: "set_storage", customStorage: true, returnStorage: [] },
        requireFields: ["customStorage", "returnStorage"],
        requirement:
          "Enter the measured registers or stack pieces. No register is assumed.",
      },
      {
        id: "mcp.get-call-graph",
        label: "Inspect callers and callees",
        target: "address",
      },
      {
        id: "mcp.manage-function",
        label: "Edit the C prototype",
        target: "address",
        params: { mode: "set_prototype", prototype: "" },
        requirement: "Enter the complete evidence-backed C signature.",
      },
    ],
    note: "The guide’s register and layout examples describe one 32-bit x86 build. They are not defaults for other ABIs. Explicit storage editing is available only when advertised by the server. Review register sizes and parameter ordinals against the selected program’s ABI.",
  },
  {
    title: "Recover structures and virtual dispatch",
    guide: "12–13 · Structures and vtables",
    description:
      "Compare observed offsets and access widths with the proposed layout. A vtable slot can differ across derived classes.",
    tasks: [
      {
        id: "mcp.manage-structures",
        label: "Browse structures",
        target: "program",
        params: { mode: "list" },
      },
      {
        id: "mcp.manage-structures",
        label: "Inspect a structure layout",
        target: "program",
        params: { mode: "info", name: "" },
        requirement: "Enter the exact structure name.",
      },
      {
        id: "mcp.manage-structures",
        label: "Validate a C structure",
        target: "program",
        params: { mode: "validate", cDefinition: "" },
        requirement:
          "Enter a C definition. Parsing is not proof of binary layout.",
      },
      {
        id: "mcp.analyze-vtables",
        label: "Inspect a vtable",
        target: "program",
        params: { mode: "analyze", addressOrSymbol: "" },
        requirement:
          "Enter a vtable address; do not substitute the current function address.",
      },
    ],
    note: "Vtable analysis can provide candidates and references. It does not prove class identity or resolve every inherited slot.",
  },
  {
    title: "Compare template instantiations",
    guide: "14 · Template classes",
    description:
      "Inspect each concrete type and its pointer width, size, capacity, and element layout. Carry knowledge across builds only when the evidence agrees.",
    tasks: [
      {
        id: "mcp.manage-data-types",
        label: "Find a concrete template type",
        target: "program",
        params: { mode: "info", dataTypeString: "" },
        requirement: "Enter the concrete instantiated type name.",
      },
      {
        id: "mcp.manage-structures",
        label: "Inspect fields and offsets",
        target: "program",
        params: { mode: "info", name: "" },
        requirement: "Enter the exact structure name.",
      },
    ],
    note: "No fixed 12-byte or 4-byte template layout is assumed. The walkthrough’s examples must be checked against the selected binary.",
  },
  {
    title: "Diagnose decompiler inconsistencies",
    guide: "15–16 · Common issues and next steps",
    description:
      "extraout, unaff, and reused stack slots are clues about missing or conflicting analysis. Inspect the relevant callee and register flow before changing names or types.",
    tasks: [
      {
        id: "mcp.analyze-data-flow",
        label: "Trace variable data flow",
        target: "address",
        params: { functionAddress: "" },
        requirement: "Choose a variable and flow direction in the form.",
      },
      {
        id: "mcp.get-function",
        label: "Check instructions and callers",
        target: "address",
      },
      {
        id: "mcp.manage-function",
        label: "Correct a justified prototype",
        target: "address",
        params: { mode: "set_prototype", prototype: "" },
        requirement:
          "Select the function whose signature is wrong, often the callee.",
      },
      {
        id: "mcp.decompile-function",
        label: "Inspect the revised decompilation",
        target: "address",
        params: { includeDisassembly: true },
      },
    ],
    note: "Stack-slot reuse and unusual register preservation may remain unresolved. A cleaner decompilation is not a verified source match.",
  },
];
/** Shared, ordered workflow launcher. All execution stays in the existing action runner. */
export function GuideWorkflows(props: SurfaceProps) {
  const catalog = useData("/dashboard/api/actions");
  const [chapter, setChapter] = useState(0);
  const active = chapters[chapter];
  const available: Data[] = catalog.data.actions || [];
  const hasProgram = Boolean(props.selection.program || props.selection.slug);
  const hasProject = Boolean(props.selection.locator || hasProgram);
  function launch(task: Task) {
    const spec = available.find((a) => a.id === task.id);
    if (!spec) return;
    const allowed = new Set(
      (spec.fields || []).map((f: Data) =>
        String(f.name).replace(/[_-]/g, "").toLowerCase(),
      ),
    );
    const values = { ...task.params };
    if (task.id === "mcp.analyze-data-flow")
      values.functionAddress = props.selection.addr;
    const params = Object.fromEntries(
      Object.entries(values).filter(([key]) =>
        allowed.has(key.replace(/[_-]/g, "").toLowerCase()),
      ),
    );
    props.onAction(task.id, params, [{ ...props.selection }]);
  }
  return (
    <section
      className="guide-workflows"
      aria-label="Guided reverse engineering"
    >
      <header>
        <div>
          <h2>Work through the evidence</h2>
          <p>
            Follow the Code Browser guide, with tools scoped to your current
            selection.
          </p>
        </div>
        <span>
          {props.selection.addr ||
            props.selection.program ||
            props.selection.slug ||
            "No program selected"}
        </span>
      </header>
      <div className="guide-layout">
        <nav aria-label="Guide chapters">
          {chapters.map((c, i) => (
            <button
              key={c.title}
              aria-current={chapter === i ? "step" : undefined}
              onClick={() => setChapter(i)}
            >
              <span>{String(i + 1).padStart(2, "0")}</span>
              {c.title}
            </button>
          ))}
        </nav>
        <article>
          <small>{active.guide}</small>
          <h3>{active.title}</h3>
          <p>{active.description}</p>
          {catalog.error && (
            <p role="alert">Tool catalogue unavailable: {catalog.error}</p>
          )}
          <div className="guide-tasks">
            {active.tasks.map((task, i) => {
              const spec = available.find((a) => a.id === task.id);
              const supported =
                spec &&
                (!task.requireFields ||
                  task.requireFields.every((key) =>
                    (spec.fields || []).some(
                      (f: Data) =>
                        String(f.name).replace(/[_-]/g, "").toLowerCase() ===
                        key.replace(/[_-]/g, "").toLowerCase(),
                    ),
                  ));
              const missing =
                task.target === "address"
                  ? !hasProgram || !props.selection.addr
                  : task.target === "program"
                    ? !hasProgram
                    : !hasProject;
              const requirement = missing
                ? task.target === "address"
                  ? "Select a function or data address first."
                  : task.target === "program"
                    ? "Select a program first."
                    : "Open a project first."
                : task.requirement;
              return (
                <div key={task.id + i}>
                  <button
                    disabled={!supported || missing}
                    onClick={() => launch(task)}
                  >
                    {task.label}
                    <span aria-hidden>↗</span>
                  </button>
                  <small>
                    {!supported
                      ? catalog.loading
                        ? "Loading catalogue…"
                        : "Unavailable in this server’s catalogue."
                      : requirement ||
                        "Opens a reviewable form with the selected context."}
                  </small>
                </div>
              );
            })}
          </div>
          {active.note && <p className="guide-boundary">{active.note}</p>}
          <footer>
            <button
              disabled={!chapter}
              onClick={() => setChapter((c) => c - 1)}
            >
              Previous
            </button>
            <span>
              {chapter + 1} / {chapters.length}
            </span>
            <button
              disabled={chapter === chapters.length - 1}
              onClick={() => setChapter((c) => c + 1)}
            >
              Next topic
            </button>
          </footer>
        </article>
      </div>
    </section>
  );
}
