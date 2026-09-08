import { useEffect, useState } from "react";
import { type Data, type SurfaceProps } from "./contracts";
import { ErrorLine, RecordView } from "./ui";
import { useTool } from "./CodeBrowser";
export function FunctionEditor({
  props,
  address,
}: {
  props: SurfaceProps;
  address: string;
}) {
  const [open, setOpen] = useState(false),
    [draft, setDraft] = useState<Data>({}),
    [storage, setStorage] = useState<Data[]>([]),
    [returnType, setReturnType] = useState("");
  const selected = {
    ...props,
    selection: { ...props.selection, addr: address },
  };
  const info = useTool(
    "manage-function",
    { mode: "info", functionIdentifier: address },
    selected,
    open && Boolean(address),
  );
  const targetKey = JSON.stringify([
    props.selection.locator,
    props.selection.program,
    address,
  ]);
  const [baseline, setBaseline] = useState<{
    target: string;
    data: Data;
  } | null>(null);
  const [pending, setPending] = useState<Data | null>(null);
  const [dirty, setDirty] = useState(false);
  const value = baseline?.target === targetKey ? baseline.data : {};
  function adopt(data: Data) {
    setBaseline({ target: targetKey, data });
    setDraft({ ...data });
    setStorage((data.returnStorage || []).map((row: Data) => ({ ...row })));
    setReturnType(data.returnType || "");
    setDirty(false);
    setPending(null);
  }
  useEffect(() => {
    setBaseline(null);
    setPending(null);
    setDraft({});
    setStorage([]);
    setReturnType("");
    setDirty(false);
  }, [targetKey]);
  useEffect(() => {
    if (
      info.status !== "loaded" ||
      info.target !== address ||
      info.context !== props.selection.locator + "|" + props.selection.program
    )
      return;
    const incoming = info.data.properties || info.data;
    if (dirty && baseline?.target === targetKey) {
      if (JSON.stringify(incoming) !== JSON.stringify(baseline.data))
        setPending(incoming);
    } else adopt(incoming);
  }, [info.data, info.status, targetKey]);
  const edit = (key: string, next: any) => {
    setDirty(true);
    setDraft((d) => ({ ...d, [key]: next }));
  };
  const changeStorage = (next: Data[] | ((rows: Data[]) => Data[])) => {
    setDirty(true);
    setStorage(next);
  };
  const changeReturnType = (next: string) => {
    setDirty(true);
    setReturnType(next);
  };
  const save = () => {
    const changed = Object.fromEntries(
      ["namespace", "inline", "noReturn", "varArgs", "callFixup", "thunkTarget"]
        .filter((k) => draft[k] !== value[k])
        .map((k) => [k, draft[k]]),
    );
    props.onAction(
      "mcp.manage-function",
      { mode: "set_properties", ...changed },
      [{ ...props.selection, addr: address }],
    );
  };
  return (
    <details onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary>Edit function signature and storage</summary>
      <p>
        Target function: <code>{address}</code>. Changes remain analysis
        evidence.
      </p>
      <ErrorLine error={info.error} />
      {dirty && baseline?.target === targetKey && (
        <p role="status">
          Unsaved function edits are preserved.
          {pending
            ? " The recorded function changed after this draft was opened. Review the new values before submitting."
            : ""}{" "}
          <button type="button" onClick={() => adopt(pending || baseline.data)}>
            Discard draft and load {pending ? "updated" : "recorded"} values
          </button>
        </p>
      )}
      {pending && (
        <details>
          <summary>Updated recorded values</summary>
          <RecordView value={pending} />
        </details>
      )}
      {baseline?.target === targetKey ? (
        <>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              save();
            }}
          >
            <label>
              Namespace{" "}
              <input
                value={draft.namespace || ""}
                onChange={(e) => edit("namespace", e.target.value)}
              />
            </label>
            <label>
              Call fixup{" "}
              <select
                value={draft.callFixup || ""}
                onChange={(e) => edit("callFixup", e.target.value)}
              >
                <option value="">None</option>
                {(value.availableCallFixups || []).map((s: string) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <label>
              Thunk target{" "}
              <input
                value={draft.thunkTarget || ""}
                onChange={(e) => edit("thunkTarget", e.target.value)}
                placeholder="Function entry address, or empty"
              />
            </label>
            {["inline", "noReturn", "varArgs"].map((k) => (
              <label key={k}>
                <input
                  type="checkbox"
                  checked={Boolean(draft[k])}
                  onChange={(e) => edit(k, e.target.checked)}
                />
                {k === "noReturn"
                  ? "Does not return"
                  : k === "varArgs"
                    ? "Variable arguments"
                    : "Inline"}
              </label>
            ))}
            <button>Review property changes</button>
          </form>
          <div className="cb-toolbar">
            <label>
              Calling convention{" "}
              <select
                aria-label="Calling convention"
                value={draft.callingConvention || ""}
                onChange={(e) => edit("callingConvention", e.target.value)}
              >
                {!(value.availableCallingConventions || []).includes(
                  value.callingConvention,
                ) && (
                  <option value={value.callingConvention || ""}>
                    {value.callingConvention || "Unspecified"}
                  </option>
                )}
                {(value.availableCallingConventions || []).map((s: string) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <button
              disabled={
                !(value.availableCallingConventions || []).includes(
                  draft.callingConvention,
                )
              }
              onClick={() =>
                props.onAction(
                  "mcp.manage-function",
                  {
                    mode: "set_calling_convention",
                    callingConvention: draft.callingConvention,
                  },
                  [{ ...props.selection, addr: address }],
                )
              }
            >
              Review convention change
            </button>
          </div>
          <h4>Return storage</h4>
          <p>
            Storage follows the selected language. Piece order determines the
            composite value; size is in bytes.
          </p>
          <label>
            Return type{" "}
            <input
              aria-label="Stored return type"
              value={returnType}
              onChange={(e) => changeReturnType(e.target.value)}
            />
          </label>
          <table>
            <thead>
              <tr>
                <th>Location</th>
                <th>Register or stack offset</th>
                <th>Bytes</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {storage.map((piece, i) => (
                <tr key={i}>
                  <td>
                    <select
                      aria-label={`Storage location ${i + 1}`}
                      value={piece.register ? "register" : "stack"}
                      onChange={(e) =>
                        changeStorage((rows) =>
                          rows.map((r, j) =>
                            j === i
                              ? {
                                  size: r.size,
                                  ...(e.target.value === "register"
                                    ? {
                                        register:
                                          value.availableRegisters?.[0]?.name ||
                                          "",
                                      }
                                    : { stackOffset: 0 }),
                                }
                              : r,
                          ),
                        )
                      }
                    >
                      <option value="register">Register</option>
                      <option value="stack">Stack</option>
                    </select>
                  </td>
                  <td>
                    {piece.register !== undefined ? (
                      <select
                        aria-label={`Storage register ${i + 1}`}
                        value={piece.register}
                        onChange={(e) =>
                          changeStorage((rows) =>
                            rows.map((r, j) =>
                              j === i ? { ...r, register: e.target.value } : r,
                            ),
                          )
                        }
                      >
                        {(value.availableRegisters || []).map((r: Data) => (
                          <option key={r.name} value={r.name}>
                            {r.name} ({r.size} bytes)
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        aria-label={`Stack offset ${i + 1}`}
                        type="number"
                        value={piece.stackOffset}
                        onChange={(e) =>
                          changeStorage((rows) =>
                            rows.map((r, j) =>
                              j === i
                                ? { ...r, stackOffset: Number(e.target.value) }
                                : r,
                            ),
                          )
                        }
                      />
                    )}
                  </td>
                  <td>
                    <input
                      aria-label={`Storage bytes ${i + 1}`}
                      type="number"
                      min="1"
                      value={piece.size}
                      onChange={(e) =>
                        changeStorage((rows) =>
                          rows.map((r, j) =>
                            j === i
                              ? { ...r, size: Number(e.target.value) }
                              : r,
                          ),
                        )
                      }
                    />
                  </td>
                  <td>
                    <button
                      onClick={() =>
                        changeStorage((rows) => rows.filter((_, j) => j !== i))
                      }
                    >
                      Remove piece
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button
            onClick={() =>
              changeStorage((rows) => [
                ...rows,
                {
                  register: value.availableRegisters?.[0]?.name || "",
                  size: 1,
                },
              ])
            }
          >
            Add storage piece
          </button>
          <button
            disabled={!storage.length || !returnType}
            onClick={() =>
              props.onAction(
                "mcp.manage-function",
                {
                  mode: "set_storage",
                  customStorage: true,
                  returnType,
                  returnStorage: storage.map(
                    ({ register, stackOffset, size }) =>
                      register ? { register, size } : { stackOffset, size },
                  ),
                },
                [{ ...props.selection, addr: address }],
              )
            }
          >
            Review return storage
          </button>
          <h4>Parameter storage</h4>
          <table>
            <thead>
              <tr>
                <th>Parameter</th>
                <th>Type</th>
                <th>Storage</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(value.parameters || []).map((p: Data) => (
                <tr key={p.ordinal}>
                  <td>{p.name}</td>
                  <td>{p.dataType}</td>
                  <td>
                    {(p.storage || [])
                      .map(
                        (s: Data) =>
                          `${s.register || "stack " + s.stackOffset}:${s.size}`,
                      )
                      .join(", ")}
                  </td>
                  <td>
                    <button
                      onClick={() =>
                        props.onAction(
                          "mcp.manage-function",
                          {
                            mode: "set_storage",
                            customStorage: true,
                            parameterStorage: [
                              {
                                ordinal: p.ordinal,
                                dataType: p.dataType,
                                storage: (p.storage || []).map(
                                  ({ register, stackOffset, size }: Data) =>
                                    register
                                      ? { register, size }
                                      : { stackOffset, size },
                                ),
                              },
                            ],
                          },
                          [{ ...props.selection, addr: address }],
                        )
                      }
                    >
                      Edit parameter storage
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : (
        <p>{info.status || "Open to read the current function properties."}</p>
      )}
    </details>
  );
}
