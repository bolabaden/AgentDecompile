"""Call graphs for the corpus and for one function.

Edges carry callers, callees, cross-build identity, confidence, and
provenance. The landing page should stay on progress tables; these graphs
are evidence, not the home view.
"""

from __future__ import annotations

from typing import Any


def build_call_graph(
    functions_by_binary: dict[str, list[dict[str, Any]]],
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for binary_id, rows in functions_by_binary.items():
        for row in rows:
            nodes.append(
                {
                    "id": f"{binary_id}:{row.get('id')}",
                    "binary": binary_id,
                    "name": row.get("name"),
                    "logical_id": row.get("logical_id") or row.get("id"),
                }
            )
            for callee in row.get("callees") or []:
                edges.append(
                    {
                        "from": f"{binary_id}:{row.get('id')}",
                        "to": f"{binary_id}:{callee}",
                        "kind": "callee",
                    }
                )
            for caller in row.get("callers") or []:
                edges.append(
                    {
                        "from": f"{binary_id}:{caller}",
                        "to": f"{binary_id}:{row.get('id')}",
                        "kind": "caller",
                    }
                )
    for bind in bindings:
        edges.append(
            {
                "from": f"{bind['left']['binary']}:{bind['left']['id']}",
                "to": f"{bind['right']['binary']}:{bind['right']['id']}",
                "kind": "identity",
                "confidence": bind.get("confidence"),
                "provenance": bind.get("provenance") or [],
            }
        )
    return {"nodes": nodes, "edges": edges}


def function_view(graph: dict[str, Any], node_id: str) -> dict[str, Any]:
    callers = [e for e in graph["edges"] if e.get("to") == node_id]
    callees = [e for e in graph["edges"] if e.get("from") == node_id]
    return {"id": node_id, "callers": callers, "callees": callees}
