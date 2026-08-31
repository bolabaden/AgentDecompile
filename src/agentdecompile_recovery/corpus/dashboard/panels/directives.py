"""Render the engagement as one actionable, evidence-backed mission contract."""
from __future__ import annotations
import sys
from pathlib import Path
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from agentdecompile_recovery.corpus.dashboard.panels.common import ROOT, ago, esc, load_json, missing, rel  # noqa: E402

TITLE = "Mission contract"
from agentdecompile_recovery.corpus.dashboard.common import as_root
CONTRACT = as_root() / ".mission" / "directives.json"

def _resolve(path_text: str):
    text = (path_text or "").strip()
    if not text:
        return None, False, "empty path"
    root = ROOT.resolve()
    candidate = (as_root() / text).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return candidate, candidate.exists(), "outside the repo root"
    return candidate, candidate.exists(), "" if candidate.exists() else "not on disk"

def _evidence(path_text: str) -> str:
    path, exists, note = _resolve(path_text)
    if not exists:
        return f'<li class="ev broken"><code>{esc(path_text)}</code><span class="tag warn">{esc(note)}</span></li>'
    if note:
        return f'<li class="ev"><code>{esc(path_text)}</code><span class="tag">{esc(note)}</span></li>'
    return (f'<li class="ev"><a href="/artifact?p={esc(rel(path))}"><code>{esc(rel(path))}</code></a>'
            f'<span class="age">{esc(ago(path.stat().st_mtime))}</span></li>')

def _load_goal():
    data, err = load_json(CONTRACT)
    if err or not isinstance(data, dict):
        return None, err or "mission contract is not an object"
    goal = data.get("master_goal")
    return (goal, None) if isinstance(goal, dict) else (None, "master_goal is missing")

def summary() -> str:
    goal, err = _load_goal()
    if err:
        return '<span class="miss">mission contract unreadable</span>'
    criteria = [x for x in goal.get("acceptance_criteria", []) if isinstance(x, str)]
    evidence = [x for x in goal.get("evidence", []) if isinstance(x, str)]
    broken = sum(not _resolve(item)[1] for item in evidence)
    state = str(goal.get("status") or "in_progress").replace("_", " ")
    audit = (f'<span class="st-failed">{broken} broken evidence links</span>' if broken
             else '<span class="st-done">all evidence paths exist</span>')
    return (f'<span class="dcount">1 goal</span><span class="dstats">'
            f'<span class="st-running">{esc(state)}</span><span>{len(criteria)} acceptance criteria</span></span>'
            f'<span class="dbroken">{audit}</span>')

def render() -> str:
    goal, err = _load_goal()
    if err:
        return missing(err)
    criteria = [x for x in goal.get("acceptance_criteria", []) if isinstance(x, str)]
    evidence = [x for x in goal.get("evidence", []) if isinstance(x, str)]
    criteria_html = "".join(f'<li>{esc(item)}</li>' for item in criteria)
    evidence_html = "".join(_evidence(item) for item in evidence)
    return (f'<div class="dsummary">{summary()}</div><article class="drow st-running">'
            f'<header><span class="did">{esc(goal.get("id") or "MASTER")}</span>'
            f'<span class="pill st-running">{esc(goal.get("status") or "in_progress")}</span>'
            '<span class="dcat">authoritative engagement goal</span></header>'
            f'<h3 class="headline">{esc(goal.get("title") or "Complete the mission")}</h3>'
            f'<p>{esc(goal.get("objective") or "")}</p><h4>Acceptance criteria</h4>'
            f'<ol class="contract-list">{criteria_html}</ol><h4>Live evidence</h4>'
            f'<ul class="paths">{evidence_html}</ul></article>'
            f'<div class="srcs"><a class="src" href="/artifact?p={esc(rel(CONTRACT))}">{esc(rel(CONTRACT))}</a>'
            f'<span class="age">{esc(ago(CONTRACT.stat().st_mtime))}</span></div>')

if __name__ == "__main__":
    print(render())
