"""Standalone worker for auto match-function propagation in a child process.

When AGENTDECOMPILE_AUTO_MATCH_PROPAGATE is set, the main MCP server can run
match-function propagation in a separate process via ProcessPoolExecutor so
the server stays responsive. This module is the entry point for that subprocess.

Flow:
  1. Main process calls run_auto_match_subprocess(project_dir, project_name, ...) with
     only serializable args (strings, lists, floats).
  2. This process opens the Ghidra project, resolves the source function, and for each
     target program finds the best match by (param_count, return_type) + optional name.
  3. For each matched target: optionally checkout (if versioned), then propagate name,
     prototype, tags, comments, bookmarks; then checkin if we modified anything.
  4. Returns a dict with success, error, results (per-target), count.

Only supports local .gpr projects (no shared-server or HTTP); the worker has no
MCP session and no access to the main process's ProgramInfo objects.
"""

from __future__ import annotations

import logging

from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers: transaction, function resolution, signature index
# ---------------------------------------------------------------------------


def _run_program_transaction(program: Any, label: str, operation: Any) -> Any:
    """Run an operation inside a Ghidra transaction; commit on success, rollback on exception."""
    tx: Any = program.startTransaction(label)
    try:
        result: Any = operation()
        program.endTransaction(tx, True)
        return result
    except Exception:
        program.endTransaction(tx, False)
        raise


def _resolve_function(program: Any, function_identifier: str) -> Any | None:
    """Resolve function by exact name, entry point string, or symbol/address via AddressUtil."""
    if not function_identifier or not program:
        return None
    fm: Any = program.getFunctionManager()
    if fm is None:
        return None
    for func in fm.getFunctions(True):
        if func.getName() == function_identifier or str(func.getEntryPoint()) == function_identifier:
            return func
    try:
        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, function_identifier)
        if addr is not None:
            return fm.getFunctionContaining(addr)
    except Exception:
        pass
    return None


def _build_by_signature(program: Any) -> dict[tuple[int, str], list[Any]]:
    """Build index (param_count, return_type) → list of functions for fast signature-based matching."""
    fm: Any = program.getFunctionManager()
    if fm is None:
        return {}
    by_sig: dict[tuple[int, str], list[Any]] = defaultdict(list)
    for func in fm.getFunctions(True):
        key = (func.getParameterCount(), str(func.getReturnType()))
        by_sig[key].append(func)
    return dict(by_sig)


def run_auto_match_subprocess(
    project_dir: str,
    project_name: str,
    source_program_path: str,
    function_identifier: str,
    target_program_paths: list[str],
    propagate_names: bool = True,
    propagate_tags: bool = True,
    propagate_comments: bool = True,
    propagate_prototype: bool = True,
    propagate_bookmarks: bool = True,
    min_similarity: float = 0.7,
) -> dict[str, Any]:
    """Run match-function propagation in this process (invoked by ProcessPoolExecutor).

    Opens the Ghidra project, resolves the source function, and for each target
    program finds the best match by (param_count, return_type) and optional name.
    Then propagates name/prototype/tags/comments/bookmarks as requested; handles
    versioned checkout/checkin when needed. Caller must pass only serializable
    arguments (strings, lists, floats). Returns a dict with success, error,
    results (list of per-target entries), count, and sourceFunction.
    """
    result: dict[str, Any] = {"success": False, "error": None, "results": [], "count": 0}
    try:
        from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingModuleSource]

        ghidra_project = GhidraProject.openProject(project_dir, project_name, False)
    except Exception as e:
        result["error"] = f"Failed to open project: {e}"
        logger.warning("Auto-match worker: %s", result["error"])
        return result

    try:
        project_data = ghidra_project.getProject().getProjectData()
        if project_data is None:
            result["error"] = "No project data"
            return result

        # Resolve source program by path (e.g. /folder/binary.exe)
        domain_file = project_data.getFile(source_program_path)
        if domain_file is None:
            result["error"] = f"Source program not found: {source_program_path}"
            return result

        try:
            source_program: Any = ghidra_project.openProgram(domain_file)  # pyright: ignore[reportCallIssue]
        except Exception:
            source_program = ghidra_project.openProgram(domain_file, programName=source_program_path, readOnly=False)
        if source_program is None:
            result["error"] = f"Failed to open source program: {source_program_path}"
            return result

        try:
            source_func = _resolve_function(source_program, function_identifier)
            if source_func is None:
                result["error"] = f"Function not found: {function_identifier}"
                return result

            source_name = source_func.getName()
            source_sig = str(source_func.getSignature())
            sig_key = (source_func.getParameterCount(), str(source_func.getReturnType()))
            results_per_target: list[dict[str, Any]] = []

            for target_path in target_program_paths:
                target_path = str(target_path).strip()
                if not target_path:
                    continue
                try:
                    tgt_df = project_data.getFile(target_path)
                    if tgt_df is None:
                        results_per_target.append({"targetProgramPath": target_path, "matched": None, "error": "Program not found"})
                        continue
                    try:
                        target_program: Any = ghidra_project.openProgram(tgt_df)  # pyright: ignore[reportCallIssue]
                    except Exception:
                        # Some Ghidra API versions require programName and readOnly
                        target_program = ghidra_project.openProgram(tgt_df, programName=target_path, readOnly=False)
                    if target_program is None:
                        results_per_target.append({"targetProgramPath": target_path, "matched": None, "error": "Failed to open"})
                        continue
                except Exception as outer_e:
                    results_per_target.append({"targetProgramPath": target_path, "matched": None, "error": str(outer_e)})
                    continue

                try:
                    by_sig = _build_by_signature(target_program)
                    candidates = by_sig.get(sig_key, [])
                    # Score: 1.0 if name matches, 0.7 if signature only (same param_count + return_type)
                    best_func: Any | None = None
                    best_score: float = 0.0
                    for func in candidates:
                        score = 1.0 if func.getName() == source_name else 0.7
                        if score >= min_similarity and score > best_score:
                            best_score = score
                            best_func = func

                    if best_func is None:
                        results_per_target.append({"targetProgramPath": target_path, "matched": None, "candidatesBySignature": len(candidates)})
                        target_program.close()
                        continue

                    target_func = best_func
                    # Build result entry for this target; we'll append to propagated[] as we apply each kind of propagation
                    entry: dict[str, Any] = {
                        "targetProgramPath": target_path,
                        "matched": {"name": target_func.getName(), "address": str(target_func.getEntryPoint())},
                        "propagated": [],
                    }

                    domain_file_tgt = target_program.getDomainFile()
                    is_versioned = domain_file_tgt.isVersioned() if domain_file_tgt else False
                    we_did_checkout: bool = False
                    did_propagate: bool = False  # True if we wrote any changes (used to decide whether to checkin)

                    # If target is under version control and not checked out, checkout so we can modify
                    if is_versioned and domain_file_tgt is not None and not domain_file_tgt.isCheckedOut():
                        try:
                            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

                            domain_file_tgt.checkout(False, TaskMonitor.DUMMY)
                            we_did_checkout = True
                        except Exception as e:
                            results_per_target.append({"targetProgramPath": target_path, "matched": None, "error": f"Checkout: {e}"})
                            target_program.close()
                            continue

                    if propagate_names and target_func.getName() != source_name:

                        def _rename() -> None:
                            # Persist name in program transaction
                            from ghidra.program.model.symbol import SourceType  # pyright: ignore[reportMissingModuleSource]

                            target_func.setName(source_name, SourceType.USER_DEFINED)

                        _run_program_transaction(target_program, "match-function-rename", _rename)
                        entry["propagated"].append("name")
                        did_propagate = True

                    if propagate_prototype:
                        target_sig = str(target_func.getSignature())
                        if source_sig != target_sig:
                            try:

                                def _set_proto() -> None:
                                    target_func.setSignature(source_sig)

                                _run_program_transaction(target_program, "match-function-prototype", _set_proto)
                                entry["propagated"].append("prototype")
                                did_propagate = True
                            except Exception:
                                pass  # setSignature not supported on all Ghidra versions or target may be read-only

                    if propagate_tags:
                        source_tags = [t.getName() for t in source_func.getTags()]
                        existing = {t.getName() for t in target_func.getTags()}
                        to_add = [t for t in source_tags if t not in existing]
                        if to_add:
                            # Add only tags the target doesn't already have
                            def _add_tags() -> None:
                                for tag in to_add:
                                    target_func.addTag(tag)

                            _run_program_transaction(target_program, "match-function-tags", _add_tags)
                            entry["propagated"].extend(to_add)
                            did_propagate = True

                    if propagate_comments:
                        try:
                            from ghidra.program.model.listing import CodeUnit  # pyright: ignore[reportMissingModuleSource]

                            source_listing = source_program.getListing()
                            target_listing = target_program.getListing()
                            source_entry = source_func.getEntryPoint()
                            target_entry_addr = target_func.getEntryPoint()
                            for ctype in (
                                CodeUnit.PLATE_COMMENT,
                                CodeUnit.PRE_COMMENT,
                                CodeUnit.POST_COMMENT,
                                CodeUnit.EOL_COMMENT,
                                CodeUnit.REPEATABLE_COMMENT,
                            ):
                                try:
                                    comment = source_listing.getComment(ctype, source_entry)
                                    if comment and str(comment).strip():
                                        _comment = comment  # Capture for closure; _set_comment runs in transaction later
                                        def _set_comment() -> None:
                                            target_listing.setComment(target_entry_addr, ctype, _comment)

                                        _run_program_transaction(target_program, "match-function-comment", _set_comment)
                                        entry["propagated"].append("comment")
                                        did_propagate = True
                                except Exception:
                                    continue
                        except Exception:
                            pass

                    if propagate_bookmarks:
                        try:
                            source_bm_mgr = source_program.getBookmarkManager()
                            target_bm_mgr = target_program.getBookmarkManager()
                            source_entry_addr = source_func.getEntryPoint()
                            target_entry_addr = target_func.getEntryPoint()
                            # Collect bookmarks at source function entry; fallback to iterator if getBookmarks(addr) not available
                            source_bms = list(source_bm_mgr.getBookmarks(source_entry_addr)) if hasattr(source_bm_mgr, "getBookmarks") else []
                            if not source_bms and hasattr(source_bm_mgr, "getBookmarksIterator"):
                                for bm in source_bm_mgr.getBookmarksIterator():
                                    if bm.getAddress().equals(source_entry_addr):
                                        source_bms.append(bm)
                            bm_data = [(bm.getTypeString(), bm.getCategory(), bm.getComment() or "") for bm in source_bms]
                            if bm_data:

                                def _set_bookmarks() -> None:
                                    for bm_type, bm_cat, bm_comment in bm_data:
                                        target_bm_mgr.setBookmark(target_entry_addr, bm_type, bm_cat, bm_comment)

                                _run_program_transaction(target_program, "match-function-bookmarks", _set_bookmarks)
                                entry["propagated"].append("bookmarks")
                                did_propagate = True
                        except Exception:
                            pass

                    # If we modified the target (or checked it out), checkin so changes are committed to the repo
                    if is_versioned and domain_file_tgt is not None and (we_did_checkout or did_propagate):
                        try:
                            from ghidra.framework.data import CheckinHandler  # pyright: ignore[reportMissingModuleSource]
                            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

                            # keepCheckedOut=true when we only propagated (didn't checkout ourselves) so caller can keep editing
                            keep_out = not we_did_checkout and did_propagate

                            class _MatchCheckinHandler(CheckinHandler):  # type: ignore[misc]
                                def getComment(self) -> str:
                                    return "Auto match-function propagation"

                                def keepCheckedOut(self) -> bool:
                                    return keep_out

                                def createKeepFile(self) -> bool:
                                    return False

                            domain_file_tgt.checkin(_MatchCheckinHandler(), TaskMonitor.DUMMY)
                        except Exception as e:
                            logger.debug("Checkin after propagation failed: %s", e)

                    results_per_target.append(entry)
                finally:
                    target_program.close()

            source_program.close()
            result["success"] = True
            result["results"] = results_per_target
            result["count"] = len(results_per_target)
            result["sourceFunction"] = source_name
            return result
        finally:
            source_program.close()
    except Exception as e:
        result["error"] = str(e)
        logger.warning("Auto-match worker failed: %s", e)
        return result
