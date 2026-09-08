"""Resolve a finite cross-game sibling queue from an explicit review ledger.

Unknown pairs remain in ``verify``. The default ledger is the reviewed
accessor/mutator contradictions measured on the original corpus; operators
may replace it with a JSON object mapping ``src|dst`` keys to rationales.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_LEDGER: dict[tuple[str, str], str] = {
    (
        "CSWSCreatureStats::GetTalentHasCompatibleCategory",
        "CSWSCreatureStats::AddSpellLikeAbilityToList",
    ): "a compatibility query and a list mutation are different operations",
    (
        "Gob::GetPartLocalPosition",
        "Gob::SetPartLocalPosition",
    ): "an accessor and mutator have incompatible direction and signatures",
    (
        "PartTriMesh::RestoreTextureMatrix",
        "PartTriMesh::TransformTextureMatrix",
    ): "restoring saved state and applying a transform are different operations",
    (
        "GLRender::DrawLightmappedGrass",
        "GLRender::FrameBufferModificationsATI",
    ): "grass drawing and ATI framebuffer handling are unrelated render stages",
    (
        "CClientExoAppInternal::SetPlayerCharacterName",
        "CClientExoAppInternal::GetPlayerCharacterName",
    ): "a setter taking a string and a zero-argument getter are different operations",
    (
        "GLRender::SetTexCoordBuffer",
        "GLRender::SetClientArray8",
    ): "a semantic texture-coordinate buffer setter is not the typed client-array helper",
    (
        "GLRender::SetVertexBuffer",
        "GLRender::SetClientArray12",
    ): "a semantic vertex buffer setter is not the typed client-array helper",
    (
        "GLRender::SetColorBuffer",
        "GLRender::SetClientArray4ub",
    ): "a semantic color buffer setter is not the typed client-array helper",
    (
        "CServerExoAppInternal::TogglePauseState",
        "CServerExoAppInternal::GetPauseState",
    ): "a state-changing toggle and a state query are different operations",
    (
        "PartEmitter::RenderNothing",
        "PartEmitter::chkParticleLife",
    ): "a render path and a particle-lifetime check are different emitter operations",
    (
        "GLRender::FrameBufferModifications2",
        "GLRender::RenderFrameToTextureATI",
    ): "general framebuffer modification and ATI frame-to-texture rendering are distinct paths",
    (
        "GLRender::SetNormalBuffer",
        "GLRender::MakeNormalizationCubeMap",
    ): "binding a normal buffer and constructing a normalization cube map are different operations",
    (
        "GLRender::SetInterleavedBuffer",
        "GLRender::SetLightmapTexCoordToStage0",
    ): "setting an interleaved buffer and assigning lightmap coordinates to a stage are different operations",
    (
        "CSWSEncounter::LineSegmentIntersectActivateArea",
        "CSWSEncounter::ClearSpawnList",
    ): "geometry intersection and clearing encounter spawn state are unrelated operations",
    (
        "CSWSItemPropertyHandler::ApplyDecreasedAC",
        "CSWSItemPropertyHandler::ApplyImprovedForceResistance",
    ): "the handlers apply different item-property effects despite similar control flow",
    (
        "CSWGuiLabelHilight::Load",
        "CSWGuiLabelHilight::Draw",
    ): "resource loading and drawing are different GUI lifecycle operations",
    (
        "CSWParty::RemoveCharacter",
        "CSWParty::GetIndex",
    ): "party mutation and index lookup are different operations",
}


def load_ledger(path: Path | None = None) -> dict[tuple[str, str], str]:
    if path is None or not Path(path).is_file():
        return dict(DEFAULT_LEDGER)
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for key, rationale in data.items():
        if "|" in key:
            src, dst = key.split("|", 1)
            out[(src, dst)] = rationale
    return out


REVIEW_RATIONALES = DEFAULT_LEDGER


def classify(row: dict, ledger: dict[tuple[str, str], str] | None = None) -> dict:
    """Apply only explicit, reviewed cross-game decisions."""
    table = ledger if ledger is not None else REVIEW_RATIONALES
    decision = dict(row)
    rationale = table.get((row["src_key"], row["dst_key"]))
    if rationale:
        decision.update(
            decision="rejected",
            reason="independent_cross_game_names_and_semantics_disagree",
            review_rationale=rationale,
        )
    else:
        decision.update(
            decision="verify",
            reason="cross_game_rename_requires_evidence",
        )
    return decision


def load_candidates(queue_path: Path, decisions_path: Path) -> list[dict]:
    """Keep completed reviews replayable after the live queue reaches zero."""
    rows = [json.loads(line) for line in Path(queue_path).read_text(encoding="utf-8").splitlines() if line]
    if rows or not Path(decisions_path).is_file():
        return rows
    return [json.loads(line) for line in Path(decisions_path).read_text(encoding="utf-8").splitlines() if line]
