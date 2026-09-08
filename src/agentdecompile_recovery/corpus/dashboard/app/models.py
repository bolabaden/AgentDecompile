"""Small, dependency-free contracts shared by dashboard routes and views.

The dashboard renders several different entities from artifacts with different
scopes and refresh times.  These immutable records keep those distinctions in
the call signatures instead of relying on an untyped integer or URL string.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias


class EntityKind(str, Enum):
    CORPUS = "corpus"
    BINARY = "binary"
    LOGICAL_FUNCTION = "logical_function"
    CONCRETE_FUNCTION = "concrete_function"
    RECOVERY_ARTIFACT = "recovery_artifact"


class MetricUniverse(str, Enum):
    RAW = "raw"
    NON_DRM = "non_drm"
    UNIQUE_NON_DRM = "unique_non_drm"
    EMITTER_SUBSET = "emitter_subset"
    RECOVERY_QUEUE = "recovery_queue"
    EXPORTED_SUBSET = "exported_subset"


def _positive_int(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be positive")
    return value


@dataclass(frozen=True, slots=True)
class BinaryRef:
    """A canonical slug and, optionally, its current database compatibility id.

    Numeric ids are allowed on their own only while parsing old dashboard URLs.
    New URL builders require ``slug`` so a database rebuild cannot change a
    link's meaning.
    """

    slug: str | None = None
    binary_id: int | None = None

    def __post_init__(self) -> None:
        slug = self.slug.strip() if isinstance(self.slug, str) else None
        if slug == "":
            slug = None
        if slug is not None and any(ord(char) < 32 for char in slug):
            raise ValueError("binary slug cannot contain control characters")
        binary_id = self.binary_id
        if binary_id is not None:
            binary_id = _positive_int(binary_id, "binary_id")
        if slug is None and binary_id is None:
            raise ValueError("binary reference needs a slug or binary_id")
        object.__setattr__(self, "slug", slug)
        object.__setattr__(self, "binary_id", binary_id)

    @property
    def is_canonical(self) -> bool:
        return self.slug is not None


@dataclass(frozen=True, slots=True)
class ConcreteFunctionRef:
    binary: BinaryRef
    address: int
    bits: int | None = None

    def __post_init__(self) -> None:
        if isinstance(self.address, bool) or not isinstance(self.address, int):
            raise ValueError("address must be an integer")
        address = self.address
        if address < 0:
            raise ValueError("address cannot be negative")
        if self.bits is not None and self.bits not in (16, 32, 64):
            raise ValueError("bits must be 16, 32, or 64")
        if self.bits is not None and address >= (1 << self.bits):
            raise ValueError(f"address does not fit in {self.bits} bits")
        object.__setattr__(self, "address", address)


@dataclass(frozen=True, slots=True)
class LogicalFunctionRef:
    logical_id: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "logical_id", _positive_int(self.logical_id, "logical_id"))


EntityRef: TypeAlias = BinaryRef | ConcreteFunctionRef | LogicalFunctionRef
GraphFocus: TypeAlias = ConcreteFunctionRef | LogicalFunctionRef


@dataclass(frozen=True, slots=True)
class GraphRoute:
    focus: GraphFocus
    depth: int = 2

    def __post_init__(self) -> None:
        if self.depth not in (1, 2):
            raise ValueError("graph depth must be 1 or 2")

    @property
    def uses_legacy_binary_id(self) -> bool:
        return (
            isinstance(self.focus, ConcreteFunctionRef)
            and self.focus.binary.slug is None
            and self.focus.binary.binary_id is not None
        )


@dataclass(frozen=True, slots=True)
class MetricScope:
    """The population and evidence boundary for one metric.

    ``snapshot`` is deliberately required.  Two equal-looking counts read from
    different artifact revisions are not the same measurement.
    """

    entity: EntityKind
    universe: MetricUniverse
    snapshot: str
    evidence: tuple[str, ...]
    qualifiers: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.entity, EntityKind):
            raise TypeError("entity must be an EntityKind")
        if not isinstance(self.universe, MetricUniverse):
            raise TypeError("universe must be a MetricUniverse")
        snapshot = str(self.snapshot).strip()
        if isinstance(self.evidence, (str, bytes)):
            raise TypeError("evidence must be a sequence of sources")
        evidence = tuple(str(item).strip() for item in self.evidence if str(item).strip())
        qualifiers = tuple((str(k).strip(), str(v).strip()) for k, v in self.qualifiers)
        if not snapshot:
            raise ValueError("metric scope needs a snapshot")
        if not evidence:
            raise ValueError("metric scope needs at least one evidence source")
        if any(not key or not value for key, value in qualifiers):
            raise ValueError("metric qualifiers need non-empty keys and values")
        object.__setattr__(self, "snapshot", snapshot)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "qualifiers", qualifiers)


@dataclass(frozen=True, slots=True)
class MetricRef:
    """A named metric whose value is only meaningful inside ``scope``."""

    key: str
    label: str
    unit: str
    scope: MetricScope

    def __post_init__(self) -> None:
        for field in ("key", "label", "unit"):
            value = str(getattr(self, field)).strip()
            if not value:
                raise ValueError(f"metric {field} cannot be empty")
            object.__setattr__(self, field, value)
