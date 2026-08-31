"""Transport-neutral page response returned by dashboard page functions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PageResult:
    body: str
    status: int = 200
    headers: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not 100 <= int(self.status) <= 599:
            raise ValueError("HTTP status must be between 100 and 599")
        headers = tuple((str(name), str(value)) for name, value in self.headers)
        if any(not name.strip() for name, _value in headers):
            raise ValueError("HTTP header names cannot be empty")
        object.__setattr__(self, "status", int(self.status))
        object.__setattr__(self, "headers", headers)

    def header(self, name: str, default: str | None = None) -> str | None:
        wanted = name.casefold()
        return next((value for key, value in self.headers if key.casefold() == wanted), default)

    @classmethod
    def ok(cls, body: str, *, headers: tuple[tuple[str, str], ...] = ()) -> "PageResult":
        return cls(body=body, status=200, headers=headers)

    @classmethod
    def not_found(cls, body: str) -> "PageResult":
        return cls(body=body, status=404)

    @classmethod
    def redirect(cls, location: str, *, permanent: bool = False) -> "PageResult":
        if not str(location).startswith("/"):
            raise ValueError("dashboard redirects must use an absolute-path location")
        return cls(body="", status=308 if permanent else 302,
                   headers=(("Location", str(location)),))
