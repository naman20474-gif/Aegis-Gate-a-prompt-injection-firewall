"""SQLite/SQLModel database setup."""
from __future__ import annotations

from collections.abc import Generator

from sqlmodel import Session, SQLModel, create_engine
from sqlalchemy.pool import StaticPool


class Database:
    def __init__(self, url: str):
        kwargs: dict[str, object] = {"echo": False}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        if url in {"sqlite://", "sqlite:///:memory:"}:
            kwargs["poolclass"] = StaticPool
        self.engine = create_engine(url, **kwargs)

    def create_all(self) -> None:
        # Import tables before metadata creation.
        from . import models  # noqa: F401

        SQLModel.metadata.create_all(self.engine)

    def session(self) -> Session:
        return Session(self.engine)

    def get_session(self) -> Generator[Session, None, None]:
        with self.session() as session:
            yield session
