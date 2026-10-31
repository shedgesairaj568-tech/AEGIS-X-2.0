"""
Cross-dialect column types.

`GUID` stores a native UUID on PostgreSQL (production/dev) and a CHAR(36)
on any other dialect (SQLite, used by the test suite) — the standard
SQLAlchemy recipe for keeping ORM models portable between a real Postgres
database and a fast in-memory test database, without needing a Postgres
instance just to run unit tests.

`JSONB_OR_JSON` stores native JSONB on PostgreSQL (indexable, queryable)
and plain JSON on other dialects — same portability rationale.
"""

import uuid

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.types import CHAR, JSON, TypeDecorator


class GUID(TypeDecorator):
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return str(value)
        if not isinstance(value, uuid.UUID):
            return str(uuid.UUID(value))
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)


class JSONB_OR_JSON(TypeDecorator):
    """
    Native JSONB on PostgreSQL; falls back to generic JSON (stored as TEXT)
    on other dialects such as SQLite. Use for flexible/semi-structured
    columns (raw event payloads, arbitrary metadata) where a fixed schema
    isn't appropriate.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())
