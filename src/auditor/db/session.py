"""SQLAlchemy engine initialisation and session factory.

The engine is constructed from the DATABASE_URL environment variable rather
than from the Settings object so that session.py can be safely imported by
Alembic migration scripts, which run before the full application config is
loaded and may not have all Settings fields available.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://auditor:auditor_dev_only@localhost:5432/auditor",
)

engine = create_engine(
    _DATABASE_URL,
    # pool_size=5: maintain five idle connections in the pool.  The ingestion
    # service is single-process and never needs more than one concurrent
    # connection, but 5 leaves headroom for future parallelism without pool
    # exhaustion errors.
    pool_size=5,
    # max_overflow=0: forbid connections beyond pool_size.  Without this cap
    # an unexpected burst (e.g. a runaway analysis loop) could open hundreds
    # of connections and exhaust PostgreSQL's connection limit.  Hard failures
    # are preferable to silent resource exhaustion.
    max_overflow=0,
    # pool_pre_ping=True: before handing out a pooled connection, send a cheap
    # "SELECT 1" to verify it is still alive.  Without this, the first query
    # after a PostgreSQL restart or network interruption always fails with an
    # OperationalError; with it, the stale connection is discarded and a fresh
    # one is opened transparently.
    pool_pre_ping=True,
)

_SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)
# expire_on_commit=False: after a commit, ORM objects remain usable without
# triggering lazy-load SELECT queries.  The ingestion service reads freshly
# committed rows immediately after writing them, so expiry would cause
# unnecessary round-trips.


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Yield a database session, committing on clean exit and rolling back on error."""
    session: Session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
