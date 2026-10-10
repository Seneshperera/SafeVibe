from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool


def normalize_url(url: str) -> str:
    """Accept the plain postgres:// URLs that hosts like Neon/Render hand out."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


def make_engine(url: str) -> Engine:
    url = normalize_url(url)
    kw: dict = {}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kw["poolclass"] = StaticPool          # one shared in-memory DB (tests)
    else:
        kw["pool_pre_ping"] = True                # free hosts drop idle connections
    return create_engine(url, **kw)
