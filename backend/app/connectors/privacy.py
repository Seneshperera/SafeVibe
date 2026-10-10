"""Privacy filter for external queries (FR-01-007)."""
from urllib.parse import urlsplit, urlunsplit

SCOPE = "canonical URL; user-info and query string removed"


def privacy_filter_url(canonical_url: str) -> str:
    """Strip credentials and query string, which may carry tokens or personal data."""
    p = urlsplit(canonical_url)
    host = p.hostname or ""
    netloc = host + (f":{p.port}" if p.port else "")
    return urlunsplit((p.scheme, netloc, p.path, "", ""))
