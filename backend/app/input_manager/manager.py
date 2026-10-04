"""Input Manager: validate, classify, canonicalise (SRS F1 / FR-01-*)."""
import re
from urllib.parse import urlsplit, urlunsplit, quote

from app.core.config import Settings
from app.models.schemas import AnalysisRequestIn, Artefact, ArtefactType


class InputValidationError(Exception):
    """Carries field-level errors (FR-01-005)."""

    def __init__(self, errors: list[dict]):
        self.errors = errors
        super().__init__("Input validation failed")


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def canonicalize_url(raw: str) -> str:
    """Normalise a URL for analysis. The original is kept separately.

    - adds http:// if no scheme (an assumption; the analyzer flags missing HTTPS)
    - lowercases scheme/host, IDNA-encodes host, strips default port & fragment
    - never fetches or opens the URL
    Raises ValueError for unusable URLs.
    """
    s = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        s = "http://" + s
    parts = urlsplit(s)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http and https URLs are supported")
    host = parts.hostname
    if not host:
        raise ValueError("URL has no host")
    try:
        host_ascii = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("URL host is not a valid domain name")
    netloc = host_ascii
    if parts.username:  # keep userinfo visible: '@' tricks are a phishing signal
        userinfo = parts.username + (":" + parts.password if parts.password else "")
        netloc = f"{userinfo}@{netloc}"
    default = {"http": 80, "https": 443}[parts.scheme.lower()]
    if parts.port and parts.port != default:
        netloc += f":{parts.port}"
    path = quote(parts.path, safe="/%:@!$&'()*+,;=-._~")
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def build_artefacts(req: AnalysisRequestIn, cfg: Settings) -> list[Artefact]:
    errors: list[dict] = []
    artefacts: list[Artefact] = []

    def check_text(field: str, value: str, limit: int):
        if _CONTROL_CHARS.search(value):
            errors.append({"field": field, "message": "Contains unsupported control characters."})
        if len(value) > limit:
            errors.append({"field": field, "message": f"Too long (max {limit} characters)."})

    if req.text is not None and req.text.strip():
        check_text("text", req.text, cfg.max_text_chars)
        artefacts.append(Artefact(type=ArtefactType.TEXT, original=req.text, canonical=req.text.strip()))
    elif req.text is not None and not req.text.strip():
        errors.append({"field": "text", "message": "Text is empty."})

    if len(req.urls) > cfg.max_urls:
        errors.append({"field": "urls", "message": f"Too many URLs (max {cfg.max_urls})."})
    else:
        for i, u in enumerate(req.urls):
            field = f"urls[{i}]"
            if not u.strip():
                errors.append({"field": field, "message": "URL is empty."})
                continue
            if len(u) > cfg.max_url_chars:
                errors.append({"field": field, "message": f"URL too long (max {cfg.max_url_chars})."})
                continue
            if _CONTROL_CHARS.search(u) or re.search(r"\s", u.strip()):
                errors.append({"field": field, "message": "URL contains whitespace or control characters."})
                continue
            try:
                artefacts.append(Artefact(type=ArtefactType.URL, original=u, canonical=canonicalize_url(u), index=i))
            except ValueError as e:
                errors.append({"field": field, "message": str(e)})

    if req.conversation:
        if len(req.conversation) > cfg.max_conversation_messages:
            errors.append({"field": "conversation",
                           "message": f"Too many messages (max {cfg.max_conversation_messages})."})
        else:
            for i, m in enumerate(req.conversation):
                if not m.strip():
                    errors.append({"field": f"conversation[{i}]", "message": "Message is empty."})
                    continue
                check_text(f"conversation[{i}]", m, cfg.max_message_chars)
                artefacts.append(Artefact(type=ArtefactType.CONVERSATION, original=m,
                                          canonical=m.strip(), index=i))

    if req.email_headers is not None and req.email_headers.strip():
        check_text("email_headers", req.email_headers, cfg.max_text_chars)
        artefacts.append(Artefact(type=ArtefactType.EMAIL_HEADERS, original=req.email_headers,
                                  canonical=req.email_headers.strip()))

    if not artefacts and not errors:
        errors.append({"field": "__root__", "message": "Provide at least one of: text, urls, conversation, email_headers."})
    if errors:
        raise InputValidationError(errors)
    return artefacts
