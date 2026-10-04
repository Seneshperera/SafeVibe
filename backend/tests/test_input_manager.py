import pytest
from app.core.config import Settings
from app.input_manager.manager import InputValidationError, build_artefacts, canonicalize_url
from app.models.schemas import AnalysisRequestIn

cfg = Settings()


def test_canonical_keeps_original():  # FR-01-002
    arts = build_artefacts(AnalysisRequestIn(urls=["HTTP://Example.COM:80/a#frag"]), cfg)
    assert arts[0].original == "HTTP://Example.COM:80/a#frag"
    assert arts[0].canonical == "http://example.com/a"


def test_missing_scheme_gets_http():
    assert canonicalize_url("example.com/x").startswith("http://example.com")


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "ftp://x.com", "http://", "has space.com"])
def test_bad_urls_rejected(bad):
    with pytest.raises(InputValidationError):
        build_artefacts(AnalysisRequestIn(urls=[bad]), cfg)


def test_empty_request_rejected():  # FR-01-005
    with pytest.raises(InputValidationError):
        build_artefacts(AnalysisRequestIn(), cfg)


def test_oversized_text_rejected():
    with pytest.raises(InputValidationError) as e:
        build_artefacts(AnalysisRequestIn(text="a" * (cfg.max_text_chars + 1)), cfg)
    assert e.value.errors[0]["field"] == "text"


def test_conversation_order_preserved():  # FR-01-004
    arts = build_artefacts(AnalysisRequestIn(conversation=["hi", "pay now"]), cfg)
    assert [a.index for a in arts] == [0, 1]
