"""Sender/authentication analyzer (SRS F3, FR-03-003). Input: pasted raw email headers.

Missing data is UNKNOWN, never evidence: a 'pass' or an absent header adds nothing.
Only explicit anomalies (fail, mismatch, spoofed display name) are scored.
"""
import re
from email import message_from_string
from email.header import decode_header, make_header
from email.utils import parseaddr
from typing import Optional

from app.analyzers.base import Analyzer
from app.analyzers.url import BRANDS, _extract
from app.models.schemas import Artefact, ArtefactType, EvidenceItem, SignalFamily

RULES_VERSION = "sender_rules_v1"
_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


def _decode(v: Optional[str]) -> str:
    if not v:
        return ""
    try:
        return str(make_header(decode_header(v)))
    except Exception:
        return str(v)


def _reg(addr: str) -> str:
    domain = addr.rsplit("@", 1)[-1].strip(" <>").lower() if "@" in addr else ""
    ext = _extract(domain)
    return getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or domain


class SenderAnalyzer(Analyzer):
    family = SignalFamily.SENDER

    @staticmethod
    def parse(text: str):
        return message_from_string(text)

    @staticmethod
    def has_from(text: str) -> bool:
        return bool(SenderAnalyzer.parse(text).get("From"))

    @staticmethod
    def auth_results(text: str) -> dict[str, list[str]]:
        msg = SenderAnalyzer.parse(text)
        found: dict[str, list[str]] = {}
        for h in msg.get_all("Authentication-Results") or []:
            for mech, res in _AUTH.findall(str(h)):
                found.setdefault(mech.lower(), []).append(res.lower())
        if "spf" not in found and msg.get("Received-SPF"):
            first = str(msg["Received-SPF"]).split()[0].lower() if str(msg["Received-SPF"]).split() else ""
            if first:
                found["spf"] = [first]
        return found

    def _ev(self, art, rid, contrib, technical, plain, **details):
        return EvidenceItem(signal_family=self.family, rule_id=rid, rule_version=RULES_VERSION,
                            contribution=contrib, artefact_id=art.artefact_id,
                            technical=technical, plain=plain, details=details)

    def analyze(self, artefact: Artefact) -> list[EvidenceItem]:
        if artefact.type != ArtefactType.EMAIL_HEADERS:
            return []
        text = artefact.canonical or artefact.original
        msg = self.parse(text)
        ev: list[EvidenceItem] = []

        name, addr = parseaddr(_decode(msg.get("From")))
        from_reg = _reg(addr)

        # display-name spoofing
        if name and from_reg:
            lowered = name.lower()
            hit: Optional[str] = None
            m = re.search(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", lowered)
            if m and _reg(m.group(0)) != from_reg:
                hit = f"display name contains a different address ({m.group(0)})"
            else:
                for brand, owners in BRANDS.items():
                    if brand in lowered.replace(" ", "") and from_reg not in owners:
                        hit = f"display name references '{brand}' but the sender domain is '{from_reg}'"
                        break
            if hit:
                ev.append(self._ev(artefact, "S-DISPLAY-01", 0.45,
                                   f"Possible display-name spoofing: {hit}.",
                                   "The sender's shown name suggests a trusted organisation, but the real address belongs to someone else.",
                                   header="From", display_name=name, sender_domain=from_reg))

        # return-path / reply-to consistency
        _, rp = parseaddr(_decode(msg.get("Return-Path")))
        if rp and from_reg and _reg(rp) != from_reg:
            ev.append(self._ev(artefact, "S-RETPATH-01", 0.20,
                               f"Return-Path domain '{_reg(rp)}' differs from From domain '{from_reg}'.",
                               "The address replies and bounces go to differs from the visible sender (weak signal on its own).",
                               header="Return-Path"))
        _, rt = parseaddr(_decode(msg.get("Reply-To")))
        if rt and from_reg and _reg(rt) != from_reg:
            ev.append(self._ev(artefact, "S-REPLYTO-01", 0.25,
                               f"Reply-To domain '{_reg(rt)}' differs from From domain '{from_reg}'.",
                               "If you reply, your answer would go to a different address than the one shown as sender.",
                               header="Reply-To"))

        # authentication results (only explicit failures count)
        auth = self.auth_results(text)
        table = {("spf", "fail"): ("S-AUTH-SPF-01", 0.35), ("spf", "softfail"): ("S-AUTH-SPF-02", 0.20),
                 ("dkim", "fail"): ("S-AUTH-DKIM-01", 0.30), ("dmarc", "fail"): ("S-AUTH-DMARC-01", 0.40)}
        for mech, results in auth.items():
            for res in dict.fromkeys(results):
                if (mech, res) in table:
                    rid, c = table[(mech, res)]
                    ev.append(self._ev(artefact, rid, c,
                                       f"{mech.upper()} result is '{res}' in the supplied headers.",
                                       "The email failed a standard check that proves who really sent it.",
                                       header="Authentication-Results", mechanism=mech, result=res))
        return ev
