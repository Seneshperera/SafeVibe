"""URL analyzer (SRS F3). Pure string analysis: it NEVER fetches or opens the URL."""
import ipaddress
from urllib.parse import urlsplit

import tldextract

from app.analyzers.base import Analyzer
from app.models.schemas import Artefact, ArtefactType, EvidenceItem, SignalFamily

RULES_VERSION = "url_rules_v1"
# offline: use the suffix list bundled with the package, no network call
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf",
              "ga", "work", "support", "loan", "rest", "icu", "cyou", "monster"}
# brand keyword -> registered domains that legitimately own it (extend as needed)
BRANDS = {
    "paypal": {"paypal.com"}, "amazon": {"amazon.com", "amazon.co.uk", "amazonaws.com"},
    "apple": {"apple.com", "icloud.com"}, "microsoft": {"microsoft.com", "live.com", "office.com"},
    "google": {"google.com", "gmail.com", "goo.gl"}, "netflix": {"netflix.com"},
    "dhl": {"dhl.com"}, "fedex": {"fedex.com"}, "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"}, "whatsapp": {"whatsapp.com"},
    "commercialbank": {"combank.lk"}, "sampath": {"sampath.lk"}, "hnb": {"hnb.net"},
}


class UrlAnalyzer(Analyzer):
    family = SignalFamily.URL

    def _ev(self, art: Artefact, rid: str, contrib: float, technical: str, plain: str, **details):
        return EvidenceItem(
            signal_family=self.family, rule_id=rid, rule_version=RULES_VERSION,
            contribution=contrib, artefact_id=art.artefact_id,
            technical=technical, plain=plain, details=details,
        )

    def analyze(self, artefact: Artefact) -> list[EvidenceItem]:
        if artefact.type != ArtefactType.URL or not artefact.canonical:
            return []
        url = artefact.canonical
        parts = urlsplit(url)
        host = parts.hostname or ""
        ext = _extract(host)
        registered = getattr(ext, 'top_domain_under_public_suffix', None) or ext.registered_domain  # '' for IPs
        ev: list[EvidenceItem] = []

        # IP-address host
        try:
            ipaddress.ip_address(host)
            ev.append(self._ev(artefact, "U-IP-01", 0.5,
                               f"Host is a raw IP address ({host}) instead of a domain name.",
                               "The link points to a numeric address instead of a normal website name."))
        except ValueError:
            pass

        if parts.scheme == "http":
            ev.append(self._ev(artefact, "U-NOHTTPS-01", 0.15,
                               "URL uses HTTP (or no scheme was given), so traffic is not encrypted.",
                               "The link does not use a secure (https) connection."))

        if registered in SHORTENERS:
            ev.append(self._ev(artefact, "U-SHORT-01", 0.35,
                               f"Known URL shortener ({registered}) hides the final destination.",
                               "This is a shortened link, so you cannot see where it really leads.",
                               shortener=registered))

        if parts.username:
            ev.append(self._ev(artefact, "U-AT-01", 0.5,
                               "URL contains user-info ('@'), which can disguise the real host.",
                               "The link contains an '@' trick that can make it look like a different site."))

        if "xn--" in host:
            ev.append(self._ev(artefact, "U-PUNY-01", 0.45,
                               "Host contains punycode (xn--), possible look-alike (homograph) domain.",
                               "The website name uses special characters that can imitate a real brand."))

        sub_labels = [s for s in ext.subdomain.split(".") if s]
        if len(sub_labels) >= 3:
            ev.append(self._ev(artefact, "U-SUBDOM-01", 0.25,
                               f"Excessive subdomain depth ({len(sub_labels)} labels).",
                               "The link has an unusually long chain of name parts, often used to hide the real site.",
                               subdomain=ext.subdomain))

        if ext.suffix.split(".")[-1] in RISKY_TLDS:
            ev.append(self._ev(artefact, "U-TLD-01", 0.20,
                               f"Top-level domain '.{ext.suffix}' is frequently abused.",
                               "The website ending is one that scammers often use.",
                               tld=ext.suffix))

        if "%" in (parts.path + parts.query) and len(url) > 0:
            ev.append(self._ev(artefact, "U-ENC-01", 0.10,
                               "URL contains percent-encoded characters.",
                               "The link contains encoded characters, which can hide what it contains."))

        if len(url) > 100:
            ev.append(self._ev(artefact, "U-LONG-01", 0.10,
                               f"Unusually long URL ({len(url)} characters).",
                               "The link is unusually long."))

        # visible brand vs registered domain (FR-03-002)
        if registered:
            haystack = (ext.subdomain + "." + ext.domain + parts.path).lower()
            for brand, owners in BRANDS.items():
                if brand in haystack and registered not in owners:
                    ev.append(self._ev(artefact, "U-BRAND-01", 0.55,
                                       f"Brand '{brand}' appears in the URL but the registered domain is "
                                       f"'{registered}', not one of {sorted(owners)}.",
                                       f"The link mentions '{brand}' but actually belongs to '{registered}'.",
                                       brand=brand, registered_domain=registered))
                    break
        return ev
