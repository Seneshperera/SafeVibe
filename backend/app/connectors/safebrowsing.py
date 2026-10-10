"""Google Safe Browsing Lookup (v4 threatMatches:find). Verify current API/terms (ISS-002)."""
from app.connectors.base import Connector, ConnectorResult, MALICIOUS, NO_MATCH, OK

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class SafeBrowsingConnector(Connector):
    name = "safe_browsing"

    def _query(self, url: str) -> ConnectorResult:
        body = {
            "client": {"clientId": "safevibe", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = self.client.post(ENDPOINT, params={"key": self.api_key}, json=body)
        if (fail := self._http_failure(resp)):
            return fail
        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError("bad shape")
        matches = data.get("matches") or []
        if matches:
            types = sorted({m["threatType"] for m in matches})
            return ConnectorResult(self.name, OK, MALICIOUS, details={"threat_types": types})
        return ConnectorResult(self.name, OK, NO_MATCH, note="No match in Safe Browsing lists.")
