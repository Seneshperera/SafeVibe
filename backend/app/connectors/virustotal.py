"""VirusTotal v3 URL lookup (free tier ~4 req/min, non-commercial use). Verify terms (ISS-002)."""
import base64

from app.connectors.base import Connector, ConnectorResult, MALICIOUS, NO_MATCH, OK, SUSPICIOUS

BASE = "https://www.virustotal.com/api/v3/urls/"


class VirusTotalConnector(Connector):
    name = "virustotal"

    def _query(self, url: str) -> ConnectorResult:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = self.client.get(BASE + url_id, headers={"x-apikey": self.api_key})
        if resp.status_code == 404:   # URL not in VT's dataset: unknown, not clean
            return ConnectorResult(self.name, OK, NO_MATCH, note="URL not previously analysed by VirusTotal.")
        if (fail := self._http_failure(resp)):
            return fail
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        details = {"malicious_engines": mal, "suspicious_engines": sus}
        if mal >= 3:
            return ConnectorResult(self.name, OK, MALICIOUS, details=details)
        if mal >= 1 or sus >= 1:   # 1-2 engines is a weak, FP-prone signal
            return ConnectorResult(self.name, OK, SUSPICIOUS, details=details)
        return ConnectorResult(self.name, OK, NO_MATCH, details=details,
                               note="No engine flagged this URL (not proof of safety).")
