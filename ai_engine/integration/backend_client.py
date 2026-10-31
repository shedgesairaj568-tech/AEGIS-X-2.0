"""
Backend API client.

Wraps the REST calls Module 9 needs against the live FastAPI backend
(Module 2/3): authenticate as a service account, create alerts, add
timeline entries, create reports, and fetch related alerts for
correlation. This is the ONLY place in the AI pipeline that knows the
backend's HTTP contract — everything else (the agents, the graph) stays
completely decoupled from how results get persisted.

Handles token expiry transparently: if a call gets a 401, it re-logs-in
once and retries, rather than making every caller worry about token
lifetime (access tokens expire after 30 minutes by default — see
backend/app/core/config.py).
"""

import uuid

import requests

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


class BackendAuthError(Exception):
    """Raised when login to the backend fails — credentials wrong, service down, etc."""


class BackendClient:
    def __init__(self, base_url: str, email: str, password: str):
        self.base_url = base_url.rstrip("/")
        self._email = email
        self._password = password
        self._access_token: str | None = None

    def _login(self) -> None:
        resp = requests.post(
            f"{self.base_url}/api/v1/auth/login",
            json={"email": self._email, "password": self._password},
            timeout=10,
        )
        if resp.status_code != 200:
            raise BackendAuthError(f"Login failed for '{self._email}': {resp.status_code} {resp.text}")
        self._access_token = resp.json()["access_token"]
        logger.info("BackendClient authenticated as %s", self._email)

    def _headers(self) -> dict:
        if self._access_token is None:
            self._login()
        return {"Authorization": f"Bearer {self._access_token}"}

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        resp = requests.request(method, url, headers=self._headers(), timeout=15, **kwargs)

        if resp.status_code == 401:
            # Access token likely expired mid-run; re-authenticate once and retry.
            logger.info("Got 401 from backend, re-authenticating and retrying once.")
            self._login()
            resp = requests.request(method, url, headers=self._headers(), timeout=15, **kwargs)

        resp.raise_for_status()
        return resp

    # --- Alerts -------------------------------------------------------------

    def create_alert(self, alert_data: dict) -> dict:
        return self._request("POST", "/api/v1/alerts", json=alert_data).json()

    def get_related_alerts(
        self,
        attack_type: str | None = None,
        source_ip: str | None = None,
        exclude_id: uuid.UUID | str | None = None,
        limit: int = 20,
    ) -> list[dict]:
        params = {"limit": limit}
        if attack_type:
            params["attack_type"] = attack_type
        if source_ip:
            params["source_ip"] = source_ip
        if exclude_id:
            params["exclude_id"] = str(exclude_id)
        return self._request("GET", "/api/v1/alerts/related", params=params).json()

    def add_history_entry(
        self, alert_id: uuid.UUID | str, event_type: str, description: str, event_metadata: dict | None = None
    ) -> dict:
        payload = {"event_type": event_type, "description": description, "event_metadata": event_metadata}
        return self._request("POST", f"/api/v1/alerts/{alert_id}/history", json=payload).json()

    def create_report(self, alert_id: uuid.UUID | str, report_data: dict) -> dict:
        return self._request("POST", f"/api/v1/alerts/{alert_id}/reports", json=report_data).json()
