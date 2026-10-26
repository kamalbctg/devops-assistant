import httpx

from .base import Connector, ConnectorError


class HttpConnector(Connector):
    """Shared httpx client. Tests inject `transport` (httpx.MockTransport)."""

    transport: httpx.BaseTransport | None = None

    def base_url(self) -> str:
        return self.setting("url").rstrip("/")

    def headers(self) -> dict:
        token = self.secret("token", required=False)
        return {"Authorization": f"Bearer {token}"} if token else {}

    def http(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url(), headers=self.headers(),
                            timeout=self.settings.get("timeout_s", 15), transport=self.transport)

    def get(self, path: str, **params) -> httpx.Response:
        with self.http() as c:
            return self._check(c.get(path, params=params))

    def post(self, path: str, body: dict) -> httpx.Response:
        with self.http() as c:
            return self._check(c.post(path, json=body))

    def _check(self, r: httpx.Response) -> httpx.Response:
        if r.status_code in (401, 403):
            raise ConnectorError(f"{self.type}: access denied ({r.status_code}) for {r.request.url.path}")
        r.raise_for_status()
        return r
