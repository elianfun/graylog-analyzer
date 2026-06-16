import requests
from datetime import datetime, timezone
from requests.auth import HTTPBasicAuth

ANOMALY_QUERY = (
    "message:error OR message:fail OR message:down "
    "OR message:critical OR message:alarm OR message:FAILURE "
    "OR message:WRITE_DMA OR message:spinning "
    "OR message:overheat OR message:reboot OR message:restart "
    "OR message:panic OR message:storm"
)


class GraylogClient:
    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.auth = HTTPBasicAuth(token, "token")
        self.headers = {"Accept": "application/json"}

    def _parse_messages(self, raw: list[dict]) -> list[dict]:
        results = []
        for msg in raw:
            m = msg.get("message", {})
            results.append({
                "timestamp": m.get("timestamp", ""),
                "source": m.get("source", "unknown"),
                "level": m.get("level", -1),
                "message": m.get("message", ""),
            })
        return results

    def search_relative(self, query: str, range_seconds: int = 3600, limit: int = 200) -> list[dict]:
        endpoint = f"{self.url}/api/search/universal/relative"
        params = {"query": query, "range": range_seconds, "limit": limit}
        try:
            resp = requests.get(endpoint, params=params, auth=self.auth,
                                headers=self.headers, timeout=30)
            resp.raise_for_status()
            return self._parse_messages(resp.json().get("messages", []))
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Graylog 查詢失敗: {e}")
            return []

    def search_absolute(self, query: str, from_dt: datetime, to_dt: datetime,
                        limit: int = 500) -> list[dict]:
        endpoint = f"{self.url}/api/search/universal/absolute"
        params = {
            "query": query,
            "from": from_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "to": to_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "limit": limit,
        }
        try:
            resp = requests.get(endpoint, params=params, auth=self.auth,
                                headers=self.headers, timeout=30)
            resp.raise_for_status()
            return self._parse_messages(resp.json().get("messages", []))
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Graylog 查詢失敗: {e}")
            return []

    def fetch_anomalies(self, range_seconds: int = 86400, limit: int = 200) -> list[dict]:
        """單次撈取（相對時間，向下相容）"""
        return self.search_relative(ANOMALY_QUERY, range_seconds, limit)

    def fetch_anomalies_by_hour(self, from_dt: datetime, to_dt: datetime,
                                limit: int = 1000) -> list[dict]:
        """撈取指定小時區間的異常 log"""
        return self.search_absolute(ANOMALY_QUERY, from_dt, to_dt, limit)
