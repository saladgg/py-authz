"""
OpenFGA REST client implementation for DRF2Auth.

This client communicates directly with OpenFGA's REST API using
`requests`. It implements the BaseOpenFGAClient interface, ensuring
compatibility with higher-level DRF2Auth components.
"""

import requests
from typing import Any, Dict, List
from drf_authz.authorization.base import BaseOpenFGAClient

class OpenFGAClient(BaseOpenFGAClient):
    """
    A lightweight OpenFGA client using REST API calls via `requests`.
    """

    def __init__(self, api_url: str, store_id: str):
        self.api_url = api_url.rstrip("/")
        self.store_id = store_id

    def check(self, user: str, relation: str, object_: str) -> bool:
        resp = requests.post(
            f"{self.api_url}/stores/{self.store_id}/check",
            json={"tuple_key": {"user": user, "relation": relation, "object": object_}},
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json().get("allowed", False)

    def write(self, tuples: List[Dict[str, Any]]) -> None:
        resp = requests.post(
            f"{self.api_url}/stores/{self.store_id}/write",
            json={"writes": {"tuple_keys": tuples}},
            timeout=5,
        )
        resp.raise_for_status()

    def list_relations(self, user: str, object_: str) -> List[str]:
        resp = requests.get(
            f"{self.api_url}/stores/{self.store_id}/list-relations",
            params={"user": user, "object": object_},
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json().get("relations", [])
