"""
OpenFGA REST client implementation.

This client communicates directly with OpenFGA's REST API using
`requests`. It implements the BaseOpenFGAClient interface.
"""

from typing import Any

import requests

from django_authz.authorization.base import BaseOpenFGAClient


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

    def write(self, tuples: list[dict[str, Any]]) -> None:
        resp = requests.post(
            f"{self.api_url}/stores/{self.store_id}/write",
            json={"writes": {"tuple_keys": tuples}},
            timeout=5,
        )
        resp.raise_for_status()

    def list_relations(self, user: str, object_: str) -> list[str]:
        resp = requests.get(
            f"{self.api_url}/stores/{self.store_id}/list-relations",
            params={"user": user, "object": object_},
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json().get("relations", [])
