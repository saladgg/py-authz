"""
OpenFGA SDK client implementation for DRF2Auth.

This client wraps the official `openfga-sdk` Python library.
It implements the BaseOpenFGAClient interface, ensuring
compatibility with higher-level DRF2Auth components.
"""

from typing import Any, Dict, List
from openfga_sdk import Client, ClientConfiguration
from drf_authz.authorization.base import BaseOpenFGAClient


class OpenFGASDKClient(BaseOpenFGAClient):
    """
    A high-level OpenFGA client using the official `openfga-sdk`.
    """

    def __init__(self, api_url: str, store_id: str):
        self.client = Client(
            ClientConfiguration(api_url=api_url.rstrip("/"), store_id=store_id)
        )

    def check(self, user: str, relation: str, object_: str) -> bool:
        resp = self.client.check(
            body={"tuple_key": {"user": user, "relation": relation, "object": object_}}
        )
        return resp.get("allowed", False)

    def write(self, tuples: List[Dict[str, Any]]) -> None:
        self.client.write(body={"writes": {"tuple_keys": tuples}})

    def list_relations(self, user: str, object_: str) -> List[str]:
        resp = self.client.list_relations(
            params={"user": user, "object": object_}
        )
        return resp.get("relations", [])
