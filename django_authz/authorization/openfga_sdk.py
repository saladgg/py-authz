"""
OpenFGA SDK client implementation.

The official `openfga-sdk` is async-native.  This module exposes two classes:

- ``OpenFGASDKClient`` — synchronous wrapper (blocks via ``asyncio.run``), suitable
  for standard Django views.
- ``AsyncOpenFGASDKClient`` — native async client for use with Django async views or
  ASGI deployments.

Both implement ``BaseOpenFGAClient``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from openfga_sdk import TupleKey
from openfga_sdk.client import (
    ClientCheckRequest,
    ClientConfiguration,
)
from openfga_sdk.client import (
    OpenFgaClient as _OpenFgaClient,
)
from openfga_sdk.client.models.write_request import ClientWriteRequest

from django_authz.authorization.base import BaseOpenFGAClient


class AsyncOpenFGASDKClient(BaseOpenFGAClient):
    """Native async OpenFGA client using the official ``openfga-sdk``."""

    def __init__(self, api_url: str, store_id: str, model_id: str | None = None):
        self._config = ClientConfiguration(
            api_url=api_url.rstrip("/"),
            store_id=store_id,
            authorization_model_id=model_id,
        )

    async def _client(self) -> _OpenFgaClient:  # context manager kept per-call
        return _OpenFgaClient(self._config)

    async def check(self, user: str, relation: str, object_: str) -> bool:  # type: ignore[override]
        async with _OpenFgaClient(self._config) as client:
            resp = await client.check(
                ClientCheckRequest(
                    user=user,
                    relation=relation,
                    object=object_,
                )
            )
            return bool(resp.allowed)

    async def write(self, tuples: list[dict[str, Any]]) -> None:  # type: ignore[override]
        keys = [
            TupleKey(user=t["user"], relation=t["relation"], object=t["object"]) for t in tuples
        ]
        async with _OpenFgaClient(self._config) as client:
            await client.write(ClientWriteRequest(writes=keys))

    async def list_relations(self, user: str, object_: str) -> list[str]:  # type: ignore[override]
        async with _OpenFgaClient(self._config) as client:
            resp = await client.list_relations({"user": user, "object": object_})
            return list(resp.relations or [])


class OpenFGASDKClient(BaseOpenFGAClient):
    """Synchronous wrapper around ``AsyncOpenFGASDKClient``.

    Calls are dispatched via ``asyncio.run()``, which is safe for standard
    synchronous Django views.  For ASGI / async views use ``AsyncOpenFGASDKClient``
    directly.
    """

    def __init__(self, api_url: str, store_id: str, model_id: str | None = None):
        self._async = AsyncOpenFGASDKClient(api_url=api_url, store_id=store_id, model_id=model_id)

    def check(self, user: str, relation: str, object_: str) -> bool:
        return asyncio.run(self._async.check(user=user, relation=relation, object_=object_))

    def write(self, tuples: list[dict[str, Any]]) -> None:
        asyncio.run(self._async.write(tuples))

    def list_relations(self, user: str, object_: str) -> list[str]:
        return asyncio.run(self._async.list_relations(user=user, object_=object_))
