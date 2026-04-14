from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx

import auth
from config import settings

logger = logging.getLogger(__name__)


class GraphClient:
    def __init__(self) -> None:
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_requests)
        self._client: Optional[httpx.AsyncClient] = None
        self._direct_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self, trust_env: bool = True) -> httpx.AsyncClient:
        if trust_env:
            if self._client is None or self._client.is_closed:
                self._client = httpx.AsyncClient(timeout=60.0, trust_env=True)
            return self._client

        if self._direct_client is None or self._direct_client.is_closed:
            self._direct_client = httpx.AsyncClient(timeout=60.0, trust_env=False)
        return self._direct_client

    async def _get_headers(self) -> dict[str, str]:
        token = auth.get_token()
        if not token:
            raise RuntimeError("Not authenticated — call /api/auth/login first")
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "ConsistencyLevel": "eventual",
        }

    async def _request_with_retry(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        headers = await self._get_headers()

        async with self._semaphore:
            for trust_env in (True, False):
                client = await self._get_client(trust_env=trust_env)
                try:
                    for attempt in range(3):
                        response = await client.request(
                            method, url, headers=headers, **kwargs
                        )

                        if response.status_code == 429:
                            retry_after = int(response.headers.get("Retry-After", "5"))
                            logger.warning(
                                "Rate limited (429), retrying after %ds (attempt %d/3)",
                                retry_after,
                                attempt + 1,
                            )
                            await asyncio.sleep(retry_after)
                            # Refresh headers in case token was close to expiry
                            headers = await self._get_headers()
                            continue

                        return response

                    return response
                except httpx.ConnectError as exc:
                    if not trust_env:
                        raise
                    logger.warning(
                        "Graph connection failed with environment settings; retrying direct connection: %s",
                        exc,
                    )
                    continue
            raise RuntimeError("Graph request failed without an HTTP response")

    async def get(
        self, endpoint: str, params: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        url = f"{settings.graph_base_url}/{endpoint}"
        all_items: list[dict[str, Any]] = []

        while url:
            response = await self._request_with_retry("GET", url, params=params)
            response.raise_for_status()
            data = response.json()

            items = data.get("value", [])
            all_items.extend(items)

            # Follow pagination — nextLink is a full URL
            url = data.get("@odata.nextLink")
            # Only use params on the first request; nextLink includes them
            params = None

        return all_items

    async def get_single(self, endpoint: str) -> dict[str, Any]:
        url = f"{settings.graph_base_url}/{endpoint}"
        response = await self._request_with_retry("GET", url)
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        if self._direct_client and not self._direct_client.is_closed:
            await self._direct_client.aclose()
