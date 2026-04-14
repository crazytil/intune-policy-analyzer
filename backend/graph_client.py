import asyncio
import logging
from typing import Any

import httpx

import auth
from config import settings

logger = logging.getLogger(__name__)


class GraphClient:
    def __init__(self) -> None:
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_requests)
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    async def _get_headers(self) -> dict[str, str]:
        token = auth.get_token()
        if not token:
            raise RuntimeError("Not authenticated — call /api/auth/login first")
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    async def _request_with_retry(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        client = await self._get_client()
        headers = await self._get_headers()

        async with self._semaphore:
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

            # Return the last response even if it was 429
            return response

    async def get(
        self, endpoint: str, params: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
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
