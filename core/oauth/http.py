from __future__ import annotations

import aiohttp

from .errors import HTTPException


__all__: tuple = (
    "Route",
    "HTTPClient"
)


class Route:
    BASE = "https://discord.com/api/v9"

    def __init__(self, method: str, endpoint: str, **params):
        self.url = self.BASE + endpoint.format(**params)
        self.method = method


class HTTPClient:
    def __init__(self):
        self.__session: aiohttp.ClientSession | None = None  # filled in later
        self._state_info = {}  # client fills this

    async def _createSession(self) -> aiohttp.ClientSession:
        self.__session = aiohttp.ClientSession()
        return self.__session

    async def request(self, route: Route, **kwargs) -> dict:
        if not self.__session or self.__session.closed:
            await self._createSession()

        headers = kwargs.pop("headers", {})

        headers["Content-Type"] = "application/x-www-form-urlencoded"  # the discord OAuth2 api requires this header to be set to this
        kwargs["headers"] = headers

        async with self.__session.request(route.method, route.url, **kwargs) as resp:  # type: ignore
            json = await resp.json()
            if 200 <= resp.status < 300:
                return json
            else:
                raise HTTPException(resp, json=json)

    async def close(self):
        if self.__session:
            await self.__session.close()
        self.__session = None
