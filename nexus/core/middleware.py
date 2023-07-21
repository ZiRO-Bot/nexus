import json
import os
from base64 import b64decode, b64encode

from cryptography.fernet import Fernet
from itsdangerous import BadSignature
from redis import asyncio as aioredis
from starlette.datastructures import MutableHeaders
from starlette.middleware.sessions import SessionMiddleware as Origin
from starlette.requests import HTTPConnection
from starlette.types import Message, Receive, Scope, Send

from nexus.utils.session import snowflake


class SessionMiddleware(Origin):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.redis = aioredis.from_url(os.getenv("REDIS_URL", ""))
        self.security_flags += f"; domain={os.getenv('DASHBOARD_HOSTNAME')}"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):  # pragma: no cover
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        initial_session_was_empty = True

        if self.session_cookie in connection.cookies:
            data = connection.cookies[self.session_cookie].encode("utf-8")
            try:
                data = self.signer.unsign(data, max_age=self.max_age)
                _internal = json.loads(b64decode(data))
                sessionId = _internal.get("__ssid")
                sessionKey = _internal.get("__sskey").encode("utf-8")
                scope["session"] = json.loads(
                    Fernet(sessionKey).decrypt(await self.redis.get(str(sessionId)) or b"").decode("utf-8")
                )
                scope["__ssid"] = sessionId
                scope["__sskey"] = sessionKey
                initial_session_was_empty = False
            except BadSignature:
                scope["session"] = {}
        else:
            scope["session"] = {}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                sessionId: int = scope.pop("__ssid", snowflake())
                sessionKey: bytes = scope.pop("__sskey", Fernet.generate_key())

                if scope["session"]:
                    # We have session data to persist.

                    await self.redis.set(
                        str(sessionId),
                        Fernet(sessionKey).encrypt(json.dumps(scope["session"]).encode("utf-8")),
                        ex=self.max_age,
                    )
                    cookieData = {"__ssid": sessionId, "__sskey": sessionKey.decode("utf-8")}

                    data = b64encode(json.dumps(cookieData).encode("utf-8"))
                    data = self.signer.sign(data)

                    headers = MutableHeaders(scope=message)
                    header_value = self._construct_cookie(False, data)
                    headers.append("Set-Cookie", header_value)
                elif not initial_session_was_empty:
                    # The session has been cleared.
                    await self.redis.delete(str(sessionId))

                    headers = MutableHeaders(scope=message)
                    header_value = self._construct_cookie(True)
                    headers.append("Set-Cookie", header_value)
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _construct_cookie(self, clear: bool = False, data: bytes = b"") -> str:
        if clear:
            cookie = f"{self.session_cookie}=null; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; {self.security_flags}"
        else:
            cookie = f"{self.session_cookie}={data.decode('utf-8')}; Path=/; Max-Age={self.max_age}; {self.security_flags}"
        return cookie
