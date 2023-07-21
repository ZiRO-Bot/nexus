import os
import secrets
import time
from logging import getLogger
from typing import TYPE_CHECKING, Any, Optional

import zmq
import zmq.asyncio
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request

from nexus.core import constants
from nexus.core.middleware import SessionMiddleware
from nexus.core.oauth import OAuth2Session
from nexus.utils import cache


class Nexus(FastAPI):
    if TYPE_CHECKING:
        reqSocket: zmq.asyncio.Socket
        subSocket: Optional[zmq.asyncio.Socket]

    def __init__(self, context: Optional[zmq.asyncio.Context] = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = context or zmq.asyncio.Context.instance()
        self.subSocket = None

        # Auth related stuff
        self.clientId = int(os.getenv("DISCORD_CLIENT_ID", 0))
        self.clientSecret = os.getenv("DISCORD_CLIENT_SECRET", "")
        self.redirectUri = os.getenv("DISCORD_REDIRECT_URI", "")
        self.frontendUri = os.getenv("DASHBOARD_FRONTEND_URI", "")
        self.scopes: tuple[str, ...] = ("identify", "guilds")

        # Cache
        self.cachedUser = cache.ExpiringDict(maxAgeSeconds=60)
        self.cachedGuilds = cache.ExpiringDict(maxAgeSeconds=60)

        # FastAPI and Starlette stuff
        self.add_event_handler("startup", self.onStartup)
        self.add_event_handler("shutdown", self.onShutdown)
        self.add_middleware(
            CORSMiddleware,
            allow_origins=[self.frontendUri],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        secretKey = (
            os.getenv("DASHBOARD_SECRET_KEY_DEBUG", "hmmmwhatsthis")
            if self.debug
            else os.getenv("DASHBOARD_SECRET_KEY") or secrets.token_urlsafe(32)
        )
        self.add_middleware(
            SessionMiddleware,
            session_cookie="user_session",
            secret_key=secretKey,
            max_age=constants.SESSION_EXPIRY if not self.debug else constants.SESSION_EXPIRY_DEBUG,
        )

        self.logger = getLogger("uvicorn")

        self.initSockets()

    def initSockets(self) -> None:
        self.connectReqSocket()
        self.connectSubSocket()

    def connectReqSocket(self):
        dest = os.getenv("DASHBOARD_ZMQ_REQ")
        if not dest:
            raise RuntimeError("Nexus requires at least a request socket to function properly!")
        self.reqSocket = self.context.socket(zmq.REQ)
        self.reqSocket.setsockopt(zmq.IPV6, True)
        self.reqSocket.setsockopt(zmq.RCVTIMEO, constants.REQUEST_TIMEOUT)
        self.reqSocket.connect(f"tcp://{dest}")

    def connectSubSocket(self):
        subDest = os.getenv("DASHBOARD_ZMQ_SUB")
        if subDest:
            self.subSocket = self.context.socket(zmq.SUB)
            self.subSocket.setsockopt(zmq.IPV6, True)
            self.subSocket.setsockopt(zmq.SUBSCRIBE, b"guild.update")
            self.subSocket.connect(f"tcp://{subDest}")

    def getTokenUpdater(self, request: Optional[Request] = None):
        if not request:
            return None

        async def tokenUpdater(token):
            request.session["oauthToken"] = token

        return tokenUpdater

    def validateAuth(self, authToken: dict[str, Any]) -> bool:
        # authToken = {'access_token': 'REDACTED', 'expires_in': 604800, 'refresh_token': 'REDACTED', 'scope': ['email', 'connections', 'identify', 'guilds', 'guilds.join'], 'token_type': 'Bearer', 'expires_at': 1678933659.2419164}

        return not time.time() - authToken.get("expires_at", 0) >= 0

    def session(self, token=None, state=None, request: Optional[Request] = None) -> OAuth2Session:
        currentToken = getattr(request, "session", {}).get("authToken")
        return OAuth2Session(
            backendObj=self,
            token=token or currentToken,
            state=state,
            scope=self.scopes,
            redirectUri=self.redirectUri,
            autoRefreshKwargs={
                "client_id": str(self.clientId),
                "client_secret": self.clientSecret,
            },
            tokenUpdater=self.getTokenUpdater(request),
        )

    def attachIsLoggedIn(self, response: Response):
        response.set_cookie("loggedIn", "yes", domain=os.getenv("DASHBOARD_HOSTNAME"), max_age=31556926)

    def detachIsLoggedIn(self, response: Response):
        response.delete_cookie("loggedIn", domain=os.getenv("DASHBOARD_HOSTNAME"))

    async def onStartup(self):
        pass

    async def closeSockets(self):
        self.logger.info("Closing sockets...")
        sockets = (self.reqSocket, self.subSocket)
        for socket in sockets:
            if not socket:
                continue
            socket.setsockopt(zmq.LINGER, 0)
            socket.close()

        self.logger.info("Terminating context...")
        self.context.term()
        self.logger.info("ZeroMQ has been closed")

    async def onShutdown(self):
        await self.closeSockets()
