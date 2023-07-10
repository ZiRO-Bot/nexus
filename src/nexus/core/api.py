import os
import secrets
from logging import getLogger
from typing import Optional

import zmq
import zmq.asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request

from nexus.core import constants
from nexus.core.oauth import OAuth2Session
from nexus.utils import cache


class Nexus(FastAPI):
    def __init__(self, context: Optional[zmq.asyncio.Context] = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = context or zmq.asyncio.Context.instance()
        self._reqSocket: Optional[zmq.asyncio.Socket] = None
        self._subSocket: Optional[zmq.asyncio.Socket] = None

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
            else os.getenv("DASHBOARD_SECRET_KEY", secrets.token_urlsafe(32))
        )
        self.add_middleware(SessionMiddleware, secret_key=secretKey, max_age=None)

        self.logger = getLogger("uvicorn")

    def getTokenUpdater(self, request: Optional[Request] = None):
        if not request:
            return None

        async def tokenUpdater(token):
            request.session["oauthToken"] = token

        return tokenUpdater

    def session(self, token=None, state=None, request: Optional[Request] = None) -> OAuth2Session:
        return OAuth2Session(
            backendObj=self,
            token=token or getattr(request, "session", {}).get("authToken"),
            state=state,
            scope=self.scopes,
            redirectUri=self.redirectUri,
            autoRefreshKwargs={
                "client_id": str(self.clientId),
                "client_secret": self.clientSecret,
            },
            tokenUpdater=self.getTokenUpdater(request),
        )

    def initRequestSocket(self):
        self._reqSocket = self.context.socket(zmq.REQ)
        self._reqSocket.setsockopt(zmq.RCVTIMEO, constants.REQUEST_TIMEOUT)
        self._reqSocket.connect("tcp://" + os.getenv("DASHBOARD_ZMQ_REQ", "127.0.0.1:5556"))

    def initSubscriptionSocket(self):
        self._subSocket = self.context.socket(zmq.SUB)
        self._subSocket.setsockopt(zmq.SUBSCRIBE, b"guild.update")
        self._subSocket.connect("tcp://" + os.getenv("DASHBOARD_ZMQ_SUB", "127.0.0.1:5554"))

    def initSockets(self):
        self.initRequestSocket()
        self.initSubscriptionSocket()

    @property
    def isZMQAvailable(self) -> bool:
        return self._reqSocket is not None or self._subSocket is not None

    def _getSocket(self, socket: str) -> zmq.asyncio.Socket:
        _socket = getattr(self, f"_{socket}Socket", None)
        if not _socket:
            self.initSockets()
            _socket = getattr(self, socket)

        return _socket

    @property
    def reqSocket(self) -> zmq.asyncio.Socket:
        return self._getSocket("req")

    @property
    def subSocket(self) -> zmq.asyncio.Socket:
        return self._getSocket("sub")

    async def onStartup(self):
        self.initSockets()

    def close(self):
        self.logger.info("Closing sockets...")
        sockets = (self._reqSocket, self._subSocket)
        for socket in sockets:
            if not socket:
                continue
            socket.setsockopt(zmq.LINGER, 0)
            socket.close()

        self.logger.info("Terminating context...")
        self.context.term()
        self.logger.info("ZeroMQ has been closed")

    def onShutdown(self):
        self.close()
