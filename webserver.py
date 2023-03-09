from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
import traceback
from functools import wraps
from logging import getLogger
from typing import Any, List, overload

import discord
import uvicorn
import zmq
import zmq.asyncio
from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    WebSocketException,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from core.oauth import Guild, OAuth2Session, User
from utils import cache

load_dotenv()


os.environ[
    "OAUTHLIB_RELAX_TOKEN_SCOPE"
] = "1"  # Discord response with different scope for some reason
DEBUG: bool = bool(os.getenv("DASHBOARD_IS_DEBUG", 0))
LOGGER = getLogger("uvicorn")
REQUEST_TIMEOUT = 2500
REQUEST_RETRIES = 3


class PrefixRequest(BaseModel):
    prefix: str
    guildId: int


class API(FastAPI):
    def __init__(self, context: zmq.asyncio.Context = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = context or zmq.asyncio.Context.instance()
        self._reqSocket: zmq.asyncio.Socket | None = None
        self._subSocket: zmq.asyncio.Socket | None = None

        # Auth related stuff
        self.clientId = int(os.getenv("DISCORD_CLIENT_ID", 0))
        self.clientSecret = os.getenv("DISCORD_CLIENT_SECRET", "")
        self.redirectUri = os.getenv("DISCORD_REDIRECT_URI", "")
        self.frontendUri = os.getenv("DASHBOARD_FRONTEND_URI", "")
        self.scopes = ("identify", "guilds")

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
            if DEBUG
            else os.getenv("DASHBOARD_SECRET_KEY", secrets.token_urlsafe(32))
        )
        self.add_middleware(SessionMiddleware, secret_key=secretKey, max_age=None)

    def session(self, token=None, state=None, token_updater=None) -> OAuth2Session:
        return OAuth2Session(
            backendObj=self,
            token=token,
            clientId=self.clientId,
            state=state,
            scope=self.scopes,
            redirectUri=self.redirectUri,
            auto_refresh_kwargs={
                "client_id": str(self.clientId),
                "client_secret": self.clientSecret,
            },
            # auto_refresh_url=_oauth2['token_url'],
            token_updater=token_updater,
        )

    def initRequestSocket(self):
        self._reqSocket = self.context.socket(zmq.REQ)
        self._reqSocket.setsockopt(zmq.RCVTIMEO, REQUEST_TIMEOUT)
        self._reqSocket.connect(
            "tcp://" + os.getenv("DASHBOARD_ZMQ_REQ", "127.0.0.1:5556")
        )

    def initSockets(self):
        self.initRequestSocket()

        self._subSocket = app.context.socket(zmq.SUB)
        self._subSocket.setsockopt(zmq.SUBSCRIBE, b"guild.update")
        self._subSocket.connect(
            "tcp://" + os.getenv("DASHBOARD_ZMQ_SUB", "127.0.0.1:5554")
        )

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
        LOGGER.info("Closing sockets...")
        sockets = (self._reqSocket, self._subSocket)
        for socket in sockets:
            if not socket:
                continue
            socket.setsockopt(zmq.LINGER, 0)
            socket.close()

        LOGGER.info("Terminating context...")
        self.context.term()
        LOGGER.info("ZeroMQ has been closed")

    def onShutdown(self):
        self.close()


app = API(debug=DEBUG)


@overload
async def requestBot(requestMessage: dict, userId: str | None = None) -> list[Any]:
    ...


@overload
async def requestBot(requestMessage: dict, userId: str | None = None) -> dict[str, Any]:
    ...


async def requestBot(
    requestMessage: dict, userId: str | None = None
) -> dict[str, Any] | list[Any]:
    retries = 0

    if userId:
        requestMessage["userId"] = userId

    request = json.dumps(requestMessage)

    while True:
        try:
            await app.reqSocket.send_string(request)
            message = json.loads(await app.reqSocket.recv_string())
            return message
        except Exception as e:
            print(e)
            if retries >= REQUEST_RETRIES:
                raise HTTPException(502, str(e))

            if app._reqSocket:
                app._reqSocket.setsockopt(zmq.LINGER, 0)
                app._reqSocket.close()
            LOGGER.info("Reconnecting to bot...")
            app.initRequestSocket()
            retries += 1
            LOGGER.info("Retrying...")
            continue  # we let the loop retry the send request


async def getch_user(request: Request) -> User:
    user = app.cachedUser.get(request.session.get("userId", 0))

    if not user:
        async with app.session(token=request.session.get("authToken")) as session:
            user = await session.identify()  # type: ignore

            request.session["userId"] = user.id

    return user


async def getch_guilds(request: Request) -> List[Guild]:
    userId = request.session.get("userId", 0)
    if not userId:
        user = await getch_user(request)
        userId = user.id

    guilds = app.cachedGuilds.get(userId)

    if not guilds:
        async with app.session(token=request.session.get("authToken")) as session:
            guilds = await session.guilds(userId)  # type: ignore

    filtered = []
    for guild in guilds:
        # get managable guilds
        if (guild.permissions & 1 << 4) != 1 << 4:
            continue

        stats = await requestBot(
            {"type": "guilds", "id": guild.id}, request.session.get("userId")
        )
        guild._data["stats"] = stats
        filtered.append(guild)

    return filtered


def updateToken(request: Request):
    def token_updater(token):
        request.session["oauthToken"] = token

    return token_updater


@app.get("/api/login")
async def login(request: Request):
    # TODO:
    #  - Store token and user ID into Session DB
    #  - Give client unique ID and store it into browser cookie
    session: OAuth2Session = app.session(token_updater=updateToken(request))
    authorization_url, state = session.authorization_url()
    # authorization_url, state = session.authorization_url(prompt="none")
    request.session["state"] = state
    await session.close()
    return RedirectResponse(authorization_url)


def validateAuth(authToken: Any, authTime: int) -> bool:
    return not any([authToken is None, int(time.time()) - authTime > 604800])


def requireValidAuth(func):
    @wraps(func)
    async def predicate(request: Request, *args, **kwargs):
        valid = validateAuth(
            request.session.get("authToken"), request.session.get("authTime", 0)
        )
        if not valid:
            raise HTTPException(401)

        return await func(request, *args, **kwargs)

    return predicate


@app.get("/api/v1/callback")
async def callback(request: Request, code: str = None, state: str = None):
    # TODO: Handle redirect (If I click login in Guild page, I should be redirected to Guild page)
    if not code and not state:
        return RedirectResponse(url=app.frontendUri)

    try:
        if request.session.get("authToken") or not code:
            # TODO: Handle refresh token
            raise

        async with app.session(token=request.session.get("authToken"), state=state) as session:  # type: ignore
            session: OAuth2Session
            token = await session.fetch_token(code=code, client_secret=app.clientSecret)
            user = await session.identify()
    except Exception:
        print(traceback.format_exc())
        return RedirectResponse(url=app.frontendUri)

    request.session["authToken"] = token
    request.session["authTime"] = int(time.time())
    request.session["userId"] = user.id

    resp = RedirectResponse(url=app.frontendUri)
    resp.set_cookie("loggedIn", "yes", max_age=31556926)
    return resp


@app.get("/api/v1/@me")
@requireValidAuth
async def me(request: Request):
    user = await getch_user(request)
    resp = JSONResponse(user.json())

    return resp


@app.get("/api/v1/@me/managed-guilds")
@requireValidAuth
async def managedGuilds(request: Request):
    """Get guilds that managed by the user"""
    guilds = await getch_guilds(request)
    botGuilds: list[int] = await requestBot(
        {"type": "managed-guilds"}, request.session.get("userId")
    )
    ret = []

    for guild in guilds:
        guildJson = guild.json()
        # for some reason 'guild.id in botGuilds' always returns False
        guildJson["bot"] = int(guild.id) in [int(i) for i in botGuilds]
        guildJson["invite"] = discord.utils.oauth_url(
            app.clientId,
            permissions=discord.Permissions(4260883702),
            guild=guild,
            redirect_uri="http://127.0.0.1/api/guild-callback",
        )
        ret.append(guildJson)

    # show guilds that has the bot in it first, while also sort them by name
    return sorted(ret, key=lambda g: (not g["bot"], g["name"]))


@app.get("/api/v1/@me/guilds")
@requireValidAuth
async def myGuilds(request: Request):
    guilds = await getch_guilds(request)

    # show invited guilds first, while also sort them by name
    return [guild.json() for guild in guilds]


@app.get("/api/v1/guild-callback")
@requireValidAuth
async def guildAuth(request: Request, guild_id: int):
    return "hello world"


@app.get("/api/v1/guildstats")
@requireValidAuth
async def guildStats(request: Request, guild_id: int):
    return await requestBot(
        {"type": "guild", "id": guild_id}, request.session.get("userId")
    )


@app.post("/api/logout")
@requireValidAuth
async def logout(request: Request):
    request.session.clear()
    resp = JSONResponse({"status": 200, "detail": "success"})
    if request.cookies.get("loggedIn"):
        resp.delete_cookie("loggedIn")
    return resp


@app.get("/api/v1/botstats")
async def botstats():
    return await requestBot({"type": "bot-stats"})


@app.put("/api/v1/prefix")
@requireValidAuth
async def prefixPut(request: Request, prefix: PrefixRequest):
    return await requestBot(
        {"type": "prefix-add", "guildId": prefix.guildId, "prefix": prefix.prefix},
        request.session.get("userId"),
    )


@app.exception_handler(HTTPException)
async def errorHandler(request, exc):
    resp = JSONResponse(
        {"status": exc.status_code, "detail": str(exc.detail)},
        status_code=exc.status_code,
    )
    if exc.status_code == 401:
        if request.cookies.get("loggedIn"):
            resp.delete_cookie("loggedIn")
    return resp


async def websocketSubcribeLoop(websocket: WebSocket, guildId: int):
    try:
        while True:
            _, msg = await app.subSocket.recv_multipart()
            decodedMsg = msg.decode()
            if json.loads(decodedMsg)["before"].get("id") != guildId:
                return
            await websocket.send_text(f"{decodedMsg}")
    except Exception as e:
        print(e)


@app.websocket("/api/ws")
async def ws(websocket: WebSocket):
    # Auth checker for WebSocket
    scope = websocket.scope
    scope["type"] = "http"
    request = Request(scope=scope, receive=websocket._receive)
    if not request.session.get("userId"):
        scope["type"] = "websocket"  # WebSocketException would raise error without this
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)

    await websocket.accept()
    task: asyncio.Task | None = None
    try:
        while True:
            msg = await websocket.receive_json()
            match (msg):
                case {"t": "ping"}:
                    await websocket.send_json({"t": "pong"})
                case {"t": "guild", "i": _}:
                    if task:
                        continue

                    try:
                        id = int(msg["i"])
                    except ValueError:
                        await websocket.send_json(json.dumps({"e": "Invalid ID"}))
                        continue

                    task = asyncio.create_task(websocketSubcribeLoop(websocket, id))
                    await websocket.send_json({"i": id})
                case _:
                    await websocket.send_json({"o": f"{msg}"})
    except Exception as e:
        if task:
            task.cancel()

        if not isinstance(e, WebSocketDisconnect):
            await websocket.close()


if __name__ == "__main__":
    uvicorn.run("webserver:app", reload=DEBUG)
