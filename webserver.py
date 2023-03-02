from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
import time
import traceback
from functools import wraps
from typing import Any, Dict, List

import discord
import uvicorn
import zmq
import zmq.asyncio
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from core.oauth import Guild, OAuth2Client, OAuth2Session, User
from utils.cache import ExpiringDict

load_dotenv()


DEBUG: bool = bool(os.getenv("DASHBOARD_IS_DEBUG", 0))

CLIENT_ID = int(os.getenv("DISCORD_CLIENT_ID", 0))
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", "")
FRONTEND_URI = os.getenv("DASHBOARD_FRONTEND_URI", "")
if DEBUG:
    FRONTEND_URI += ":8080"  # vue.js' dev build


SESSION = ExpiringDict()  # TODO: Store to DB instead, use Redis maybe?


class LoginRequest(BaseModel):
    code: str


class API(FastAPI):
    def __init__(self, context: zmq.asyncio.Context = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = context or zmq.asyncio.Context.instance()
        self._reqSocket: zmq.asyncio.Socket | None = None
        self.add_event_handler("startup", self.onStartup)
        self.add_event_handler("shutdown", self.onShutdown)

    def initSockets(self):
        self._reqSocket = self.context.socket(zmq.REQ)
        self._reqSocket.connect(
            "tcp://" + os.getenv("DASHBOARD_ZMQ_REQ", "127.0.0.1:5556")
        )

    @property
    def reqSocket(self) -> zmq.asyncio.Socket:
        if not self._reqSocket:
            self.initSockets()
        return self._reqSocket  # type: ignore

    async def onStartup(self):
        self.initSockets()

    def onShutdown(self):
        self.close()

    def close(self):
        self.reqSocket.close()
        self.context.term()


app = API(debug=DEBUG)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URI],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=secrets.token_urlsafe(32))
client = OAuth2Client(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri=REDIRECT_URI,
    scopes=("identify", "guilds", "email", "connections"),
)


async def requestBot(request: dict) -> dict[str, Any]:
    try:
        await app.reqSocket.send_string(json.dumps(request))
        message = json.loads(await app.reqSocket.recv_string())
        return message
    except Exception as e:
        print(e)
        return {"error": str(e)}


async def getch_user(request: Request, token: Dict[str, Any]) -> User:
    user = client.cached_user.get(request.session.get("userId", 0))

    if not user:
        async with client.session(token=token) as session:
            user = await session.identify()  # type: ignore

            request.session["userId"] = user.id

    return user


async def getch_guilds(request: Request, token: Dict[str, Any]) -> List[Guild]:
    userId = request.session.get("userId", 0)
    if not userId:
        user = await getch_user(request, token)
        userId = user.id

    guilds = client.cached_guilds.get(userId)

    if not guilds:
        async with client.session(token=token) as session:
            guilds = await session.guilds(userId)  # type: ignore

    filtered = []
    for guild in guilds:
        # get managable guilds
        if (guild.permissions & 1 << 4) != 1 << 4:
            continue

        stats = await requestBot({"type": "guild", "id": guild.id})
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
    session: OAuth2Session = client.session(token_updater=updateToken(request))
    authorization_url, state = session.authorization_url()
    # authorization_url, state = session.authorization_url(prompt="none")
    request.session["state"] = state
    await session.close()
    return RedirectResponse(authorization_url)


def validateAuth(oauthToken: Any, oauthTime: int) -> bool:
    return not ((oauthToken is None) or (int(time.time()) - oauthTime > 604800))


def requireValidAuth(func):
    @wraps(func)
    async def predicate(request: Request, *args, **kwargs):
        valid = validateAuth(
            request.session.get("oauthToken"), request.session.get("oauthTime", 0)
        )
        if not valid:
            raise HTTPException(401)

        return await func(request, *args, **kwargs)

    return predicate


@app.get("/api/callback")
async def callback(code: str = None, error: str = None):
    if (not code and not error) or error:
        if error:
            print(error)
        return RedirectResponse(url=FRONTEND_URI)

    return RedirectResponse(url=FRONTEND_URI + f"/login?code={code}")


@app.post("/api/v1/auth")
async def auth(request: Request, data: LoginRequest):
    code = data.code
    token = request.session.get("oauthToken")
    if token or not code:
        return token
        # return RedirectResponse(url=FRONTEND_URI)

    try:
        async with client.session(state=request.session["state"]) as session:
            token = await session.fetch_token(  # type: ignore
                code=code, client_secret=client.secret
            )
    except Exception:
        print(traceback.format_exc())
        return RedirectResponse(url=FRONTEND_URI)
        # return RedirectResponse("/api/login")

    request.session["oauthToken"] = token
    request.session["oauthTime"] = int(time.time())

    return token


@app.get("/api/v1/@me")
@requireValidAuth
async def me(request: Request):
    token = request.session["oauthToken"]

    user = await getch_user(request, token)

    return user.json()


@app.get("/api/v1/@me/guilds")
@requireValidAuth
async def myGuilds(request: Request):
    token = request.session["oauthToken"]

    guilds = await getch_guilds(request, token)
    botGuilds: dict = await requestBot({"type": "managed-guilds"})
    ret = []
    for guild in guilds:
        guildJson = guild.json()
        guildJson["bot"] = guild.name in botGuilds
        guildJson["invite"] = discord.utils.oauth_url(
            CLIENT_ID,
            permissions=discord.Permissions(4260883702),
            guild=guild,
            redirect_uri="http://127.0.0.1:8000/api/guild-auth",
        )
        ret.append(guildJson)

    # show invited guilds first, while also sort them by name
    return sorted(ret, key=lambda g: (not g["bot"], g["name"]))


@app.get("/api/guild-auth")
@requireValidAuth
async def guildAuth(request: Request, guild_id: int):
    return "hello world"


@app.get("/api/v1/guildstats")
# @requireValidAuth
async def guildStats(request: Request, guild_id: int):
    return await requestBot({"type": "guild", "id": guild_id})


@app.post("/api/logout")
@requireValidAuth
async def logout(request: Request):
    request.session.clear()
    return {"status": 200, "detail": "success"}


@app.get("/api/v1/botstats")
async def botstats(requests: Request):
    stats = await requestBot({"type": "bot"})
    stats["isLoggedIn"] = validateAuth(
        requests.session.get("oauthToken"), requests.session.get("oauthTime", 0)
    )

    return stats


@app.exception_handler(HTTPException)
async def notAuthorized(request, exc):
    return JSONResponse(
        {"status": exc.status_code, "detail": str(exc.detail)},
        status_code=exc.status_code,
    )


@app.get("/api")
async def hello():
    return {"data": "Hello World!"}


if __name__ == "__main__":
    uvicorn.run("webserver:app", reload=DEBUG)
