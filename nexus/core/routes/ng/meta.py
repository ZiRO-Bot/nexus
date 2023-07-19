# FIXME: __future__.annotations broke pydantics
# REF: https://github.com/tiangolo/fastapi/discussions/9709#discussioncomment-6449458
# from __future__ import annotations

import asyncio
import json
import traceback
from typing import TYPE_CHECKING, Any, List, Optional, Union, overload

import zmq  # type: ignore
import zmq.asyncio
from fastapi import HTTPException
from fastapi.routing import APIRouter
from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import JSONResponse

from nexus.core import constants
from nexus.core.oauth import Guild, User
from nexus.core.oauth.decorators import requireValidAuth
from nexus.utils.discord_utils import generateInviteLink


if TYPE_CHECKING:
    from nexus.core.api import Nexus


router = APIRouter()


@overload
async def requestBot(app: "Nexus", requestMessage: dict, userId: Optional[str] = None) -> list[Any]:
    ...


@overload
async def requestBot(app: "Nexus", requestMessage: dict, userId: Optional[str] = None) -> dict[str, Any]:
    ...


async def requestBot(app: "Nexus", requestMessage: dict, userId: Optional[str] = None) -> Union[dict[str, Any], list[Any]]:
    retries = 0

    if userId:
        requestMessage["userId"] = userId

    request = json.dumps(requestMessage)

    while True:
        try:
            app.logger.info("Sending request...")
            await app.reqSocket.send_string(request)
            app.logger.info("Receiving response...")
            string = await asyncio.wait_for(app.reqSocket.recv_string(), timeout=constants.REQUEST_TIMEOUT / 1000)
            message = json.loads(string)
            return message
        except (Exception, asyncio.CancelledError) as e:
            traceback.print_exc()
            app.logger.error(e or e.__class__)
            if retries >= constants.REQUEST_RETRIES:
                raise HTTPException(502, str(e))

            app.connectReqSocket()
            retries += 1
            app.logger.info("Retrying...")
            continue  # we let the loop retry the send request


async def getchUser(request: Request) -> User:
    app: "Nexus" = request.app
    sessionId = request.session.get("sessionId", -1)
    data = app.sessionData.renew(sessionId)
    user = app.cachedUser.get(data.get("userId", 0))

    if not user:
        async with app.session(token=data.get("authToken"), request=request) as session:
            user = await session.identify()  # type: ignore

            data["userId"] = user.id
            app.sessionData[sessionId] = data

    return user


async def getchGuilds(request: Request) -> List[Guild]:
    app: "Nexus" = request.app
    sessionId = request.session.get("sessionId", -1)
    data = app.sessionData.renew(sessionId)
    userId = data.get("userId")
    if not userId:
        user = await getchUser(request)
        userId = user.id

    guilds = app.cachedGuilds.get(userId)

    if not guilds:
        async with app.session(request=request) as session:
            guilds = await session.guilds(userId)  # type: ignore

    filtered = []
    for guild in guilds:
        # get managable guilds
        if (guild.permissions & 1 << 4) != 1 << 4:
            continue

        stats = await requestBot(app, {"type": "guild-stats", "id": guild.id, "userId": userId}, str(userId))
        guild._data["stats"] = stats
        filtered.append(guild)

    return filtered


@router.get("/@me")
@requireValidAuth
async def me(request: Request):
    user = await getchUser(request)
    resp = JSONResponse(user.json())

    return resp


@router.get("/@me/managed-guilds")
@requireValidAuth
async def managedGuilds(request: Request):
    """Get guilds that managed by the user"""
    guilds = await getchGuilds(request)
    app: "Nexus" = request.app
    sessionId = request.session.get("sessionId", -1)
    botGuilds: list[int] = await requestBot(
        request.app, {"type": "managed-guilds", "userId": app.userIdFromSessionId(sessionId)}
    )
    ret = []

    for guild in guilds:
        guildJson = guild.json()
        # for some reason 'guild.id in botGuilds' always returns False
        guildJson["bot"] = int(guild.id) in [int(i) for i in botGuilds]
        guildJson["invite"] = generateInviteLink(request, guild)
        ret.append(guildJson)

    # show guilds that has the bot in it first, while also sort them by name
    return sorted(ret, key=lambda g: (not g["bot"], g["name"]))


@router.get("/@me/guilds")
@requireValidAuth
async def myGuilds(request: Request):
    guilds = await getchGuilds(request)

    # show invited guilds first, while also sort them by name
    return [guild.json() for guild in guilds]


@router.get("/guild-callback")
@requireValidAuth
async def guildAuth(request: Request, guild_id: int):
    return "hello world"


@router.get("/guild/{guildId}/stats")
@requireValidAuth
async def guildStats(request: Request, guildId: int):
    app: "Nexus" = request.app
    sessionId = request.session.get("sessionId", -1)
    return await requestBot(request.app, {"type": "guild", "id": guildId, "userId": app.userIdFromSessionId(sessionId)})


@router.get("/botstats")
async def botstats(request: Request):
    return await requestBot(request.app, {"type": "bot-stats"})


class Prefix(BaseModel):
    prefix: str


@router.put("/guild/{guildId}/prefix")
@requireValidAuth
async def prefixPut(request: Request, guildId: int, prefix: Prefix):
    app: "Nexus" = request.app
    sessionId = request.session.get("sessionId", -1)
    return await requestBot(
        request.app,
        {"type": "prefix-add", "guildId": guildId, "prefix": prefix.prefix, "userId": app.userIdFromSessionId(sessionId)},
    )


@router.delete("/guild/{guildId}/prefix")
@requireValidAuth
async def prefixDelete(request: Request, guildId: int, prefix: Prefix):
    app: "Nexus" = request.app
    sessionId = request.session.get("sessionId", -1)
    return await requestBot(
        request.app,
        {"type": "prefix-rm", "guildId": guildId, "prefix": prefix.prefix, "userId": app.userIdFromSessionId(sessionId)},
    )


@router.get("/ping")
async def ping(request: Request):
    app: "Nexus" = request.app
    sessionId = request.session.get("sessionId", -1)

    try:
        botPing: dict[str, Any] = await requestBot(request.app, {"type": "ping"})  # type: ignore
    except HTTPException:
        botPing = {}

    isLoggedIn = app.validateAuth(sessionId)
    resp = JSONResponse({"isLoggedIn": isLoggedIn, "botPing": botPing.get("self")})
    if isLoggedIn:
        request.app.attachIsLoggedIn(resp)
    else:
        request.app.detachIsLoggedIn(resp)
    return resp
