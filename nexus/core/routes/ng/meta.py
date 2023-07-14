from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, List, Optional, Union, overload

import discord
import zmq
import zmq.asyncio
from fastapi import HTTPException
from fastapi.routing import APIRouter
from starlette.requests import Request
from starlette.responses import JSONResponse

from nexus.core import constants
from nexus.core.oauth import Guild, User
from nexus.core.oauth.decorators import requireValidAuth


if TYPE_CHECKING:
    from nexus.core.api import Nexus


router = APIRouter()


@overload
async def requestBot(app: Nexus, requestMessage: dict, userId: Optional[str] = None) -> list[Any]:
    ...


@overload
async def requestBot(app: Nexus, requestMessage: dict, userId: Optional[str] = None) -> dict[str, Any]:
    ...


async def requestBot(app: Nexus, requestMessage: dict, userId: Optional[str] = None) -> Union[dict[str, Any], list[Any]]:
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
            app.logger.error(e)
            if retries >= constants.REQUEST_RETRIES:
                raise HTTPException(502, str(e))

            if app._reqSocket:
                app._reqSocket.setsockopt(zmq.LINGER, 0)
                app._reqSocket.close()
            app.logger.info("Reconnecting to bot...")
            app.initRequestSocket()
            retries += 1
            app.logger.info("Retrying...")
            continue  # we let the loop retry the send request


async def getchUser(request: Request) -> User:
    app: Nexus = request.app
    user = app.cachedUser.get(request.session.get("userId", 0))

    if not user:
        async with app.session(token=request.session.get("authToken"), request=request) as session:
            user = await session.identify()  # type: ignore

            request.session["userId"] = user.id

    return user


async def getchGuilds(request: Request) -> List[Guild]:
    userId = request.session.get("userId", 0)
    if not userId:
        user = await getchUser(request)
        userId = user.id

    app: Nexus = request.app

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
    botGuilds: list[int] = await requestBot(request.app, {"type": "bot-guilds"}, request.session.get("userId"))
    ret = []

    for guild in guilds:
        guildJson = guild.json()
        # for some reason 'guild.id in botGuilds' always returns False
        guildJson["bot"] = int(guild.id) in [int(i) for i in botGuilds]
        guildJson["invite"] = discord.utils.oauth_url(
            request.app.clientId,
            permissions=discord.Permissions(4260883702),
            guild=guild,
            redirect_uri="http://127.0.0.1/api/guild-callback",
        )
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


@router.get("/guildstats")
@requireValidAuth
async def guildStats(request: Request, guild_id: int):
    return await requestBot(request.app, {"type": "guild", "id": guild_id}, request.session.get("userId"))


@router.get("/botstats")
async def botstats(request: Request):
    return await requestBot(request.app, {"type": "bot-stats"})


@router.put("/prefix")
@requireValidAuth
async def prefixPut(request: Request, guildId: int, prefix: str):
    return await requestBot(
        request.app,
        {"type": "prefix-add", "guildId": guildId, "prefix": prefix},
        request.session.get("userId"),
    )
