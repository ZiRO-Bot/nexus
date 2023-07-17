from typing import Optional
import discord
from discord.abc import MISSING
from starlette.requests import Request

from nexus.core.oauth.models import Guild


def generateInviteLink(request: Request, guild: Optional[Guild] = None):
    return discord.utils.oauth_url(
        request.app.clientId,
        permissions=discord.Permissions(4260883702),
        guild=guild or MISSING,
        # redirect_uri=os.getenv("DISCORD_GUILD_REDIRECT_URI"),
    )
