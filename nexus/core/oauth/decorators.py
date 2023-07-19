from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING

from fastapi import HTTPException
from starlette.requests import Request


if TYPE_CHECKING:
    from nexus.core.api import Nexus


def requireValidAuth(func):
    @wraps(func)
    async def predicate(request: Request, *args, **kwargs):
        app: Nexus = request.app
        sessionId = request.session.get("sessionId", -1)
        valid = app.validateAuth(sessionId)
        if not valid:
            raise HTTPException(401)

        return await func(request, *args, **kwargs)

    return predicate
