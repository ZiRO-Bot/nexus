from functools import wraps

from fastapi import HTTPException
from starlette.requests import Request

from nexus.core.oauth.utils import validateAuth


def requireValidAuth(func):
    @wraps(func)
    async def predicate(request: Request, *args, **kwargs):
        valid = validateAuth(request.session.get("authToken") or {})
        if not valid:
            raise HTTPException(401)

        return await func(request, *args, **kwargs)

    return predicate
