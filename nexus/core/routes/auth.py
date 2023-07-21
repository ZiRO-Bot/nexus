from typing import Union

from fastapi.requests import Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.routing import APIRouter

from nexus.core.oauth import OAuth2Session
from nexus.core.oauth.decorators import requireValidAuth
from nexus.utils.discord_utils import generateInviteLink


router = APIRouter()


@router.get("/login")
async def login(request: Request):
    session: OAuth2Session = request.app.session(request=request)
    authorization_url, state = session.authorizationUrl()
    # authorization_url, state = session.authorization_url(prompt="none")
    request.session["state"] = state
    await session.close()
    return RedirectResponse(authorization_url)


@router.post("/logout")
@requireValidAuth
async def logout(request: Request):
    request.session.clear()
    resp = JSONResponse({"status": 200, "detail": "success"})
    if request.cookies.get("loggedIn"):
        resp.delete_cookie("loggedIn")
    return resp


@router.get("/invite")
async def invite(request: Request):
    inviteLink = generateInviteLink(request)
    resp = RedirectResponse(inviteLink)
    contentType: Union[str, None] = request.headers.get("content-type")
    if contentType == "application/json":
        resp = JSONResponse({"invite": inviteLink})
    return resp
