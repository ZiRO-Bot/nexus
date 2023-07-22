from __future__ import annotations

import asyncio
import json
import traceback
from typing import TYPE_CHECKING, Any, Optional

from fastapi import WebSocket, WebSocketDisconnect, WebSocketException, status
from fastapi.responses import HTMLResponse, Response
from fastapi.routing import APIRouter
from starlette.requests import Request

from nexus.core.oauth.session import OAuth2Session


if TYPE_CHECKING:
    from nexus.core.api import Nexus


router = APIRouter()


@router.get("/callback")
async def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
    app: Nexus = request.app

    def generateResponse(doReload: bool = True) -> Response:
        return HTMLResponse(
            f"""
          <html>
            <head>
              <title>Z3R0</title>
            </head>
            <body>
              <script>
                if (window.opener) {"{"}
                    window.opener.postMessage({"{ message: 'authSuccess' }" if (doReload) else "{ message: 'authFailed' }"}, "*")
                    window.opener.focus()
                    window.close()
                {"} else {"}
                    window.location.href = "{request.app.frontendUri}"
                {"}"}
              </script>
            </body>
          </html>
        """
        )

    if not code:
        return generateResponse(False)

    try:
        curToken = request.session.get("authToken") or {}
        async with request.app.session(state=state, request=request) as session:
            session: OAuth2Session
            if not app.validateAuth(curToken):
                curToken = await session.fetchToken(code=code, client_secret=request.app.clientSecret)
                request.session["authToken"] = curToken
            user = await session.identify()
    except Exception:
        print(traceback.format_exc())
        return generateResponse(False)

    request.session["userId"] = user.id
    resp = generateResponse()
    request.app.attachIsLoggedIn(resp)
    return resp


@router.websocket("/ws/{_type}/{_data}")
async def ws(websocket: WebSocket, _type: str, _data: Any):
    app: "Nexus" = websocket.app

    if _type not in ("guild",):
        raise WebSocketException(status.WS_1003_UNSUPPORTED_DATA)

    conn = await app.websocketManager.connect(websocket, type=_type, data=_data)
    try:
        while True:
            # Just to keep the connection alive
            await websocket.receive_json()
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        app.websocketManager.disconnect(conn)
