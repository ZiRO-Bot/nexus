from __future__ import annotations

import asyncio
import json
import traceback
from typing import TYPE_CHECKING, Optional

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


async def websocketSubcribeLoop(websocket: WebSocket, guildId: int):
    try:
        while True:
            _, msg = await websocket.app.subSocket.recv_multipart()
            decodedMsg = msg.decode()
            if json.loads(decodedMsg).get("guildId") != guildId:
                return
            await websocket.send_text(f"{decodedMsg}")
    except Exception as e:
        print(e)


@router.websocket("/ws")
async def ws(websocket: WebSocket):
    # Auth checker for WebSocket
    scope = websocket.scope
    scope["type"] = "http"
    request = Request(scope=scope, receive=websocket._receive)
    if not request.session.get("userId"):
        scope["type"] = "websocket"  # WebSocketException would raise error without this
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)

    await websocket.accept()
    task: Optional[asyncio.Task] = None
    try:
        while True:
            msg = await websocket.receive_json()
            _type = msg.get("t")
            if _type == "ping":
                await websocket.send_json({"t": "pong"})
            elif _type == "guild":
                if task:
                    continue

                try:
                    id = int(msg["i"])
                except ValueError:
                    await websocket.send_json(json.dumps({"e": "Invalid ID"}))
                    continue

                task = asyncio.create_task(websocketSubcribeLoop(websocket, id))
                await websocket.send_json({"i": id})
            else:
                await websocket.send_json({"o": f"{msg}"})
    except Exception as e:
        if task:
            task.cancel()

        if not isinstance(e, WebSocketDisconnect):
            await websocket.close()
