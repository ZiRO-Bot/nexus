import asyncio
import json
from typing import TYPE_CHECKING, Generic, List, TypeVar

from fastapi import WebSocket, WebSocketException, status


if TYPE_CHECKING:
    from nexus.core.api import Nexus


T = TypeVar("T")


class Connection(Generic[T]):
    def __init__(self, type: str, data: T, websocket: WebSocket) -> None:
        self.type: str = type
        self.data: T = data
        self.websocket: WebSocket = websocket


class WebSocketManager:
    def __init__(self, app):
        self.app: "Nexus" = app
        self.activeConnections: List[Connection] = []

        asyncio.create_task(self.updatePublishLoop())

    async def handleGuildUpdate(self, decodedData: str):
        data = json.loads(decodedData)

        for conn in self.activeConnections:
            if conn.type != "guild":
                continue

            if data["before"].get("guildId") != conn.data:
                continue

            await self.send(decodedData, conn.websocket)

    async def updatePublishLoop(self):
        if not self.app.subSocket:
            return

        try:
            while True:
                msgType, msg = await self.app.subSocket.recv_multipart()

                if msgType.startswith(b"guild"):
                    if msgType.endswith(b"update"):
                        await self.handleGuildUpdate(msg.decode("utf-8"))
        except Exception as e:
            print(e)

    async def connect(self, websocket: WebSocket, **kwargs):
        if not self.app.subSocket:
            raise WebSocketException(status.WS_1011_INTERNAL_ERROR, "Nexus is not connected to any sub sockets.")

        # Auth checker for WebSocket
        if not self.app.validateAuth(websocket.session.get("authToken", {})) or not websocket.session.get("userId"):
            raise WebSocketException(status.WS_1008_POLICY_VIOLATION)

        await websocket.accept()
        conn = Connection(kwargs["type"], kwargs["data"], websocket)
        self.activeConnections.append(conn)
        return conn

    def disconnect(self, connection: Connection):
        self.activeConnections.remove(connection)

    async def send(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for conn in self.activeConnections:
            await self.send(message, conn.websocket)
