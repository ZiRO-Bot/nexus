from __future__ import annotations
from starlette.requests import Request
from typing import Any


CDN_BASE = "https://cdn.discordapp.com"


class DiscordObject:
    def __init__(self, data):
        self._data = data

        self.id: int = data["id"]

    def __eq__(self, other) -> bool:
        return other.id == self.id

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return self.id >> 22

    def json(self):
        """Returns the original JSON data for this model."""
        return self._data


class SessionUser(DiscordObject):
    def __init__(self, token: str, userId: int) -> None:
        self.oauthToken: str = token
        self.userId: int = userId


class Guild(DiscordObject):
    def __init__(self, *, data: dict) -> None:
        super().__init__(data)

        icon = self._data.get("icon")
        format = None if not icon else "gif" if icon.startswith("a") else "png"

        self.name: str = self._data["name"]
        self.iconUrl: str | None = (
            f"{CDN_BASE}/icons/{self.id}/{icon}.{format}" if icon else None
        )
        self.isOwner: bool | None = self._data.get("owner")
        self.features: list[str] = self._data.get("features", [])
        self.permissions: int = int(self._data.get("permissions", 0))

    def json(self):
        """Returns the original JSON data for this model."""
        data = super().json()
        data["icon"] = self.iconUrl
        return data


class User(DiscordObject):
    def __init__(self, *, data: dict):
        super().__init__(data)

        avatar = self._data.get("avatar")
        format = None if not avatar else "gif" if avatar.startswith("a") else "png"

        self.name: str = self._data["username"]
        self.avatarUrl: str = (
            f"{CDN_BASE}/avatars/{self.id}/{avatar}.{format}"
            if avatar
            else f"{CDN_BASE}/embed/avatars/{int(self.discriminator) % 5}.png"
        )
        self.discriminator: int = self._data["discriminator"]
        self.mfaEnabled: bool | None = self._data.get("mfa_enabled")
        self.email: str | None = self._data.get("email")
        self.verified: bool | None = self._data.get("verified")

        # self.guilds: List[Guild] = []  # this is filled in when fetch_guilds is called

    def __str__(self) -> str:
        return "{0.name}#{0.discriminator}".format(self)

    def __repr__(self) -> str:
        return "<User id={0.id} name={0.name} discriminator={0.discriminator} verified={0.verified}>".format(
            self
        )

    def json(self):
        """Returns the original JSON data for this model."""
        data = super().json()
        data["avatar"] = self.avatarUrl
        return data
