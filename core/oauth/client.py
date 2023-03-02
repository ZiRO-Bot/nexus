from typing import Iterable, Optional

# from .http import HTTPClient, Route
from .session import OAuth2Session
from utils import cache

__all__: tuple = ("OAuth2Client",)


class OAuth2Client:
    """
    A class representing a client interacting with the discord OAuth2 API.
    """

    def __init__(
        self,
        *,
        client_id: int,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[Iterable[str]] = None,
    ):
        """A class representing a client interacting with the discord OAuth2 API.

        :param client_id: The OAuth application's client_id
        :type client_id: int
        :param client_secret: The OAuth application's client_secret
        :type client_secret: str
        :param redirect_uri: The OAuth application's redirect_uri. Must be from one of the configured uri's on the developer portal
        :type redirect_uri: str
        :param scopes: A list of OAuth2 scopes, defaults to None
        :type scopes: Optional[Iterable[str]], optional
        """
        self.id = client_id
        self.secret = client_secret
        self.redirect = redirect_uri
        self.scopes = " ".join(scopes) if scopes is not None else None
        self.cached_user = cache.ExpiringDict(maxAgeSeconds=60)
        self.cached_guilds = cache.ExpiringDict(maxAgeSeconds=60)

    def session(self, token=None, state=None, token_updater=None) -> OAuth2Session:
        return OAuth2Session(
            discord_client=self,
            client_id=self.id,
            token=token,
            state=state,
            scope=self.scopes,
            redirect_uri=self.redirect,
            auto_refresh_kwargs={
                'client_id': str(self.id),
                'client_secret': self.secret,
            },
            # auto_refresh_url=_oauth2['token_url'],
            token_updater=token_updater,
        )
