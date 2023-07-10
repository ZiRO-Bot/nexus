from __future__ import annotations, unicode_literals

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional, Union

import aiohttp
from oauthlib.common import generate_token, urldecode
from oauthlib.oauth2 import (
    InsecureTransportError,
    TokenExpiredError,
    WebApplicationClient,
    is_secure_transport,
)

from nexus.core.oauth.models import Guild, User


if TYPE_CHECKING:
    from nexus.app import API


log = logging.getLogger(__name__)


DISCORD_URL = "https://discord.com"
API_URL = DISCORD_URL + "/api/v10"
TOKEN_URL = "/oauth2/token"
AUTH_URL = API_URL + "/oauth2/authorize"


class TokenUpdated(Warning):
    def __init__(self, token):
        super(TokenUpdated, self).__init__()
        self.token = token


class OAuth2Session(aiohttp.ClientSession):
    def __init__(
        self,
        *,
        backendObj: API,
        token: Optional[str] = None,
        autoRefreshKwargs: dict[str, Any] = {},
        scope: Optional[tuple[str, ...]] = None,
        redirectUri: Optional[str] = None,
        state: Optional[Union[str, Callable]] = None,
        tokenUpdater: Optional[Callable[..., Awaitable[None]]] = None,
        **kwargs,
    ) -> None:
        """Construct a new OAuth 2 client session.
        :param client_id: Client id obtained during registration
        :param client: :class:`oauthlib.oauth2.Client` to be used. Default is
                       WebApplicationClient which is useful for any
                       hosted application but not mobile or desktop.
        :param scope: List of scopes you wish to request access to
        :param redirect_uri: Redirect URI you registered as callback
        :param token: Token dictionary, must include access_token
                      and token_type.
        :param state: State string used to prevent CSRF. This will be given
                      when creating the authorization url and must be supplied
                      when parsing the authorization response.
                      Can be either a string or a no argument callable.
        :auto_refresh_url: Refresh token endpoint URL, must be HTTPS. Supply
                           this if you wish the client to automatically refresh
                           your access tokens.
        :auto_refresh_kwargs: Extra arguments to pass to the refresh token
                              endpoint.
        :token_updater: Method with one argument, token, to be used to update
                        your token database on automatic token refresh. If not
                        set a TokenUpdated warning will be raised when a token
                        has been refreshed. This warning will carry the token
                        in its token argument.
        :param kwargs: Arguments to pass to the Session constructor.
        """
        super().__init__(**kwargs)
        # Client for Backend
        self.backendObj: API = backendObj
        # Client exclusively for Auth functions
        self.authClient: WebApplicationClient = WebApplicationClient(str(self.backendObj.clientId), token=token)
        self.scope: Optional[tuple[str, ...]] = scope
        self.redirectUri = redirectUri
        self.state: Union[str, Callable] = state or generate_token
        self._state = state
        self.autoRefreshKwargs: dict[str, Any] = autoRefreshKwargs
        self.tokenUpdater: Optional[Callable[..., Awaitable[None]]] = tokenUpdater

        # Allow customizations for non compliant providers through various
        # hooks to adjust requests and responses.
        self.complianceHook = {
            "access_token_response": set(),
            "refresh_token_response": set(),
            "protected_request": set(),
        }

    def newState(self):
        """Generates a state string to be used in authorizations."""
        try:
            self._state = self.state()  # type: ignore
            log.debug("Generated new state %s.", self._state)
        except TypeError:
            self._state = self.state
            log.debug("Re-using previously supplied state %s.", self._state)
        return self._state

    @property
    def clientId(self) -> Optional[str]:
        return getattr(self.authClient, "client_id", None)

    @clientId.setter
    def clientId(self, value: str) -> None:
        self.authClient.client_id = value

    @clientId.deleter
    def clientId(self) -> None:
        del self.authClient.client_id

    @property
    def token(self) -> dict[str, Any]:
        return getattr(self.authClient, "token", {})

    @token.setter
    def token(self, value: dict[str, Any]) -> None:
        self.authClient.token = value
        self.authClient.populate_token_attributes(value)

    @property
    def accessToken(self) -> Optional[str]:
        return getattr(self.authClient, "access_token", None)

    @accessToken.setter
    def accessToken(self, value: str) -> None:
        self.authClient.access_token = value

    @accessToken.deleter
    def accessToken(self) -> None:
        del self.authClient.access_token

    @property
    def authorized(self) -> bool:
        """Boolean that indicates whether this session has an OAuth token
        or not. If `self.authorized` is True, you can reasonably expect
        OAuth-protected requests to the resource to succeed. If
        `self.authorized` is False, you need the user to go through the OAuth
        authentication dance before OAuth-protected requests to the resource
        will succeed.
        """
        return bool(self.accessToken)

    def authorizationUrl(self, state=None, **kwargs):
        """Form an authorization URL.
        :param url: Authorization endpoint url, must be HTTPS.
        :param state: An optional state string for CSRF protection. If not
                      given it will be generated for you.
        :param kwargs: Extra parameters to include.
        :return: authorization_url, state
        """
        state = state or self.newState()
        return (
            self.authClient.prepare_request_uri(
                AUTH_URL,
                redirect_uri=self.redirectUri,
                scope=self.scope,
                state=state,
                **kwargs,
            ),
            state,
        )

    async def fetchToken(
        self,
        # token_url,
        code=None,
        authorization_response=None,
        body="",
        auth=None,
        method="POST",
        force_querystring=False,
        timeout=None,
        headers=None,
        verify_ssl=True,
        proxies=None,
        include_client_id=None,
        **kwargs,
    ):
        """Generic method for fetching an access token from the token endpoint.
        If you are using the MobileApplicationClient you will want to use
        `token_from_fragment` instead of `fetch_token`.
        The current implementation enforces the RFC guidelines.
        :param token_url: Token endpoint URL, must use HTTPS.
        :param code: Authorization code (used by WebApplicationClients).
        :param authorization_response: Authorization response URL, the callback
                                       URL of the request back to you. Used by
                                       WebApplicationClients instead of code.
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by `requests`.
        :param method: The HTTP method used to make the request. Defaults
                       to POST, but may also be GET. Other methods should
                       be added as needed.
        :param force_querystring: If True, force the request body to be sent
            in the querystring instead.
        :param timeout: Timeout of the request in seconds.
        :param headers: Dict to default request headers with.
        :param verify: Verify SSL certificate.
        :param proxies: The `proxies` argument is passed onto `requests`.
        :param include_client_id: Should the request body include the
                                  `client_id` parameter. Default is `None`,
                                  which will attempt to autodetect. This can be
                                  forced to always include (True) or never
                                  include (False).
        :param client_secret: The `client_secret` paired to the `client_id`.
                              This is generally required unless provided in the
                              `auth` tuple. If the value is `None`, it will be
                              omitted from the request, however if the value is
                              an empty string, an empty string will be sent.
        :param kwargs: Extra parameters to include in the token request.
        :return: A token dict
        """
        if not is_secure_transport(API_URL + TOKEN_URL):
            raise InsecureTransportError()

        if not code and authorization_response:
            log.debug("-- response %s", authorization_response)
            self.authClient.parse_request_uri_response(str(authorization_response), state=self._state)
            code = self.authClient.code
            log.debug("--code %s", code)

        clientId = self.backendObj.clientId
        clientSecret = self.backendObj.clientSecret

        if not auth:
            log.debug(
                'Encoding `client_id` "%s" with `client_secret` ' "as Basic auth credentials.",
                clientId,
            )
            auth = aiohttp.BasicAuth(login=str(clientId), password=clientSecret)

        if include_client_id:
            # this was pulled out of the params
            # it needs to be passed into prepare_request_body
            kwargs["client_secret"] = clientSecret

        body = self.authClient.prepare_request_body(
            code=code,
            body=body,
            redirect_uri=self.redirectUri,
            include_client_id=include_client_id,
            **kwargs,
        )

        headers = headers or {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        }
        token = {}
        request_kwargs = {}
        if method.upper() == "POST":
            request_kwargs["params" if force_querystring else "data"] = dict(urldecode(body))
        elif method.upper() == "GET":
            request_kwargs["params"] = dict(urldecode(body))
        else:
            raise ValueError("The method kwarg must be POST or GET.")

        async with self.request(
            method=method,
            url=TOKEN_URL,
            timeout=timeout,
            headers=headers,
            auth=auth,
            verify_ssl=verify_ssl,
            proxy=proxies,
            data=request_kwargs["data"],
        ) as resp:
            log.debug("Request to fetch token completed with status %s.", resp.status)
            log.debug("Request headers were %s", headers)
            log.debug("Request body was %s", body)
            text = await resp.text()

            log.debug("Response headers were %s and content %s.", resp.headers, text)
            (resp,) = self._invokeHooks("access_token_response", resp)

        self.authClient.parse_request_body_response(await resp.text(), scope=self.scope)
        token = self.authClient.token
        log.debug("Obtained token %s.", token)
        return token

    async def refreshToken(
        self,
        refreshToken: str | None = None,
        auth: tuple | None = None,
        timeout: int | None = None,
        headers: dict = {},
        verify_ssl: bool = True,
        proxies=None,
        **kwargs,
    ):
        """Fetch a new access token using a refresh token.
        :param refresh_token: The refresh_token to use.
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by `requests`.
        :param timeout: Timeout of the request in seconds.
        :param headers: A dict of headers to be used by `requests`.
        :param verify: Verify SSL certificate.
        :param proxies: The `proxies` argument will be passed to `requests`.
        :param kwargs: Extra parameters to include in the token request.
        :return: A token dict
        """
        if not is_secure_transport(API_URL + TOKEN_URL):
            raise InsecureTransportError()

        refreshToken = refreshToken or self.token.get("refresh_token")

        log.debug("Adding auto refresh key word arguments %s.", self.autoRefreshKwargs)

        kwargs.update(self.autoRefreshKwargs)
        data = {
            "client_id": self.backendObj.clientId,
            "client_secret": self.backendObj.clientSecret,
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
        }
        log.debug("Prepared refresh token request body %s", data)

        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        resp = await self.request(
            "POST",
            TOKEN_URL,
            data=data,
            auth=auth,
            timeout=timeout,
            headers=headers,
            verify_ssl=verify_ssl,
            withhold_token=True,
            proxy=proxies,
        )

        log.debug("Request to refresh token completed with status %s.", resp.status)
        text = await resp.text()
        log.debug("Response headers were %s and content %s.", resp.headers, text)
        (resp,) = self._invokeHooks("access_token_response", resp)

        self.token = self.authClient.parse_request_body_response(text, scope=self.scope)
        if "refresh_token" not in self.token:
            log.debug("No new refresh token given. Re-using old.")
            self.token["refresh_token"] = refreshToken
        return self.token

    async def _request(
        self,
        method: str,
        urlFragment: str,
        *,
        data: dict[str, Any] = None,
        headers: dict[str, Any] = None,
        withholdToken: bool = False,
        **kwargs,
    ):
        """Intercept all requests and add the OAuth 2 token if present."""
        url = API_URL + urlFragment

        if not is_secure_transport(url):
            raise InsecureTransportError()

        if self.token and not withholdToken:
            url, headers, data = self._invokeHooks("protected_request", url, headers, data)
            log.debug("Adding token %s to request.", self.token)
            try:
                url, headers, data = self.authClient.add_token(url, http_method=method, body=data, headers=headers)
            # Attempt to retrieve and save new access token if expired
            except TokenExpiredError:
                log.debug(
                    "Auto refresh is set, attempting to refresh at %s.",
                    TOKEN_URL,
                )

                # We mustn't pass auth twice.
                auth = kwargs.pop("auth", None)

                if not auth:
                    clientId = self.backendObj.clientId
                    clientSecret = self.backendObj.clientSecret
                    log.debug(
                        'Encoding `client_id` "%s" with `client_secret` ' "as Basic auth credentials.",
                        clientId,
                    )
                    auth = aiohttp.BasicAuth(login=str(clientId), password=clientSecret)
                token = await self.refreshToken(auth=auth, **kwargs)
                if self.tokenUpdater:
                    log.debug("Updating token to %s using %s.", token, self.tokenUpdater)
                    await self.tokenUpdater(token)
                    url, headers, data = self.authClient.add_token(url, http_method=method, body=data, headers=headers)
                else:
                    raise TokenUpdated(token)

        log.debug("Requesting url %s using method %s.", url, method)
        log.debug("Supplying headers %s and data %s", headers, data)
        log.debug("Passing through key word arguments %s.", kwargs)
        return await super()._request(method, url, headers=headers, data=data, **kwargs)

    def registerComplianceHook(self, hookType: str, hook):
        """Register a hook for request/response tweaking.
        Available hooks are:
            access_token_response invoked before token parsing.
            refresh_token_response invoked before refresh token parsing.
            protected_request invoked before making a request.
        If you find a new hook is needed please send a GitHub PR request
        or open an issue.
        """
        if hookType not in self.complianceHook:
            raise ValueError("Hook type {} is not in {}.".format(hookType, self.complianceHook))
        self.complianceHook[hookType].add(hook)

    def _invokeHooks(self, hookType, *hookData) -> tuple[Any, ...]:
        log.debug("Invoking %d %s hooks.", len(self.complianceHook[hookType]), hookType)
        for hook in self.complianceHook[hookType]:
            log.debug("Invoking hook %s.", hook)
            hookData = hook(*hookData)
        return hookData

    async def _discordRequest(self, method: str, endpoint: str, **kwargs) -> dict[Any, Any]:
        """Request discord data with rate limit handler."""
        for _ in range(5):  # 5 tries before giving up
            resp = await self._request(method, endpoint, **kwargs)
            data = await resp.json()

            if resp.status == 429:
                if not resp.headers.get("Via"):
                    # Probably banned from cloudflare
                    raise RuntimeError

                retryAfter: float = data["retry_after"]

                log.debug(f"Failed to request, retrying in {retryAfter}")
                await asyncio.sleep(retryAfter)

                continue

            return data

        raise RuntimeError("Failed to request data from discord")

    async def identify(self):
        """Identify a user.
        Returns
        -------
        :class:`User`
            The user who authorized the application.
        """
        data = await self._discordRequest("GET", "/users/@me")
        user = User(data=data)
        self.backendObj.cachedUser[user.id] = user
        return user

    async def guilds(self, user_id: int = None) -> list[Guild]:
        data = await self._discordRequest("GET", "/users/@me/guilds")
        guilds = []
        try:
            data["global"]
        except TypeError:
            for guild in data:
                guilds.append(Guild(data=guild))
        # guilds = [Guild(data=g) for g in data]
        if user_id is None:
            self.backendObj.cachedGuilds[user_id] = guilds
        return guilds
