from __future__ import annotations, unicode_literals

import asyncio
import logging
from typing import Any, Dict, Tuple

from oauthlib.common import generate_token, urldecode
from oauthlib.oauth2 import WebApplicationClient, InsecureTransportError
from oauthlib.oauth2 import LegacyApplicationClient
from oauthlib.oauth2 import TokenExpiredError, is_secure_transport
import aiohttp

from core.oauth.models import User, Guild


log = logging.getLogger(__name__)


DISCORD_URL = "https://discord.com"
API_URL = DISCORD_URL + "/api/v9"
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
        discord_client,
        client_id=None,
        client=None,
        auto_refresh_url=None,
        auto_refresh_kwargs=None,
        scope=None,
        redirect_uri=None,
        token=None,
        state=None,
        token_updater=None,
        **kwargs
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
        super(OAuth2Session, self).__init__(**kwargs)
        self.discord_client = discord_client
        self._client = client or WebApplicationClient(str(client_id), token=token)
        # self.token = token or {}
        self.scope = scope
        self.redirect_uri = redirect_uri
        self.state = state or generate_token
        self._state = state
        self.auto_refresh_url = auto_refresh_url or TOKEN_URL
        self.auto_refresh_kwargs = auto_refresh_kwargs or {}
        self.token_updater = token_updater

        if self.token_updater:
            assert self.auto_refresh_url, "Auto refresh URL required if token updater"

        # Allow customizations for non compliant providers through various
        # hooks to adjust requests and responses.
        self.compliance_hook = {
            "access_token_response": set(),
            "refresh_token_response": set(),
            "protected_request": set(),
        }

    def new_state(self):
        """Generates a state string to be used in authorizations."""
        try:
            self._state = self.state()
            log.debug("Generated new state %s.", self._state)
        except TypeError:
            self._state = self.state
            log.debug("Re-using previously supplied state %s.", self._state)
        return self._state

    @property
    def client_id(self):
        return getattr(self._client, "client_id", None)

    @client_id.setter
    def client_id(self, value):
        self._client.client_id = value

    @client_id.deleter
    def client_id(self):
        del self._client.client_id

    @property
    def token(self):
        return getattr(self._client, "token", {})

    @token.setter
    def token(self, value):
        self._client.token = value
        self._client.populate_token_attributes(value)

    @property
    def access_token(self):
        return getattr(self._client, "access_token", None)

    @access_token.setter
    def access_token(self, value):
        self._client.access_token = value

    @access_token.deleter
    def access_token(self):
        del self._client.access_token

    @property
    def authorized(self):
        """Boolean that indicates whether this session has an OAuth token
        or not. If `self.authorized` is True, you can reasonably expect
        OAuth-protected requests to the resource to succeed. If
        `self.authorized` is False, you need the user to go through the OAuth
        authentication dance before OAuth-protected requests to the resource
        will succeed.
        """
        return bool(self.access_token)

    def authorization_url(self, state=None, **kwargs):
        """Form an authorization URL.
        :param url: Authorization endpoint url, must be HTTPS.
        :param state: An optional state string for CSRF protection. If not
                      given it will be generated for you.
        :param kwargs: Extra parameters to include.
        :return: authorization_url, state
        """
        state = state or self.new_state()
        return (
            self._client.prepare_request_uri(
                AUTH_URL,
                redirect_uri=self.redirect_uri,
                scope=self.scope,
                state=state,
                **kwargs
            ),
            state,
        )

    async def fetch_token(
        self,
        # token_url,
        code=None,
        authorization_response=None,
        body="",
        auth=None,
        username=None,
        password=None,
        method="POST",
        force_querystring=False,
        timeout=None,
        headers=None,
        verify_ssl=True,
        proxies=None,
        include_client_id=None,
        client_id=None,
        client_secret=None,
        **kwargs
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
        :param username: Username required by LegacyApplicationClients to appear
                         in the request body.
        :param password: Password required by LegacyApplicationClients to appear
                         in the request body.
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
        # print('fetch_token')
        if not is_secure_transport(API_URL + TOKEN_URL):
            raise InsecureTransportError()

        if not code and authorization_response:
            log.debug("-- response %s", authorization_response)
            self._client.parse_request_uri_response(
                str(authorization_response), state=self._state
            )
            code = self._client.code
            log.debug("--code %s", code)
        elif not code and isinstance(self._client, WebApplicationClient):
            code = self._client.code
            if not code:
                raise ValueError(
                    "Please supply either code or " "authorization_response parameters."
                )

        # Earlier versions of this library build an HTTPBasicAuth header out of
        # `username` and `password`. The RFC states, however these attributes
        # must be in the request body and not the header.
        # If an upstream server is not spec compliant and requires them to
        # appear as an Authorization header, supply an explicit `auth` header
        # to this function.
        # This check will allow for empty strings, but not `None`.
        #
        # Refernences
        # 4.3.2 - Resource Owner Password Credentials Grant
        #         https://tools.ietf.org/html/rfc6749#section-4.3.2

        if isinstance(self._client, LegacyApplicationClient):
            if username is None:
                raise ValueError(
                    "`LegacyApplicationClient` requires both the "
                    "`username` and `password` parameters."
                )
            if password is None:
                raise ValueError(
                    "The required parameter `username` was supplied, "
                    "but `password` was not."
                )

        # merge username and password into kwargs for `prepare_request_body`
        if username is not None:
            kwargs["username"] = username
        if password is not None:
            kwargs["password"] = password

        # is an auth explicitly supplied?
        if auth is not None:
            # if we're dealing with the default of `include_client_id` (None):
            # we will assume the `auth` argument is for an RFC compliant server
            # and we should not send the `client_id` in the body.
            # This approach allows us to still force the client_id by submitting
            # `include_client_id=True` along with an `auth` object.
            if include_client_id is None:
                include_client_id = False

        # otherwise we may need to create an auth header
        else:
            # since we don't have an auth header, we MAY need to create one
            # it is possible that we want to send the `client_id` in the body
            # if so, `include_client_id` should be set to True
            # otherwise, we will generate an auth header
            if include_client_id is not True:
                client_id = self.client_id
            if client_id:
                log.debug(
                    'Encoding `client_id` "%s" with `client_secret` '
                    "as Basic auth credentials.",
                    client_id,
                )
                client_id = client_id
                client_secret = client_secret if client_secret is not None else ""
                auth = aiohttp.BasicAuth(login=client_id, password=client_secret)

        if include_client_id:
            # this was pulled out of the params
            # it needs to be passed into prepare_request_body
            if client_secret is not None:
                kwargs["client_secret"] = client_secret

        body = self._client.prepare_request_body(
            code=code,
            body=body,
            redirect_uri=self.redirect_uri,
            include_client_id=include_client_id,
            **kwargs
        )

        headers = headers or {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        }
        self.token = {}
        request_kwargs = {}
        if method.upper() == "POST":
            request_kwargs["params" if force_querystring else "data"] = dict(
                urldecode(body)
            )
        elif method.upper() == "GET":
            request_kwargs["params"] = dict(urldecode(body))
        else:
            raise ValueError("The method kwarg must be POST or GET.")
        # print(method, TOKEN_URL, timeout, headers, auth, verify_ssl, proxies, request_kwargs['data'])
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
            (resp,) = self._invoke_hooks("access_token_response", resp)
        self._client.parse_request_body_response(await resp.text(), scope=self.scope)
        self.token = self._client.token
        log.debug("Obtained token %s.", self.token)
        return self.token

    def token_from_fragment(self, authorization_response):
        """Parse token from the URI fragment, used by MobileApplicationClients.
        :param authorization_response: The full URL of the redirect back to you
        :return: A token dict
        """
        self._client.parse_request_uri_response(
            authorization_response, state=self._state
        )
        self.token = self._client.token
        return self.token

    async def refresh_token(
        self,
        refresh_token=None,
        body="",
        auth=None,
        timeout=None,
        headers=None,
        verify_ssl=True,
        proxies=None,
        **kwargs
    ):
        """Fetch a new access token using a refresh token.
        :param token_url: The token endpoint, must be HTTPS.
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

        refresh_token = refresh_token or self.token.get("refresh_token")

        log.debug(
            "Adding auto refresh key word arguments %s.", self.auto_refresh_kwargs
        )

        kwargs.update(self.auto_refresh_kwargs)
        body = self._client.prepare_refresh_body(
            body=body, refresh_token=refresh_token, scope=self.scope, **kwargs
        )
        log.debug("Prepared refresh token request body %s", body)

        if headers is None:
            headers = {
                "Accept": "application/json",
                "Content-Type": ("application/x-www-form-urlencoded;charset=UTF-8"),
            }

        resp = await self.request(
            "POST",
            TOKEN_URL,
            data=dict(urldecode(body)),
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
        (resp,) = self._invoke_hooks("access_token_response", resp)

        self.token = self._client.parse_request_body_response(await resp.text(), scope=self.scope)
        if "refresh_token" not in self.token:
            log.debug("No new refresh token given. Re-using old.")
            self.token["refresh_token"] = refresh_token
        return self.token

    async def _request(
        self,
        method,
        url_fragment,
        *,
        data=None,
        headers=None,
        withhold_token=False,
        client_id=None,
        client_secret=None,
        **kwargs
    ):
        """Intercept all requests and add the OAuth 2 token if present."""
        url = API_URL + url_fragment

        if not is_secure_transport(url):
            raise InsecureTransportError()

        if self.token and not withhold_token:

            url, headers, data = self._invoke_hooks(
                "protected_request", url, headers, data
            )
            log.debug("Adding token %s to request.", self.token)
            try:
                url, headers, data = self._client.add_token(
                    url, http_method=method, body=data, headers=headers
                )
            # Attempt to retrieve and save new access token if expired
            except TokenExpiredError:
                if self.auto_refresh_url:
                    log.debug(
                        "Auto refresh is set, attempting to refresh at %s.",
                        self.auto_refresh_url,
                    )

                    # We mustn't pass auth twice.
                    auth = kwargs.pop("auth", None)
                    if client_id and client_secret and (auth is None):
                        log.debug(
                            'Encoding client_id "%s" with client_secret as Basic auth credentials.',
                            client_id,
                        )
                        auth = aiohttp.BasicAuth(
                            login=client_id, password=client_secret
                        )
                    token = await self.refresh_token(
                        self.auto_refresh_url, auth=auth, **kwargs
                    )
                    if self.token_updater:
                        log.debug(
                            "Updating token to %s using %s.", token, self.token_updater
                        )
                        await self.token_updater(token)
                        url, headers, data = self._client.add_token(
                            url, http_method=method, body=data, headers=headers
                        )
                    else:
                        raise TokenUpdated(token)
                else:
                    raise

        log.debug("Requesting url %s using method %s.", url, method)
        log.debug("Supplying headers %s and data %s", headers, data)
        log.debug("Passing through key word arguments %s.", kwargs)
        return await super()._request(method, url, headers=headers, data=data, **kwargs)

    def register_compliance_hook(self, hook_type, hook):
        """Register a hook for request/response tweaking.
        Available hooks are:
            access_token_response invoked before token parsing.
            refresh_token_response invoked before refresh token parsing.
            protected_request invoked before making a request.
        If you find a new hook is needed please send a GitHub PR request
        or open an issue.
        """
        if hook_type not in self.compliance_hook:
            raise ValueError(
                "Hook type {} is not in {}.".format(hook_type, self.compliance_hook)
            )
        self.compliance_hook[hook_type].add(hook)

    def _invoke_hooks(self, hook_type, *hook_data) -> Tuple[Any, ...]:
        log.debug(
            "Invoking %d %s hooks.", len(self.compliance_hook[hook_type]), hook_type
        )
        for hook in self.compliance_hook[hook_type]:
            log.debug("Invoking hook %s.", hook)
            hook_data = hook(*hook_data)
        return hook_data

    # async def _discord_request(self, url_fragment, method='GET'):
    #     if not self.token:
    #         url = API_URL + '/oauth2/token'
    #         self._discord_token = await self.fetch_token(
    #             url,
    #             code=self._discord_auth_code,
    #             client_secret=self._discord_client_secret
    #         )

    #     token = self.token['access_token']
    #     url = API_URL + url_fragment
    #     headers = {
    #         'Authorization': 'Authorization: Bearer ' + token
    #     }
    #     async with self.request(method, url, headers=headers) as resp:
    #         resp.raise_for_status()
    #         return await resp.json()

    async def discord_request(self, method, endpoint, **kwargs) -> Dict[Any, Any]:
        """Request discord data with rate limit handler."""
        for _ in range(5):  # 5 tries before giving up
            resp = await self._request(method, endpoint, **kwargs)
            data = await resp.json()

            # print(resp.headers)
            # print(resp.status)

            if resp.status == 429:
                if not resp.headers.get('Via'):
                    # Probably banned from cloudflare
                    raise RuntimeError

                retry_after: float = data["retry_after"]

                await asyncio.sleep(retry_after)

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
        data = await self.discord_request('GET', '/users/@me')
        user = User(data=data)
        self.discord_client.cached_user[user.id] = user
        return user

    async def guilds(self, user_id: int = None):
        data = await self.discord_request('GET', '/users/@me/guilds')
        guilds = []
        try:
            data["global"]
        except TypeError:
            for guild in data:
                guilds.append(Guild(data=guild))
        # guilds = [Guild(data=g) for g in data]
        if user_id is None:
            self.discord_client.cached_guilds[user_id] = guilds
        return guilds
