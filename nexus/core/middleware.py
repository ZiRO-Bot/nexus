import os

from starlette.middleware.sessions import SessionMiddleware as Origin


class SessionMiddleware(Origin):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.security_flags = f"same-site={kwargs.get('same_site', 'lax')}; domain={os.getenv('DASHBOARD_HOSTNAME')}"
