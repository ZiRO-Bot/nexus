import time


def validateAuth(authToken: dict) -> bool:
    # authToken = {'access_token': 'REDACTED', 'expires_in': 604800, 'refresh_token': 'REDACTED', 'scope': ['email', 'connections', 'identify', 'guilds', 'guilds.join'], 'token_type': 'Bearer', 'expires_at': 1678933659.2419164}

    return not time.time() - authToken.get("expires_at", 0) >= 0
