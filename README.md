# `nexus`

[![pdm-managed](https://img.shields.io/badge/pdm-managed-blueviolet)](https://pdm.fming.dev)

Codename `nexus` is a backend API that act as a link between Z3R0 (`zibot`) and Codename `cockpit`.

## Configuration

> **Note**
>
> This project is managed using [`pdm`](https://github.com/pdm-project/pdm), please install it for easier usage

`nexus` is mainly configured via environment variables:

```py
DISCORD_CLIENT_ID=0
DISCORD_CLIENT_SECRET=""
DISCORD_REDIRECT_URI="http://127.0.0.1:8000/callback"
DISCORD_GUILD_REDIRECT_URI="http://127.0.0.1:8000/guild-callback"
DASHBOARD_FRONTEND_URI="http://127.0.0.1"
# optional, if empty it'll use DASHBOARD_FRONTEND_URI by default, separated by comma
DASHBOARD_FRONTEND_CORS="http://zibot.local,http://dev.zibot.local"
DASHBOARD_HOSTNAME="127.0.0.1"  # mainly for cookie domain
DASHBOARD_ZMQ_SUB="127.0.0.1:5554"
# in docker-compose you can do something like this depending on your setup
# DASHBOARD_ZMQ_SUB="zibot.internal:5554"
DASHBOARD_ZMQ_PUB="127.0.0.1:5555"
DASHBOARD_ZMQ_REQ="127.0.0.1:5556"
# you should set this to 0 on prod
DASHBOARD_IS_DEBUG=1
# you should set this with strong passkey on prod
# leaving it empty will make nexus generate a random key by default on prod (on DEBUG=0) on boot
DASHBOARD_SECRET_KEY="you shall not pass"
REDIS_URL="redis://localhost:6379"
```

To run `nexus` you can simply run `pdm run start`

For dual stacking (listening to IPv4 and IPv6) you just need to not use `--host` flag:

```zsh
uvicorn nexus.app:app --port 80
```

## License
This software is licensed under [MPL-2.0](./LICENSE).
