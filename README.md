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
DISCORD_REDIRECT_URI="http://127.0.0.1:8000/api/callback"
DASHBOARD_FRONTEND_URI="http://127.0.0.1"
DASHBOARD_HOSTNAME="127.0.0.1"
DASHBOARD_ZMQ_SUB="127.0.0.1:5554"
DASHBOARD_ZMQ_PUB="127.0.0.1:5555"
DASHBOARD_ZMQ_REQ="127.0.0.1:5556"
DASHBOARD_IS_DEBUG=1
```

To run `nexus` you can simply run `pdm run start`

For dual stacking (listening to IPv4 and IPv6) you just need to not use `--host` flag:

```zsh
uvicorn nexus.app:app --port 80
```

## License
This software is licensed under [MPL-2.0](./LICENSE).
