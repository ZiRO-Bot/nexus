# `nexus`

Codename `nexus` is a backend API that act as a link between Z3R0 (`zibot`) and Codename `cockpit`.

## Configuration

`nexus` is mainly configured via environment variables:

```py
DISCORD_CLIENT_ID=0
DISCORD_CLIENT_SECRET=""
DISCORD_REDIRECT_URI="http://127.0.0.1:8000/api/callback"
DASHBOARD_FRONTEND_URI="http://127.0.0.1"
DASHBOARD_ZMQ_SUB="127.0.0.1:5554"
DASHBOARD_ZMQ_PUB="127.0.0.1:5555"
DASHBOARD_ZMQ_REQ="127.0.0.1:5556"
DASHBOARD_IS_DEBUG=1
```

To run `nexus` you can simply run `py webserver`

## License
This software is licensed under [New BSD License](./LICENSE).
