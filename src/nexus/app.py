from __future__ import annotations

import os

import uvicorn
from dotenv import load_dotenv
from fastapi import HTTPException
from starlette.responses import JSONResponse

from nexus.core import constants, routes
from nexus.core.api import Nexus


load_dotenv()


os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"  # Discord response with different scope for some reason
DEBUG: bool = bool(os.getenv("DASHBOARD_IS_DEBUG", 0))


app = Nexus(debug=DEBUG)
app.include_router(routes.legacy.google.router, prefix=constants.PREFIX_V1)
app.include_router(routes.legacy.imagemanip.router, prefix=constants.PREFIX_V1)
app.include_router(routes.ng.core.router, prefix=constants.PREFIX_V2)
app.include_router(routes.ng.meta.router, prefix=constants.PREFIX_V2)
app.include_router(routes.auth.router, prefix=constants.PREFIX)


@app.exception_handler(HTTPException)
async def errorHandler(request, exc):
    resp = JSONResponse(
        {"status": exc.status_code, "detail": str(exc.detail)},
        status_code=exc.status_code,
    )
    if exc.status_code == 401:
        if request.cookies.get("loggedIn"):
            resp.delete_cookie("loggedIn")
    return resp


if __name__ == "__main__":
    uvicorn.run("nexus.app:app", reload=DEBUG)
