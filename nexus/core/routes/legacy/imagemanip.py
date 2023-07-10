from io import BytesIO

import aiohttp
from fastapi import APIRouter, Response

from nexus.core import imagemanip


router = APIRouter(prefix="/image")


ENABLED_SYMBOLS = ("true", "t", "yes", "y", "on", "1")
DISABLED_SYMBOLS = ("false", "f", "no", "n", "off", "0")


async def manipulate(img_url: str, manip_type: str, **kwargs) -> BytesIO:
    async with aiohttp.ClientSession() as session:
        async with session.get(str(img_url)) as resp:
            img_bytes = await resp.read()
            return getattr(imagemanip, manip_type)(img_bytes, **kwargs)


@router.get("/invert")
async def invert(url: str, fixed: str):
    is_fixed = True
    if fixed.lower() in ENABLED_SYMBOLS:
        is_fixed = True
    if fixed.lower() in DISABLED_SYMBOLS:
        is_fixed = False

    return Response(
        content=(await manipulate(url, "invert", fixed=is_fixed)).read(),
        media_type="image/png",
    )


@router.get("/red")
async def red(url: str):
    return Response(
        content=(await manipulate(url, "red")).read(),
        media_type="image/png",
    )


@router.get("/polaroid")
async def polaroid(url: str, fixed: str = "on"):
    is_fixed = True
    if fixed.lower() in ENABLED_SYMBOLS:
        is_fixed = True
    if fixed.lower() in DISABLED_SYMBOLS:
        is_fixed = False

    return Response(
        content=(await manipulate(url, "polaroid", fixed=is_fixed)).read(),
        media_type="image/png",
    )


@router.get("/sad")
async def sad(url: str):
    return Response(
        content=(await manipulate(url, "sad")).read(),
        media_type="image/png",
    )


@router.get("/blurplify")
async def blurplify(url: str):
    return Response(
        content=(await manipulate(url, "blurplify")).read(),
        media_type="image/png",
    )


@router.get("/triggered")
async def triggered(url: str):
    return Response(
        content=(await manipulate(url, "triggered")).read(),
        media_type="image/gif",
    )


@router.get("/blur")
async def blur(url: str, fixed: str = "on"):
    is_fixed = True
    if fixed.lower() in ENABLED_SYMBOLS:
        is_fixed = True
    if fixed.lower() in DISABLED_SYMBOLS:
        is_fixed = False

    return Response(
        content=(await manipulate(url, "blur", fixed=is_fixed)).read(),
        media_type="image/png",
    )
