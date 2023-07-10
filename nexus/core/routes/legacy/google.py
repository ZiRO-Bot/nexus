from typing import Union

from fastapi import APIRouter

from nexus.core.google import Google


google = Google()
router = APIRouter()


@router.get("/search")
async def search(q: Union[str, None] = None):
    if not q:
        return {}
    return await google.search(q)
