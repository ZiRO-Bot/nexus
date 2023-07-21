import random
import datetime as dt
from typing import Optional
from discord.utils import utcnow

from nexus.core.constants import NEXUS_EPOCH


def snowflake(datetime: Optional[dt.datetime] = None, /, *, high: bool = False) -> int:
    """Simplified version of how discord ID generated

    REF: https://github.com/Rapptz/discord.py/blob/e870bb1335e3f824c83a40df4ea9b17f215fde63/discord/utils.py#L395-L422
    """
    if not datetime:
        datetime = utcnow()
    millis = int(datetime.timestamp() * 1000 - NEXUS_EPOCH)
    return (millis << 22) + (2**22 - 1 if high else 0) + random.randint(0, 10)


def timeFromSnowflake(id: int, /) -> dt.datetime:
    """REF: https://github.com/Rapptz/discord.py/blob/e870bb1335e3f824c83a40df4ea9b17f215fde63/discord/utils.py#L375-L392"""
    millis = ((id >> 22) + NEXUS_EPOCH) / 1000
    return dt.datetime.fromtimestamp(millis, tz=dt.timezone.utc)
