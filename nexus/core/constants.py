import os
from nexus.utils.humanize import str_bool


REQUEST_TIMEOUT = 2500
REQUEST_RETRIES = 3
PREFIX_V1 = "/v1"
PREFIX_V2 = "/v2"
NEXUS_EPOCH = 1689740330
DEBUG = str_bool(os.getenv("DASHBOARD_IS_DEBUG", "0"))
SESSION_EXPIRY = 14 * 24 * 60 * 60  # 14 days
SESSION_EXPIRY_DEBUG = 24 * 60 * 60
