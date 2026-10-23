"""Constants for the CVE Insights (Patch My PC) API client."""

from __future__ import annotations

from enum import IntEnum, StrEnum

DEFAULT_BASE_URL: str = "https://us.portal.patchmypc.com"
DEFAULT_API_KEY: str = "PatchMyPCRocks!"
DEFAULT_USER_AGENT: str = "CVEInsights/1.0 (Android; PatchMyPC)"


class SortType(IntEnum):
    """Sort criteria for CVE search."""

    PUBLISH_DATE = 0
    UPDATE_DATE = 1
    SCORE = 2


class AnalyticsPeriod(IntEnum):
    """Analytics time period filter."""

    LAST_DAY = 0
    LAST_7_DAYS = 1
    LAST_30_DAYS = 2
    LAST_90_DAYS = 3


class PlatformType(StrEnum):
    """Push notification platform types."""

    FCM = "fcm"
    APNS = "apns"
