"""CVE Insights (Patch My PC) API client library."""

from __future__ import annotations

from .client import CveInsightsClient
from .const import (
    DEFAULT_API_KEY,
    DEFAULT_BASE_URL,
    DEFAULT_USER_AGENT,
    AnalyticsPeriod,
    PlatformType,
    SortType,
)
from .exceptions import (
    CveInsightsAuthError,
    CveInsightsError,
    CveInsightsHttpError,
    CveInsightsNotFoundError,
    CveInsightsRateLimitError,
)
from .models import (
    AffectedProduct,
    AlertNotification,
    AlertRule,
    CveDetails,
    CveSearchResult,
    CveSummary,
    NewsArticle,
    ProductCompact,
    VendorModel,
)

__all__ = [
    "DEFAULT_API_KEY",
    "DEFAULT_BASE_URL",
    "DEFAULT_USER_AGENT",
    "AffectedProduct",
    "AlertNotification",
    "AlertRule",
    "AnalyticsPeriod",
    "CveDetails",
    "CveInsightsAuthError",
    "CveInsightsClient",
    "CveInsightsError",
    "CveInsightsHttpError",
    "CveInsightsNotFoundError",
    "CveInsightsRateLimitError",
    "CveSearchResult",
    "CveSummary",
    "NewsArticle",
    "PlatformType",
    "ProductCompact",
    "SortType",
    "VendorModel",
]

__version__ = "1.0.0"
