"""Exceptions for CVE Insights library."""

from __future__ import annotations


class CveInsightsError(Exception):
    """Base exception for all CVE Insights errors."""


class CveInsightsHttpError(CveInsightsError):
    """Exception raised when an HTTP request fails."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"HTTP {status_code}: {message}")


class CveInsightsAuthError(CveInsightsHttpError):
    """Exception raised on 401/403 authentication failures."""


class CveInsightsNotFoundError(CveInsightsHttpError):
    """Exception raised when an entity is not found."""


class CveInsightsRateLimitError(CveInsightsHttpError):
    """Exception raised when rate limit is exceeded."""
