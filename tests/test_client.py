"""Unit tests for CveInsightsClient."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cveinsights.client import CveInsightsClient
from cveinsights.const import SortType
from cveinsights.exceptions import (
    CveInsightsAuthError,
    CveInsightsNotFoundError,
    CveInsightsRateLimitError,
)
from cveinsights.models import ProductCompact


class MockResponse:
    """Mock aiohttp ClientResponse."""

    def __init__(
        self,
        status: int,
        json_data: Any = None,
        text_data: str = "",
    ) -> None:
        self.status = status
        self._json_data = json_data
        self._text_data = text_data

    async def text(self) -> str:
        if self._text_data:
            return self._text_data
        if self._json_data is not None:
            return json.dumps(self._json_data)
        return ""

    async def json(self) -> Any:
        return self._json_data

    async def __aenter__(self) -> MockResponse:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        pass


def make_mock_session(status: int = 200, json_data: Any = None, text_data: str = "") -> MagicMock:
    """Create a mock aiohttp session returning a specified response."""
    session = MagicMock()
    session.closed = False
    response = MockResponse(status, json_data=json_data, text_data=text_data)
    session.request = MagicMock(return_value=response)
    session.close = AsyncMock()
    return session


async def test_get_vendors() -> None:
    """Test get_vendors returns parsed models."""
    sample_data = [
        {"name": "Signal", "products": ["Signal Desktop", "Signal Android"]},
        {"name": "Google", "products": ["Chrome"]},
    ]
    session = make_mock_session(200, sample_data)
    client = CveInsightsClient(session=session)

    vendors = await client.get_vendors()
    assert len(vendors) == 2
    assert vendors[0].name == "Signal"
    assert "Signal Desktop" in vendors[0].products


async def test_search_cves() -> None:
    """Test search_cves sends correct payload and parses results."""
    sample_data = {
        "data": [
            {
                "cveId": "CVE-2026-113380",
                "description": "Signal vulnerability",
                "baseScores": {"3.1": 9.3},
            }
        ],
        "page": 1,
        "pageSize": 5,
        "totalResults": 1,
    }
    session = make_mock_session(200, sample_data)
    client = CveInsightsClient(session=session)

    result = await client.search_cves(
        vendor="Signal",
        product="Signal",
        min_base_score=7.0,
        sort_by=SortType.SCORE,
    )
    assert result.total_results == 1
    assert result.data[0].cve_id == "CVE-2026-113380"
    assert result.data[0].max_score == 9.3

    # Verify session call
    session.request.assert_called_once()
    args, kwargs = session.request.call_args
    assert args[0] == "POST"
    assert kwargs["json"]["vendor"] == "Signal"
    assert kwargs["json"]["minBaseScore"] == 7.0


async def test_get_cve_details() -> None:
    """Test get_cve_details."""
    sample_data = {
        "cveId": "CVE-2026-113380",
        "description": "Test description",
        "dateUpdated": "2026-10-23T00:00:00Z",
        "references": ["https://signal.org"],
    }
    session = make_mock_session(200, sample_data)
    client = CveInsightsClient(session=session)

    details = await client.get_cve_details("CVE-2026-113380")
    assert details.cve_id == "CVE-2026-113380"
    assert details.references == ("https://signal.org",)


async def test_alert_lifecycle() -> None:
    """Test creating, listing, getting, and deleting alerts."""
    session = make_mock_session(200, {})
    client = CveInsightsClient(session=session)

    # Create alert
    alert = await client.create_alert(
        name="Security Apps",
        device_id="test-dev-1",
        vendors=["Signal"],
        products=[ProductCompact("Signal", "Signal")],
        min_base_score=5.0,
        alert_id="rule-uuid-1",
    )
    assert alert.name == "Security Apps"
    assert alert.alert_id == "rule-uuid-1"

    # List alerts
    list_data = {
        "data": [
            {
                "alertId": "rule-uuid-1",
                "deviceId": "test-dev-1",
                "name": "Security Apps",
                "vendors": ["Signal"],
                "products": [{"vendorName": "Signal", "productName": "Signal"}],
            }
        ]
    }
    client._session = make_mock_session(200, list_data)
    alerts = await client.get_alerts("test-dev-1")
    assert len(alerts) == 1
    assert alerts[0].alert_id == "rule-uuid-1"

    # Delete alert
    client._session = make_mock_session(200, {})
    deleted = await client.delete_alert("rule-uuid-1")
    assert deleted is True


async def test_notifications() -> None:
    """Test notifications list and unread count."""
    notif_data = {
        "data": [
            {
                "notificationId": "notif-1",
                "cveId": "CVE-2026-1111",
                "baseScore": 8.5,
                "markedAsRead": False,
            }
        ]
    }
    client = CveInsightsClient(session=make_mock_session(200, notif_data))
    notifs = await client.get_notifications("dev-1")
    assert len(notifs) == 1
    assert notifs[0].cve_id == "CVE-2026-1111"

    client._session = make_mock_session(200, {"count": 3})
    count = await client.get_unread_count("dev-1")
    assert count == 3


async def test_error_handling() -> None:
    """Test mapped exceptions for HTTP status codes."""
    # 401 Auth error
    client = CveInsightsClient(session=make_mock_session(401, text_data="Unauthorized"))
    with pytest.raises(CveInsightsAuthError):
        await client.get_vendors()

    # 404 Not found
    client = CveInsightsClient(session=make_mock_session(404, text_data="Not found"))
    with pytest.raises(CveInsightsNotFoundError):
        await client.get_cve_details("CVE-NONEXISTENT")

    # 429 Rate limit
    client = CveInsightsClient(session=make_mock_session(429, text_data="Rate limited"))
    with pytest.raises(CveInsightsRateLimitError):
        await client.get_vendors()
