"""Asynchronous API client for CVE Insights (Patch My PC)."""

from __future__ import annotations

import logging
import uuid
from types import TracebackType
from typing import Any, Self

import aiohttp
from yarl import URL

from .const import (
    DEFAULT_API_KEY,
    DEFAULT_BASE_URL,
    DEFAULT_USER_AGENT,
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
    NewsArticle,
    ProductCompact,
    VendorModel,
)

_LOGGER = logging.getLogger(__name__)


class CveInsightsClient:
    """Client for interacting with the Patch My PC CVE Insights REST API."""

    def __init__(
        self,
        api_key: str = DEFAULT_API_KEY,
        base_url: str = DEFAULT_BASE_URL,
        session: aiohttp.ClientSession | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        """Initialize the client."""
        self._api_key = api_key
        self._base_url = URL(base_url.rstrip("/"))
        self._session = session
        self._own_session = session is None
        self._user_agent = user_agent

    @property
    def base_url(self) -> URL:
        """Return the base URL."""
        return self._base_url

    async def _get_session(self) -> aiohttp.ClientSession:
        """Return the active ClientSession or create a new internal one."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
            self._own_session = True
        return self._session

    async def close(self) -> None:
        """Close the underlying session if owned by this client."""
        if self._own_session and self._session is not None and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> Self:
        """Async context manager enter."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Async context manager exit."""
        await self.close()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | list[Any] | None = None,
    ) -> Any:
        """Execute an HTTP request with proper headers and error handling."""
        session = await self._get_session()
        url = self._base_url / path.lstrip("/")

        clean_params: dict[str, str] = {}
        if params:
            for k, v in params.items():
                if v is not None:
                    clean_params[k] = str(v)

        headers = {
            "x-api-key": self._api_key,
            "User-Agent": self._user_agent,
            "Accept": "application/json",
        }
        if json_data is not None:
            headers["Content-Type"] = "application/json"

        try:
            async with session.request(
                method,
                str(url),
                params=clean_params if clean_params else None,
                json=json_data,
                headers=headers,
            ) as response:
                status = response.status
                if status in (200, 201):
                    text = await response.text()
                    if not text.strip():
                        return None
                    return await response.json()
                if status == 204:
                    return None
                if status in (401, 403):
                    err_msg = await response.text()
                    raise CveInsightsAuthError(status, err_msg)
                if status == 404:
                    err_msg = await response.text()
                    raise CveInsightsNotFoundError(status, err_msg)
                if status == 429:
                    err_msg = await response.text()
                    raise CveInsightsRateLimitError(status, err_msg)

                err_msg = await response.text()
                raise CveInsightsHttpError(status, err_msg)

        except (CveInsightsError, aiohttp.ClientError):
            raise
        except Exception as err:
            raise CveInsightsError(
                f"Unexpected error during API request: {err}"
            ) from err

    # -------------------------------------------------------------------------
    # Catalogs and Lookups
    # -------------------------------------------------------------------------

    async def get_vendors(self) -> list[VendorModel]:
        """Fetch all known vendors and their catalog of products."""
        data = await self._request("GET", "api/vulnerability/lookup/vendors")
        if not isinstance(data, list):
            return []
        return [VendorModel.from_dict(v) for v in data if isinstance(v, dict)]

    # -------------------------------------------------------------------------
    # CVE Searches & Details
    # -------------------------------------------------------------------------

    async def search_cves(
        self,
        *,
        vendor: str | None = None,
        product: str | None = None,
        keywords: str | None = None,
        publish_date_start: str | None = None,
        publish_date_end: str | None = None,
        update_date_start: str | None = None,
        update_date_end: str | None = None,
        min_base_score: float | None = None,
        max_base_score: float | None = None,
        sort_by: SortType = SortType.PUBLISH_DATE,
        descending: bool = True,
        page: int = 1,
        page_size: int = 10,
    ) -> CveSearchResult:
        """Search vulnerabilities matching criteria."""
        payload: dict[str, Any] = {
            "page": page,
            "pageSize": page_size,
            "sortBy": int(sort_by),
            "descending": descending,
        }
        if vendor:
            payload["vendor"] = vendor
        if product:
            payload["product"] = product
        if keywords:
            payload["keywords"] = keywords
        if publish_date_start:
            payload["publishDateStart"] = publish_date_start
        if publish_date_end:
            payload["publishDateEnd"] = publish_date_end
        if update_date_start:
            payload["updateDateStart"] = update_date_start
        if update_date_end:
            payload["updateDateEnd"] = update_date_end
        if min_base_score is not None:
            payload["minBaseScore"] = min_base_score
        if max_base_score is not None:
            payload["maxBaseScore"] = max_base_score

        data = await self._request("POST", "api/vulnerability", json_data=payload)
        if isinstance(data, dict):
            return CveSearchResult.from_dict(data)
        return CveSearchResult(data=(), page=page, page_size=page_size, total_results=0)

    async def get_cve_details(self, cve_id: str) -> CveDetails:
        """Fetch complete details of a specific CVE."""
        data = await self._request(
            "GET",
            f"api/vulnerability/{cve_id}",
            params={"api-version": "2.0"},
        )
        if isinstance(data, dict):
            return CveDetails.from_dict(data)
        raise CveInsightsNotFoundError(404, f"CVE {cve_id} not found")

    async def get_cve_affected_products(
        self,
        cve_id: str,
        page: int = 1,
        page_size: int = 20,
    ) -> list[AffectedProduct]:
        """Fetch list of products affected by a CVE."""
        data = await self._request(
            "GET",
            f"api/vulnerability/{cve_id}/products-affected",
            params={
                "api-version": "2.0",
                "Page": page,
                "PageSize": page_size,
            },
        )
        if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
            return [
                AffectedProduct.from_dict(p)
                for p in data["data"]
                if isinstance(p, dict)
            ]
        return []

    # -------------------------------------------------------------------------
    # Alert Rules
    # -------------------------------------------------------------------------

    async def create_alert(
        self,
        name: str,
        device_id: str,
        *,
        vendors: list[str] | None = None,
        products: list[ProductCompact] | None = None,
        min_base_score: float = 0.0,
        max_base_score: float = 10.0,
        alert_id: str | None = None,
    ) -> AlertRule:
        """Create or update an alert rule."""
        rule_id = alert_id or str(uuid.uuid4())
        vendors_list = list(vendors) if vendors else []
        prods_list = list(products) if products else []

        alert = AlertRule(
            alert_id=rule_id,
            device_id=device_id,
            name=name,
            vendors=tuple(vendors_list),
            products=tuple(prods_list),
            min_base_score=min_base_score,
            max_base_score=max_base_score,
        )

        await self._request(
            "POST",
            "api/vulnerability/alert",
            json_data=alert.to_request_payload(),
        )
        return alert

    async def get_alerts(self, device_id: str) -> list[AlertRule]:
        """List all configured alert rules for a device."""
        data = await self._request(
            "GET",
            f"api/vulnerability/alert/list/{device_id}",
        )
        if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
            return [
                AlertRule.from_dict(rule)
                for rule in data["data"]
                if isinstance(rule, dict)
            ]
        return []

    async def get_alert(self, device_id: str, alert_id: str) -> AlertRule:
        """Fetch a specific alert rule."""
        data = await self._request(
            "GET",
            f"api/vulnerability/alert/{device_id}/{alert_id}",
        )
        if isinstance(data, dict):
            return AlertRule.from_dict(data)
        raise CveInsightsNotFoundError(404, f"Alert {alert_id} not found")

    async def delete_alert(self, alert_id: str) -> bool:
        """Delete an alert rule by ID."""
        await self._request("DELETE", f"api/vulnerability/alert/{alert_id}")
        return True

    # -------------------------------------------------------------------------
    # Notifications
    # -------------------------------------------------------------------------

    async def get_notifications(
        self,
        device_id: str,
        *,
        alert_id: str | None = None,
        skip: int = 0,
        limit: int = 20,
    ) -> list[AlertNotification]:
        """Fetch notifications generated for a device or specific alert rule."""
        path = (
            f"api/vulnerability/notification/{device_id}/{alert_id}"
            if alert_id
            else f"api/vulnerability/notification/{device_id}"
        )
        data = await self._request(
            "GET",
            path,
            params={"Skip": skip, "Limit": limit},
        )
        if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
            return [
                AlertNotification.from_dict(n)
                for n in data["data"]
                if isinstance(n, dict)
            ]
        return []

    async def get_unread_count(self, device_id: str) -> int:
        """Get the count of unread notifications for a device."""
        data = await self._request(
            "GET",
            f"api/vulnerability/notification/unread/{device_id}",
        )
        if isinstance(data, dict):
            return int(data.get("count") or 0)
        return 0

    async def mark_all_read(
        self,
        device_id: str,
        alert_id: str | None = None,
    ) -> bool:
        """Mark all notifications as read for a device or alert."""
        path = (
            f"api/vulnerability/notification/markAsRead/{device_id}/{alert_id}"
            if alert_id
            else f"api/vulnerability/notification/markAsRead/{device_id}"
        )
        payload = {"deviceId": device_id}
        if alert_id:
            payload["alertId"] = alert_id

        await self._request("POST", path, json_data=payload)
        return True

    async def mark_read(self, notification_ids: list[str]) -> bool:
        """Mark specific notification IDs as read."""
        await self._request(
            "POST",
            "api/vulnerability/notification/markAsRead",
            json_data={"notificationIds": notification_ids},
        )
        return True

    async def delete_notification(self, notification_id: str) -> bool:
        """Delete a single notification by ID."""
        await self._request(
            "DELETE",
            f"api/vulnerability/notification/{notification_id}",
        )
        return True

    async def delete_all_notifications(
        self,
        device_id: str,
        alert_id: str | None = None,
    ) -> bool:
        """Delete all notifications for a device or specific alert."""
        path = (
            f"api/vulnerability/notification/all/{device_id}/{alert_id}"
            if alert_id
            else f"api/vulnerability/notification/all/{device_id}"
        )
        await self._request("DELETE", path)
        return True

    # -------------------------------------------------------------------------
    # News Feed
    # -------------------------------------------------------------------------

    async def get_news(
        self,
        page: int = 1,
        page_size: int = 10,
        category: str | None = None,
        tag: str | None = None,
    ) -> list[NewsArticle]:
        """Fetch vulnerability news articles."""
        params: dict[str, Any] = {
            "Page": page,
            "PageSize": page_size,
            "api-version": "2.0",
        }
        if category:
            params["category"] = category
        if tag:
            params["tags"] = tag

        data = await self._request("GET", "api/vulnerability/news", params=params)
        if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
            return [
                NewsArticle.from_dict(article)
                for article in data["data"]
                if isinstance(article, dict)
            ]
        return []

    async def get_news_details(self, news_id: str) -> NewsArticle:
        """Fetch detailed news article."""
        data = await self._request(
            "GET",
            f"api/vulnerability/news/{news_id}",
            params={"api-version": "2.0"},
        )
        if isinstance(data, dict):
            return NewsArticle.from_dict(data)
        raise CveInsightsNotFoundError(404, f"News article {news_id} not found")
