"""Data models for CVE Insights."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ProductCompact:
    """Compact vendor-product pair."""

    vendor_name: str
    product_name: str

    def to_dict(self) -> dict[str, str]:
        """Serialize for API payload."""
        return {
            "vendorName": self.vendor_name,
            "productName": self.product_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProductCompact:
        """Parse from API response."""
        return cls(
            vendor_name=str(data.get("vendorName") or data.get("vendor") or ""),
            product_name=str(data.get("productName") or data.get("product") or ""),
        )


@dataclass(frozen=True, slots=True)
class VendorModel:
    """Vendor and their catalog of known products."""

    name: str
    products: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VendorModel:
        """Parse from API response."""
        prods = tuple(str(p) for p in data.get("products", []))
        return cls(name=str(data.get("name", "")), products=prods)


@dataclass(frozen=True, slots=True)
class AffectedProduct:
    """Product affected by a CVE."""

    vendor: str
    product: str
    version: str | None = None
    cpe_name: str | None = None
    version_end_excluding: str | None = None
    version_end_including: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AffectedProduct:
        """Parse from API response."""
        return cls(
            vendor=str(data.get("vendor", "")),
            product=str(data.get("product", "")),
            version=data.get("version"),
            cpe_name=data.get("cpeName"),
            version_end_excluding=data.get("versionEndExcluding"),
            version_end_including=data.get("versionEndIncluding"),
        )


@dataclass(frozen=True, slots=True)
class CveSummary:
    """Summary of a CVE item returned from searches or notifications."""

    cve_id: str
    description: str
    date_updated: str | None = None
    date_published: str | None = None
    base_scores: dict[str, float] = field(default_factory=dict)
    products_affected: tuple[AffectedProduct, ...] = field(default_factory=tuple)
    patches_count: int = 0

    @property
    def max_score(self) -> float | None:
        """Return the highest CVSS score available."""
        if not self.base_scores:
            return None
        return max(self.base_scores.values())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CveSummary:
        """Parse from API response."""
        scores_raw = data.get("baseScores") or {}
        scores: dict[str, float] = {}
        if isinstance(scores_raw, dict):
            for k, v in scores_raw.items():
                try:
                    scores[str(k)] = float(v)
                except (ValueError, TypeError):
                    continue

        prods_raw = data.get("productsAffected") or []
        prods = tuple(AffectedProduct.from_dict(p) for p in prods_raw if isinstance(p, dict))

        return cls(
            cve_id=str(data.get("cveId", "")),
            description=str(data.get("description", "")),
            date_updated=data.get("dateUpdated"),
            date_published=data.get("datePublished"),
            base_scores=scores,
            products_affected=prods,
            patches_count=int(data.get("patchesCount") or 0),
        )


@dataclass(frozen=True, slots=True)
class CveDetails:
    """Full detail view of a single CVE."""

    cve_id: str
    description: str
    date_updated: str | None = None
    date_published: str | None = None
    source: str | None = None
    vulnerability_status: int = 0
    references: tuple[str, ...] = field(default_factory=tuple)
    patches: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    news: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CveDetails:
        """Parse from API response."""
        refs = tuple(str(r) for r in data.get("references", []))
        patches = tuple(p for p in data.get("patches", []) if isinstance(p, dict))
        news = tuple(n for n in data.get("news", []) if isinstance(n, dict))

        return cls(
            cve_id=str(data.get("cveId", "")),
            description=str(data.get("description", "")),
            date_updated=data.get("dateUpdated"),
            date_published=data.get("datePublished"),
            source=data.get("source"),
            vulnerability_status=int(data.get("vulnerabilityStatus") or 0),
            references=refs,
            patches=patches,
            news=news,
        )


@dataclass(frozen=True, slots=True)
class CveSearchResult:
    """Paginated CVE search results."""

    data: tuple[CveSummary, ...]
    page: int
    page_size: int
    total_results: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CveSearchResult:
        """Parse from API response."""
        items = tuple(
            CveSummary.from_dict(item) for item in data.get("data", []) if isinstance(item, dict)
        )
        return cls(
            data=items,
            page=int(data.get("page") or 1),
            page_size=int(data.get("pageSize") or 10),
            total_results=int(data.get("totalResults") or len(items)),
        )


@dataclass(frozen=True, slots=True)
class AlertRule:
    """Alert monitoring rule for a device."""

    alert_id: str
    device_id: str
    name: str
    vendors: tuple[str, ...] = field(default_factory=tuple)
    products: tuple[ProductCompact, ...] = field(default_factory=tuple)
    min_base_score: float = 0.0
    max_base_score: float = 10.0
    date_created: str | None = None
    date_updated: str | None = None
    notifications_count: int = 0
    new_notifications_count: int = 0

    def to_request_payload(self) -> dict[str, Any]:
        """Format as JSON request payload for API."""
        return {
            "alertId": self.alert_id,
            "deviceId": self.device_id,
            "name": self.name,
            "vendors": list(self.vendors),
            "products": [p.to_dict() for p in self.products],
            "minBaseScore": self.min_base_score,
            "maxBaseScore": self.max_base_score,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlertRule:
        """Parse from API response."""
        vendors = tuple(str(v) for v in data.get("vendors", []))
        products = tuple(
            ProductCompact.from_dict(p) for p in data.get("products", []) if isinstance(p, dict)
        )
        return cls(
            alert_id=str(data.get("alertId", "")),
            device_id=str(data.get("deviceId", "")),
            name=str(data.get("name", "")),
            vendors=vendors,
            products=products,
            min_base_score=float(data.get("minBaseScore") or 0.0),
            max_base_score=float(data.get("maxBaseScore") or 10.0),
            date_created=data.get("dateCreated"),
            date_updated=data.get("dateUpdated"),
            notifications_count=int(data.get("notificationsCount") or 0),
            new_notifications_count=int(data.get("newNotificationsCount") or 0),
        )


@dataclass(frozen=True, slots=True)
class AlertNotification:
    """Notification triggered by an alert rule."""

    notification_id: str
    cve_id: str
    marked_as_read: bool = False
    base_score: float | None = None
    metric_version: str | None = None
    alert_id: str | None = None
    alert_name: str | None = None
    date_created: str | None = None
    date_updated: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlertNotification:
        """Parse from API response."""
        alerts = data.get("alerts") or []
        alert_id: str | None = None
        alert_name: str | None = None
        if alerts and isinstance(alerts, list) and isinstance(alerts[0], dict):
            alert_id = alerts[0].get("alertId")
            alert_name = alerts[0].get("name")

        base_score_val = data.get("baseScore")
        base_score = float(base_score_val) if base_score_val is not None else None

        return cls(
            notification_id=str(data.get("notificationId", "")),
            cve_id=str(data.get("cveId", "")),
            marked_as_read=bool(data.get("markedAsRead", False)),
            base_score=base_score,
            metric_version=data.get("metricVersion"),
            alert_id=alert_id,
            alert_name=alert_name,
            date_created=data.get("dateCreated"),
            date_updated=data.get("dateUpdated"),
        )


@dataclass(frozen=True, slots=True)
class NewsArticle:
    """Vulnerability news article."""

    id: str
    title: str
    description: str
    views: int = 0
    date_published: str | None = None
    date_updated: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NewsArticle:
        """Parse from API response."""
        return cls(
            id=str(data.get("id", "")),
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            views=int(data.get("views") or 0),
            date_published=data.get("datePublished"),
            date_updated=data.get("dateUpdated"),
        )
