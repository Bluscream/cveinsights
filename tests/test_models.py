"""Unit tests for cveinsights data models."""

from __future__ import annotations

import ast
from pathlib import Path

from cveinsights.models import (
    AlertNotification,
    AlertRule,
    CveDetails,
    CveSearchResult,
    CveSummary,
    NewsArticle,
    ProductCompact,
    VendorModel,
)


def test_product_compact() -> None:
    """Test ProductCompact model serialization and deserialization."""
    prod = ProductCompact(vendor_name="Google", product_name="Chrome")
    payload = prod.to_dict()
    assert payload == {"vendorName": "Google", "productName": "Chrome"}

    parsed = ProductCompact.from_dict({"vendor": "Mozilla", "product": "Firefox"})
    assert parsed.vendor_name == "Mozilla"
    assert parsed.product_name == "Firefox"


def test_vendor_model() -> None:
    """Test VendorModel parsing."""
    data = {"name": "Microsoft", "products": ["Windows", "Office"]}
    vendor = VendorModel.from_dict(data)
    assert vendor.name == "Microsoft"
    assert vendor.products == ("Windows", "Office")


def test_cve_summary_and_scores() -> None:
    """Test CveSummary parsing and max_score logic."""
    data = {
        "cveId": "CVE-2026-99999",
        "description": "Test vulnerability",
        "dateUpdated": "2026-10-24T00:00:00Z",
        "datePublished": "2026-10-23T00:00:00Z",
        "baseScores": {"3.1": 7.5, "2.0": 5.0},
        "productsAffected": [
            {
                "vendor": "TestVendor",
                "product": "TestProd",
                "versionEndExcluding": "2.0.0",
            }
        ],
        "patchesCount": 2,
    }
    cve = CveSummary.from_dict(data)
    assert cve.cve_id == "CVE-2026-99999"
    assert cve.max_score == 7.5
    assert len(cve.products_affected) == 1
    assert cve.products_affected[0].vendor == "TestVendor"
    assert cve.products_affected[0].version_end_excluding == "2.0.0"
    assert cve.patches_count == 2


def test_cve_search_result() -> None:
    """Test CveSearchResult paginated model."""
    data = {
        "data": [
            {
                "cveId": "CVE-2026-0001",
                "description": "First CVE",
                "baseScores": {"3.1": 9.8},
            }
        ],
        "page": 1,
        "pageSize": 10,
        "totalResults": 42,
    }
    result = CveSearchResult.from_dict(data)
    assert result.page == 1
    assert result.total_results == 42
    assert len(result.data) == 1
    assert result.data[0].cve_id == "CVE-2026-0001"


def test_cve_details() -> None:
    """Test CveDetails parsing."""
    data = {
        "cveId": "CVE-2026-0002",
        "description": "Detail description",
        "source": "NVD",
        "vulnerabilityStatus": 1,
        "references": ["https://example.com/ref1"],
        "patches": [{"patchId": "KB12345"}],
        "news": [{"id": "news-1"}],
    }
    details = CveDetails.from_dict(data)
    assert details.cve_id == "CVE-2026-0002"
    assert details.references == ("https://example.com/ref1",)
    assert len(details.patches) == 1


def test_alert_rule_and_notification() -> None:
    """Test AlertRule payload roundtrip and AlertNotification parsing."""
    rule = AlertRule(
        alert_id="rule-123",
        device_id="dev-456",
        name="Critical Apps",
        vendors=("Google",),
        products=(ProductCompact("Google", "Chrome"),),
        min_base_score=8.0,
        max_base_score=10.0,
    )
    payload = rule.to_request_payload()
    assert payload["alertId"] == "rule-123"
    assert payload["minBaseScore"] == 8.0
    assert payload["products"] == [{"vendorName": "Google", "productName": "Chrome"}]

    notif_data = {
        "notificationId": "notif-789",
        "cveId": "CVE-2026-9999",
        "markedAsRead": False,
        "baseScore": 9.1,
        "alerts": [{"alertId": "rule-123", "name": "Critical Apps"}],
    }
    notif = AlertNotification.from_dict(notif_data)
    assert notif.notification_id == "notif-789"
    assert notif.cve_id == "CVE-2026-9999"
    assert notif.base_score == 9.1
    assert notif.alert_id == "rule-123"
    assert notif.alert_name == "Critical Apps"
    assert not notif.marked_as_read


def test_news_article() -> None:
    """Test NewsArticle parsing."""
    data = {
        "id": "article-1",
        "title": "Security Headline",
        "description": "<p>Content</p>",
        "views": 150,
        "datePublished": "2026-10-24T00:00:00Z",
    }
    art = NewsArticle.from_dict(data)
    assert art.id == "article-1"
    assert art.title == "Security Headline"
    assert art.views == 150


def test_size_limits() -> None:
    """Enforce size limits: max 1000 lines per file, max 200 lines per function."""
    repo_root = Path(__file__).resolve().parent.parent / "src"
    py_files = list(repo_root.rglob("*.py"))
    assert py_files, "No python source files found to check size limits"

    for file_path in py_files:
        lines = file_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) <= 1000, f"{file_path} exceeds 1000 lines limit ({len(lines)})"

        tree = ast.parse("\n".join(lines), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_len = (node.end_lineno or 0) - node.lineno + 1
                assert fn_len <= 200, (
                    f"Function {node.name} in {file_path}:{node.lineno} "
                    f"exceeds 200 lines limit ({fn_len})"
                )
