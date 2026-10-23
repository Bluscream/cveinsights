"""Command line interface for cveinsights."""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from .client import CveInsightsClient
from .const import SortType


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="cveinsights",
        description="CLI tool to query Patch My PC CVE Insights API",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Custom API key (defaults to standard client key)",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Custom base URL (defaults to production portal)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Search CVEs
    search_parser = subparsers.add_parser("search", help="Search CVE vulnerabilities")
    search_parser.add_argument("--vendor", "-v", help="Filter by vendor name")
    search_parser.add_argument("--product", "-p", help="Filter by product name")
    search_parser.add_argument("--keywords", "-k", help="Keyword search")
    search_parser.add_argument("--min-score", type=float, help="Minimum CVSS score")
    search_parser.add_argument("--max-score", type=float, help="Maximum CVSS score")
    search_parser.add_argument(
        "--sort",
        choices=["publish", "update", "score"],
        default="publish",
        help="Sort by field",
    )
    search_parser.add_argument("--limit", type=int, default=10, help="Results limit")
    search_parser.add_argument("--page", type=int, default=1, help="Page number")

    # Get single CVE
    cve_parser = subparsers.add_parser("cve", help="Get details for a specific CVE")
    cve_parser.add_argument("cve_id", help="CVE identifier (e.g. CVE-2026-113380)")

    # Vendors lookup
    subparsers.add_parser("vendors", help="List supported vendors and their product count")

    # News
    news_parser = subparsers.add_parser("news", help="Fetch recent vulnerability news")
    news_parser.add_argument("--limit", type=int, default=5, help="Number of news items")

    # Alerts
    alert_parser = subparsers.add_parser("alerts", help="Manage alert rules")
    alert_sub = alert_parser.add_subparsers(dest="alert_command", required=True)
    list_alerts = alert_sub.add_parser("list", help="List alert rules for a device")
    list_alerts.add_argument("--device-id", required=True, help="Device ID")

    return parser


async def _async_main(args: argparse.Namespace) -> int:
    """Async main handler."""
    kwargs: dict[str, Any] = {}
    if args.api_key:
        kwargs["api_key"] = args.api_key
    if args.base_url:
        kwargs["base_url"] = args.base_url

    async with CveInsightsClient(**kwargs) as client:
        if args.command == "search":
            sort_map = {
                "publish": SortType.PUBLISH_DATE,
                "update": SortType.UPDATE_DATE,
                "score": SortType.SCORE,
            }
            results = await client.search_cves(
                vendor=args.vendor,
                product=args.product,
                keywords=args.keywords,
                min_base_score=args.min_score,
                max_base_score=args.max_score,
                sort_by=sort_map[args.sort],
                page=args.page,
                page_size=args.limit,
            )
            print(f"Found {results.total_results} CVEs (showing {len(results.data)}):")
            for cve in results.data:
                score_str = f" [CVSS {cve.max_score}]" if cve.max_score is not None else ""
                print(f"• {cve.cve_id}{score_str}: {cve.description[:120]}...")
            return 0

        if args.command == "cve":
            details = await client.get_cve_details(args.cve_id)
            print(f"ID:          {details.cve_id}")
            print(f"Published:   {details.date_published}")
            print(f"Updated:     {details.date_updated}")
            print(f"Description: {details.description}\n")
            if details.references:
                print("References:")
                for ref in details.references:
                    print(f"  - {ref}")
            return 0

        if args.command == "vendors":
            vendors = await client.get_vendors()
            print(f"Total vendors: {len(vendors)}")
            for v in vendors[:20]:
                print(f"• {v.name} ({len(v.products)} products)")
            if len(vendors) > 20:
                print(f"... and {len(vendors) - 20} more.")
            return 0

        if args.command == "news":
            articles = await client.get_news(page=1, page_size=args.limit)
            print(f"Recent vulnerability news ({len(articles)}):")
            for a in articles:
                print(f"• [{a.date_published}] {a.title}")
            return 0

        if args.command == "alerts" and args.alert_command == "list":
            alerts = await client.get_alerts(args.device_id)
            print(f"Alerts for device {args.device_id} ({len(alerts)}):")
            for al in alerts:
                print(
                    f"• [{al.alert_id}] {al.name} (vendors={len(al.vendors)}, products={len(al.products)})"
                )
            return 0

    return 0


def main() -> None:
    """CLI entrypoint."""
    parser = _build_parser()
    args = parser.parse_args()
    code = asyncio.run(_async_main(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
