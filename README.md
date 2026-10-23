# cveinsights

Async Python library and CLI client for the **Patch My PC CVE Insights** API (`https://us.portal.patchmypc.com`), reverse-engineered from the Android application (`com.patchmypc.cveinsights`).

## Features

- **Asynchronous**: Built on `aiohttp` with connection pooling and async context manager support.
- **Strict Typing**: Fully typed with Python 3.11+ type annotations (`mypy --strict` clean).
- **Vulnerability Search**: Query CVEs by vendor, product, keywords, date ranges, and CVSS scores.
- **Alert Rules**: Create, list, and delete custom CVE alert rules for devices.
- **Notifications**: Check unread notifications, mark read, and manage alert event feeds.
- **Catalogs & News**: Fetch supported vendor/product listings and cybersecurity news.
- **Home Assistant Ready**: Designed to seamlessly accept Home Assistant's `aiohttp.ClientSession`.

## Installation

```bash
pip install .
```

## Quick Start

```python
import asyncio
from cveinsights import CveInsightsClient


async def main():
    async with CveInsightsClient() as client:
        # Search recent CVEs for a product
        result = await client.search_cves(vendor="Google", product="Chrome", page_size=5)
        for cve in result.data:
            print(f"{cve.cve_id} (CVSS: {cve.max_score}): {cve.description[:80]}...")

        # Get details for a specific CVE
        details = await client.get_cve_details("CVE-2026-113380")
        print(f"Published: {details.date_published}")


asyncio.run(main())
```

## CLI Usage

```bash
# Search CVEs
cveinsights search --vendor Signal --limit 5

# Inspect specific CVE
cveinsights cve CVE-2026-113380

# List news
cveinsights news --limit 3

# Browse vendors
cveinsights vendors
```
