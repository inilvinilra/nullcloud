"""Netlas API integration for NullCloud.

Queries Netlas for responses and domains related to a target domain and feeds
discovered assets back into NullCloud's origin detection pipeline.

API documentation: https://docs.netlas.io/
"""

import json
import ssl
import urllib.parse
import urllib.request
from typing import Optional

from .base import BaseRecon, ReconResult


NETLAS_API_URL = "https://app.netlas.io/api/responses"
DEFAULT_SIZE = 20


def _context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _is_valid_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False


def query_netlas(
    query: str,
    api_key: str,
    start: int = 0,
    timeout: int = 30,
) -> dict:
    """Execute a single Netlas responses search query."""
    params = {
        "q": query,
        "source_type": "include",
        "start": start,
        "fields": "ip,uri,domain,http.title",
    }
    url = f"{NETLAS_API_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NullCloud/1.0",
            "Accept": "application/json",
            "X-API-Key": api_key,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout, context=_context()) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def fetch_netlas(
    domain: str,
    api_key: str,
    max_results: int = 200,
    timeout: int = 30,
) -> tuple[set, set, list]:
    """Fetch Netlas results for a domain.

    Queries Netlas responses and aggregates unique subdomains and IPs. Returns a
    tuple of ``(subdomains, ips, pairs)``.
    """
    subdomains = set()
    ips = set()
    pairs = []
    seen = set()

    queries = [
        f"domain:*.{domain}",
        f"host:*.{domain} OR host:{domain}",
    ]

    for query in queries:
        start = 0
        while start < max_results:
            try:
                data = query_netlas(
                    query=query,
                    api_key=api_key,
                    start=start,
                    timeout=timeout,
                )
            except Exception as exc:
                raise RuntimeError(f"Netlas request failed: {exc}") from exc

            items = data.get("items", [])
            if not items:
                break

            for item in items:
                data_obj = item.get("data", {}) or {}
                ip = (data_obj.get("ip") or "").strip()
                if not ip or not _is_valid_ip(ip):
                    continue

                host = (data_obj.get("domain") or "").strip().lower()
                if not host:
                    uri = (data_obj.get("uri") or "").strip().lower()
                    if uri.startswith("http://"):
                        host = uri[7:].split("/")[0]
                    elif uri.startswith("https://"):
                        host = uri[8:].split("/")[0]

                title = ""
                http = data_obj.get("http", {}) or {}
                if isinstance(http, dict):
                    title = http.get("title", "") or ""

                ips.add(ip)

                if host and (host.endswith(f".{domain}") or host == domain):
                    subdomains.add(host)
                else:
                    host = domain

                key_pair = (host, ip)
                if key_pair in seen:
                    continue
                seen.add(key_pair)
                pairs.append(
                    {
                        "subdomain": host,
                        "ip": ip,
                        "port": "",
                        "title": title,
                    }
                )

            if len(items) < DEFAULT_SIZE:
                break
            start += len(items)

    return subdomains, ips, pairs


class NetlasRecon(BaseRecon):
    """Passive recon adapter for Netlas results."""

    name = "netlas"
    needs_key = True

    def run(self, domain, network_map, config) -> ReconResult:
        result = ReconResult(self.name)
        api_key = config.get("keys", {}).get("netlas", {}).get("api_key")
        if not api_key:
            result.errors.append("Netlas API key missing")
            return result

        timeout = config.get("timeout", 30)
        max_results = config.get("netlas_max_results", 200)

        try:
            subdomains, ips, pairs = fetch_netlas(
                domain=domain,
                api_key=api_key,
                max_results=max_results,
                timeout=timeout,
            )
        except Exception as exc:
            result.errors.append(str(exc))
            return result

        result.data["pairs"] = sorted(pairs, key=lambda x: (x["subdomain"], x["ip"]))
        result.data["subdomains"] = sorted(subdomains)
        result.data["ips"] = sorted(ips)
        result.data["checked"] = len(pairs)
        return result
