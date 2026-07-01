"""Shodan API integration for NullCloud.

Queries Shodan's host search API for IPs and hostnames related to a target
domain and feeds discovered assets back into NullCloud's origin detection
pipeline.

API documentation: https://developer.shodan.io/api
"""

import json
import ssl
import urllib.parse
import urllib.request
from typing import Optional

from .base import BaseRecon, ReconResult


SHODAN_API_URL = "https://api.shodan.io/shodan/host/search"
DEFAULT_SIZE = 100


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


def query_shodan(
    query: str,
    api_key: str,
    page: int = 1,
    timeout: int = 30,
) -> dict:
    """Execute a single Shodan search query."""
    params = {
        "key": api_key,
        "query": query,
        "page": page,
        "minify": "True",
    }
    url = f"{SHODAN_API_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "NullCloud/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=_context()) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def fetch_shodan(
    domain: str,
    api_key: str,
    max_pages: int = 10,
    timeout: int = 30,
) -> tuple[set, set, list]:
    """Fetch Shodan results for a domain.

    Queries multiple Shodan dorks and aggregates unique subdomains and IPs.
    Returns a tuple of ``(subdomains, ips, pairs)``.
    """
    subdomains = set()
    ips = set()
    pairs = []
    seen = set()

    queries = [
        f"hostname:{domain}",
        f"ssl.cert.subject.cn:{domain}",
    ]

    for query in queries:
        for page in range(1, max_pages + 1):
            try:
                data = query_shodan(query, api_key, page=page, timeout=timeout)
            except Exception as exc:
                raise RuntimeError(f"Shodan request failed: {exc}") from exc

            matches = data.get("matches", [])
            if not matches:
                break

            for match in matches:
                ip = match.get("ip_str", "").strip()
                if not ip or not _is_valid_ip(ip):
                    continue

                hostnames = match.get("hostnames", []) or []
                port = match.get("port", "")
                title = ""
                if match.get("http") and isinstance(match["http"], dict):
                    title = match["http"].get("title", "") or ""

                ips.add(ip)

                for host in hostnames:
                    host = host.strip().lower()
                    if not host:
                        continue
                    if host.endswith(f".{domain}") or host == domain:
                        subdomains.add(host)
                    key_pair = (host, ip)
                    if key_pair in seen:
                        continue
                    seen.add(key_pair)
                    pairs.append(
                        {
                            "subdomain": host,
                            "ip": ip,
                            "port": port,
                            "title": title,
                        }
                    )

                # Also add IP with the target domain as fallback subdomain
                fallback_key = (domain, ip)
                if fallback_key not in seen:
                    seen.add(fallback_key)
                    pairs.append(
                        {
                            "subdomain": domain,
                            "ip": ip,
                            "port": port,
                            "title": title,
                        }
                    )

            if len(matches) < DEFAULT_SIZE:
                break

    return subdomains, ips, pairs


class ShodanRecon(BaseRecon):
    """Passive recon adapter for Shodan results."""

    name = "shodan"
    needs_key = True

    def run(self, domain, network_map, config) -> ReconResult:
        result = ReconResult(self.name)
        api_key = config.get("keys", {}).get("shodan", {}).get("api_key")
        if not api_key:
            result.errors.append("Shodan API key missing")
            return result

        timeout = config.get("timeout", 30)
        max_pages = config.get("shodan_max_pages", 10)

        try:
            subdomains, ips, pairs = fetch_shodan(
                domain=domain,
                api_key=api_key,
                max_pages=max_pages,
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
