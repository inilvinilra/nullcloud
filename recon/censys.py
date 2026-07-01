"""Censys API v2 integration for NullCloud.

Queries Censys Search v2 for hosts presenting certificates or services related
to a target domain and feeds discovered assets back into NullCloud's origin
detection pipeline.

API documentation: https://docs.censys.com/docs/ls-api
"""

import base64
import json
import ssl
import urllib.parse
import urllib.request
from typing import Optional

from .base import BaseRecon, ReconResult


CENSYS_API_URL = "https://search.censys.io/api/v2/hosts/search"
DEFAULT_PER_PAGE = 100


def _context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _basic_auth(api_id: str, api_secret: str) -> str:
    creds = f"{api_id}:{api_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(creds).decode("utf-8")


def _is_valid_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False


def query_censys(
    query: str,
    api_id: str,
    api_secret: str,
    cursor: Optional[str] = None,
    per_page: int = DEFAULT_PER_PAGE,
    timeout: int = 30,
) -> dict:
    """Execute a single Censys v2 search query."""
    params = {
        "q": query,
        "per_page": per_page,
    }
    if cursor:
        params["cursor"] = cursor
    url = f"{CENSYS_API_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NullCloud/1.0",
            "Accept": "application/json",
            "Authorization": _basic_auth(api_id, api_secret),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout, context=_context()) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def _extract_names(host: dict, domain: str) -> set:
    names = set()
    for service in host.get("services", []) or []:
        tls = service.get("tls", {}) or {}
        certs = tls.get("certificates", {}) or {}
        leaf = certs.get("leaf_data", {}) or {}
        subject = leaf.get("subject", {}) or {}
        for name in subject.get("names", []) or []:
            name = name.strip().lower()
            if name and (name.endswith(f".{domain}") or name == domain):
                names.add(name)
        for name in leaf.get("names", []) or []:
            name = name.strip().lower()
            if name and (name.endswith(f".{domain}") or name == domain):
                names.add(name)
    return names


def fetch_censys(
    domain: str,
    api_id: str,
    api_secret: str,
    max_pages: int = 10,
    timeout: int = 30,
) -> tuple[set, set, list]:
    """Fetch Censys results for a domain.

    Queries multiple Censys search queries and aggregates unique subdomains and
    IPs. Returns a tuple of ``(subdomains, ips, pairs)``.
    """
    subdomains = set()
    ips = set()
    pairs = []
    seen = set()

    queries = [
        f"services.tls.certificates.leaf_data.subject.common_name: {domain}",
        f"services.tls.certificates.leaf_data.names: {domain}",
    ]

    for query in queries:
        cursor = None
        for _ in range(max_pages):
            try:
                data = query_censys(
                    query=query,
                    api_id=api_id,
                    api_secret=api_secret,
                    cursor=cursor,
                    timeout=timeout,
                )
            except Exception as exc:
                raise RuntimeError(f"Censys request failed: {exc}") from exc

            result = data.get("result", {}) or {}
            hits = result.get("hits", [])
            if not hits:
                break

            for host in hits:
                ip = host.get("ip", "").strip()
                if not ip or not _is_valid_ip(ip):
                    continue

                ips.add(ip)
                host_names = _extract_names(host, domain)
                subdomains.update(host_names)

                names = host_names or {domain}
                for name in names:
                    key_pair = (name, ip)
                    if key_pair in seen:
                        continue
                    seen.add(key_pair)
                    pairs.append(
                        {
                            "subdomain": name,
                            "ip": ip,
                            "port": "",
                            "title": "",
                        }
                    )

            cursor = result.get("links", {}).get("next")
            if not cursor:
                break

    return subdomains, ips, pairs


class CensysRecon(BaseRecon):
    """Passive recon adapter for Censys results."""

    name = "censys"
    needs_key = True

    def run(self, domain, network_map, config) -> ReconResult:
        result = ReconResult(self.name)
        keys = config.get("keys", {}).get("censys", {})
        api_id = keys.get("api_id")
        api_secret = keys.get("api_secret")
        if not api_id or not api_secret:
            result.errors.append("Censys API credentials missing (api_id + api_secret)")
            return result

        timeout = config.get("timeout", 30)
        max_pages = config.get("censys_max_pages", 10)

        try:
            subdomains, ips, pairs = fetch_censys(
                domain=domain,
                api_id=api_id,
                api_secret=api_secret,
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
