"""FOFA API integration for NullCloud.

FOFA (https://fofa.info) is a cyberspace search engine. This module queries
FOFA's API v1 for hosts and IPs related to a target domain and feeds the
discovered subdomains / origin candidates back into NullCloud's origin
detection pipeline.

API documentation: https://en.fofa.info/api
"""

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from .base import BaseRecon, ReconResult


FOFA_API_URL = "https://fofa.info/api/v1/search/all"
DEFAULT_FIELDS = "host,ip,port,title,domain"
DEFAULT_SIZE = 100
MAX_SIZE_PER_QUERY = 10000


def _context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _encode_query(query: str) -> str:
    return base64.b64encode(query.encode("utf-8")).decode("utf-8")


def _is_valid_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False


def query_fofa(
    query: str,
    email: str,
    key: str,
    page: int = 1,
    size: int = DEFAULT_SIZE,
    fields: str = DEFAULT_FIELDS,
    timeout: int = 30,
) -> dict:
    """Execute a single FOFA API v1 search query.

    Args:
        query: Raw FOFA query string, e.g. 'domain="example.com"'.
        email: FOFA account email.
        key: FOFA API key.
        page: Result page number (1-based).
        size: Results per page (max 10,000).
        fields: Comma-separated FOFA fields to return.
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON response as a dictionary.

    Raises:
        urllib.error.HTTPError on non-2xx responses.
        ValueError when FOFA returns an API-level error.
    """
    size = max(1, min(size, MAX_SIZE_PER_QUERY))
    params = {
        "qbase64": _encode_query(query),
        "email": email,
        "key": key,
        "page": page,
        "size": size,
        "fields": fields,
    }
    url = f"{FOFA_API_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "NullCloud/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=_context()) as resp:
        data = json.loads(resp.read().decode("utf-8", "ignore"))
    if data.get("error"):
        raise ValueError(f"FOFA API error: {data.get('error')}")
    return data


def fetch_fofa(
    domain: str,
    email: str,
    key: str,
    max_size: int = 1000,
    timeout: int = 30,
    fields: str = DEFAULT_FIELDS,
) -> tuple[set, set, list]:
    """Fetch FOFA results for a domain.

    Queries both ``domain="<domain>"`` and ``host="<domain>"`` and aggregates
    unique subdomains and IPs. Returns a tuple of ``(subdomains, ips, pairs)``.

    Args:
        domain: Target domain.
        email: FOFA account email.
        key: FOFA API key.
        max_size: Maximum total results to retrieve per query.
        timeout: Request timeout in seconds.
        fields: Comma-separated FOFA fields to return.

    Returns:
        Tuple ``(subdomains, ips, pairs)`` where ``pairs`` is a list of
        dictionaries with keys ``subdomain``, ``ip``, ``port`` and ``title``.
    """
    subdomains = set()
    ips = set()
    pairs = []
    seen = set()

    field_list = [f.strip() for f in fields.split(",")]
    try:
        host_idx = field_list.index("host")
    except ValueError:
        host_idx = 0
    try:
        ip_idx = field_list.index("ip")
    except ValueError:
        ip_idx = 1
    try:
        port_idx = field_list.index("port")
    except ValueError:
        port_idx = 2
    try:
        title_idx = field_list.index("title")
    except ValueError:
        title_idx = 3

    queries = [f'domain="{domain}"', f'host="{domain}"']
    page_size = min(max_size, MAX_SIZE_PER_QUERY)

    for query in queries:
        remaining = max_size
        page = 1
        while remaining > 0:
            current_size = min(page_size, remaining)
            try:
                data = query_fofa(
                    query=query,
                    email=email,
                    key=key,
                    page=page,
                    size=current_size,
                    fields=fields,
                    timeout=timeout,
                )
            except urllib.error.HTTPError as exc:
                raise RuntimeError(f"FOFA HTTP error {exc.code}: {exc.reason}") from exc
            except Exception as exc:
                raise RuntimeError(f"FOFA request failed: {exc}") from exc

            results = data.get("results", [])
            if not results:
                break

            for row in results:
                if not isinstance(row, (list, tuple)) or len(row) < 2:
                    continue
                host = row[host_idx] if host_idx < len(row) else ""
                ip = row[ip_idx] if ip_idx < len(row) else ""
                port = row[port_idx] if port_idx < len(row) else ""
                title = row[title_idx] if title_idx < len(row) else ""

                if not host or not ip:
                    continue

                key_pair = (host.lower(), ip)
                if key_pair in seen:
                    continue
                seen.add(key_pair)

                if host.endswith(f".{domain}") or host == domain:
                    subdomains.add(host.lower())
                ips.add(ip)
                pairs.append(
                    {
                        "subdomain": host.lower(),
                        "ip": ip,
                        "port": port,
                        "title": title,
                    }
                )

            if len(results) < current_size:
                break

            remaining -= len(results)
            page += 1

    return subdomains, ips, pairs


class FofaRecon(BaseRecon):
    """Active recon adapter for FOFA results.

    This module is primarily used from ``find_origins()`` as a passive source.
    It can also be invoked as an active recon module when ``--origin-module
    fofa`` is supplied and a FOFA key is configured.
    """

    name = "fofa"
    needs_key = True

    def run(self, domain, network_map, config) -> ReconResult:
        result = ReconResult(self.name)
        keys = config.get("keys", {}).get("fofa", {})
        email = keys.get("email")
        key = keys.get("key")
        if not email or not key:
            result.errors.append("FOFA credentials missing (email + key)")
            return result

        timeout = config.get("timeout", 30)
        max_size = config.get("fofa_max_size", 1000)
        fields = config.get("fofa_fields", DEFAULT_FIELDS)

        try:
            subdomains, ips, pairs = fetch_fofa(
                domain=domain,
                email=email,
                key=key,
                max_size=max_size,
                timeout=timeout,
                fields=fields,
            )
        except Exception as exc:
            result.errors.append(str(exc))
            return result

        result.data["pairs"] = sorted(pairs, key=lambda x: (x["subdomain"], x["ip"]))
        result.data["subdomains"] = sorted(subdomains)
        result.data["ips"] = sorted(ips)
        result.data["checked"] = len(pairs)
        return result
