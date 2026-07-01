"""Criminal IP API integration for NullCloud.

Queries Criminal IP domain reports for subdomains and IPs related to a target
domain and feeds discovered assets back into NullCloud's origin detection
pipeline.

API documentation: https://www.criminalip.io/
"""

import json
import ssl
import urllib.parse
import urllib.request
from typing import Optional

from .base import BaseRecon, ReconResult


CRIMINALIP_API_URL = "https://api.criminalip.io/v1/domain/reports"
DEFAULT_OFFSET = 0
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


def query_criminalip(
    domain: str,
    api_key: str,
    offset: int = DEFAULT_OFFSET,
    timeout: int = 30,
) -> dict:
    """Execute a Criminal IP domain reports query."""
    params = {
        "query": domain,
        "offset": offset,
    }
    url = f"{CRIMINALIP_API_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NullCloud/1.0",
            "Accept": "application/json",
            "x-api-key": api_key,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout, context=_context()) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def _extract_ip(value) -> Optional[str]:
    if not value:
        return None
    if isinstance(value, dict):
        for key in ("ip_address", "ip", "addr", "address"):
            candidate = value.get(key)
            if candidate and _is_valid_ip(candidate):
                return candidate
    if isinstance(value, str) and _is_valid_ip(value):
        return value
    return None


def _walk_data(obj, domain: str, found: list):
    """Recursively walk response data looking for domain/IP pairs."""
    if isinstance(obj, dict):
        ip = _extract_ip(obj)
        subdomain = ""
        for key in ("domain", "subdomain", "hostname", "host_name", "name"):
            val = obj.get(key)
            if isinstance(val, str):
                val = val.strip().lower()
                if val and (val.endswith(f".{domain}") or val == domain):
                    subdomain = val
                    break
        if ip and subdomain:
            found.append((subdomain, ip))
        elif ip:
            found.append((domain, ip))
        for value in obj.values():
            _walk_data(value, domain, found)
    elif isinstance(obj, list):
        for item in obj:
            _walk_data(item, domain, found)


def fetch_criminalip(
    domain: str,
    api_key: str,
    max_offsets: int = 10,
    timeout: int = 30,
) -> tuple[set, set, list]:
    """Fetch Criminal IP results for a domain.

    Queries domain reports and aggregates unique subdomains and IPs. Returns a
    tuple of ``(subdomains, ips, pairs)``.
    """
    subdomains = set()
    ips = set()
    pairs = []
    seen = set()

    offset = DEFAULT_OFFSET
    for _ in range(max_offsets):
        try:
            data = query_criminalip(
                domain=domain,
                api_key=api_key,
                offset=offset,
                timeout=timeout,
            )
        except Exception as exc:
            raise RuntimeError(f"Criminal IP request failed: {exc}") from exc

        found = []
        _walk_data(data, domain, found)
        if not found:
            break

        for subdomain, ip in found:
            if subdomain.endswith(f".{domain}") or subdomain == domain:
                subdomains.add(subdomain)
            ips.add(ip)
            key_pair = (subdomain, ip)
            if key_pair in seen:
                continue
            seen.add(key_pair)
            pairs.append(
                {
                    "subdomain": subdomain,
                    "ip": ip,
                    "port": "",
                    "title": "",
                }
            )

        if len(found) < DEFAULT_SIZE:
            break
        offset += DEFAULT_SIZE

    return subdomains, ips, pairs


class CriminalIpRecon(BaseRecon):
    """Passive recon adapter for Criminal IP results."""

    name = "criminalip"
    needs_key = True

    def run(self, domain, network_map, config) -> ReconResult:
        result = ReconResult(self.name)
        api_key = config.get("keys", {}).get("criminalip", {}).get("api_key")
        if not api_key:
            result.errors.append("Criminal IP API key missing")
            return result

        timeout = config.get("timeout", 30)
        max_offsets = config.get("criminalip_max_offsets", 10)

        try:
            subdomains, ips, pairs = fetch_criminalip(
                domain=domain,
                api_key=api_key,
                max_offsets=max_offsets,
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
