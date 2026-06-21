import ipaddress
import json
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseRecon, ReconResult
from . import fingerprint


def _context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def asn_for_ip(ip, timeout=10):
    try:
        url = f"https://stat.ripe.net/data/routing-status/data.json?resource={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=timeout, context=_context())
        data = json.loads(resp.read().decode("utf-8", "ignore"))
        origin = data.get("data", {}).get("last_seen", {}).get("origin")
        if origin:
            return origin
    except Exception:
        pass
    try:
        url = f"https://api.hackertarget.com/aslookup/?q={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=timeout, context=_context())
        text = resp.read().decode("utf-8", "ignore").strip()
        if text.startswith('"'):
            parts = text.split('","')
            if len(parts) >= 2:
                return parts[1].strip().strip('"')
    except Exception:
        pass
    return None


def prefixes_for_asn(asn, timeout=10):
    prefixes = []
    try:
        asn_number = asn.upper().replace("AS", "")
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_number}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=timeout, context=_context())
        data = json.loads(resp.read().decode("utf-8", "ignore"))
        for item in data.get("data", {}).get("prefixes", []):
            prefix = item.get("prefix")
            if not prefix:
                continue
            try:
                net = ipaddress.ip_network(prefix)
                if isinstance(net, ipaddress.IPv4Network):
                    prefixes.append(net)
            except Exception:
                pass
    except Exception:
        pass
    return prefixes


def is_provider_prefix(prefix, network_map):
    for net, _ in network_map:
        try:
            if prefix.subnet_of(net):
                return True
        except Exception:
            continue
    return False


def is_provider_ip(ip, network_map):
    try:
        addr = ipaddress.ip_address(ip)
        for net, _ in network_map:
            if addr in net:
                return True
    except Exception:
        pass
    return False


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_link_local)
    except Exception:
        return False


def ip_generator(prefixes, sample=False):
    for net in prefixes:
        hosts = list(net.hosts())
        if not hosts:
            continue
        if sample:
            yield str(hosts[len(hosts) // 2])
        else:
            for host in hosts:
                yield str(host)


def probe_ip(ip, host, timeout=5):
    try:
        resp = fingerprint.fetch(f"https://{ip}/", host=host, timeout=timeout)
        data = resp.read(8192)
        return {
            "ip": ip,
            "status": resp.status,
            "title": fingerprint.get_title(data),
            "body_hash": fingerprint.body_hash(data),
        }
    except Exception as exc:
        return {"ip": ip, "error": str(exc)}


class AsnSweepRecon(BaseRecon):
    name = "asnsweep"
    needs_key = False

    def run(self, domain, network_map, config):
        result = ReconResult(self.name)
        timeout = config.get("timeout", 10)
        active_timeout = config.get("active_timeout", 5)
        threads = config.get("threads", 20)
        sample = config.get("sample", False)
        max_ips = config.get("max_ips", 256)
        max_prefixes = config.get("max_prefixes", 50)
        seed_ips = config.get("seed_ips", [])
        reference = fingerprint.fetch_reference(domain, timeout=timeout)
        result.data["reference"] = reference
        valid_seeds = []
        for raw in seed_ips:
            if is_public_ip(raw) and not is_provider_ip(raw, network_map):
                valid_seeds.append(raw)
        valid_seeds = sorted(set(valid_seeds))[:10]
        asns = set()
        prefixes = []

        def asn_worker(ip):
            return asn_for_ip(ip, timeout=min(timeout, 8))

        if valid_seeds:
            with ThreadPoolExecutor(max_workers=min(len(valid_seeds), 10)) as executor:
                futures = {executor.submit(asn_worker, ip): ip for ip in valid_seeds}
                for future in as_completed(futures):
                    asn = future.result()
                    if asn and asn.lower() != "none":
                        asns.add(asn)

        def prefix_worker(asn):
            return prefixes_for_asn(asn, timeout=min(timeout, 15))

        if asns:
            with ThreadPoolExecutor(max_workers=min(len(asns), 5)) as executor:
                futures = {executor.submit(prefix_worker, asn): asn for asn in asns}
                for future in as_completed(futures):
                    for prefix in future.result():
                        if not is_provider_prefix(prefix, network_map):
                            prefixes.append(prefix)
        prefixes = sorted(set(prefixes), key=lambda n: (n.prefixlen, str(n)), reverse=True)[:max_prefixes]
        result.data["asns"] = sorted(asns)
        result.data["prefixes"] = [str(p) for p in prefixes]
        candidates = []
        if not prefixes:
            result.data["candidates"] = candidates
            return result
        ips = list(ip_generator(prefixes, sample=sample))[:max_ips]

        def worker(ip):
            return probe_ip(ip, domain, timeout=active_timeout)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(worker, ip): ip for ip in ips}
            for future in as_completed(futures):
                try:
                    info = future.result()
                except Exception:
                    continue
                if "error" in info:
                    continue
                score, reasons = fingerprint.compare(info, reference)
                if score > 0 and reasons:
                    info["confidence"] = round(score, 2)
                    info["match_reasons"] = reasons
                    candidates.append(info)
        result.data["candidates"] = sorted(candidates, key=lambda x: x.get("confidence", 0), reverse=True)
        return result
