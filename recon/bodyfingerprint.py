import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseRecon, ReconResult
from . import fingerprint


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


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_link_local)
    except Exception:
        return False


class BodyFingerprintRecon(BaseRecon):
    name = "bodyfingerprint"
    needs_key = False

    def run(self, domain, network_map, config):
        result = ReconResult(self.name)
        timeout = config.get("timeout", 10)
        active_timeout = config.get("active_timeout", 5)
        threads = config.get("threads", 20)
        seed_ips = config.get("seed_ips", [])
        reference = fingerprint.fetch_reference(domain, timeout=timeout)
        result.data["reference"] = reference
        candidates = []
        valid_ips = [ip for ip in seed_ips if is_public_ip(ip)]
        if not valid_ips:
            result.data["candidates"] = candidates
            return result

        def worker(ip):
            return probe_ip(ip, domain, timeout=active_timeout)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(worker, ip): ip for ip in valid_ips}
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
