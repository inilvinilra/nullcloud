import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseRecon, ReconResult


def _context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def check_url(url, timeout=10):
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=timeout, context=_context())
        return {"url": url, "status": resp.status, "exists": True}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code, "exists": exc.code in (200, 403, 400)}
    except Exception as exc:
        return {"url": url, "status": 0, "exists": False, "error": str(exc)}


def generate_names(domain):
    base = domain.lower().strip()
    parts = base.split(".")
    short = parts[0] if parts else base
    names = {
        base,
        base.replace(".", "-"),
        short,
        f"{short}-prod",
        f"{short}-production",
        f"{short}-dev",
        f"{short}-staging",
        f"{short}-test",
        f"{short}-assets",
        f"{short}-files",
        f"{short}-data",
        f"{short}-backup",
        f"{short}-bak",
        f"{short}-public",
        f"{short}-private",
        f"{short}-media",
        f"{short}-uploads",
        f"{short}-static",
        f"{short}-content",
    }
    return names


def build_urls(domain):
    urls = []
    for name in generate_names(domain):
        urls.append(f"https://s3.amazonaws.com/{name}")
        urls.append(f"https://{name}.s3.amazonaws.com/")
        urls.append(f"https://storage.googleapis.com/{name}/")
        urls.append(f"https://{name}.blob.core.windows.net/")
    return urls


class CloudStorageRecon(BaseRecon):
    name = "cloudstorage"
    needs_key = False

    def run(self, domain, network_map, config):
        result = ReconResult(self.name)
        timeout = config.get("timeout", 10)
        threads = config.get("threads", 20)
        urls = build_urls(domain)
        found = []

        def worker(url):
            return check_url(url, timeout=timeout)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(worker, url): url for url in urls}
            for future in as_completed(futures):
                try:
                    info = future.result()
                except Exception:
                    continue
                if info.get("exists"):
                    found.append(info)
        result.data["found"] = sorted(found, key=lambda x: x["url"])
        result.data["checked"] = len(urls)
        return result
