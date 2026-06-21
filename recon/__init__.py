from .base import BaseRecon, ReconResult
from .asnsweep import AsnSweepRecon
from .cloudstorage import CloudStorageRecon
from .bodyfingerprint import BodyFingerprintRecon

__all__ = [
    "BaseRecon",
    "ReconResult",
    "AsnSweepRecon",
    "CloudStorageRecon",
    "BodyFingerprintRecon",
    "run_modules",
]

REGISTRY = {
    "asn": AsnSweepRecon,
    "cloud": CloudStorageRecon,
    "body": BodyFingerprintRecon,
}


def run_modules(names, domain, network_map, config):
    results = {}
    for name in names:
        cls = REGISTRY.get(name)
        if not cls:
            continue
        instance = cls()
        if instance.needs_key and not config.get("keys", {}).get(name):
            continue
        try:
            results[instance.name] = instance.run(domain, network_map, config).data
        except Exception as exc:
            results[instance.name] = {"error": str(exc)}
    return results
