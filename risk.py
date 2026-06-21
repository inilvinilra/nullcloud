import ipaddress


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_LABELS = ["info", "low", "medium", "high", "critical"]


def _is_private(ip):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except Exception:
        return False


def _extract_ip_from_value(value):
    if not value:
        return None
    value = str(value)
    for token in value.replace(",", " ").replace(";", " ").split():
        try:
            ipaddress.ip_address(token)
            return token
        except Exception:
            continue
    return None


def active_confidence_map(origins):
    return _active_confidence_map(origins)


def _active_confidence_map(origins):
    mapping = {}
    for key in ("asnsweep", "bodyfingerprint"):
        data = origins.get(key, {})
        for cand in data.get("candidates", []):
            ip = cand.get("ip")
            conf = cand.get("confidence", 0)
            if ip:
                mapping[ip] = max(mapping.get(ip, 0), conf)
    return mapping


def severity_from_score(score):
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


def score_origin_candidate(entry, active_conf=None):
    active_conf = active_conf or {}
    ip = entry.get("ip", "")
    source = entry.get("source", "")
    confidence = active_conf.get(ip, 0)

    if _is_private(ip):
        return 95, "critical", ["private_ip"]

    if confidence >= 0.7:
        return 80, "high", ["active_fingerprint_match"]

    if source in ("dns", "external"):
        return 80, "high", ["direct_dns_resolution"]

    if source in ("mx", "txt"):
        return 55, "medium", [source]

    if source == "external_db":
        return 55, "medium", ["external_database"]

    if isinstance(source, str) and source.startswith("header:"):
        return 55, "medium", ["http_header_leak"]

    return 30, "low", ["origin_candidate"]


def score_cloudstorage(entry):
    status = entry.get("status")
    if status in (200, 403, 401):
        return 70, "high", ["publicly_responsive_bucket"]
    if status is not None:
        return 20, "low", ["bucket_probe_response"]
    return 0, "info", ["not_tested"]


def score_header_leak(leak):
    header = (leak.get("header") or "").lower()
    raw = leak.get("raw") or ""
    leaked_ip = _extract_ip_from_value(raw)

    if leaked_ip and _is_private(leaked_ip):
        return 95, "critical", ["private_ip_in_header"]

    if header in ("x-forwarded-for", "x-real-ip", "x-original-url", "x-envoy-external-address", "cf-connecting-ip"):
        return 70, "high", ["sensitive_forwarding_header"]

    if header in ("via", "x-served-by", "x-cache"):
        return 40, "medium", ["infrastructure_header_leak"]

    return 20, "low", ["header_leak"]


def score_real_subdomain(item):
    ips = item.get("ips", [])
    if any(_is_private(ip) for ip in ips):
        return 95, "critical", ["private_ip_resolution"]
    return 75, "high", ["real_ip_resolution"]


def score_active_candidate(candidate):
    confidence = candidate.get("confidence", 0)
    if confidence >= 0.9:
        return 95, "critical", ["very_high_confidence_active_match"]
    if confidence >= 0.7:
        return 80, "high", ["high_confidence_active_match"]
    if confidence >= 0.4:
        return 55, "medium", ["medium_confidence_active_match"]
    return 30, "low", ["low_confidence_active_match"]


def _overall_rating(counts):
    for sev in SEVERITY_LABELS[::-1]:
        if counts.get(sev, 0) > 0:
            return sev
    return "info"


def summarize(results, origins):
    active_conf = _active_confidence_map(origins)
    risks = []
    counts = {sev: 0 for sev in SEVERITY_LABELS}

    for entry in origins.get("origin_ips", []):
        score, severity, reasons = score_origin_candidate(entry, active_conf)
        risks.append({
            "type": "origin_candidate",
            "subdomain": entry.get("subdomain", ""),
            "target": entry.get("ip", ""),
            "score": score,
            "severity": severity,
            "reasons": reasons,
        })
        counts[severity] = counts.get(severity, 0) + 1

    for leak in origins.get("header_leaks", []):
        score, severity, reasons = score_header_leak(leak)
        risks.append({
            "type": "header_leak",
            "subdomain": "",
            "target": f"{leak.get('header', '')}: {leak.get('raw', '')}",
            "score": score,
            "severity": severity,
            "reasons": reasons,
        })
        counts[severity] = counts.get(severity, 0) + 1

    cloud = origins.get("cloudstorage", {})
    for entry in cloud.get("found", []):
        score, severity, reasons = score_cloudstorage(entry)
        risks.append({
            "type": "cloudstorage",
            "subdomain": "",
            "target": entry.get("url", ""),
            "score": score,
            "severity": severity,
            "reasons": reasons,
        })
        counts[severity] = counts.get(severity, 0) + 1

    risks.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 0), x["score"]), reverse=True)

    return {
        "risks": risks,
        "counts": counts,
        "top_risks": risks[:10],
        "overall": _overall_rating(counts),
    }
