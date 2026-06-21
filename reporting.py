import html
import risk


def _group_by_provider(protected_results):
    grouped = {}
    for item in protected_results:
        for entry in item.get("protected", []):
            grouped.setdefault(entry["service"], []).append(
                (item["subdomain"], entry["ip"])
            )
    return grouped


def _count_provider_ips(results):
    counts = {}
    for item in results:
        for entry in item.get("protected", []):
            counts[entry["service"]] = counts.get(entry["service"], 0) + 1
    return counts


def _active_conf(origins):
    return risk.active_confidence_map(origins)


def _severity_origin(entry, active_conf):
    _, severity, _ = risk.score_origin_candidate(entry, active_conf)
    return severity


def _severity_cloud(entry):
    _, severity, _ = risk.score_cloudstorage(entry)
    return severity


def _severity_header(leak):
    _, severity, _ = risk.score_header_leak(leak)
    return severity


def _severity_real(item):
    _, severity, _ = risk.score_real_subdomain(item)
    return severity


def _risk_summary_lines(summary):
    lines = []
    lines.append("## Risk Summary")
    lines.append("")
    lines.append(f"Overall risk: {summary['overall'].upper()}")
    lines.append("")
    counts = summary["counts"]
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in risk.SEVERITY_LABELS[::-1]:
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines.append("")
    lines.append("### Top Risks")
    lines.append("")
    lines.append("| Target | Severity | Reasons |")
    lines.append("|--------|----------|---------|")
    for r in summary["top_risks"]:
        target = r["target"] or r["subdomain"]
        reasons = ", ".join(r["reasons"])
        lines.append(f"| {target} | {r['severity']} | {reasons} |")
    lines.append("")
    return lines


def _generate_txt(results, origins):
    summary = risk.summarize(results, origins)
    active_conf = _active_conf(origins)
    lines = []
    lines.append("=" * 80)
    lines.append("NullCloud Scan Report")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Target: {origins.get('domain', 'unknown')}")
    lines.append(f"Total subdomains checked: {len(results)}")
    protected = [r for r in results if r.get("protected")]
    real = [r for r in results if r.get("ips")]
    lines.append(f"Protected subdomains: {len(protected)}")
    lines.append(f"Real IP subdomains: {len(real)}")
    lines.append(f"Origin candidates: {len(origins.get('origin_ips', []))}")
    lines.append(f"Overall risk: {summary['overall'].upper()}")
    lines.append("")

    lines.append("## Risk Summary")
    lines.append("-" * 80)
    counts = summary["counts"]
    for sev in risk.SEVERITY_LABELS[::-1]:
        lines.append(f"{sev:<12} {counts.get(sev, 0)}")
    lines.append("")
    lines.append("Top risks:")
    for r in summary["top_risks"]:
        target = r["target"] or r["subdomain"]
        lines.append(f"    [{r['severity']}] {target} ({', '.join(r['reasons'])})")
    lines.append("")

    lines.append("## Provider Distribution")
    lines.append("-" * 80)
    counts = _count_provider_ips(results)
    for service in sorted(counts, key=lambda x: counts[x], reverse=True):
        lines.append(f"{service:<20} {counts[service]} IP(s)")
    lines.append("")

    lines.append("## Protected Subdomains")
    lines.append("-" * 80)
    grouped = _group_by_provider(protected)
    for service in sorted(grouped):
        lines.append(f"[{service}]")
        for subdomain, ip in sorted(grouped[service]):
            lines.append(f"    {subdomain:<50} {ip}")
        lines.append("")

    lines.append("## Real IP Subdomains")
    lines.append("-" * 80)
    for item in sorted(real, key=lambda x: x["subdomain"]):
        sev = _severity_real(item)
        lines.append(f"[{sev}] {item['subdomain']}")
        for ip in item["ips"]:
            lines.append(f"    {ip}")
    lines.append("")

    lines.append("## Origin Candidates")
    lines.append("-" * 80)
    for entry in sorted(origins.get("origin_ips", []), key=lambda x: x["subdomain"]):
        sev = _severity_origin(entry, active_conf)
        lines.append(f"[{sev}] {entry['subdomain']:<50} {entry['ip']:<40} ({entry['source']})")
    lines.append("")

    lines.append("## Cloud Storage Findings")
    lines.append("-" * 80)
    cloud = origins.get("cloudstorage", {})
    for entry in sorted(cloud.get("found", []), key=lambda x: x["url"]):
        sev = _severity_cloud(entry)
        lines.append(f"[{sev}] {entry['url']:<70} status={entry.get('status')}")
    if not cloud.get("found"):
        lines.append("None")
    lines.append("")

    lines.append("## Active Recon Candidates")
    lines.append("-" * 80)
    for key in ("asnsweep", "bodyfingerprint"):
        data = origins.get(key, {})
        candidates = data.get("candidates", [])
        if candidates:
            lines.append(f"[{key}]")
            for cand in sorted(candidates, key=lambda x: x.get("confidence", 0), reverse=True):
                lines.append(f"    {cand.get('ip'):<40} confidence={cand.get('confidence')} reasons={cand.get('match_reasons')}")
            lines.append("")

    lines.append("## MX Records")
    lines.append("-" * 80)
    for mx in origins.get("mx_hosts", []):
        lines.append(mx)
    lines.append("")

    lines.append("## TXT Records")
    lines.append("-" * 80)
    for txt in origins.get("txt_records", []):
        lines.append(txt)
    lines.append("")

    lines.append("## Header Leaks")
    lines.append("-" * 80)
    for leak in origins.get("header_leaks", []):
        sev = _severity_header(leak)
        lines.append(f"[{sev}] {leak.get('header')}: {leak.get('raw')}")
    lines.append("")

    lines.append("## External Subdomain Sources")
    lines.append("-" * 80)
    for key in ("hackertarget_pairs", "rapiddns_pairs", "dnsdumpster_pairs"):
        items = origins.get(key, [])
        if items:
            lines.append(f"[{key}] ({len(items)} entries)")
            for entry in items[:100]:
                lines.append(f"    {entry['subdomain']:<50} {entry['ip']}")
            lines.append("")

    return "\n".join(lines)


def _generate_md(results, origins):
    summary = risk.summarize(results, origins)
    active_conf = _active_conf(origins)
    domain = origins.get("domain", "unknown")
    protected = [r for r in results if r.get("protected")]
    real = [r for r in results if r.get("ips")]
    lines = []
    lines.append(f"# NullCloud Scan Report: `{domain}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total checked | {len(results)} |")
    lines.append(f"| Protected | {len(protected)} |")
    lines.append(f"| Real IP | {len(real)} |")
    lines.append(f"| Origin candidates | {len(origins.get('origin_ips', []))} |")
    lines.append(f"| Overall risk | {summary['overall'].upper()} |")
    lines.append("")
    lines.extend(_risk_summary_lines(summary))

    lines.append("## Provider Distribution")
    lines.append("")
    lines.append("| Provider | IPs |")
    lines.append("|----------|-----|")
    counts = _count_provider_ips(results)
    for service in sorted(counts, key=lambda x: counts[x], reverse=True):
        lines.append(f"| {service} | {counts[service]} |")
    lines.append("")

    lines.append("## Protected Subdomains")
    lines.append("")
    lines.append("| Subdomain | IP | Provider |")
    lines.append("|-----------|----|----------|")
    for item in sorted(protected, key=lambda x: x["subdomain"]):
        for entry in item["protected"]:
            lines.append(f"| {item['subdomain']} | {entry['ip']} | {entry['service']} |")
    lines.append("")

    lines.append("## Real IP Subdomains")
    lines.append("")
    lines.append("| Subdomain | IPs | Severity |")
    lines.append("|-----------|-----|----------|")
    for item in sorted(real, key=lambda x: x["subdomain"]):
        sev = _severity_real(item)
        lines.append(f"| {item['subdomain']} | {'; '.join(item['ips'])} | {sev} |")
    lines.append("")

    lines.append("## Origin Candidates")
    lines.append("")
    lines.append("| Subdomain | IP | Source | Severity |")
    lines.append("|-----------|----|--------|----------|")
    for entry in sorted(origins.get("origin_ips", []), key=lambda x: x["subdomain"]):
        sev = _severity_origin(entry, active_conf)
        lines.append(f"| {entry['subdomain']} | {entry['ip']} | {entry['source']} | {sev} |")
    lines.append("")

    lines.append("## Cloud Storage Findings")
    lines.append("")
    lines.append("| URL | Status | Severity |")
    lines.append("|-----|--------|----------|")
    cloud = origins.get("cloudstorage", {})
    for entry in sorted(cloud.get("found", []), key=lambda x: x["url"]):
        sev = _severity_cloud(entry)
        lines.append(f"| {entry['url']} | {entry.get('status')} | {sev} |")
    if not cloud.get("found"):
        lines.append("| None | - | info |")
    lines.append("")

    lines.append("## MX Records")
    lines.append("")
    for mx in origins.get("mx_hosts", []):
        lines.append(f"- {mx}")
    lines.append("")

    lines.append("## TXT Records")
    lines.append("")
    for txt in origins.get("txt_records", []):
        lines.append(f"- `{txt}`")
    lines.append("")

    lines.append("## Header Leaks")
    lines.append("")
    lines.append("| Header | Value | Severity |")
    lines.append("|--------|-------|----------|")
    for leak in origins.get("header_leaks", []):
        sev = _severity_header(leak)
        lines.append(f"| {leak.get('header')} | {leak.get('raw')} | {sev} |")
    lines.append("")

    return "\n".join(lines)


def _generate_html(results, origins):
    summary = risk.summarize(results, origins)
    active_conf = _active_conf(origins)
    domain = origins.get("domain", "unknown")
    protected = [r for r in results if r.get("protected")]
    real = [r for r in results if r.get("ips")]
    counts = _count_provider_ips(results)
    out = []
    out.append("<!DOCTYPE html>")
    out.append('<html lang="en"><head><meta charset="utf-8"><title>NullCloud Report</title>')
    out.append("<style>body{font-family:sans-serif;margin:2em;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ccc;padding:6px;text-align:left;}th{background:#f0f0f0;}h1,h2{color:#333;}.critical{color:#c00;font-weight:bold;}.high{color:#e60;font-weight:bold;}.medium{color:#ca0;font-weight:bold;}.low{color:#08c;}.info{color:#666;}</style>")
    out.append("</head><body>")
    out.append(f"<h1>NullCloud Scan Report: <code>{html.escape(domain)}</code></h1>")

    out.append("<h2>Summary</h2><ul>")
    out.append(f"<li>Total checked: {len(results)}</li>")
    out.append(f"<li>Protected subdomains: {len(protected)}</li>")
    out.append(f"<li>Real IP subdomains: {len(real)}</li>")
    out.append(f"<li>Origin candidates: {len(origins.get('origin_ips', []))}</li>")
    out.append(f"<li>Overall risk: <span class='{summary['overall']}'>{summary['overall'].upper()}</span></li>")
    out.append("</ul>")

    out.append("<h2>Risk Summary</h2><table><tr><th>Severity</th><th>Count</th></tr>")
    for sev in risk.SEVERITY_LABELS[::-1]:
        out.append(f"<tr><td class='{sev}'>{sev}</td><td>{summary['counts'].get(sev, 0)}</td></tr>")
    out.append("</table>")

    out.append("<h3>Top Risks</h3><table><tr><th>Target</th><th>Severity</th><th>Reasons</th></tr>")
    for r in summary["top_risks"]:
        target = html.escape(r["target"] or r["subdomain"])
        reasons = html.escape(", ".join(r["reasons"]))
        out.append(f"<tr><td>{target}</td><td class='{r['severity']}'>{r['severity']}</td><td>{reasons}</td></tr>")
    out.append("</table>")

    out.append("<h2>Provider Distribution</h2><table><tr><th>Provider</th><th>IPs</th></tr>")
    for service in sorted(counts, key=lambda x: counts[x], reverse=True):
        out.append(f"<tr><td>{html.escape(service)}</td><td>{counts[service]}</td></tr>")
    out.append("</table>")

    out.append("<h2>Protected Subdomains</h2><table><tr><th>Subdomain</th><th>IP</th><th>Provider</th></tr>")
    for item in sorted(protected, key=lambda x: x["subdomain"]):
        for entry in item["protected"]:
            out.append(f"<tr><td>{html.escape(item['subdomain'])}</td><td>{html.escape(entry['ip'])}</td><td>{html.escape(entry['service'])}</td></tr>")
    out.append("</table>")

    out.append("<h2>Real IP Subdomains</h2><table><tr><th>Subdomain</th><th>IPs</th><th>Severity</th></tr>")
    for item in sorted(real, key=lambda x: x["subdomain"]):
        sev = _severity_real(item)
        out.append(f"<tr><td>{html.escape(item['subdomain'])}</td><td>{html.escape('; '.join(item['ips']))}</td><td class='{sev}'>{sev}</td></tr>")
    out.append("</table>")

    out.append("<h2>Origin Candidates</h2><table><tr><th>Subdomain</th><th>IP</th><th>Source</th><th>Severity</th></tr>")
    for entry in sorted(origins.get("origin_ips", []), key=lambda x: x["subdomain"]):
        sev = _severity_origin(entry, active_conf)
        out.append(f"<tr><td>{html.escape(entry['subdomain'])}</td><td>{html.escape(entry['ip'])}</td><td>{html.escape(entry['source'])}</td><td class='{sev}'>{sev}</td></tr>")
    out.append("</table>")

    out.append("<h2>Cloud Storage Findings</h2><table><tr><th>URL</th><th>Status</th><th>Severity</th></tr>")
    cloud = origins.get("cloudstorage", {})
    for entry in sorted(cloud.get("found", []), key=lambda x: x["url"]):
        sev = _severity_cloud(entry)
        out.append(f"<tr><td>{html.escape(entry['url'])}</td><td>{entry.get('status')}</td><td class='{sev}'>{sev}</td></tr>")
    if not cloud.get("found"):
        out.append("<tr><td colspan='3'>None</td></tr>")
    out.append("</table>")

    out.append("<h2>MX Records</h2><ul>")
    for mx in origins.get("mx_hosts", []):
        out.append(f"<li>{html.escape(mx)}</li>")
    out.append("</ul>")

    out.append("<h2>TXT Records</h2><ul>")
    for txt in origins.get("txt_records", []):
        out.append(f"<li><code>{html.escape(txt)}</code></li>")
    out.append("</ul>")

    out.append("<h2>Header Leaks</h2><table><tr><th>Header</th><th>Value</th><th>Severity</th></tr>")
    for leak in origins.get("header_leaks", []):
        sev = _severity_header(leak)
        out.append(f"<tr><td>{html.escape(leak.get('header', ''))}</td><td>{html.escape(leak.get('raw', ''))}</td><td class='{sev}'>{sev}</td></tr>")
    out.append("</table>")

    out.append("</body></html>")
    return "\n".join(out)


def generate_report(results, origins, fmt="txt"):
    if fmt == "md":
        return _generate_md(results, origins)
    if fmt == "html":
        return _generate_html(results, origins)
    return _generate_txt(results, origins)
