# NullCloud

A fast, multi-threaded command-line tool to discover real IP addresses hiding behind CDN, WAF and DDoS protection services by resolving subdomains from a wordlist.

## Features

- IPv4 and IPv6 resolution
- Multi-provider detection with live IP range fetching and offline fallback
- Supports Cloudflare, Fastly, AWS CloudFront, Google Cloud, Gcore, Akamai, Azure, BunnyCDN, Imperva, Sucuri, DDoS-Guard, Qrator, StormWall, Yandex Cloud, Tencent Cloud, Alibaba Cloud, Huawei Cloud, CDN77, KeyCDN, CDNetworks and Wangsu
- Live IP range fetching for Cloudflare, Fastly, AWS CloudFront, Google Cloud, Gcore, BunnyCDN and Azure
- Passive origin detection via CNAME chain analysis, multiple certificate transparency sources (crt.sh, CertSpotter), passive subdomain databases (HackerTarget, RapidDNS, DNSDumpster), HTTP header inspection, favicon hash extraction, MX/TXT/PTR analysis and DNS zone transfer (AXFR) attempts
- Modular active origin reconnaissance: ASN/range discovery with Host/SNI sweep and response fingerprinting (keyless), cloud storage enumeration, and pluggable API-key modules (FOFA, historical DNS, Shodan, Censys)
- Service-aware output: know which provider protects each IP
- Multiple wordlist support
- Multi-threaded scanning
- Rate limiting
- Normal, JSON, YAML and CSV output formats
- Human-readable Markdown, HTML and TXT reports with risk scoring
- Automatic severity classification for origin candidates, header leaks and cloud storage findings
- Verbose and quiet modes
- Built-in subdomain wordlist

## Installation

Requires Python 3.10 or newer.

```bash
git clone <repo-url>
cd NullCloud
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Basic scan using all providers:

```bash
python3 nullcloud.py example.com
```

Scan only specific providers:

```bash
python3 nullcloud.py example.com -s cloudflare -s aws
```

List supported providers:

```bash
python3 nullcloud.py --list-services
```

Fast scan with JSON output:

```bash
python3 nullcloud.py example.com -t 50 -o report.json -f json
```

Use custom wordlists:

```bash
python3 nullcloud.py example.com -w subs1.txt -w subs2.txt
```

Quiet mode, only real IPs:

```bash
python3 nullcloud.py example.com -q
```

Enable enhanced origin detection:

```bash
python3 nullcloud.py example.com --origin
```

Run active origin reconnaissance (sends probes directly to candidate IPs):

```bash
python3 nullcloud.py example.com -s cloudflare --origin --origin-active
```

Sample mode for faster active sweeps:

```bash
python3 nullcloud.py example.com -s cloudflare --origin --origin-active --origin-sample
```

Run only a specific active module:

```bash
python3 nullcloud.py example.com -s cloudflare --origin --origin-active --origin-module asn
```

Use FOFA for passive origin reconnaissance (requires a FOFA API key in `~/.nullcloud/keys.yaml`):

```bash
python3 nullcloud.py example.com --origin
```

Create `~/.nullcloud/keys.yaml` from the provided example:

```bash
cp keys.yaml.example ~/.nullcloud/keys.yaml
# edit ~/.nullcloud/keys.yaml and add your FOFA email + key
```

Generate a human-readable Markdown report:

```bash
python3 nullcloud.py example.com --origin --report-format md --report-output report.md
```

Available report formats: `txt`, `md`, `html`.

## Development

Install development dependencies and run the test suite:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -v
```

## Contributing

Contributions are welcome. Please open an issue or pull request on GitHub.

## Options

| Option | Description |
|--------|-------------|
| `domain` | Target domain |
| `-w, --wordlist` | Wordlist file, repeatable |
| `-t, --threads` | Number of threads (default: 10) |
| `-r, --rate` | Requests per second per thread (default: 0) |
| `-o, --output` | Save results to file |
| `-f, --format` | Output format: normal, json, yaml, csv |
| `-s, --service` | Provider to check, repeatable (default: all) |
| `--list-services` | Show supported providers |
| `-v, --verbose` | Show all attempts |
| `-q, --quiet` | Only show found real IPs |
| `--origin` | Enable CNAME/CT log/header origin detection |
| `--origin-timeout` | Timeout for origin probes (default: 10) |
| `--origin-active` | Enable active origin reconnaissance modules |
| `--origin-module` | Active module to run: `asn`, `cloud`, `body`, `fofa` (repeatable, default: `asn`, `cloud`, `body`) |
| `--origin-active-threads` | Active recon threads (default: 20) |
| `--origin-active-timeout` | Active probe timeout in seconds (default: 5) |
| `--origin-sample` | Sample one IP per discovered prefix instead of full sweep |
| `--origin-use-fofa` | Enable FOFA passive reconnaissance when API keys are configured |
| `--origin-key-file` | Path to API key file (default: `~/.nullcloud/keys.yaml`) |
| `--report-format` | Generate human-readable report: `txt`, `md`, `html` |
| `--report-output` | Report output file (default: stdout) |

## Output Formats

Normal output shows real IPs and protected IPs grouped by provider.

JSON and YAML include the full result structure with `results` (containing `ips` and `protected` arrays) and, when `--origin` is used, an `origins` object with `cname_chain`, `backend`, `header_leaks`, `ct_subdomains`, `certspotter_subdomains`, `hackertarget_pairs`, `rapiddns_pairs`, `dnsdumpster_pairs`, `external_subdomains`, `favicon_hash`, `axfr_subdomains`, `mx_hosts`, `txt_records`, `ptr_hints`, `origin_ips`, `origin_ranges` and active module results such as `asnsweep`, `bodyfingerprint` and `cloudstorage`.

Human-readable reports (`--report-format`) add a risk summary and severity columns to each origin candidate, header leak and cloud storage finding. Severity levels are `critical`, `high`, `medium`, `low` and `info`.

CSV uses the columns: `subdomain, ip, type, service` where type is `real` or `protected`. When `--origin` is used, origin candidates are appended with type `origin`.

## Provider Data Accuracy

Providers marked as live-fetch pull current IP ranges from official public APIs. Other providers use static fallback lists compiled from public ASN and routing data. Static lists are approximate and may become outdated as providers change their networks. Always verify results against the provider's official documentation when precise identification is required.

A provider not detecting its own corporate homepage is usually expected: marketing sites often sit behind a different CDN or on separate infrastructure. Customer sites on the platform are the intended detection targets.

## Legal Notice

This tool is intended for authorized security testing, bug bounty programs and educational purposes only.

Do not use NullCloud on systems you do not own or have explicit written permission to test. Unauthorized scanning may violate laws in your jurisdiction. The authors assume no liability for misuse.

## Thanks

- [FOFA](https://fofa.info/) for supporting open-source security research.

## License

MIT License. See LICENSE for details.
