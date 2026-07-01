"""Unit tests for the Shodan reconnaissance module."""

import json
from io import BytesIO
from unittest.mock import patch, MagicMock

import pytest

from recon.shodan import fetch_shodan, query_shodan, ShodanRecon


def _mock_response(payload, status=200):
    mock = MagicMock()
    mock.status = status
    mock.read.return_value = json.dumps(payload).encode("utf-8")
    return mock


def test_query_shodan_success():
    payload = {
        "total": 1,
        "matches": [
            {"ip_str": "93.184.216.34", "hostnames": ["www.example.com"], "port": 443, "http": {"title": "Example"}}
        ],
    }
    with patch("recon.shodan.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        data = query_shodan("hostname:example.com", "secret")
    assert data["total"] == 1


def test_fetch_shodan_aggregates_results():
    payload = {
        "total": 2,
        "matches": [
            {"ip_str": "93.184.216.34", "hostnames": ["www.example.com"], "port": 443},
            {"ip_str": "93.184.216.35", "hostnames": ["api.example.com"], "port": 443},
        ],
    }
    with patch("recon.shodan.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        subdomains, ips, pairs = fetch_shodan("example.com", "secret", max_pages=1)

    assert "www.example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "93.184.216.34" in ips
    assert len(pairs) == 4  # 2 hosts + 2 fallback domain pairs


def test_shodan_recon_missing_key():
    recon = ShodanRecon()
    result = recon.run("example.com", [], {"keys": {}})
    assert result.errors == ["Shodan API key missing"]


def test_shodan_recon_success():
    payload = {
        "total": 1,
        "matches": [
            {"ip_str": "93.184.216.34", "hostnames": ["www.example.com"], "port": 443}
        ],
    }
    with patch("recon.shodan.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        recon = ShodanRecon()
        config = {"keys": {"shodan": {"api_key": "secret"}}, "timeout": 10}
        result = recon.run("example.com", [], config)

    assert result.errors == []
    assert len(result.data["pairs"]) == 2
    assert result.data["checked"] == 2
