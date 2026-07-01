"""Unit tests for the Criminal IP reconnaissance module."""

import json
from unittest.mock import patch, MagicMock

import pytest

from recon.criminalip import fetch_criminalip, query_criminalip, CriminalIpRecon


def _mock_response(payload, status=200):
    mock = MagicMock()
    mock.status = status
    mock.read.return_value = json.dumps(payload).encode("utf-8")
    return mock


def test_query_criminalip_success():
    payload = {"data": {"domain": "www.example.com", "ip_address": "93.184.216.34"}}
    with patch("recon.criminalip.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        data = query_criminalip("example.com", "secret")
    assert data["data"]["domain"] == "www.example.com"


def test_fetch_criminalip_aggregates_results():
    payload = {
        "data": [
            {"domain": "www.example.com", "ip_address": "93.184.216.34"},
            {"domain": "api.example.com", "ip_address": "93.184.216.35"},
        ]
    }
    with patch("recon.criminalip.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        subdomains, ips, pairs = fetch_criminalip("example.com", "secret", max_offsets=1)

    assert "www.example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "93.184.216.34" in ips
    assert len(pairs) == 2


def test_criminalip_recon_missing_key():
    recon = CriminalIpRecon()
    result = recon.run("example.com", [], {"keys": {}})
    assert result.errors == ["Criminal IP API key missing"]


def test_criminalip_recon_success():
    payload = {"data": [{"domain": "www.example.com", "ip_address": "93.184.216.34"}]}
    with patch("recon.criminalip.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        recon = CriminalIpRecon()
        config = {"keys": {"criminalip": {"api_key": "secret"}}, "timeout": 10}
        result = recon.run("example.com", [], config)

    assert result.errors == []
    assert len(result.data["pairs"]) == 1
    assert result.data["checked"] == 1
