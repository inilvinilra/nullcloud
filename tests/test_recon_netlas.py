"""Unit tests for the Netlas reconnaissance module."""

import json
from unittest.mock import patch, MagicMock

import pytest

from recon.netlas import fetch_netlas, query_netlas, NetlasRecon


def _mock_response(payload, status=200):
    mock = MagicMock()
    mock.status = status
    mock.read.return_value = json.dumps(payload).encode("utf-8")
    return mock


def test_query_netlas_success():
    payload = {
        "items": [
            {"data": {"ip": "93.184.216.34", "domain": "www.example.com", "uri": "https://www.example.com/"}}
        ],
    }
    with patch("recon.netlas.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        data = query_netlas("domain:*.example.com", "secret")
    assert len(data["items"]) == 1


def test_fetch_netlas_aggregates_results():
    payload = {
        "items": [
            {"data": {"ip": "93.184.216.34", "domain": "www.example.com", "uri": "https://www.example.com/", "http": {"title": "Example"}}},
            {"data": {"ip": "93.184.216.35", "domain": "api.example.com", "uri": "https://api.example.com/"}},
        ],
    }
    with patch("recon.netlas.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        subdomains, ips, pairs = fetch_netlas("example.com", "secret", max_results=100)

    assert "www.example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "93.184.216.34" in ips
    assert len(pairs) == 2


def test_netlas_recon_missing_key():
    recon = NetlasRecon()
    result = recon.run("example.com", [], {"keys": {}})
    assert result.errors == ["Netlas API key missing"]


def test_netlas_recon_success():
    payload = {
        "items": [
            {"data": {"ip": "93.184.216.34", "domain": "www.example.com", "uri": "https://www.example.com/"}}
        ],
    }
    with patch("recon.netlas.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        recon = NetlasRecon()
        config = {"keys": {"netlas": {"api_key": "secret"}}, "timeout": 10}
        result = recon.run("example.com", [], config)

    assert result.errors == []
    assert len(result.data["pairs"]) == 1
    assert result.data["checked"] == 1
