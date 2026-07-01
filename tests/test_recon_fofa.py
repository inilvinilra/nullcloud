"""Unit tests for the FOFA reconnaissance module."""

import json
from io import BytesIO
from unittest.mock import patch, MagicMock

import pytest

from recon.fofa import fetch_fofa, query_fofa, FofaRecon


def _mock_response(payload, status=200):
    mock = MagicMock()
    mock.status = status
    mock.read.return_value = json.dumps(payload).encode("utf-8")
    return mock


def test_query_fofa_success():
    payload = {
        "error": None,
        "results": [["www.example.com", "93.184.216.34", "443", "Example", "example.com"]],
        "size": 1,
    }
    with patch("recon.fofa.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        data = query_fofa('domain="example.com"', "user@example.com", "secret")
    assert data["size"] == 1
    assert data["results"][0][0] == "www.example.com"


def test_query_fofa_api_error():
    payload = {"error": "invalid email or key", "results": [], "size": 0}
    with patch("recon.fofa.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        with pytest.raises(ValueError, match="FOFA API error"):
            query_fofa('domain="example.com"', "user@example.com", "secret")


def test_fetch_fofa_aggregates_results():
    payload = {
        "error": None,
        "results": [
            ["www.example.com", "93.184.216.34", "443", "Example", "example.com"],
            ["api.example.com", "93.184.216.35", "443", "API", "example.com"],
        ],
        "size": 2,
    }
    with patch("recon.fofa.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        subdomains, ips, pairs = fetch_fofa("example.com", "user@example.com", "secret", max_size=100)

    assert "www.example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "93.184.216.34" in ips
    assert "93.184.216.35" in ips
    assert len(pairs) == 2


def test_fetch_fofa_deduplicates():
    payload = {
        "error": None,
        "results": [
            ["www.example.com", "93.184.216.34", "443", "Example", "example.com"],
            ["www.example.com", "93.184.216.34", "443", "Example", "example.com"],
        ],
        "size": 2,
    }
    with patch("recon.fofa.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        subdomains, ips, pairs = fetch_fofa("example.com", "user@example.com", "secret", max_size=100)

    assert len(subdomains) == 1
    assert len(ips) == 1
    assert len(pairs) == 1


def test_fofa_recon_missing_key():
    recon = FofaRecon()
    result = recon.run("example.com", [], {"keys": {}})
    assert result.errors == ["FOFA credentials missing (email + key)"]
    assert result.data == {}


def test_fofa_recon_success():
    payload = {
        "error": None,
        "results": [
            ["www.example.com", "93.184.216.34", "443", "Example", "example.com"],
        ],
        "size": 1,
    }
    with patch("recon.fofa.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        recon = FofaRecon()
        config = {"keys": {"fofa": {"email": "user@example.com", "key": "secret"}}, "timeout": 10}
        result = recon.run("example.com", [], config)

    assert result.errors == []
    assert len(result.data["pairs"]) == 1
    assert result.data["checked"] == 1
    assert "93.184.216.34" in result.data["ips"]
