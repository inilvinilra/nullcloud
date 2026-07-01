"""Unit tests for the Censys reconnaissance module."""

import json
from unittest.mock import patch, MagicMock

import pytest

from recon.censys import fetch_censys, query_censys, CensysRecon


def _mock_response(payload, status=200):
    mock = MagicMock()
    mock.status = status
    mock.read.return_value = json.dumps(payload).encode("utf-8")
    return mock


def test_query_censys_success():
    payload = {
        "result": {
            "hits": [
                {"ip": "93.184.216.34", "services": []}
            ],
            "links": {},
        }
    }
    with patch("recon.censys.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        data = query_censys("example.com", "id", "secret")
    assert len(data["result"]["hits"]) == 1


def test_fetch_censys_aggregates_results():
    payload = {
        "result": {
            "hits": [
                {
                    "ip": "93.184.216.34",
                    "services": [
                        {
                            "tls": {
                                "certificates": {
                                    "leaf_data": {
                                        "subject": {"common_name": ["www.example.com"]},
                                        "names": ["www.example.com"],
                                    }
                                }
                            }
                        }
                    ],
                }
            ],
            "links": {},
        }
    }
    with patch("recon.censys.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        subdomains, ips, pairs = fetch_censys("example.com", "id", "secret", max_pages=1)

    assert "www.example.com" in subdomains
    assert "93.184.216.34" in ips
    assert len(pairs) == 1


def test_censys_recon_missing_key():
    recon = CensysRecon()
    result = recon.run("example.com", [], {"keys": {}})
    assert result.errors == ["Censys API credentials missing (api_id + api_secret)"]


def test_censys_recon_success():
    payload = {
        "result": {
            "hits": [{"ip": "93.184.216.34", "services": []}],
            "links": {},
        }
    }
    with patch("recon.censys.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = _mock_response(payload)
        recon = CensysRecon()
        config = {"keys": {"censys": {"api_id": "id", "api_secret": "secret"}}, "timeout": 10}
        result = recon.run("example.com", [], config)

    assert result.errors == []
    assert len(result.data["pairs"]) == 1
    assert result.data["checked"] == 1
