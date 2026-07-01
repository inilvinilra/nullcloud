"""Unit tests for core NullCloud helpers in nullcloud.py."""

import os
import tempfile

import pytest

import nullcloud


def test_classify_ip_with_provider():
    network_map = [
        (nullcloud.ipaddress.ip_network("1.2.3.0/24"), "testprovider"),
    ]
    assert nullcloud.classify_ip("1.2.3.4", network_map) == "testprovider"


def test_classify_ip_unknown():
    network_map = [
        (nullcloud.ipaddress.ip_network("1.2.3.0/24"), "testprovider"),
    ]
    assert nullcloud.classify_ip("8.8.8.8", network_map) is None


def test_classify_ip_invalid():
    assert nullcloud.classify_ip("not-an-ip", []) is None


def test_extract_ips():
    text = "Server at 192.168.1.1 and 10.0.0.1, also 192.168.1.1"
    assert sorted(nullcloud.extract_ips(text)) == ["10.0.0.1", "192.168.1.1"]


def test_extract_ips_empty():
    assert nullcloud.extract_ips("no addresses here") == []


def test_extract_cidrs():
    text = "Ranges: 192.168.0.0/24 and 10.0.0.0/8"
    assert sorted(nullcloud.extract_cidrs(text)) == ["10.0.0.0/8", "192.168.0.0/24"]


def test_is_valid_ip_ipv4():
    assert nullcloud.is_valid_ip("8.8.8.8") is True


def test_is_valid_ip_ipv6():
    assert nullcloud.is_valid_ip("2001:4860:4860::8888") is True


def test_is_valid_ip_invalid():
    assert nullcloud.is_valid_ip("example.com") is False


def test_build_subdomains():
    assert nullcloud.build_subdomains("example.com", ["www", "api"]) == [
        "www.example.com",
        "api.example.com",
    ]


def test_load_wordlists():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("www\napi\n# comment\n\nWWW\n")
        path = f.name
    try:
        words = nullcloud.load_wordlists([path])
        assert words == ["api", "www"]
    finally:
        os.unlink(path)


def test_load_wordlists_missing_file():
    assert nullcloud.load_wordlists(["/nonexistent/path/words.txt"]) == []
