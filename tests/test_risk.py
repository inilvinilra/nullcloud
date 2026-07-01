"""Unit tests for risk scoring helpers in risk.py."""

import pytest

import risk


def test_score_origin_candidate_private_ip():
    score, severity, reasons = risk.score_origin_candidate({"ip": "192.168.1.1", "source": "dns"})
    assert score == 95
    assert severity == "critical"
    assert "private_ip" in reasons


def test_score_origin_candidate_dns():
    score, severity, reasons = risk.score_origin_candidate({"ip": "8.8.8.8", "source": "dns"})
    assert score == 80
    assert severity == "high"


def test_score_origin_candidate_external_db():
    score, severity, reasons = risk.score_origin_candidate({"ip": "8.8.8.8", "source": "external_db"})
    assert score == 55
    assert severity == "medium"


def test_score_origin_candidate_header_leak():
    score, severity, reasons = risk.score_origin_candidate(
        {"ip": "8.8.8.8", "source": "header:x-forwarded-for"}
    )
    assert score == 55
    assert severity == "medium"


def test_score_cloudstorage_responsive():
    score, severity, reasons = risk.score_cloudstorage({"status": 200})
    assert score == 70
    assert severity == "high"


def test_score_cloudstorage_not_found():
    score, severity, reasons = risk.score_cloudstorage({"status": 404})
    assert score == 20
    assert severity == "low"


def test_score_header_leak_private_ip():
    score, severity, reasons = risk.score_header_leak({"header": "X-Forwarded-For", "raw": "192.168.1.1"})
    assert score == 95
    assert severity == "critical"


def test_score_header_leak_sensitive_forwarding():
    score, severity, reasons = risk.score_header_leak({"header": "x-real-ip", "raw": "8.8.8.8"})
    assert score == 70
    assert severity == "high"


def test_score_header_leak_infrastructure():
    score, severity, reasons = risk.score_header_leak({"header": "via", "raw": "1.1 proxy"})
    assert score == 40
    assert severity == "medium"


def test_summarize_counts():
    origins = {
        "origin_ips": [
            {"ip": "8.8.8.8", "source": "dns"},
            {"ip": "192.168.1.1", "source": "dns"},
        ],
        "header_leaks": [
            {"header": "x-real-ip", "raw": "8.8.8.8"},
        ],
        "cloudstorage": {"found": [{"url": "https://s3.amazonaws.com/bucket", "status": 200}]},
    }
    summary = risk.summarize([], origins)
    assert summary["overall"] == "critical"
    assert summary["counts"]["critical"] == 1
    assert summary["counts"]["high"] == 3
