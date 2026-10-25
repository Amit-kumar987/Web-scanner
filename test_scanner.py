import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from web_scanner import scan_target, summarize          # noqa: E402
from web_scanner.lab_servers import start_lab_servers   # noqa: E402


@pytest.fixture(scope="module")
def results():
    servers, targets = start_lab_servers()
    findings = []
    for name, url in targets.items():
        findings += scan_target(name, url)
    yield findings
    for s in servers:
        s.shutdown()


def sev(findings, target, check):
    return next(f["severity"] for f in findings if f["target"] == target and f["check"] == check)


def test_scores_rise_with_hardening(results):
    s = summarize(results)
    assert s["insecure-lab"]["score"] < s["partial-lab"]["score"] < s["hardened-lab"]["score"]


def test_grades(results):
    s = summarize(results)
    assert s["insecure-lab"]["grade"] == "F"
    assert s["hardened-lab"]["grade"] == "A"
    assert s["hardened-lab"]["High"] == 0


def test_cors_findings(results):
    assert sev(results, "insecure-lab", "Reflected origin") == "High"
    assert sev(results, "insecure-lab", "Null origin") == "High"
    assert sev(results, "partial-lab", "Wildcard origin") == "Low"
    assert sev(results, "hardened-lab", "Reflected origin") == "Pass"


def test_cookie_findings(results):
    assert sev(results, "insecure-lab", "Cookie HttpOnly") == "Medium"
    assert sev(results, "partial-lab", "Cookie HttpOnly") == "Pass"
    assert sev(results, "hardened-lab", "Cookie SameSite") == "Pass"


def test_header_findings(results):
    assert sev(results, "insecure-lab", "Content-Security-Policy") == "Medium"
    assert sev(results, "partial-lab", "X-Content-Type-Options") == "Pass"
    assert sev(results, "hardened-lab", "Content-Security-Policy") == "Pass"
