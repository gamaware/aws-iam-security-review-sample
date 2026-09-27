"""Tests for the Checkov evidence gate."""

from __future__ import annotations

import json

import checkov_summary


def report(*failures: tuple[str, str]) -> dict:
    return {
        "check_type": "terraform",
        "results": {
            "failed_checks": [{"check_id": c, "resource": r} for c, r in failures],
            "passed_checks": [],
        },
    }


def test_lines_are_sorted_and_deduplicated():
    data = report(("CKV_AWS_67", "aws_cloudtrail.t"), ("CKV_AWS_36", "aws_cloudtrail.t"))
    data["results"]["failed_checks"].append(data["results"]["failed_checks"][0])
    assert checkov_summary.failed_checks(data) == [
        "CKV_AWS_36 aws_cloudtrail.t",
        "CKV_AWS_67 aws_cloudtrail.t",
    ]


def test_multi_framework_list_output():
    data = [report(("A", "r1")), report(("B", "r2"))]
    assert checkov_summary.failed_checks(data) == ["A r1", "B r2"]


def test_expect_gate(tmp_path, capsys):
    path = tmp_path / "checkov.json"
    path.write_text(json.dumps(report(("A", "r1"))))
    good = tmp_path / "good.txt"
    good.write_text("A r1\n")
    drifted = tmp_path / "drifted.txt"
    drifted.write_text("A r1\nB r2\n")

    assert checkov_summary.main([str(path), "--expect", str(good)]) == 0
    assert checkov_summary.main([str(path), "--expect", str(drifted)]) == 1
    assert "expected but not reported: B r2" in capsys.readouterr().err


def test_unreadable_report_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert checkov_summary.main([str(bad)]) == 2
    assert "cannot read Checkov report" in capsys.readouterr().err
