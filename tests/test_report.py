"""Keep the report, the evidence and the rest of the documentation telling the same story.

The report quotes tool output; these tests fail when a quote no longer matches the evidence
files that `make evidence` produces, when a count drifts, or when a link breaks.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
REPORT = (REPO / "report" / "REPORT.md").read_text()
EVIDENCE_MAP = (REPO / "report" / "control-evidence-map.md").read_text()
EVIDENCE = REPO / "evidence"
HIT = re.compile(r"^(CRITICAL|HIGH|MEDIUM|LOW)\s")
SKIP_DIRS = {".git", ".venv", ".terraform", ".pytest_cache", ".ruff_cache", "build", ".claude-flow"}
ALLOWED_ACCOUNT_IDS = {"111122223333", "123456789012", "444455556666"}


def hits(text: str) -> list[str]:
    return [line for line in text.splitlines() if HIT.match(line)]


def cited_hits() -> list[str]:
    blocks = re.findall(r"```text\n(.*?)```", REPORT, re.S)
    return [line for block in blocks for line in hits(block)]


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in REPO.rglob("*.md")
        if not SKIP_DIRS.intersection(path.relative_to(REPO).parts)
    )


def test_every_quoted_hit_is_in_the_evidence_and_every_hit_is_quoted():
    evidence = hits((EVIDENCE / "iam-review-before.txt").read_text())
    cited = cited_hits()
    assert sorted(set(cited)) == sorted(evidence)


def test_severity_table_matches_the_evidence_totals():
    totals_line = (EVIDENCE / "iam-review-before.txt").read_text().splitlines()[-1]
    totals = {name.title(): int(n) for name, n in re.findall(r"([A-Z]+) (\d+)", totals_line)}
    table = dict(re.findall(r"^\| (Critical|High|Medium|Low) \| (\d+) \|", REPORT, re.M))
    assert {k: int(v) for k, v in table.items()} == totals


def test_checkov_ids_named_in_findings_are_in_the_evidence():
    findings = REPORT[REPORT.index("## Findings") : REPORT.index("## Quick wins")]
    named = set(re.findall(r"CKV2?_AWS_\d+", findings))
    lines = (EVIDENCE / "checkov-before.txt").read_text().splitlines()
    reported = {line.split()[0] for line in lines if line}
    assert named <= reported, sorted(named - reported)


def test_every_finding_in_the_evidence_map_exists_in_the_report():
    in_report = re.findall(r"^### (F-\d\d) ", REPORT, re.M)
    in_map = set(re.findall(r"F-\d\d", EVIDENCE_MAP))
    # Findings are numbered F-01, F-02, ... with no gaps and in rank order.
    assert in_report == [f"F-{n:02d}" for n in range(1, len(in_report) + 1)]
    assert in_report
    assert in_map <= set(in_report)


def test_fictional_label_opens_and_closes_the_report():
    assert "FICTIONAL" in REPORT.split("\n## ", 1)[0]
    footer = REPORT.rstrip().rsplit("\n---\n", 1)[-1]
    assert "fictional" in footer.lower()


@pytest.mark.parametrize("path", markdown_files(), ids=lambda p: str(p.relative_to(REPO)))
def test_relative_links_resolve(path):
    text = re.sub(r"```.*?```", "", path.read_text(), flags=re.S)
    broken = []
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if re.match(r"[a-z]+:", target) or target.startswith("#"):
            continue
        resolved = (path.parent / target.split("#", 1)[0]).resolve()
        if not resolved.is_relative_to(REPO) or not resolved.exists():
            broken.append(target)
    assert not broken, broken


def test_only_documentation_account_ids_appear():
    suffixes = {".md", ".json", ".csv", ".tf", ".hcl", ".txt", ".py", ".sh", ".yml", ".yaml"}
    suffixes |= {".toml", ".drawio", ".cfg", ".ini"}
    names = {"Makefile", "CODEOWNERS", ".gitignore"}
    found = set()
    for path in REPO.rglob("*"):
        if SKIP_DIRS.intersection(path.relative_to(REPO).parts) or not path.is_file():
            continue
        if path.suffix not in suffixes and path.name not in names:
            continue
        found |= set(re.findall(r"(?<![\w.-])\d{12}(?!\w)", path.read_text(errors="ignore")))
    assert found <= ALLOWED_ACCOUNT_IDS, sorted(found - ALLOWED_ACCOUNT_IDS)
