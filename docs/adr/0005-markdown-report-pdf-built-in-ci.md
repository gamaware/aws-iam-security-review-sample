# ADR 0005: Markdown is the canonical report; CI builds the PDF

## Status

Accepted

## Context

Clients read a security review as a PDF: they forward it, attach it to an audit request and print it. Engineers
review it as text: they diff a finding, check a quoted line against the evidence, and comment on a pull request.
Keeping two hand-edited copies lets them drift, and a committed PDF cannot be diffed or tested.

## Decision

`report/REPORT.md` and `report/control-evidence-map.md` are the only sources. CI renders them into one PDF with
pandoc on every run and publishes it as a build artifact. The PDF is not committed; `make report` builds the same
file locally into `build/`.

## Consequences

- The tests that tie the report to the evidence run on the text the client receives.
- A reader browsing GitHub gets the Markdown; the PDF is one click away in the latest CI run, or attached to a
  release.
- PDF layout depends on the pandoc version and PDF engine that CI pins; local output may differ in fonts and page
  breaks, not in content.

## Compliance

- `.gitignore` excludes `build/` and `*.pdf`, so a PDF cannot be committed by accident.
- The CI report job fails if pandoc cannot render the Markdown.
- `tests/test_report.py` checks the Markdown's quotes, counts, finding IDs, links and fictional label.

## Notes

Pandoc reads both files in order, so the control map becomes the PDF's appendix.
