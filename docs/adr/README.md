# Architecture decision records

Architecture decision records follow the *Fundamentals of Software Architecture* (2nd ed.) format: title, status,
context, decision, consequences, compliance and notes. Each Compliance section says how the decision is checked,
automatically where possible.

| Number | Title | Status |
| --- | --- | --- |
| [0001](0001-review-offline-exports.md) | Review read-only exports offline, not the live account | Accepted |
| [0002](0002-stdlib-checker-alongside-checkov.md) | A stdlib-only Python checker alongside Checkov | Accepted |
| [0003](0003-soc2-evidence-map-not-opinion.md) | The SOC 2 deliverable is an evidence map, not an opinion | Accepted |
| [0004](0004-keep-vulnerable-sample-out-of-the-gate.md) | Gate the remediated code; assert the before state still fails | Accepted |
| [0005](0005-markdown-report-pdf-built-in-ci.md) | Markdown is the canonical report; the shared pipeline builds the PDF | Accepted |
| [0006](0006-semgrep-iam-findings-restructure-or-document.md) | Semgrep IAM findings: restructure the policy, or document why not | Accepted |
