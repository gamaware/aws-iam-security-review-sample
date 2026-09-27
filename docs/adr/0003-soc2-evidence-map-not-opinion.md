# ADR 0003: The SOC 2 deliverable is an evidence map, not an opinion

## Status

Accepted

## Context

Clients preparing for SOC 2 ask whether their AWS setup "is SOC 2 compliant". SOC 2 reports are attestation
engagements under AICPA standards; only a licensed CPA firm can issue one, and the opinion covers the whole system
description and control environment, not an AWS account. A consultant who implies otherwise misleads the client and
takes on liability.

What a consultant can usefully provide is the link between each relevant Trust Services Criterion, the AWS
configuration that supports it, and where the proof lives, so the auditor can test it quickly.

## Decision

We deliver a control to evidence map. It cites criteria by their AICPA IDs (for example CC6.1, CC7.2), summarizes
rather than quotes them, points to evidence artifacts in the repository, and uses four status values: Gap,
Supported, Partial and Not covered. The opening paragraph states that it is not an audit opinion.

## Consequences

- The map is honest about what a configuration snapshot proves (design at a point in time) and what it does not
  (operation through a Type 2 period).
- Several rows stay Partial after remediation because they depend on processes, such as access reviews and vendor
  due diligence, that no Terraform change can provide.
- The map needs updating when the report's findings change.

## Compliance

- Every Gap in the map links a finding ID (F-NN) that exists in the report; reviewers check this in the pull request
  template.
- The opening disclaimer is part of the document, and the report's Out of scope section repeats it.

## Notes

Criteria IDs follow the 2017 Trust Services Criteria with the revised points of focus. Physical security (CC6.4)
is carved out to AWS as a subservice organization and is not mapped.
