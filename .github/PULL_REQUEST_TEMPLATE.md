# Pull request

## What changed

<!-- One or two sentences. Link the finding (F-NN) or check ID (IAM-NNN) if relevant. -->

## Checklist

- [ ] `make all` passes locally (pytest, review, checkov, terraform).
- [ ] If a check or fixture changed, `make evidence` was re-run and the evidence diff is explained here.
- [ ] The report and the SOC 2 map still match the evidence files.
- [ ] Placeholder IDs only (`123456789012`, `111122223333`); no real names, accounts or keys.
- [ ] Any new Checkov skip carries its reason next to the resource.
- [ ] Conventional commit title.
