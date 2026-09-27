# Every target except test-live runs offline: no AWS account, no credentials.
# CI calls `make verify`, so a green local run means a green pipeline.

SHELL := bash
.SHELLFLAGS := -o pipefail -c

PYTHON ?= python3
CHECKOV ?= uvx checkov==3.3.19
TERRAFORM ?= terraform
PANDOC ?= pandoc
PDF_ENGINE ?= typst
BUILD := build
EVIDENCE ?= evidence
BEFORE := data/synthetic/before
AFTER := data/synthetic/after
TF_ROOTS := $(BEFORE)/terraform remediation/terraform

.PHONY: verify test review checkov terraform evidence evidence-check report test-live clean

verify: test review checkov terraform evidence-check
	@echo "make verify: all offline checks passed"

test:
	$(PYTHON) -m pytest

# The before account must fail with exactly the findings the report cites; the after
# account must produce none.
review:
	@$(PYTHON) scripts/iam_review.py $(BEFORE)/export > /dev/null; rc=$$?; \
	  test $$rc -eq 1 || { echo "before: expected exit 1, got $$rc"; exit 1; }
	$(PYTHON) scripts/iam_review.py $(AFTER)/export > /dev/null

# Remediated Terraform must pass Checkov; the before Terraform must fail with exactly the
# expected checks (ADR 0004).
checkov: | $(BUILD)
	$(CHECKOV) --directory remediation/terraform --framework terraform --quiet --compact
	$(CHECKOV) --directory $(BEFORE)/terraform --framework terraform --output json \
	  --soft-fail > $(BUILD)/checkov-before.json
	$(PYTHON) scripts/checkov_summary.py $(BUILD)/checkov-before.json \
	  --expect evidence/checkov-before.txt

terraform:
	$(TERRAFORM) fmt -check -recursive
	@for root in $(TF_ROOTS); do \
	  $(TERRAFORM) -chdir=$$root init -backend=false -input=false > /dev/null || exit 1; \
	  $(TERRAFORM) -chdir=$$root validate || exit 1; \
	done

# Regenerate the evidence files the report cites. Review the diff before committing.
evidence: | $(BUILD)
	mkdir -p $(EVIDENCE)
	@$(PYTHON) scripts/iam_review.py $(BEFORE)/export > $(EVIDENCE)/iam-review-before.txt; rc=$$?; \
	  test $$rc -eq 1 || { echo "before: expected exit 1, got $$rc"; exit 1; }
	$(PYTHON) scripts/iam_review.py $(AFTER)/export > $(EVIDENCE)/iam-review-after.txt
	$(CHECKOV) --directory $(BEFORE)/terraform --framework terraform --output json \
	  --soft-fail > $(BUILD)/checkov-before.json
	$(PYTHON) scripts/checkov_summary.py $(BUILD)/checkov-before.json > $(EVIDENCE)/checkov-before.txt
	$(CHECKOV) --directory remediation/terraform --framework terraform --quiet --compact \
	  | awk 'NF' > $(EVIDENCE)/checkov-after.txt

# Regenerate every evidence file into build/ and fail if any committed file differs.
evidence-check:
	rm -rf $(BUILD)/evidence
	$(MAKE) --no-print-directory evidence EVIDENCE=$(BUILD)/evidence
	diff -ru --exclude=README.md evidence $(BUILD)/evidence
	@echo "evidence/ matches a fresh run"

# Render the client PDF from the canonical Markdown. CI does this on every run; locally it
# needs pandoc and the PDF engine (typst by default).
report: | $(BUILD)
	$(PANDOC) report/REPORT.md report/control-evidence-map.md \
	  --resource-path=report --pdf-engine=$(PDF_ENGINE) \
	  --metadata title="Harbor Goods (fictional client)" \
	  --output $(BUILD)/REPORT.pdf
	@echo "wrote $(BUILD)/REPORT.pdf"

# Optional, manual, never run in CI. Asks IAM Access Analyzer and the IAM policy simulator to
# judge the remediated policies; creates no resources. See docs/methodology.md.
test-live:
	scripts/test-live.sh

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD) .pytest_cache .ruff_cache
