# Every check in this repository runs offline: no AWS account, no credentials.
# CI calls these same targets, so a green local run means a green pipeline.

PYTHON ?= python3
CHECKOV ?= uvx checkov==3.3.19
TERRAFORM ?= terraform
BUILD := build
EVIDENCE := report/evidence
TF_ROOTS := sample-account/terraform remediated/terraform

.PHONY: all test review checkov terraform evidence clean

all: test review checkov terraform

test:
	$(PYTHON) -m pytest

# The sample account must produce exactly the findings cited in the report, and the
# remediated account must produce none.
review: | $(BUILD)
	@$(PYTHON) checks/iam_review.py sample-account/export > $(BUILD)/iam-review-sample.txt; \
	  rc=$$?; test $$rc -eq 1 || { echo "sample-account: expected exit 1, got $$rc"; exit 1; }
	diff -u $(EVIDENCE)/iam-review-sample.txt $(BUILD)/iam-review-sample.txt
	$(PYTHON) checks/iam_review.py remediated/export

# Remediated Terraform must pass Checkov; the sample must fail with exactly the
# expected checks.
checkov: | $(BUILD)
	$(CHECKOV) --directory remediated/terraform --framework terraform --quiet --compact
	$(CHECKOV) --directory sample-account/terraform --framework terraform --output json \
	  --soft-fail > $(BUILD)/checkov-sample.json
	$(PYTHON) checks/checkov_summary.py $(BUILD)/checkov-sample.json \
	  --expect $(EVIDENCE)/checkov-sample.txt

terraform:
	$(TERRAFORM) fmt -check -recursive
	@for root in $(TF_ROOTS); do \
	  $(TERRAFORM) -chdir=$$root init -backend=false -input=false > /dev/null || exit 1; \
	  $(TERRAFORM) -chdir=$$root validate || exit 1; \
	done

# Regenerate the evidence files the report cites. Review the diff before committing.
evidence: | $(BUILD)
	-$(PYTHON) checks/iam_review.py sample-account/export > $(EVIDENCE)/iam-review-sample.txt
	$(PYTHON) checks/iam_review.py remediated/export > $(EVIDENCE)/iam-review-remediated.txt
	$(CHECKOV) --directory sample-account/terraform --framework terraform --output json \
	  --soft-fail > $(BUILD)/checkov-sample.json
	$(PYTHON) checks/checkov_summary.py $(BUILD)/checkov-sample.json > $(EVIDENCE)/checkov-sample.txt
	$(CHECKOV) --directory remediated/terraform --framework terraform --quiet --compact \
	  | awk 'NF' > $(EVIDENCE)/checkov-remediated.txt

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD) .pytest_cache .ruff_cache
