# CLAUDE.md

Sample AWS IAM and security review for a FICTIONAL account. Public portfolio repository.

- `sample-account/` is insecure on purpose. Never "fix" it; fixes go in `remediated/`.
- Placeholder IDs only: `123456789012` (client), `111122223333` (partner). No real names, accounts, keys or employers.
- `checks/` is Python standard library only; pytest is the only dev dependency.
- If a fixture or check changes, run `make evidence` and update `report/` so the evidence and the prose agree.
  `make all` must pass before a commit.
- Checkov is pinned to 3.3.19 in `.pre-commit-config.yaml` (frozen SHA) and the Makefile; bump both together
  (ADR 0004). Pre-commit hooks are pinned by commit SHA with a `# frozen:` tag comment.
- ADRs in `docs/adr/` use the FoSA2 format with a Compliance section.
