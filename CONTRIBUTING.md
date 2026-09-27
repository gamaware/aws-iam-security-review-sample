# Contributing

Thanks for helping improve this sample. Keep changes small and keep the evidence honest.

## Set up

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
pre-commit install --hook-type pre-commit --hook-type commit-msg
make all PYTHON=.venv/bin/python
```

`make checkov` uses `uvx` to run a pinned Checkov, so install [uv](https://docs.astral.sh/uv/) as well. Terraform 1.10
or later is needed for `make terraform`.

## Rules

- Work on a branch and open a pull request; `main` is protected.
- Conventional commit titles (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`, `refactor:`).
- A new check needs unit tests, a line in the report's check reference, and a fixture that triggers it in
  `sample-account/export/` and stays clean in `remediated/export/`.
- If a fixture or check changes, run `make evidence` and explain the evidence diff in the pull request.
- Placeholder IDs only: `123456789012` for the client, `111122223333` for a third party. No real names or accounts.
- Checkov skips on `remediated/` code need a reason on the same line, next to the resource.
- Record significant design decisions as an ADR in [`docs/adr/`](docs/adr/).
