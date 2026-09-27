#!/usr/bin/env bash
# Post-edit hook: auto-format the file that was just edited.
set -euo pipefail

if ! command -v jq > /dev/null 2>&1; then
  exit 0
fi

FILE_PATH="$(jq -r '.tool_input.file_path // empty' 2> /dev/null || true)"

case "$FILE_PATH" in
  *.sh)
    if command -v shellharden > /dev/null 2>&1; then
      shellharden --replace "$FILE_PATH" 2> /dev/null || true
    fi
    ;;
  *.md)
    if command -v markdownlint-cli2 > /dev/null 2>&1; then
      markdownlint-cli2 --fix "$FILE_PATH" > /dev/null 2>&1 || true
    fi
    ;;
  *.tf)
    if command -v terraform > /dev/null 2>&1; then
      terraform fmt "$FILE_PATH" > /dev/null 2>&1 || true
    fi
    ;;
  *.py)
    if command -v ruff > /dev/null 2>&1; then
      ruff format "$FILE_PATH" > /dev/null 2>&1 || true
    fi
    ;;
esac
