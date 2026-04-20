# Contributing to LLM Shield

Thank you for your interest in contributing. LLM Shield is built to be a
reference implementation — contributions that improve correctness, coverage,
or usability are very welcome.

## What we most need

**Injection patterns** — if you encounter a novel injection technique not
covered by `injection_detector.py`, please open an issue with a proof-of-concept
prompt (sanitised if needed) and the expected risk classification.

**PII entity types** — the current regex library covers US-centric patterns.
Contributions for UK, EU, Indian, or APAC formats (Aadhaar, PAN, NHS numbers,
sort codes, etc.) would meaningfully expand coverage.

**LLM backend adapters** — OpenAI-compatible backends work out of the box.
If your backend has a different API shape, a thin adapter layer is welcome.

**Documentation** — architecture explanations, deployment guides, and
use-case walkthroughs help practitioners adopt the project confidently.

## How to contribute

1. **Fork** the repo and create a feature branch: `git checkout -b feat/my-feature`
2. **Write tests** for any new detection patterns or logic changes
3. **Run the test suite**: `pytest tests/ -v`
4. **Run the linter**: `ruff check gateway/`
5. **Open a PR** with a clear description of what changed and why

## Contributor/Contact
 Shashankitrai@gmail.com

## Pull request guidelines

- Keep PRs focused — one feature or fix per PR
- New injection patterns must include a test case in `tests/test_security.py`
- New PII patterns must include at least one positive and one negative test
- Do not include real PII in test cases — use synthetic data only
- Update `README.md` if your change affects the public interface or configuration

## Reporting security issues

If you discover a bypass or vulnerability in LLM Shield itself, please **do not
open a public issue**. Open a private security advisory on GitHub instead.

## Code style

- Python 3.11+, type hints where practical
- `ruff` for linting (config in `pyproject.toml` if present, else defaults)
- Docstrings on all public functions and classes
- No dependencies beyond what is in `requirements.txt` without discussion

## Disclaimer reminder

LLM Shield is a defence-in-depth layer. Contributors should not claim or imply
that any change achieves perfect security — the project README carries a
deliberate disclaimer about this and we intend to keep it.
