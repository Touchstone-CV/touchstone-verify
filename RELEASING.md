# Releasing `touchstone-verify` to PyPI

Zero-dependency pure-Python package. Build is deterministic; the only human step is the
authenticated upload (needs a PyPI API token — the project owner's identity, with 2FA).

## Cut a release

1. Bump `version` in `pyproject.toml` and commit.
2. Tag: `git tag -a vX.Y.Z -m "…" && git push origin vX.Y.Z`
3. Build + validate:
   ```
   rm -rf dist build src/*.egg-info
   python3 -m build
   python3 -m twine check dist/*
   ```
4. Smoke the wheel in a clean venv (accepts valid, rejects tampered):
   ```
   python3 -m venv /tmp/tv && /tmp/tv/bin/pip install dist/*.whl
   /tmp/tv/bin/python -m pytest -q   # (from a checkout)
   ```
5. Upload. Put the token in a file (never on the command line / in shell history):
   ```
   # ~/.pypirc  OR pass via env read from a file:
   TWINE_USERNAME=__token__ TWINE_PASSWORD="$(cat ~/.pypi-token)" \
     python3 -m twine upload dist/*
   ```

## Notes
- `__token__` is the literal username for API-token auth.
- First publish creates the project and binds it to the uploading account.
- Prefer **PyPI Trusted Publishing** (OIDC from GitHub Actions) long-term — no long-lived
  token. Configure a publisher on PyPI for `Touchstone-CV/touchstone-verify` + a release
  workflow, then uploads need no secret.
- Version parity: keep this in lockstep with the in-repo PHP/JS verifiers. The differential
  fuzz (`verifier/fuzz_differential.py` in the Touchstone server repo) gates PHP/JS/Python
  agreement — a divergence here means a soundness regression, not a flaky test.
