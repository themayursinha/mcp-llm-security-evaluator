# Contributing

## Local Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Before Opening a PR
```bash
python -m black --check app evaluator tests
python -m flake8 app evaluator tests
python -m mypy
python -m pytest --cov=app --cov=evaluator
python -m app.main --quick --provider mock --format html
```

## Contribution Expectations
- Keep changes scoped and reviewable.
- Update docs when behavior or configuration changes.
- Add tests for public behavior changes.
- Do not commit real secrets, production credentials, or sensitive customer data.

## Areas That Need Care
- Report shape used by both CLI and API
- Redaction patterns and false-positive behavior
- Mock-provider behavior used in CI and smoke tests
- API security defaults
