# Release Checklist

- Recreate a clean virtualenv and install from `requirements.txt`
- Run `python -m black --check app evaluator tests`
- Run `python -m flake8 app evaluator tests`
- Run `python -m mypy`
- Run `python -m pytest --cov=app --cov=evaluator`
- Run `python -m app.main --quick --provider mock --format html`
- Confirm `README.md` matches current CLI and API behavior
- Confirm `.env.example` matches supported configuration
- Confirm generated reports and SQLite DB are not committed
- Review open issues or TODO markers that would undermine a public release
