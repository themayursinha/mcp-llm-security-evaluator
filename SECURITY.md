# Security Policy

## Reporting a Vulnerability
If you find a vulnerability in this project, do not open a public issue with exploit details. Share the report privately with the project maintainer first.

Include:
- affected version or commit
- reproduction steps
- impact assessment
- suggested mitigation if available

## Scope Notes
- Fixture secrets in `data/` are synthetic and intentionally included for evaluator testing.
- `.env.example` contains placeholders only.
- The built-in monitor UI and mock provider are intended for local or trusted demo use unless you harden deployment settings yourself.

## Hardening Expectations
Before deploying beyond local development:
- enable API auth if remote users can trigger evaluations
- restrict `API_ALLOWED_ORIGINS`
- use real provider credentials through environment variables or a secrets manager
- treat generated reports as sensitive review artifacts
