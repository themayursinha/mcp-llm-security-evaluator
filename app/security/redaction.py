def redact(text: str) -> str:
    return text.replace("secret", "[REDACTED]")
