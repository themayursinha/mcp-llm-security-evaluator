from .llm import LLMClient

def run(prompt: str) -> str:
    client = LLMClient()
    return client.generate(prompt)
