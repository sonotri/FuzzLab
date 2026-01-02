import requests

def call_ollama(model: str, prompt: str, base_url: str = "http://localhost:11434") -> str:
    r = requests.post(
        f"{base_url}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False},
        timeout=120,
    )
    r.raise_for_status()
    return r.json()["response"]