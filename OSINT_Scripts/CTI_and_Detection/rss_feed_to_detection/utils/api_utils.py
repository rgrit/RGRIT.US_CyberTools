import requests
import time
from config import OLLAMA_API_URL, MODEL_NAME

def call_ollama_api_with_retry(prompt, retries=3, delay=5):
    """Query the LLaMA API with retries for reliability."""
    payload = {
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    for attempt in range(1, retries + 1):
        try:
            response = requests.post(OLLAMA_API_URL, json=payload, timeout=300)
            response.raise_for_status()
            data = response.json()
            return data.get("message", {}).get("content", "").strip()
        except requests.RequestException as e:
            print(f"[WARNING] API call attempt {attempt} failed: {e}")
            if attempt < retries:
                time.sleep(delay)
    print("[ERROR] LLaMA API query failed after multiple attempts.")
    return "No response from LLaMA."
