from utils.api_utils import call_ollama_api_with_retry

def summarize_article(title: str, link: str, content: str) -> str:
    """
    Summarizes an article in 5-7 sentences, with an emphasis on
    detection-engineering or threat-hunting relevance if needed.
    """
    prompt = f"""\
You are a cyber threat intelligence and specialized in detection engineering.
Please review the following article and provide a concise summary.
Ensure you highlight any potential cybersecurity or threat-hunting angles if present.

Title: {title}
Link: {link}
Content: {content}

Return a short paragraph (5-7 sentences) that captures the main idea, emphasizing
any detection engineering insights (e.g., IoCs, TTPs) if relevant.
"""
    try:
        response = call_ollama_api_with_retry(prompt)
        return response.strip()
    except Exception as e:
        print(f"Error summarizing article: {e}")
        return "Error: Unable to summarize the article at this time."
