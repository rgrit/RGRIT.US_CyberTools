import feedparser
import requests

def fetch_rss_feed(rss_url):
    """Fetch and parse the RSS feed."""
    try:
        response = requests.get(rss_url, timeout=60)
        response.raise_for_status()
        return feedparser.parse(response.content).entries
    except requests.RequestException as e:
        print(f"[ERROR] Failed to fetch RSS feed: {e}")
        return []
