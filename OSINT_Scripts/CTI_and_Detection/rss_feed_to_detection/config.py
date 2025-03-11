from datetime import datetime, timedelta

from Email.email_security_report import MODEL_NAME

# RSS Configuration
RSS_URL = "<<YOUR FRESHRSS API>>"

# API Configuration
OLLAMA_API_URL = "http://localhost:11434/api/chat"
#MODEL_NAME = "qwen2.5-coder:32b"
# MODEL_NAME = "llama3.3:latest"
# MODEL_NAME = "qwen2.5-coder:latest"
# MODEL_NAME = "gemma2:27b"
MODEL_NAME = "granite3.2-vision "
# File Paths
PROCESSED_ARTICLES_FILE = "processed_articles.json"
OUTPUT_DIR = "reports"

# Time Handling
now = datetime.now()
yesterday = now - timedelta(days=1)
