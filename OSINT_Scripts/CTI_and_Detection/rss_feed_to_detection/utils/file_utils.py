import json

def load_processed_articles(file_path):
    """Load processed article IDs from a JSON file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return set(json.load(file))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def save_processed_articles(file_path, processed_ids):
    """Save processed article IDs to a JSON file."""
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(list(processed_ids), file, indent=4)
