from config import PROCESSED_ARTICLES_FILE, OUTPUT_DIR, RSS_URL
from utils.file_utils import load_processed_articles, save_processed_articles
from utils.rss_utils import fetch_rss_feed
from analysis.text_analysis import summarize_article
from analysis.threat_analysis import (
    identify_threats,
    extract_iocs,
    assess_sigma_rule_feasibility,
    suggest_sigma_tags,
    generate_detection_story
)
from reporting.report_generator import create_individual_report

def main():
    """Main function to fetch, analyze, and report threat intelligence articles."""
    print("[INFO] Starting threat intelligence processing...")

    processed_articles = load_processed_articles(PROCESSED_ARTICLES_FILE)
    articles = fetch_rss_feed(RSS_URL)
    print(f"[INFO] Total articles fetched: {len(articles)}")

    for article in articles:
        article_id = article.get("link", "No Link")
        if article_id in processed_articles:
            continue

        title = article.get("title", "No Title")
        link = article.get("link", "No Link")
        content = article.get("summary", "No Content")

        print(f"[INFO] Processing article: {title}")

        # 1. Summarize the article
        summary = summarize_article(title, link, content)

        # 2. Identify threats based on extracted artifacts
        threats = identify_threats(summary)

        # 3. Extract IoCs from the summary
        iocs = extract_iocs(summary)

        # 4. Assess Sigma rule feasibility
        sigma_assessment = assess_sigma_rule_feasibility(summary)

        # 5. Suggest Sigma tags
        sigma_tags = suggest_sigma_tags(summary)

        # 6. Generate a detection story
        detection_story = generate_detection_story(summary)

        # Build the data for the report
        actionable_article = {
            "title": title,
            "link": link,
            "summary": summary,
            "threats": threats,
            "iocs": iocs,
            "sigma_assessment": sigma_assessment,
            "sigma_tags": sigma_tags,
            "detection_story": detection_story
        }

        # Immediately generate an individual Markdown report for this article.
        create_individual_report(actionable_article, OUTPUT_DIR)

        processed_articles.add(article_id)

    save_processed_articles(PROCESSED_ARTICLES_FILE, processed_articles)
    print("[INFO] Threat intelligence processing complete.")

if __name__ == "__main__":
    main()
