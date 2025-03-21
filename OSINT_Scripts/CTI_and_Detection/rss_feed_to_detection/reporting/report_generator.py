# # # # import os
# # # # from config import now, OUTPUT_DIR
# # # #
# # # # def create_final_report(actionable_articles, output_dir):
# # # #     """Generate a Markdown report for threat intelligence, prioritizing articles with IoCs first."""
# # # #     if not actionable_articles:
# # # #         print("[INFO] No actionable intelligence to report.")
# # # #         return
# # # #
# # # #     # Ensure the reports directory exists
# # # #     if not os.path.exists(output_dir):
# # # #         os.makedirs(output_dir)
# # # #         print(f"[INFO] Created reports directory: {output_dir}")
# # # #
# # # #     # Separate articles with and without IoCs
# # # #     articles_with_iocs = [
# # # #         article for article in actionable_articles
# # # #         if "No IoCs found" not in article["iocs"]
# # # #     ]
# # # #     articles_without_iocs = [
# # # #         article for article in actionable_articles
# # # #         if "No IoCs found" in article["iocs"]
# # # #     ]
# # # #
# # # #     # Combine sorted articles (IoCs first, then non-IoCs)
# # # #     sorted_articles = articles_with_iocs + articles_without_iocs
# # # #
# # # #     # Generate the report filename
# # # #     report_filename = f"threat_report_{now.strftime('%Y%m%d')}.md"
# # # #     output_file = os.path.join(output_dir, report_filename)
# # # #
# # # #     with open(output_file, "w", encoding="utf-8") as file:
# # # #         file.write("# Threat Intelligence Report\n")
# # # #         file.write(f"## Report Date: {now.strftime('%B %d, %Y')}\n\n")
# # # #
# # # #         for article in sorted_articles:
# # # #             file.write(f"## {article['title']}\n")
# # # #             file.write(f"**Link:** {article['link']}\n\n")
# # # #             file.write(f"### Summary\n{article['summary']}\n\n")
# # # #
# # # #             # IoC Section
# # # #             if "No IoCs found" not in article["iocs"]:
# # # #                 file.write("### **Indicators of Compromise (IoCs) Found**\n")
# # # #                 file.write(f"{article['iocs']}\n\n")
# # # #             else:
# # # #                 file.write("### No Known IoCs\n(This article contained no detected indicators of compromise.)\n\n")
# # # #
# # # #             # Sigma Rule Feasibility Section (wrapped in code block)
# # # #             if article.get("sigma_assessment") and article["sigma_assessment"] != "Not enough information to create a Sigma rule.":
# # # #                 file.write("### **Sigma Rule Feasibility**\n")
# # # #                 file.write("```\n")
# # # #                 file.write(f"{article['sigma_assessment']}\n")
# # # #                 file.write("```\n\n")
# # # #
# # # #             # Sigma Tags Section (wrapped in code block)
# # # #             if article.get("sigma_tags"):
# # # #                 file.write("### Sigma Tags\n")
# # # #                 file.write("```\n")
# # # #                 file.write(f"{article['sigma_tags']}\n")
# # # #                 file.write("```\n\n")
# # # #
# # # #             # Detection Story Section
# # # #             if article.get("detection_story"):
# # # #                 file.write("### Detection Story\n")
# # # #                 ds = article["detection_story"]
# # # #                 file.write("**Context:**\n")
# # # #                 file.write(f"{ds.get('Context', '')}\n\n")
# # # #                 file.write("**Assumptions:**\n")
# # # #                 file.write(f"{ds.get('Assumptions', '')}\n\n")
# # # #                 file.write("**Detection Approach:**\n")
# # # #                 file.write(f"{ds.get('Detection Approach', '')}\n\n")
# # # #                 file.write("**Evaluation:**\n")
# # # #                 file.write(f"{ds.get('Evaluation', '')}\n\n")
# # # #                 file.write("**Limitations:**\n")
# # # #                 file.write(f"{ds.get('Limitations', '')}\n\n")
# # # #
# # # #             # Threats Section
# # # #             file.write(f"### Threats\n{article['threats']}\n\n")
# # # #
# # # #     print(f"[INFO] Report saved: {output_file}")
# # # import os
# # # import re
# # # from config import now, OUTPUT_DIR  # Ensure OUTPUT_DIR and now are defined in your config
# # #
# # # def sanitize_filename(filename):
# # #     """
# # #     Sanitize the filename by removing non-alphanumeric characters
# # #     and replacing spaces with underscores.
# # #     """
# # #     sanitized = re.sub(r'[^\w\s-]', '', filename).strip().lower()
# # #     sanitized = re.sub(r'[-\s]+', '_', sanitized)
# # #     return sanitized
# # #
# # # def create_final_report(actionable_articles, output_dir):
# # #     """Generate individual Markdown reports for each threat intelligence article."""
# # #     if not actionable_articles:
# # #         print("[INFO] No actionable intelligence to report.")
# # #         return
# # #
# # #     # Ensure the reports directory exists
# # #     if not os.path.exists(output_dir):
# # #         os.makedirs(output_dir)
# # #         print(f"[INFO] Created reports directory: {output_dir}")
# # #
# # #     for article in actionable_articles:
# # #         sanitized_title = sanitize_filename(article['title'])
# # #         report_filename = f"threat_report_{sanitized_title}_{now.strftime('%Y%m%d')}.md"
# # #         output_file = os.path.join(output_dir, report_filename)
# # #
# # #         with open(output_file, "w", encoding="utf-8") as file:
# # #             file.write("# Threat Intelligence Report\n")
# # #             file.write(f"## Report Date: {now.strftime('%B %d, %Y')}\n\n")
# # #             file.write(f"## {article['title']}\n")
# # #             file.write(f"**Link:** {article['link']}\n\n")
# # #             file.write(f"### Summary\n{article['summary']}\n\n")
# # #
# # #             # IoCs Section
# # #             if "No IoCs found" not in article["iocs"]:
# # #                 file.write("### **Indicators of Compromise (IoCs) Found**\n")
# # #                 file.write(f"{article['iocs']}\n\n")
# # #             else:
# # #                 file.write("### No Known IoCs\n(This article contained no detected indicators of compromise.)\n\n")
# # #
# # #             # Sigma Rule Feasibility & Recommended Sigma Tags
# # #             if article.get("sigma_assessment") and article["sigma_assessment"] != "Not enough information to create a Sigma rule.":
# # #                 file.write("### **Sigma Rule Feasibility & Recommended Sigma Tags**\n")
# # #                 file.write("```\n")
# # #                 file.write(f"{article['sigma_assessment']}\n")
# # #                 if article.get("sigma_tags"):
# # #                     file.write("\n# Recommended Sigma Tags:\n")
# # #                     for line in article['sigma_tags'].splitlines():
# # #                         file.write(f"# {line}\n")
# # #                 file.write("```\n\n")
# # #
# # #             # Detection Story Section
# # #             if article.get("detection_story"):
# # #                 file.write("### Detection Story\n")
# # #                 ds = article["detection_story"]
# # #                 file.write("**Context:**\n")
# # #                 file.write(f"{ds.get('Context', '')}\n\n")
# # #                 file.write("**Assumptions:**\n")
# # #                 file.write(f"{ds.get('Assumptions', '')}\n\n")
# # #                 file.write("**Detection Approach:**\n")
# # #                 file.write(f"{ds.get('Detection Approach', '')}\n\n")
# # #                 file.write("**Evaluation:**\n")
# # #                 file.write(f"{ds.get('Evaluation', '')}\n\n")
# # #                 file.write("**Limitations:**\n")
# # #                 file.write(f"{ds.get('Limitations', '')}\n\n")
# # #
# # #             # Threats Section
# # #             file.write(f"### Threats\n{article['threats']}\n\n")
# # #
# # #         print(f"[INFO] Report saved: {output_file}")
# # import os
# # import re
# # from config import now, OUTPUT_DIR  # Ensure OUTPUT_DIR and now are defined in your config
# #
# # def sanitize_filename(filename):
# #     """
# #     Sanitize the filename by removing non-alphanumeric characters
# #     and replacing spaces with underscores.
# #     """
# #     sanitized = re.sub(r'[^\w\s-]', '', filename).strip().lower()
# #     sanitized = re.sub(r'[-\s]+', '_', sanitized)
# #     return sanitized
# #
# # def create_individual_report(article, output_dir):
# #     """Generate a Markdown report for a single threat intelligence article."""
# #     # Ensure the reports directory exists
# #     if not os.path.exists(output_dir):
# #         os.makedirs(output_dir)
# #         print(f"[INFO] Created reports directory: {output_dir}")
# #
# #     sanitized_title = sanitize_filename(article['title'])
# #     report_filename = f"threat_report_{sanitized_title}_{now.strftime('%Y%m%d')}.md"
# #     output_file = os.path.join(output_dir, report_filename)
# #
# #     with open(output_file, "w", encoding="utf-8") as file:
# #         file.write("# Threat Intelligence Report\n")
# #         file.write(f"## Report Date: {now.strftime('%B %d, %Y')}\n\n")
# #         file.write(f"## {article['title']}\n")
# #         file.write(f"**Link:** {article['link']}\n\n")
# #         file.write(f"### Summary\n{article['summary']}\n\n")
# #
# #         # IoCs Section
# #         if "No IoCs found" not in article["iocs"]:
# #             file.write("### **Indicators of Compromise (IoCs) Found**\n")
# #             file.write(f"{article['iocs']}\n\n")
# #         else:
# #             file.write("### No Known IoCs\n(This article contained no detected indicators of compromise.)\n\n")
# #
# #         # Sigma Rule Feasibility & Recommended Sigma Tags !!!!
# #         if article.get("sigma_assessment") and article["sigma_assessment"] != "Not enough information to create a Sigma rule.":
# #             file.write("### **Sigma Rule Feasibility & Recommended Sigma Tags**\n")
# #             file.write("```\n")
# #             file.write(f"{article['sigma_assessment']}\n")
# #             if article.get("sigma_tags"):
# #                 file.write("\n# Recommended Sigma Tags:\n")
# #                 for line in article['sigma_tags'].splitlines():
# #                     file.write(f"# {line}\n")
# #             file.write("```\n\n")
# #
# #         # Detection Story Section:
# #         if article.get("detection_story"):
# #             file.write("### Detection Story\n")
# #             ds = article["detection_story"]
# #             file.write("**Context:**\n")
# #             file.write(f"{ds.get('Context', '')}\n\n")
# #             file.write("**Assumptions:**\n")
# #             file.write(f"{ds.get('Assumptions', '')}\n\n")
# #             file.write("**Detection Approach:**\n")
# #             file.write(f"{ds.get('Detection Approach', '')}\n\n")
# #             file.write("**Evaluation:**\n")
# #             file.write(f"{ds.get('Evaluation', '')}\n\n")
# #             file.write("**Limitations:**\n")
# #             file.write(f"{ds.get('Limitations', '')}\n\n")
# #
# #         # Threats Section
# #         file.write(f"### Threats\n{article['threats']}\n\n")
# #
# #     print(f"[INFO] Report saved: {output_file}")
# import os
# import re
# from config import now, OUTPUT_DIR  # Ensure OUTPUT_DIR and now are defined in your config
#
# def sanitize_filename(filename):
#     """
#     Sanitize the filename by removing non-alphanumeric characters
#     and replacing spaces with underscores.
#     """
#     sanitized = re.sub(r'[^\w\s-]', '', filename).strip().lower()
#     sanitized = re.sub(r'[-\s]+', '_', sanitized)
#     return sanitized
#
# def create_individual_report(article, output_dir):
#     """Generate a Markdown report for a single threat intelligence article."""
#     # Ensure the reports directory exists
#     if not os.path.exists(output_dir):
#         os.makedirs(output_dir)
#         print(f"[INFO] Created reports directory: {output_dir}")
#
#     sanitized_title = sanitize_filename(article['title'])
#     report_filename = f"threat_report_{sanitized_title}_{now.strftime('%Y%m%d')}.md"
#     output_file = os.path.join(output_dir, report_filename)
#
#     with open(output_file, "w", encoding="utf-8") as file:
#         file.write("# Threat Intelligence Report\n")
#         file.write(f"## Report Date: {now.strftime('%B %d, %Y')}\n\n")
#         file.write(f"## {article['title']}\n")
#         file.write(f"**Link:** {article['link']}\n\n")
#         file.write(f"### Summary\n{article['summary']}\n\n")
#
#         # IoCs Section
#         if "No IoCs found" not in article["iocs"]:
#             file.write("### **Indicators of Compromise (IoCs) Found**\n")
#             file.write(f"{article['iocs']}\n\n")
#         else:
#             file.write("### No Known IoCs\n(This article contained no detected indicators of compromise.)\n\n")
#
#         # Sigma Rule Feasibility & Recommended Sigma Tags
#         if article.get("sigma_assessment") and article["sigma_assessment"] != "Not enough information to create a Sigma rule.":
#             file.write("### **Sigma Rule Feasibility & Recommended Sigma Tags**\n")
#             file.write("```\n")
#             file.write(f"{article['sigma_assessment']}\n")
#             if article.get("sigma_tags"):
#                 file.write("\n# Recommended Sigma Tags:\n")
#                 for line in article['sigma_tags'].splitlines():
#                     file.write(f"# {line}\n")
#             file.write("```\n\n")
#
#         # Detection Story Section
#         if article.get("detection_story"):
#             file.write("### Detection Story\n")
#             ds = article["detection_story"]
#             file.write("**Context:**\n")
#             file.write(f"{ds.get('Context', '')}\n\n")
#             file.write("**Assumptions:**\n")
#             file.write(f"{ds.get('Assumptions', '')}\n\n")
#             file.write("**Detection Approach:**\n")
#             file.write(f"{ds.get('Detection Approach', '')}\n\n")
#             file.write("**Evaluation:**\n")
#             file.write(f"{ds.get('Evaluation', '')}\n\n")
#             file.write("**Limitations:**\n")
#             file.write(f"{ds.get('Limitations', '')}\n\n")
#
#         # Threats Section
#         file.write(f"### Threats\n{article['threats']}\n\n")
#
#     print(f"[INFO] Report saved: {output_file}")
import os
import re
from config import now, OUTPUT_DIR  # Ensure OUTPUT_DIR and now are defined in your config

def sanitize_filename(filename):
    """
    Sanitize the filename by removing non-alphanumeric characters
    and replacing spaces with underscores.
    """
    sanitized = re.sub(r'[^\w\s-]', '', filename).strip().lower()
    sanitized = re.sub(r'[-\s]+', '_', sanitized)
    return sanitized

def create_individual_report(article, output_dir):
    """Generate a Markdown report for a single threat intelligence article."""
    # Ensure the reports directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"[INFO] Created reports directory: {output_dir}")

    sanitized_title = sanitize_filename(article['title'])
    report_filename = f"threat_report_{sanitized_title}_{now.strftime('%Y%m%d')}.md"
    output_file = os.path.join(output_dir, report_filename)

    with open(output_file, "w", encoding="utf-8") as file:
        file.write("# Threat Intelligence Report\n")
        file.write(f"## Report Date: {now.strftime('%B %d, %Y')}\n\n")
        file.write(f"## {article['title']}\n")
        file.write(f"**Link:** {article['link']}\n\n")
        file.write(f"### Summary\n{article['summary']}\n\n")

        # IoCs Section
        if "No IoCs found" not in article["iocs"]:
            file.write("### Indicators of Compromise (IoCs) Found\n")
            file.write(f"{article['iocs']}\n\n")
        else:
            file.write("### No Known IoCs\n(This article contained no detected indicators of compromise.)\n\n")

        # Sigma Rule Feasibility & Recommended Sigma Tags Section (plain text)
        if article.get("sigma_assessment") and article["sigma_assessment"] != "Not enough information to create a Sigma rule.":
            file.write("### Sigma Rule Feasibility & Recommended Sigma Tags\n")
            file.write(f"{article['sigma_assessment']}\n")
            if article.get("sigma_tags"):
                file.write("\nRecommended Sigma Tags:\n")
                # Write each line of sigma tags without hashtags
                for line in article['sigma_tags'].splitlines():
                    file.write(f"{line}\n")
            file.write("\n\n")

        # Detection Story Section
        if article.get("detection_story"):
            file.write("### Detection Story\n")
            ds = article["detection_story"]
            file.write("Context:\n")
            file.write(f"{ds.get('Context', '')}\n\n")
            file.write("Assumptions:\n")
            file.write(f"{ds.get('Assumptions', '')}\n\n")
            file.write("Detection Approach:\n")
            file.write(f"{ds.get('Detection Approach', '')}\n\n")
            file.write("Evaluation:\n")
            file.write(f"{ds.get('Evaluation', '')}\n\n")
            file.write("Limitations:\n")
            file.write(f"{ds.get('Limitations', '')}\n\n")

        # Threats Section
        file.write("### Threats\n")
        file.write(f"{article['threats']}\n\n")

    print(f"[INFO] Report saved: {output_file}")
