import re
import logging

logging.basicConfig(level=logging.INFO, filename='data/logs/content.log')

SPAM_KEYWORDS = ['viagra', 'free money', 'win lottery', 'click here']

def check_content_filters(body: str) -> bool:
    """
    Rule-based content filter.
    Returns True if spam, False if clean.
    """
    for keyword in SPAM_KEYWORDS:
        if re.search(keyword, body, re.IGNORECASE):
            logging.info(f"Keyword '{keyword}' found in content")
            return True
    # Add more rules: URL count, attachment checks, etc.
    return False