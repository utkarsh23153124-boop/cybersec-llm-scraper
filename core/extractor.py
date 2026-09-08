"""
Content Extractor Module.
Uses trafilatura and BeautifulSoup to extract clean markdown, preserve code snippets,
strip boilerplate (nav, ads, footers, cookies), and score cybersecurity topic relevance.
"""

import re
from typing import Dict, List, Optional, Tuple
import trafilatura
from bs4 import BeautifulSoup
from config import ALL_KEYWORDS_LOWER, TARGET_CERTIFICATIONS, TARGET_TOPICS

# Compile regex pattern for fast keyword matching
_KEYWORDS_SORTED = sorted(ALL_KEYWORDS_LOWER, key=len, reverse=True)
_KEYWORD_REGEX = re.compile(r'\b(' + '|'.join(re.escape(k) for k in _KEYWORDS_SORTED) + r')\b', re.IGNORECASE)

class ContentExtractor:
    def __init__(self, min_length: int = 150):
        self.min_length = min_length

    def extract(self, html_content: str, url: str = "") -> Optional[Dict]:
        """
        Extracts clean text/markdown and metadata from raw HTML.
        Returns a dict suitable for LLM dataset generation, or None if content is invalid/too short.
        """
        if not html_content or len(html_content.strip()) < self.min_length:
            return None

        # 1. Primary extraction using trafilatura (retains markdown headers, code, tables)
        extracted_text = None
        extracted_title = None
        try:
            extracted_text = trafilatura.extract(
                html_content,
                url=url,
                output_format="markdown",
                include_links=True,
                include_images=False,
                include_tables=True,
                include_comments=False,
                favor_recall=True,
                deduplicate=True
            )
            # Try getting title via trafilatura metadata
            meta = trafilatura.extract_metadata(html_content)
            if meta and meta.title:
                extracted_title = meta.title
        except Exception:
            extracted_text = None

        # 2. Fallback to BeautifulSoup if trafilatura produces empty result
        if not extracted_text or len(extracted_text.strip()) < self.min_length:
            extracted_text, fallback_title = self._fallback_extract(html_content)
            if not extracted_title:
                extracted_title = fallback_title

        if not extracted_text or len(extracted_text.strip()) < self.min_length:
            return None

        # 3. Topic & Certification Matching
        matched_topics, score = self._match_topics(extracted_text, extracted_title or "")

        # 4. Token count estimate (~1.3 tokens per word for technical/code text)
        words = extracted_text.split()
        word_count = len(words)
        token_estimate = int(word_count * 1.33)

        return {
            "title": extracted_title or "Cybersecurity Knowledge Document",
            "text": extracted_text.strip(),
            "word_count": word_count,
            "token_estimate": token_estimate,
            "matched_topics": matched_topics,
            "relevance_score": score
        }

    def _fallback_extract(self, html_content: str) -> Tuple[Optional[str], Optional[str]]:
        """Fallback extraction using BeautifulSoup for simple or unconventional HTML structures."""
        try:
            soup = BeautifulSoup(html_content, "lxml")
            
            # Remove script, style, nav, footer, noscript, and cookie elements
            for tag in soup(["script", "style", "nav", "footer", "aside", "header", "noscript", "svg"]):
                tag.decompose()

            title = soup.title.string.strip() if soup.title and soup.title.string else None
            
            # Attempt to find main content container
            main_container = soup.find(["main", "article", "div[role='main']"]) or soup.body
            if not main_container:
                return None, title

            text = main_container.get_text(separator="\n\n", strip=True)
            # Normalize whitespace
            clean_text = re.sub(r'\n{3,}', '\n\n', text)
            return clean_text, title
        except Exception:
            return None, None

    def _match_topics(self, text: str, title: str) -> Tuple[List[str], int]:
        """Matches text against target cybersecurity topics and certifications."""
        combined_text = f"{title}\n{text[:4000]}"  # Check title and first 4000 chars for speed
        matches = set(_KEYWORD_REGEX.findall(combined_text.lower()))
        
        matched_tags = []
        score = 0
        for m in matches:
            matched_tags.append(m.upper())
            score += 1

        return matched_tags[:15], score
