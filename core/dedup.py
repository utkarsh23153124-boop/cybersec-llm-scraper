"""
Deduplication and State Management Engine.
Handles URL normalization, xxhash-based content deduplication,
and disk-backed SQLite state storage for crash resilience and resumability.
"""

import sqlite3
import urllib.parse
from pathlib import Path
from typing import Optional, Set
import xxhash

class Deduplicator:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.memory_hashes: Set[str] = set()
        self.memory_urls: Set[str] = set()
        self.max_memory_items = 500_000
        self._init_db()

    def _init_db(self):
        """Initialize SQLite state database tables with indexed columns."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS visited_urls (
                    url_hash TEXT PRIMARY KEY,
                    url TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS content_hashes (
                    content_hash TEXT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    @staticmethod
    def canonicalize_url(url: str) -> str:
        """Removes tracking query parameters, hashes, and normalizes trailing slashes."""
        try:
            parsed = urllib.parse.urlparse(url.strip())
            # Clean common tracking and session parameters
            query_params = urllib.parse.parse_qs(parsed.query)
            tracking_keys = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", 
                             "ref", "source", "fbclid", "gclid", "session_id"}
            filtered_params = {k: v for k, v in query_params.items() if k.lower() not in tracking_keys}
            new_query = urllib.parse.urlencode(filtered_params, doseq=True)
            
            clean_path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
            clean_url = urllib.parse.urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                clean_path,
                "",  # params
                new_query,
                ""   # fragment
            ))
            return clean_url
        except Exception:
            return url

    def is_url_visited(self, url: str) -> bool:
        """Checks if a URL has already been visited/crawled."""
        clean_url = self.canonicalize_url(url)
        url_hash = xxhash.xxh64(clean_url.encode("utf-8")).hexdigest()

        if url_hash in self.memory_urls:
            return True

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM visited_urls WHERE url_hash = ?", (url_hash,))
            exists = cursor.fetchone() is not None

        if exists:
            if len(self.memory_urls) < self.max_memory_items:
                self.memory_urls.add(url_hash)
            return True
        return False

    def mark_url_visited(self, url: str):
        """Marks a URL as visited in memory and disk."""
        clean_url = self.canonicalize_url(url)
        url_hash = xxhash.xxh64(clean_url.encode("utf-8")).hexdigest()
        
        if len(self.memory_urls) < self.max_memory_items:
            self.memory_urls.add(url_hash)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO visited_urls (url_hash, url) VALUES (?, ?)", (url_hash, clean_url))
            conn.commit()

    def is_duplicate_content(self, text: str) -> bool:
        """Computes content hash to verify if identical text has already been saved."""
        normalized_sample = " ".join(text[:10000].split())  # Normalize whitespaces
        c_hash = xxhash.xxh64(normalized_sample.encode("utf-8")).hexdigest()

        if c_hash in self.memory_hashes:
            return True

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM content_hashes WHERE content_hash = ?", (c_hash,))
            exists = cursor.fetchone() is not None

        if exists:
            if len(self.memory_hashes) < self.max_memory_items:
                self.memory_hashes.add(c_hash)
            return True

        # New unique content
        if len(self.memory_hashes) < self.max_memory_items:
            self.memory_hashes.add(c_hash)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO content_hashes (content_hash) VALUES (?)", (c_hash,))
            conn.commit()

        return False
