"""
Asynchronous Web Crawler Engine.
High-concurrency crawler using aiohttp, per-domain rate limiting,
URL canonicalization, trafilatura content extraction, and real-time LLM JSONL writing.
"""

import asyncio
from collections import defaultdict
import random
import time
import urllib.parse
from typing import Dict, List, Optional, Set
import aiohttp
from bs4 import BeautifulSoup
from rich.console import Console

from config import (
    ALLOWED_DOMAINS, CRAWLER_SEEDS, DEFAULT_CONCURRENCY,
    PER_DOMAIN_DELAY_SECONDS, REQUEST_TIMEOUT_SECONDS, USER_AGENTS
)
from core.dedup import Deduplicator
from core.extractor import ContentExtractor
from core.writer import DatasetWriter

console = Console()

class AsyncCybersecCrawler:
    def __init__(
        self,
        writer: DatasetWriter,
        dedup: Deduplicator,
        extractor: ContentExtractor,
        concurrency: int = DEFAULT_CONCURRENCY,
        max_gb: float = 300.0,
        max_pages: Optional[int] = None
    ):
        self.writer = writer
        self.dedup = dedup
        self.extractor = extractor
        self.concurrency = concurrency
        self.max_bytes = max_gb * 1024 * 1024 * 1024
        self.max_pages = max_pages
        
        self.queue: asyncio.Queue = asyncio.Queue()
        self.domain_last_request: Dict[str, float] = defaultdict(float)
        self.domain_locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.running = False
        self.pages_crawled = 0
        self.docs_extracted = 0

    def is_allowed_url(self, url: str) -> bool:
        """Verifies if URL belongs to permitted educational and security domains."""
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            domain = parsed.netloc.lower().split(":")[0]
            return any(domain == d or domain.endswith("." + d) for d in ALLOWED_DOMAINS)
        except Exception:
            return False

    async def _fetch(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Fetches URL with per-domain polite delay, rotating UA, and error handling."""
        domain = urllib.parse.urlparse(url).netloc.lower()

        async with self.domain_locks[domain]:
            elapsed = time.time() - self.domain_last_request[domain]
            if elapsed < PER_DOMAIN_DELAY_SECONDS:
                await asyncio.sleep(PER_DOMAIN_DELAY_SECONDS - elapsed)
            self.domain_last_request[domain] = time.time()

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                if resp.status != 200:
                    return None
                
                content_type = resp.headers.get("Content-Type", "").lower()
                if not any(t in content_type for t in ("text/html", "application/xhtml+xml", "text/plain")):
                    return None

                return await resp.text(errors="ignore")
        except Exception:
            return None

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extracts and canonicalizes hyperlinks from HTML page."""
        new_links = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                full_url = urllib.parse.urljoin(base_url, href)
                clean_url = self.dedup.canonicalize_url(full_url)
                if self.is_allowed_url(clean_url) and not self.dedup.is_url_visited(clean_url):
                    new_links.append(clean_url)
        except Exception:
            pass
        return new_links

    async def _worker(self, session: aiohttp.ClientSession, worker_id: int):
        """Asynchronous worker pulling URLs from queue and processing them."""
        while self.running:
            if self.writer.total_bytes >= self.max_bytes:
                self.running = False
                break

            if self.max_pages and self.pages_crawled >= self.max_pages:
                self.running = False
                break

            try:
                url = await asyncio.wait_for(self.queue.get(), timeout=3.0)
            except asyncio.TimeoutError:
                if not self.running or self.queue.empty():
                    break
                continue

            if self.dedup.is_url_visited(url):
                self.queue.task_done()
                continue

            self.dedup.mark_url_visited(url)
            self.pages_crawled += 1

            html = await self._fetch(session, url)
            if html:
                doc = self.extractor.extract(html, url=url)
                if doc and (doc["relevance_score"] > 0 or len(doc["matched_topics"]) > 0):
                    if not self.dedup.is_duplicate_content(doc["text"]):
                        await self.writer.write_doc(
                            title=doc["title"],
                            text=doc["text"],
                            source_url=url,
                            topics=doc["matched_topics"],
                            metadata_extra={
                                "relevance_score": doc["relevance_score"],
                                "word_count": doc["word_count"]
                            }
                        )
                        self.docs_extracted += 1

                links = self._extract_links(html, url)
                for link in links:
                    if not self.dedup.is_url_visited(link) and self.queue.qsize() < 100_000:
                        await self.queue.put(link)

            self.queue.task_done()

    async def start(self, seed_urls: Optional[List[str]] = None):
        """Launches the asynchronous crawler workers with connection pooling."""
        self.running = True
        seeds = seed_urls or CRAWLER_SEEDS

        for seed in seeds:
            clean_seed = self.dedup.canonicalize_url(seed)
            if not self.dedup.is_url_visited(clean_seed):
                await self.queue.put(clean_seed)

        console.print(f"[bold cyan]Starting Crawler with {self.concurrency} workers and {self.queue.qsize()} initial seeds...[/bold cyan]")

        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            limit_per_host=5,
            ssl=False,
            enable_cleanup_closed=True
        )

        async with aiohttp.ClientSession(connector=connector) as session:
            workers = [
                asyncio.create_task(self._worker(session, i))
                for i in range(self.concurrency)
            ]
            
            try:
                while self.running:
                    if self.max_pages and self.pages_crawled >= self.max_pages:
                        self.running = False
                        break
                    if self.queue.empty():
                        await asyncio.sleep(2.0)
                        if self.queue.empty():
                            break
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                self.running = False
            finally:
                self.running = False
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

        console.print(f"[bold green]Crawler finished: Crawled {self.pages_crawled} pages, extracted {self.docs_extracted} high-relevance docs.[/bold green]")
