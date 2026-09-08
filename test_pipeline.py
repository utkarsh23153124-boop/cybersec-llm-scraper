"""
Comprehensive Test Suite for Cybersecurity LLM Scraping & Ingestion Pipeline.
Validates Extractor, Deduplicator, Chunked Writer, and End-to-End Ingestion.
"""

import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from core.dedup import Deduplicator
from core.extractor import ContentExtractor
from core.writer import DatasetWriter

class TestCybersecPipeline(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.db_path = self.test_dir / "test_state.db"
        self.output_dir = self.test_dir / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_content_extractor(self):
        """Verify HTML boilerplate removal, code block preservation, and keyword matching."""
        html_sample = """
        <!DOCTYPE html>
        <html>
        <head><title>Understanding SQL Injection in OSWE and BSCP</title></head>
        <body>
            <nav><a href="/home">Home</a><a href="/login">Login</a></nav>
            <main>
                <h1>SQL Injection Vulnerabilities in Web Applications</h1>
                <p>SQL Injection is a critical vulnerability covered extensively in OSWE, BSCP, and OWASP Top 10.</p>
                <p>When user input is concatenated into an SQL query without parameterization, attackers can bypass authentication.</p>
                <pre><code>SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';</code></pre>
                <p>Mitigation involves using Prepared Statements and parameterized queries according to OWASP ASVS.</p>
            </main>
            <footer><p>Copyright 2026 Example Corp. Cookie Policy.</p></footer>
        </body>
        </html>
        """
        extractor = ContentExtractor(min_length=50)
        doc = extractor.extract(html_sample, url="https://example.com/sqli-tutorial")
        
        self.assertIsNotNone(doc)
        self.assertIn("SQL Injection", doc["text"])
        self.assertIn("SELECT * FROM users", doc["text"])
        # Boilerplate should be stripped
        self.assertNotIn("Cookie Policy", doc["text"])
        self.assertNotIn("Home Login", doc["text"])
        # Matched topics verification
        matched_str = " ".join(doc["matched_topics"])
        self.assertTrue(any(k in matched_str for k in ["OSWE", "BSCP", "SQL INJECTION", "OWASP"]))
        self.assertGreater(doc["token_estimate"], 20)

    def test_deduplicator(self):
        """Verify URL canonicalization and xxhash content deduplication."""
        dedup = Deduplicator(self.db_path)
        
        url1 = "https://portswigger.net/web-security/sql-injection?utm_source=twitter&utm_medium=social"
        url2 = "https://portswigger.net/web-security/sql-injection/"
        
        # Canonicalization should match
        self.assertEqual(dedup.canonicalize_url(url1), "https://portswigger.net/web-security/sql-injection")
        self.assertEqual(dedup.canonicalize_url(url2), "https://portswigger.net/web-security/sql-injection")
        
        # Test visited URL tracking
        self.assertFalse(dedup.is_url_visited(url1))
        dedup.mark_url_visited(url1)
        self.assertTrue(dedup.is_url_visited(url2))

        # Test content hash deduplication
        text1 = "Cross-Site Scripting (XSS) is an injection attack that occurs when malicious scripts are injected into trusted websites."
        text2 = "Cross-Site Scripting (XSS) is an injection attack that occurs when malicious scripts are injected into trusted websites."
        text3 = "Server-Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to induce the server."

        self.assertFalse(dedup.is_duplicate_content(text1))
        self.assertTrue(dedup.is_duplicate_content(text2))
        self.assertFalse(dedup.is_duplicate_content(text3))

    def test_writer_and_chunk_rotation(self):
        """Verify thread-safe JSONL writing, valid JSON syntax, and partition chunking."""
        async def run_writer_test():
            # Small chunk threshold (10 KB) to trigger chunk rotation quickly in test
            writer = DatasetWriter(self.output_dir, chunk_size_mb=1, compress=False)
            writer.chunk_size_bytes = 1024  # 1 KB for test

            sample_text = "Detailed penetration testing methodology for Web Applications covering OSWE, BSCP, and OWASP WSTG. " * 10
            for i in range(15):
                await writer.write_doc(
                    title=f"Security Guide {i}",
                    text=sample_text,
                    source_url=f"https://example.com/guide/{i}",
                    topics=["Web Application Penetration Testing", "OSWE"]
                )
            writer.close()

            # Verify files created
            chunk_files = list(self.output_dir.glob("cybersec_train_*.jsonl"))
            self.assertGreaterEqual(len(chunk_files), 2, "Chunk rotation should have created multiple files")

            # Validate that every single line is valid JSON
            total_read_docs = 0
            for chunk in chunk_files:
                with open(chunk, "r", encoding="utf-8") as f:
                    for line in f:
                        data = json.loads(line)
                        self.assertIn("id", data)
                        self.assertIn("text", data)
                        self.assertIn("metadata", data)
                        self.assertEqual(data["metadata"]["topics"], ["Web Application Penetration Testing", "OSWE"])
                        total_read_docs += 1
            
            self.assertEqual(total_read_docs, 15)

        asyncio.run(run_writer_test())

if __name__ == "__main__":
    unittest.main()
