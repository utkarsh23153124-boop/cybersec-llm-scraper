"""
Master Execution CLI for Cybersecurity LLM Data Pipeline.
Integrates Bulk Ingestion (MITRE CWE/CAPEC, OWASP WSTG/ASVS) and Async Crawler.
Streams clean, deduplicated JSONL files formatted for LLM training.
"""

import argparse
import asyncio
import signal
import sys
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import (
    DEFAULT_CHUNK_SIZE_MB, DEFAULT_CONCURRENCY, DEFAULT_MAX_GB,
    OUTPUT_DIR, STATE_DB_PATH
)
from core.dedup import Deduplicator
from core.extractor import ContentExtractor
from core.writer import DatasetWriter
from ingestion.async_crawler import AsyncCybersecCrawler
from ingestion.bulk_sources import BulkIngestionEngine

console = Console()

def display_banner():
    banner = """
    ███████╗███████╗██████╗ ███████╗███████╗ ██████╗██████╗  █████╗ ██████╗ 
    ██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗
    ██║     █████╗  ██████╔╝███████╗█████╗  ██║     ██████╔╝███████║██████╔╝
    ██║     ██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║     ██╔══██╗██╔══██║██╔═══╝ 
    ╚███████╗███████╗██████╔╝███████║███████╗╚██████╗██║  ██║██║  ██║██║     
     ╚══════╝╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     
    === High-Throughput Cybersecurity Ingestion Engine for LLM Training ===
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")

async def main():
    # Set Windows-compatible event loop policy if needed
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    parser = argparse.ArgumentParser(
        description="Cybersecurity LLM Dataset Ingestion & Crawling Pipeline"
    )
    parser.add_argument(
        "--mode",
        choices=["all", "bulk", "crawl"],
        default="all",
        help="Ingestion mode: 'bulk' (MITRE/OWASP repos), 'crawl' (async web crawler), or 'all' (both)"
    )
    parser.add_argument(
        "--max-gb",
        type=float,
        default=DEFAULT_MAX_GB,
        help=f"Target volume limit in Gigabytes (default: {DEFAULT_MAX_GB} GB)"
    )
    parser.add_argument(
        "--chunk-size-mb",
        type=int,
        default=DEFAULT_CHUNK_SIZE_MB,
        help=f"Partition size in MB for JSONL rotation (default: {DEFAULT_CHUNK_SIZE_MB} MB)"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Async worker count for crawler (default: {DEFAULT_CONCURRENCY})"
    )
    parser.add_argument(
        "--compress",
        action="store_true",
        help="Enable Gzip compression (.jsonl.gz) to drastically reduce disk usage"
    )
    parser.add_argument(
        "--test-sample",
        action="store_true",
        help="Run in test mode with limited samples to quickly verify pipeline health"
    )

    args = parser.parse_args()
    display_banner()

    console.print(Panel.fit(
        f"[bold green]Configuration Summary[/bold green]\n"
        f"• Mode: [yellow]{args.mode.upper()}[/yellow]\n"
        f"• Target Volume: [yellow]{args.max_gb} GB[/yellow]\n"
        f"• Chunk Size: [yellow]{args.chunk_size_mb} MB per JSONL[/yellow]\n"
        f"• Compression: [yellow]{'Enabled (.jsonl.gz)' if args.compress else 'Disabled (.jsonl)'}[/yellow]\n"
        f"• Concurrency: [yellow]{args.concurrency} async workers[/yellow]\n"
        f"• Output Directory: [cyan]{OUTPUT_DIR}[/cyan]",
        title="Pipeline Settings"
    ))

    # Initialize Core Components
    writer = DatasetWriter(
        output_dir=OUTPUT_DIR,
        chunk_size_mb=args.chunk_size_mb,
        compress=args.compress
    )
    dedup = Deduplicator(db_path=STATE_DB_PATH)
    extractor = ContentExtractor()

    start_time = time.time()

    try:
        # Step 1: Bulk Ingestion Engine
        if args.mode in ("all", "bulk"):
            console.print("\n[bold magenta]=== Starting Phase 1: High-Volume Bulk Open Data Ingestion ===[/bold magenta]")
            bulk_engine = BulkIngestionEngine(writer=writer, dedup=dedup)
            
            if args.test_sample:
                # Test with MITRE CWE and one OWASP repo for quick verification
                console.print("[yellow]Running quick sample verification for bulk ingestion...[/yellow]")
                await bulk_engine.ingest_owasp_repository(
                    repo_name="Top10",
                    zip_url="https://github.com/OWASP/Top10/archive/refs/heads/master.zip",
                    topics=["OWASP Top 10", "Web Security"]
                )
            else:
                await bulk_engine.run_all_bulk_sources()

        # Step 2: Async Web Crawler Engine
        if args.mode in ("all", "crawl"):
            console.print("\n[bold magenta]=== Starting Phase 2: High-Speed Async Web Crawler ===[/bold magenta]")
            max_pages = 25 if args.test_sample else None
            crawler = AsyncCybersecCrawler(
                writer=writer,
                dedup=dedup,
                extractor=extractor,
                concurrency=args.concurrency if not args.test_sample else 5,
                max_gb=args.max_gb,
                max_pages=max_pages
            )

            # In test mode, only crawl first 3 seeds
            seeds = None
            if args.test_sample:
                from config import CRAWLER_SEEDS
                seeds = CRAWLER_SEEDS[:3]
                console.print(f"[yellow]Test sample mode active: crawling first {len(seeds)} seeds (capped at 25 pages)...[/yellow]")

            await crawler.start(seed_urls=seeds)

    except KeyboardInterrupt:
        console.print("\n[bold red]Received interrupt signal. Gracefully flushing buffers and closing...[/bold red]")
    finally:
        writer.close()
        elapsed = time.time() - start_time
        
        # Summary Report
        summary_table = Table(title="Cybersecurity LLM Dataset Ingestion Summary", show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Total Documents Collected", f"{writer.total_docs:,}")
        summary_table.add_row("Total Data Size", f"{writer.total_megabytes:.2f} MB ({writer.total_gigabytes:.3f} GB)")
        summary_table.add_row("Elapsed Time", f"{elapsed:.1f} seconds")
        summary_table.add_row("Output Partitions", f"{writer.current_part} chunk file(s)")
        summary_table.add_row("Storage Location", str(OUTPUT_DIR))
        
        console.print("\n")
        console.print(summary_table)
        console.print("[bold green]✓ Pipeline execution finished successfully.[/bold green]\n")

if __name__ == "__main__":
    asyncio.run(main())
