"""
Partitioned JSONL Streaming Writer.
Handles chunked file rotation, optional gzip compression,
thread-safe async writing, and LLM dataset schemas (pretraining & instruction tuning).
"""

import asyncio
import datetime
import gzip
import json
from pathlib import Path
from typing import Any, Dict, Optional
import uuid

class DatasetWriter:
    def __init__(self, output_dir: Path, chunk_size_mb: int = 500, compress: bool = False):
        self.output_dir = output_dir
        self.chunk_size_bytes = chunk_size_mb * 1024 * 1024
        self.compress = compress
        self.current_part = 1
        self.current_file = None
        self.current_file_bytes = 0
        self.total_docs = 0
        self.total_bytes = 0
        self.lock = asyncio.Lock()
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._find_next_part_index()
        self._open_next_partition()

    def _find_next_part_index(self):
        """Scans directory to find highest partition index to resume safely."""
        suffix = ".jsonl.gz" if self.compress else ".jsonl"
        existing = list(self.output_dir.glob(f"cybersec_train_*{suffix}"))
        if existing:
            indices = []
            for p in existing:
                try:
                    num_part = int(p.stem.replace(".jsonl", "").split("_")[-1])
                    indices.append(num_part)
                except ValueError:
                    pass
            if indices:
                self.current_part = max(indices) + 1

    def _open_next_partition(self):
        """Closes previous partition if open, and creates a new chunk file."""
        if self.current_file:
            self.current_file.close()

        ext = ".jsonl.gz" if self.compress else ".jsonl"
        file_path = self.output_dir / f"cybersec_train_{self.current_part:04d}{ext}"
        
        if self.compress:
            self.current_file = gzip.open(file_path, "wt", encoding="utf-8")
        else:
            self.current_file = open(file_path, "a", encoding="utf-8")

        self.current_file_bytes = file_path.stat().st_size if file_path.exists() else 0

    async def write_doc(self, title: str, text: str, source_url: str, topics: list, metadata_extra: Optional[Dict] = None) -> int:
        """
        Writes a clean document in standardized LLM pre-training format.
        Thread-safe and rotates files automatically when chunk threshold is reached.
        """
        async with self.lock:
            doc_id = f"csec_{uuid.uuid4().hex[:12]}"
            record = {
                "id": doc_id,
                "text": text,
                "metadata": {
                    "title": title,
                    "source": source_url,
                    "topics": topics,
                    "token_estimate": int(len(text.split()) * 1.33),
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    **(metadata_extra or {})
                }
            }

            line = json.dumps(record, ensure_ascii=False) + "\n"
            line_bytes = len(line.encode("utf-8"))

            self.current_file.write(line)
            self.current_file.flush()

            self.current_file_bytes += line_bytes
            self.total_bytes += line_bytes
            self.total_docs += 1

            # Rotate chunk if limit exceeded
            if self.current_file_bytes >= self.chunk_size_bytes:
                self.current_part += 1
                self._open_next_partition()

            return line_bytes

    def close(self):
        """Flushes and cleanly closes the current active output file."""
        if self.current_file:
            self.current_file.flush()
            self.current_file.close()
            self.current_file = None

    @property
    def total_megabytes(self) -> float:
        return self.total_bytes / (1024 * 1024)

    @property
    def total_gigabytes(self) -> float:
        return self.total_bytes / (1024 * 1024 * 1024)
