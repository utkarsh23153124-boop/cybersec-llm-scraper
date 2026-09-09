"""
Bulk Ingestion Module.
Downloads and processes authoritative, large-scale cybersecurity knowledge bases:
- MITRE CWE (Common Weakness Enumeration XML catalog)
- MITRE CAPEC (Common Attack Pattern Enumeration XML catalog)
- OWASP Repositories (WSTG, ASVS, CheatSheetSeries, Top 10 via GitHub archives)
- Converts raw technical definitions into rich markdown formatted LLM training docs.
"""

import asyncio
import io
import os
from pathlib import Path
import re
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET
import zipfile
import requests
from rich.console import Console

from config import CACHE_DIR, BULK_DATA_FEEDS
from core.dedup import Deduplicator
from core.writer import DatasetWriter

console = Console()

class BulkIngestionEngine:
    def __init__(self, writer: DatasetWriter, dedup: Deduplicator):
        self.writer = writer
        self.dedup = dedup
        self.cache_dir = CACHE_DIR / "bulk"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _download_file(self, url: str, target_filename: str) -> Path:
        """Downloads a remote file with streaming chunks and caching."""
        target_path = self.cache_dir / target_filename
        if target_path.exists() and target_path.stat().st_size > 1000:
            console.print(f"[green][Cached][/green] Using cached file: {target_filename}")
            return target_path

        console.print(f"[cyan][Downloading][/cyan] {url} -> {target_filename}...")
        headers = {"User-Agent": "CyberSec-LLM-Ingestion/1.0"}
        response = requests.get(url, headers=headers, stream=True, timeout=60)
        response.raise_for_status()

        temp_path = target_path.with_suffix(".tmp")
        with open(temp_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
        temp_path.rename(target_path)
        console.print(f"[green][Downloaded][/green] Successfully saved {target_filename} ({target_path.stat().st_size / 1024 / 1024:.2f} MB)")
        return target_path

    async def ingest_mitre_cwe(self) -> int:
        """Downloads, unpacks, and parses the complete MITRE CWE catalog into LLM JSONL."""
        console.print("\n[bold yellow]─── Ingesting MITRE CWE (Common Weakness Enumeration) ───[/bold yellow]")
        url = BULK_DATA_FEEDS["mitre_cwe"]["url"]
        zip_path = self._download_file(url, "cwe_latest.xml.zip")
        
        count = 0
        with zipfile.ZipFile(zip_path, 'r') as z:
            xml_filenames = [n for n in z.namelist() if n.endswith(".xml")]
            if not xml_filenames:
                console.print("[red]Error: No XML file found in MITRE CWE zip.[/red]")
                return 0

            with z.open(xml_filenames[0]) as xml_file:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                # Namespace handling
                ns = {"cwe": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
                
                # Find all Weakness elements
                weaknesses = root.findall(".//{*}Weakness") or root.findall(".//Weakness")
                console.print(f"Found {len(weaknesses)} CWE weakness definitions. Processing...")

                for w in weaknesses:
                    cwe_id = w.attrib.get("ID", "")
                    name = w.attrib.get("Name", "")
                    abstraction = w.attrib.get("Abstraction", "")
                    status = w.attrib.get("Status", "")

                    desc_elem = w.find("{*}Description") or w.find("Description")
                    description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

                    ext_desc_elem = w.find("{*}Extended_Description") or w.find("Extended_Description")
                    ext_desc = ext_desc_elem.text.strip() if ext_desc_elem is not None and ext_desc_elem.text else ""

                    # Mitigations
                    mitigations = []
                    for mit in w.findall(".//{*}Mitigation") or w.findall(".//Mitigation"):
                        phase_elem = mit.find("{*}Phase") or mit.find("Phase")
                        strat_elem = mit.find("{*}Strategy") or mit.find("Strategy")
                        mit_desc = mit.find("{*}Description") or mit.find("Description")
                        phase = phase_elem.text if phase_elem is not None and phase_elem.text else "General"
                        strat = strat_elem.text if strat_elem is not None and strat_elem.text else ""
                        d = mit_desc.text if mit_desc is not None and mit_desc.text else ""
                        mitigations.append(f"- **Phase ({phase}) {strat}**: {d}")

                    # Code Demonstrative Examples
                    examples = []
                    for ex in w.findall(".//{*}Demonstrative_Example") or w.findall(".//Demonstrative_Example"):
                        ex_intro = ex.find("{*}Intro_Text_Block") or ex.find("Intro_Text_Block")
                        intro_text = ex_intro.text if ex_intro is not None and ex_intro.text else ""
                        ex_body = ex.find("{*}Example_Code") or ex.find("Example_Code")
                        code_body = ex_body.text if ex_body is not None and ex_body.text else ""
                        if intro_text or code_body:
                            examples.append(f"#### Example\n{intro_text}\n```\n{code_body}\n```")

                    # Construct rich Markdown text
                    md_parts = [
                        f"# CWE-{cwe_id}: {name}",
                        f"**Abstraction**: {abstraction} | **Status**: {status}",
                        f"## Description\n{description}",
                    ]
                    if ext_desc:
                        md_parts.append(f"## Extended Description\n{ext_desc}")
                    if examples:
                        md_parts.append("## Demonstrative Code Examples\n" + "\n\n".join(examples))
                    if mitigations:
                        md_parts.append("## Potential Mitigations\n" + "\n".join(mitigations))

                    full_text = "\n\n".join(md_parts)
                    source_url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                    
                    if not self.dedup.is_duplicate_content(full_text):
                        await self.writer.write_doc(
                            title=f"CWE-{cwe_id}: {name}",
                            text=full_text,
                            source_url=source_url,
                            topics=["MITRE CWE", "Secure Code Review", "Application Security", name]
                        )
                        count += 1

        console.print(f"[green]✓ Ingested {count} unique MITRE CWE definitions.[/green]")
        return count

    async def ingest_mitre_capec(self) -> int:
        """Downloads, unpacks, and parses the complete MITRE CAPEC attack pattern catalog."""
        console.print("\n[bold yellow]─── Ingesting MITRE CAPEC (Attack Pattern Catalog) ───[/bold yellow]")
        url = BULK_DATA_FEEDS["mitre_capec"]["url"]
        zip_path = self._download_file(url, "capec_latest.xml.zip")

        count = 0
        with zipfile.ZipFile(zip_path, 'r') as z:
            xml_filenames = [n for n in z.namelist() if n.endswith(".xml")]
            if not xml_filenames:
                console.print("[red]Error: No XML file found in MITRE CAPEC zip.[/red]")
                return 0

            with z.open(xml_filenames[0]) as xml_file:
                tree = ET.parse(xml_file)
                root = tree.getroot()

                patterns = root.findall(".//{*}Attack_Pattern") or root.findall(".//Attack_Pattern")
                console.print(f"Found {len(patterns)} CAPEC attack pattern definitions. Processing...")

                for p in patterns:
                    capec_id = p.attrib.get("ID", "")
                    name = p.attrib.get("Name", "")
                    abstraction = p.attrib.get("Abstraction", "")
                    status = p.attrib.get("Status", "")

                    desc_elem = p.find("{*}Description") or p.find("Description")
                    description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

                    # Execution flow steps
                    flow_steps = []
                    for step in p.findall(".//{*}Step") or p.findall(".//Step"):
                        phase_elem = step.find("{*}Phase") or step.find("Phase")
                        step_desc = step.find("{*}Description") or step.find("Description")
                        phase_text = phase_elem.text if phase_elem is not None and phase_elem.text else "Step"
                        d_text = step_desc.text if step_desc is not None and step_desc.text else ""
                        flow_steps.append(f"- **{phase_text}**: {d_text}")

                    # Prerequisites & Skills
                    prereqs = [pr.text for pr in (p.findall(".//{*}Prerequisite") or p.findall(".//Prerequisite")) if pr.text]
                    skills = []
                    for sk in (p.findall(".//{*}Skill") or p.findall(".//Skill")):
                        level = sk.attrib.get("Level", "")
                        skills.append(f"{level}: {sk.text or ''}")

                    # Mitigations
                    mitigations = [m.text for m in (p.findall(".//{*}Mitigation") or p.findall(".//Mitigation")) if m.text]

                    md_parts = [
                        f"# CAPEC-{capec_id}: {name}",
                        f"**Abstraction**: {abstraction} | **Status**: {status}",
                        f"## Description\n{description}",
                    ]
                    if flow_steps:
                        md_parts.append("## Attack Execution Flow\n" + "\n".join(flow_steps))
                    if prereqs:
                        md_parts.append("## Prerequisites\n" + "\n".join(f"- {pr}" for pr in prereqs))
                    if skills:
                        md_parts.append("## Skills Required\n" + "\n".join(f"- {sk}" for sk in skills))
                    if mitigations:
                        md_parts.append("## Mitigations\n" + "\n".join(f"- {m}" for m in mitigations))

                    full_text = "\n\n".join(md_parts)
                    source_url = f"https://capec.mitre.org/data/definitions/{capec_id}.html"

                    if not self.dedup.is_duplicate_content(full_text):
                        await self.writer.write_doc(
                            title=f"CAPEC-{capec_id}: {name}",
                            text=full_text,
                            source_url=source_url,
                            topics=["MITRE CAPEC", "Web Exploitation", "Advanced Web Hacking", name]
                        )
                        count += 1

        console.print(f"[green]✓ Ingested {count} unique MITRE CAPEC attack patterns.[/green]")
        return count

    async def ingest_owasp_api_security(self) -> int:
        """Downloads and parses the OWASP API Security Top 10 GitHub repository.

        Covers API-specific risks (BOLA, Broken Authentication, Excessive Data Exposure,
        BFLA, Mass Assignment, Security Misconfiguration, Injection, Improper Asset
        Management, Insufficient Logging & Monitoring, SSRF) with detailed attack
        scenarios, prevention guides, and threat model documentation.
        """
        console.print("\n[bold yellow]─── Ingesting OWASP API Security Top 10 ───[/bold yellow]")
        return await self.ingest_owasp_repository(
            repo_name="API-Security",
            zip_url="https://github.com/OWASP/API-Security/archive/refs/heads/master.zip",
            topics=[
                "OWASP API Security Top 10",
                "API Security",
                "Advanced API Security",
                "Web API Penetration Testing",
                "BOLA", "BFLA",
                "Broken Object Level Authorization",
                "Broken Function Level Authorization",
                "Excessive Data Exposure", "Mass Assignment",
                "Unrestricted Resource Consumption",
                "SSRF", "Injection",
                "CBBH", "eWPTX", "OSWE",
            ]
        )

    async def ingest_owasp_repository(self, repo_name: str, zip_url: str, topics: List[str]) -> int:
        """Downloads and unpacks an OWASP GitHub repository archive, converting markdown to JSONL."""
        console.print(f"\n[bold yellow]─── Ingesting {repo_name} ───[/bold yellow]")
        filename = f"{repo_name.lower().replace(' ', '_')}.zip"
        zip_path = self._download_file(zip_url, filename)

        count = 0
        with zipfile.ZipFile(zip_path, 'r') as z:
            md_files = [n for n in z.namelist() if n.endswith(('.md', '.markdown')) and not n.lower().endswith(('readme.md', 'license.md', 'contributing.md'))]
            console.print(f"Extracting {len(md_files)} technical guides from {repo_name}...")

            for md_path in md_files:
                try:
                    with z.open(md_path) as f:
                        raw_content = f.read().decode('utf-8', errors='ignore').strip()
                        if len(raw_content) < 200:
                            continue

                        # Extract title from first markdown header
                        title_match = re.search(r'^#\s+(.+)$', raw_content, re.MULTILINE)
                        title = title_match.group(1) if title_match else Path(md_path).stem.replace("-", " ").title()

                        source_url = f"https://github.com/OWASP/{repo_name}/blob/master/{md_path}"

                        if not self.dedup.is_duplicate_content(raw_content):
                            await self.writer.write_doc(
                                title=f"{repo_name}: {title}",
                                text=raw_content,
                                source_url=source_url,
                                topics=topics + [repo_name]
                            )
                            count += 1
                except Exception as e:
                    continue

        console.print(f"[green]✓ Ingested {count} unique guides from {repo_name}.[/green]")
        return count

    async def run_all_bulk_sources(self) -> int:
        """Executes full bulk ingestion across all authoritative security databases."""
        total = 0
        total += await self.ingest_mitre_cwe()
        total += await self.ingest_mitre_capec()
        total += await self.ingest_owasp_api_security()
        
        # OWASP WSTG
        total += await self.ingest_owasp_repository(
            repo_name="wstg",
            zip_url="https://github.com/OWASP/wstg/archive/refs/heads/master.zip",
            topics=["OWASP WSTG", "Web Application Penetration Testing", "OSWE", "BSCP", "eWPT"]
        )
        
        # OWASP Cheat Sheet Series
        total += await self.ingest_owasp_repository(
            repo_name="CheatSheetSeries",
            zip_url="https://github.com/OWASP/CheatSheetSeries/archive/refs/heads/master.zip",
            topics=["OWASP Cheat Sheets", "Secure Code Review", "Application Security", "DevSecOps"]
        )

        # OWASP ASVS
        total += await self.ingest_owasp_repository(
            repo_name="ASVS",
            zip_url="https://github.com/OWASP/ASVS/archive/refs/heads/master.zip",
            topics=["OWASP ASVS", "Application Security Verification Standard", "Threat Modeling"]
        )

        # OWASP Top 10
        total += await self.ingest_owasp_repository(
            repo_name="Top10",
            zip_url="https://github.com/OWASP/Top10/archive/refs/heads/master.zip",
            topics=["OWASP Top 10", "Web Application Security", "Web Hacking"]
        )

        return total
