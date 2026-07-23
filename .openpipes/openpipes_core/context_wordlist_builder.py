import os
import json
from collections import defaultdict
from urllib.parse import urlparse
from pathlib import Path

import db
from rich.console import Console

console = Console()

HOME = str(Path.home())
TECH_WL_DIR = os.path.join(HOME, ".openpipes", "wordlists", "tech")
GENERIC_BASE = os.path.join(HOME, ".openpipes", "wordlists", "generic.txt")


def _load_wordlist(filepath: str) -> list:
    """Load a wordlist file, one word per line."""
    if not os.path.exists(filepath):
        return []
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _load_tech_wordlists() -> dict[str, list]:
    """Load all tech-specific wordlist files."""
    wl = {}
    if not os.path.exists(TECH_WL_DIR):
        return wl
    for fname in sorted(os.listdir(TECH_WL_DIR)):
        if not fname.endswith(".txt"):
            continue
        tech_name = fname.replace(".txt", "")
        words = _load_wordlist(os.path.join(TECH_WL_DIR, fname))
        if words:
            wl[tech_name] = words
    return wl


def _extract_path_segments(urls: list) -> list:
    """Extract unique, meaningful path segments from URLs."""
    segments = set()
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        if not path:
            continue
        for part in path.split("/"):
            if part and not part.isdigit() and len(part) > 1 and not part.startswith("{"):
                segments.add(part.lower())
    return sorted(segments)


def _get_tech_stack(proj_path: str, host: str) -> list:
    """Get technology stack from endpoints for a given host."""
    techs = set()
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT tech_stack FROM endpoints WHERE host_id = (SELECT id FROM hosts WHERE host = ?)",
            (host,),
        )
        for row in cursor.fetchall():
            if not row[0]:
                continue
            try:
                for t in json.loads(row[0]):
                    techs.add(t.lower())
            except Exception:
                techs.add(row[0].lower())
    return sorted(techs)


def _tech_mapped_words(techs: list, tech_wordlists: dict) -> list:
    """Return wordlist entries matching detected technologies."""
    words = set()
    techs_lower = [t.lower() for t in techs]
    for tech_name, wl in tech_wordlists.items():
        tn = tech_name.lower()
        if any(tn in t or t in tn for t in techs_lower):
            words.update(wl)
    return sorted(words)


def build_context_wordlist(proj_path: str, nmap_dir: str):
    """Build per-target contextualized wordlists for feroxbuster."""
    tech_wordlists = _load_tech_wordlists()
    generic_base = _load_wordlist(GENERIC_BASE)

    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT h.host, h.id
            FROM hosts h
            WHERE h.is_alive = 1 AND h.in_scope = 1
            ORDER BY h.host
        """)
        hosts = cursor.fetchall()

    if not hosts:
        console.print("[yellow]⚠ Nenhum host vivo para gerar wordlist.[/yellow]")
        return

    total = 0
    for host_row in hosts:
        host = host_row["host"]
        host_id = host_row["id"]
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)

        # Get verified endpoints for this host
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT url FROM endpoints
                WHERE host_id = ?
                  AND (vulnerability_patterns NOT LIKE '%potential_false_positive%'
                       OR vulnerability_patterns IS NULL)
                ORDER BY url
            """, (host_id,))
            urls = [r["url"] for r in cursor.fetchall()]

        wl = set()

        # 1. Generic base (hand-curated, safe)
        wl.update(generic_base)

        # 2. Tech-specific paths (hand-curated, safe)
        techs = _get_tech_stack(proj_path, host)
        wl.update(_tech_mapped_words(techs, tech_wordlists))

        # 3. Path segments from target's own endpoints (target-specific)
        if urls:
            wl.update(_extract_path_segments(urls))

        # Sort and write with warning header
        sorted_wl = sorted(w.lower() for w in wl if w)

        wl_path = os.path.join(target_dir, "context_wordlist.txt")
        with open(wl_path, "w") as f:
            f.write("# WARNING: This file contains target-specific paths.\n")
            f.write("# Do NOT share outside this project.\n")
            f.write(f"# Generated for: {host}\n")
            f.write(f"# Techs: {', '.join(techs)}\n")
            f.write(f"# Endpoints: {len(urls)}\n\n")
            f.write("\n".join(sorted_wl) + "\n")

        total += len(sorted_wl)

    console.print(f" [dim]↳ Wordlist Builder: {len(hosts)} hosts, ~{total} palavras.[/dim]")
    if tech_wordlists:
        console.print(f"  [dim]↳ {len(tech_wordlists)} tech wordlists carregadas.[/dim]")
