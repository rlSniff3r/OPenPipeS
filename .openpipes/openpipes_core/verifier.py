import asyncio
import hashlib
import json
import re
from datetime import datetime

import httpx
from rich.console import Console

import db

console = Console()

BATCH_SIZE = 100
TIMEOUT = 15


def _structural_hash(html: str) -> str:
    """
    Hash the HTML structure only, ignoring variable text content.
    Two pages with the same template but different URL paths
    will produce the same structural hash.
    """
    if not html:
        return ""
    # Keep first 8KB for structural analysis
    text = html[:8192]
    # Remove text between tags, keep only structure
    structure = re.sub(r'>[^<]+<', '><', text)
    # Normalize attribute values that vary per request
    structure = re.sub(r'(href|src|action)=["\'][^"\']+["\']', r'\1=""', structure)
    # Normalize IDs and classes (often page-specific)
    structure = re.sub(r'\sid=["\'][^"\']+["\']', ' id=""', structure)
    return hashlib.md5(structure.encode()).hexdigest()


def _extract_title(html: str) -> str:
    """Extract <title> from HTML."""
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""


async def verify_endpoints(proj_path: str, limit: int = None):
    """Read unverified endpoints, make real HTTP requests, fingerprint, and tag FPs."""
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        # Only verify endpoints that have a proper URL (http/https)
        cursor.execute("""
            SELECT id, url, host_id FROM endpoints
            WHERE (response_hash IS NULL OR response_hash = '')
              AND url LIKE 'http%'
            ORDER BY id
        """ + (" LIMIT ?" if limit else ""),
                       (limit,) if limit else ())
        to_verify = cursor.fetchall()

    if not to_verify:
        console.print(" [dim]↳ Verifier: Nenhum endpoint para verificar.[/dim]")
        return

    console.print(f" [dim]↳ Verifier: Verificando {len(to_verify)} endpoints...[/dim]")

    verified = 0
    for i in range(0, len(to_verify), BATCH_SIZE):
        batch = to_verify[i:i + BATCH_SIZE]
        results = await _verify_batch(batch)
        verified += _store_results(proj_path, results)
        console.print(f"  [dim]{min(i + BATCH_SIZE, len(to_verify))}/{len(to_verify)}[/dim]")

    tagged = _cluster_by_hash(proj_path)
    console.print(f" [dim]↳ Verifier: {verified} verificados, {tagged} FPs taggeados.[/dim]")


async def _verify_batch(batch: list) -> list[dict]:
    """Verify a batch of URLs concurrently."""
    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=50),
    ) as client:
        async def check_one(row):
            try:
                r = await client.get(row["url"], headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120",
                })
                html = r.text[:8192]
                return {
                    "id": row["id"],
                    "status_code": r.status_code,
                    "content_length": len(r.content),
                    "response_hash": _structural_hash(html),
                    "title": _extract_title(html),
                    "error": None,
                }
            except Exception as e:
                return {
                    "id": row["id"],
                    "status_code": None,
                    "content_length": None,
                    "response_hash": None,
                    "title": None,
                    "error": str(e),
                }

        tasks = [check_one(row) for row in batch]
        return await asyncio.gather(*tasks)


def _store_results(proj_path: str, results: list[dict]) -> int:
    count = 0
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            for r in results:
                if r["error"]:
                    # Mark as verified (failed) so we don't retry indefinitely
                    cursor.execute("""
                        UPDATE endpoints SET
                            response_hash = '',
                            verified_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (r["id"],))
                else:
                    cursor.execute("""
                        UPDATE endpoints SET
                            status_code = ?,
                            content_length = ?,
                            response_hash = ?,
                            title = ?,
                            verified_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (r["status_code"], r["content_length"],
                          r["response_hash"], r["title"], r["id"]))
                count += 1
    return count


def _cluster_by_hash(proj_path: str) -> int:
    """Tag 5+ endpoints with same host_id + response_hash as false positives."""
    tagged = 0
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            cursor.execute("""
                SELECT host_id, response_hash, COUNT(*) as cnt
                FROM endpoints
                WHERE response_hash IS NOT NULL AND response_hash != ''
                GROUP BY host_id, response_hash
                HAVING cnt >= 5
                ORDER BY cnt DESC
            """)
            clusters = cursor.fetchall()
            for row in clusters:
                cursor.execute("""
                    SELECT id, vulnerability_patterns FROM endpoints
                    WHERE host_id = ? AND response_hash = ?
                """, (row["host_id"], row["response_hash"]))
                for ep in cursor.fetchall():
                    patterns = json.loads(ep["vulnerability_patterns"]) \
                        if ep["vulnerability_patterns"] else []
                    if "potential_false_positive" not in patterns:
                        patterns.append("potential_false_positive")
                        cursor.execute(
                            "UPDATE endpoints SET vulnerability_patterns = ? WHERE id = ?",
                            (json.dumps(patterns), ep["id"]),
                        )
                        tagged += 1

            # Also add the title column to endpoints if missing
            _add_title_column(proj_path)

    if clusters:
        console.print(f"  [dim]↳ {len(clusters)} clusters de FPs encontrados.[/dim]")
    return tagged


def _add_title_column(proj_path: str):
    """Ensure title column exists on endpoints (needed for verifier results)."""
    with db.get_connection(proj_path) as conn:
        try:
            conn.execute("ALTER TABLE endpoints ADD COLUMN title TEXT")
        except Exception:
            pass  # Column already exists


def run_sync(proj_path: str, limit: int = None):
    """Synchronous entry point called from cli.py."""
    asyncio.run(verify_endpoints(proj_path, limit))
