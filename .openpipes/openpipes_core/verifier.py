import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console

import db

console = Console()

TIMEOUT = 15
MAX_WORKERS = 50


def _structural_hash(html: str) -> str:
    """Hash HTML structure only, ignoring variable text content."""
    if not html:
        return ""
    text = html[:8192]
    structure = re.sub(r'>[^<]+<', '><', text)
    structure = re.sub(r'(href|src|action)=["\'][^"\']+["\']', r'\1=""', structure)
    structure = re.sub(r'\sid=["\'][^"\']+["\']', ' id=""', structure)
    return hashlib.md5(structure.encode()).hexdigest()


def verify_endpoints(proj_path: str, limit: int = None):
    """Read unverified endpoints, make real HTTP requests, fingerprint, tag FPs."""
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, url, host_id FROM endpoints
            WHERE (response_hash IS NULL OR response_hash = '')
              AND url LIKE 'http%'
            ORDER BY id
        """ + (" LIMIT ?" if limit else ""), (limit,) if limit else ())
        to_verify = cursor.fetchall()

    if not to_verify:
        console.print(" [dim]↳ Verifier: Nenhum endpoint para verificar.[/dim]")
        return

    console.print(f" [dim]↳ Verifier: Verificando {len(to_verify)} endpoints...[/dim]")

    def check_one(row):
        try:
            r = requests.get(row["url"], timeout=TIMEOUT, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120",
            }, allow_redirects=True)
            return {
                "id": row["id"],
                "status_code": r.status_code,
                "content_length": len(r.content),
                "response_hash": _structural_hash(r.text),
                "error": None,
            }
        except Exception as e:
            return {"id": row["id"], "error": str(e)}

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_one, row): row for row in to_verify}
        for i, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if i % 500 == 0:
                console.print(f"  [dim]{i}/{len(to_verify)}[/dim]")

    _store_results(proj_path, results)
    tagged = _cluster_by_hash(proj_path)
    console.print(f" [dim]↳ Verifier: {len(results)} verificados, {tagged} FPs taggeados.[/dim]")


def _store_results(proj_path: str, results: list[dict]) -> int:
    count = 0
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            for r in results:
                if r.get("error"):
                    cursor.execute("""
                        UPDATE endpoints SET
                            status_code = 0,
                            content_length = 0,
                            response_hash = '',
                            verified_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (r["id"],))
                else:
                    cursor.execute("""
                        UPDATE endpoints SET
                            status_code = ?, content_length = ?,
                            response_hash = ?, verified_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (r["status_code"], r["content_length"], r["response_hash"], r["id"]))
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
            for row in cursor.fetchall():
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
    return tagged


def run_sync(proj_path: str, limit: int = None):
    """Synchronous entry point called from cli.py."""
    verify_endpoints(proj_path, limit)
