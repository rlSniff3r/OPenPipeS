import os
import json
import re
import subprocess
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

import db

console = Console()
HOME = str(Path.home())
CACHE_DIR = os.path.join(HOME, ".openpipes_cache")
SECRETS_FILE = os.path.join(HOME, ".openpipes", "secrets.conf")


def _normalize_name(name: str) -> str:
    """Convert nuclei template name to cache filename format."""
    name = name.lower().strip()
    name = re.sub(r'[^a-z0-9]+', '_', name)
    name = name.strip('_')
    return name


def _load_cache() -> dict[str, dict]:
    """Load all vulnerability templates from cache. Returns {normalized_name: data}."""
    cache = {}
    if not os.path.exists(CACHE_DIR):
        return cache
    for fname in os.listdir(CACHE_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(CACHE_DIR, fname)
        try:
            with open(fpath, "r") as f:
                data = json.load(f)
            key = fname.replace(".json", "")
            cache[key] = data
        except Exception:
            continue
    return cache


def _get_openai_key() -> Optional[str]:
    """Read OpenAI API key from secrets.conf."""
    if not os.path.exists(SECRETS_FILE):
        return None
    try:
        with open(SECRETS_FILE, "r") as f:
            for line in f:
                if "OPENAI_API_KEY" in line:
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return None


def _extract_cwe(references: list) -> str:
    """Extract CWE ID from reference URLs like https://cwe.mitre.org/data/definitions/326.html"""
    if not references:
        return ""
    for ref in references:
        match = re.search(r'/definitions/(\d+)\.html', ref)
        if match:
            return f"CWE-{match.group(1)}"
    return ""


def _enrich_via_openai(vuln_name: str, description: str) -> Optional[dict]:
    """Use OpenAI to generate vulnerability data for uncached findings."""
    api_key = _get_openai_key()
    if not api_key:
        return None

    prompt = f"""Gere um JSON com dados de vulnerabilidade para: "{vuln_name}"
Descrição: {description}
Formato:
{{
  "title": "Nome da Vulnerabilidade",
  "cvssv3": "CVSS:3.1/...",
  "description": "Descrição detalhada em português",
  "observation": "Impacto técnico",
  "remediation": "Recomendação de correção",
  "references": ["url1", "url2"]
}}
Responda apenas com o JSON, sem formatação extra."""

    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
            },
            timeout=30,
        )
        if r.status_code == 200:
            content = r.json()["choices"][0]["message"]["content"]
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
    except Exception:
        pass
    return None


def enrich_nuclei_findings(proj_path: str):
    """Enrich nuclei vulnerabilities with data from cache or OpenAI."""
    cache = _load_cache()
    enriched = 0
    skipped = 0

    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, vuln_name, description, title
                FROM vulnerabilities
                WHERE source_tool = 'nuclei'
                  AND (enriched_by IS NULL OR enriched_by = '')
            """)
            to_enrich = cursor.fetchall()

            for row in to_enrich:
                vuln_id = row["id"]
                vuln_name = row["vuln_name"] or row["title"]
                description = row["description"] or ""
                normalized = _normalize_name(vuln_name)
                vuln_keywords = set(re.sub(r'[^a-z0-9]+', ' ', normalized).split())

                # Keyword-based fuzzy matching
                matched_cache = None
                best_score = 0.0

                for cache_key, cache_data in cache.items():
                    cache_keywords = set(re.sub(r'[^a-z0-9]+', ' ', cache_key).split())
                    overlap = len(vuln_keywords & cache_keywords)
                    denom = max(len(vuln_keywords), len(cache_keywords))
                    score = overlap / denom if denom > 0 else 0

                    if score > best_score:
                        best_score = score
                        matched_cache = (cache_key, cache_data)

                # Low confidence — ask user via fzf
                if best_score < 0.5 or best_score is None:
                    candidates = [
                        k for k in cache.keys()
                        if len(set(re.sub(r'[^a-z0-9]+', ' ', k).split()) & vuln_keywords) > 0
                    ]
                    if candidates:
                        from db_viewer import _fzf_select
                        console.print(f" [yellow]⚠ '{vuln_name}' — selecione a correspondência:[/yellow]")
                        selected = _fzf_select(sorted(candidates), f"Match:")
                        if selected:
                            matched_cache = (selected[0], cache[selected[0]])
                            best_score = 1.0

                cached = matched_cache[1] if matched_cache and best_score >= 0.3 else None

                if not cached:
                    console.print(f" [yellow]⚠ Sem cache para '{vuln_name}'. Tentando OpenAI...[/yellow]")
                    cached = _enrich_via_openai(vuln_name, description)

                if cached:
                    # Calculate CVSS score from vector
                    cvss_vector = cached.get("cvssv3", "")
                    score, severity = _calculate_cvss(cvss_vector)
                    cwe_id = _extract_cwe(cached.get("references", []))
                    cursor.execute("""
                        UPDATE vulnerabilities SET
                            title = ?,
                            cvss_vector = ?,
                            cvss_score = ?,
                            severity = ?,
                            description = ?,
                            impact = ?,
                            remediation = ?,
                            reference_urls = ?,
                            cwe_id = ?,
                            enriched_by = 'cache'
                        WHERE id = ?
                    """, (
                        cached.get("title", vuln_name),
                        cvss_vector,
                        score,
                        severity or "Média",
                        cached.get("description", description),
                        cached.get("observation", ""),
                        cached.get("remediation", ""),
                        json.dumps(cached.get("references", [])),
                        cwe_id,
                        vuln_id,
                    ))
                    enriched += 1
                else:
                    skipped += 1

    console.print(f" [dim]↳ Enricher: {enriched} enriquecidas, {skipped} sem dados.[/dim]")


def _calculate_cvss(cvss_vector: str) -> tuple:
    """Calculate CVSS score from vector string using cvss_calculator CLI.
    Returns (base_score, severity) or (None, None) on failure."""
    if not cvss_vector:
        return None, None
    try:
        result = subprocess.run(
            f"cvss_calculator -3jv '{cvss_vector}'",
            shell=True, capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            # Parse the JSON output (skip first 7 header lines)
            json_str = "\n".join(result.stdout.strip().split("\n")[7:])
            import json
            data = json.loads(json_str)
            score = data.get("baseScore")
            severity = data.get("baseSeverity", "")
            severity_map = {"CRITICAL": "Crítica", "HIGH": "Alta",
                           "MEDIUM": "Média", "LOW": "Baixa", "NONE": "Info"}
            return score, severity_map.get(severity.upper(), severity)
    except Exception:
        pass
    return None, None


def add_manual_vulnerability(proj_path: str):
    """Interactive manual vulnerability insertion via fzf cache selection."""
    from db_viewer import _fzf_select

    # Select target host
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, host FROM hosts WHERE is_alive = 1 ORDER BY host")
        hosts = [f"{row[0]} | {row[1]}" for row in cursor.fetchall()]

    selected_host = _fzf_select(hosts, "Select target host:")
    if not selected_host:
        return
    host_id = int(selected_host[0].split(" | ")[0])

    # Select vulnerability from cache via fzf
    cache_files = sorted(os.listdir(CACHE_DIR)) if os.path.exists(CACHE_DIR) else []
    if not cache_files:
        console.print("[yellow]⚠ Cache vazio. Use o modo manual.[/yellow]")
        return

    selected = _fzf_select(cache_files, "Select vulnerability (TAB to preview):")
    if not selected:
        return
    cache_file = os.path.join(CACHE_DIR, selected[0])
    with open(cache_file, "r") as f:
        vuln_data = json.load(f)

    # Select the specific endpoint (optional)
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, url FROM endpoints WHERE host_id = ? LIMIT 500",
            (host_id,),
        )
        endpoints = [f"{row[0]} | {row[1][:80]}" for row in cursor.fetchall()]
    endpoints.insert(0, "SKIP")

    selected_ep = _fzf_select(endpoints, "Select endpoint (optional):")
    endpoint_id = None
    if selected_ep and selected_ep[0] != "SKIP":
        endpoint_id = int(selected_ep[0].split(" | ")[0])

    # Parse CVSS score from vector
    cvss_score = None
    cvss_vector = vuln_data.get("cvssv3", "")
    if cvss_vector:
        import re
        score_match = re.search(r'CVSS:3.1[^/]*/([^/]+/[^/]+)', cvss_vector)
        if score_match:
            # We could calculate the score, but storing the vector is enough for display
            pass

    # Insert into DB
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO vulnerabilities
                    (host_id, endpoint_id, title, severity, cvss_vector,
                     description, impact, remediation, reference_urls,
                     source_tool, enriched_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual', 'user')
            """, (
                host_id, endpoint_id, vuln_data.get("title", ""),
                "Média", cvss_vector,
                vuln_data.get("description", ""),
                vuln_data.get("observation", ""),
                vuln_data.get("remediation", ""),
                json.dumps(vuln_data.get("references", [])),
            ))
            vuln_id = cursor.lastrowid

    console.print(f" [green]✔ Vulnerabilidade inserida (id={vuln_id}). Execute 'sync' para gerar o arquivo.[/green]")


def run_enricher(proj_path: str):
    """Run enricher on all unenriched nuclei findings."""
    enrich_nuclei_findings(proj_path)


def run_manual(proj_path: str):
    """Interactive manual vulnerability insertion."""
    add_manual_vulnerability(proj_path)
