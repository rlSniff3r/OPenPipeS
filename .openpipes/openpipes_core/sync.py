"""sync.py — Two-way sync: ingest user edits from the Obsidian vault back into the DB.

Called from renderer.sync_project() BEFORE render_all():
    sync.parse_vault_to_db(proj_path, obsdir, proj_name, target_name=None)

Strict-anchor parsing (Option A). Generated regions are read-only; the anchors below
are the ONLY user-editable surfaces, per design.
"""
import os
import re
import json
import hashlib
import shutil
import db
from rich.console import Console

VAULT_INDEX = {}

console = Console()

AUTO_NARRATIVE_MARKER = "_Gerado automaticamente:_"   # renderer prefix for untouched section
TASK_FALLBACK_LINE = "Todas as tarefas concluídas"

TECH_HEADING = "### 🛠️ Stack de Tecnologias"
NARRATIVE_HEADING = "## 📘 Narrativa Técnica"
PROGRESS_HEADING = "## 🚩 Progresso"

VULN_CALLOUTS = {
    "> [!note] Descrição":    "description",
    "> [!danger] Impacto":    "impact",
    "> [!success] Recomendação": "remediation",
}
VULN_PLACEHOLDERS = {
    "*Nenhuma descrição fornecida.*",
    "Impacto não especificado.",
    "Nenhuma recomendação fornecida.",
}

TASK_RE = re.compile(r"^-\s*\[( |x|X)\]\s*(.*?)(?:\s*<!--\s*id:([^>]+?)\s*-->)?\s*$")


# ── helpers ──────────────────────────────────────────────────────
def _vault_base(obsdir: str, proj_name: str) -> str:
    return os.path.join(obsdir, proj_name, "Pentest", "Alvos")


def _extract_section(text: str, heading: str) -> str:
    """Return the body of a heading section, stripped of '---' separators and blanks."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == heading:
            start = i
            break
    if start is None:
        return ""
    out = []
    for line in lines[start + 1:]:
        if line.startswith("#"):
            break
        out.append(line)
    while out and out[0].strip() in ("", "---"):
        out.pop(0)
    while out and out[-1].strip() in ("", "---"):
        out.pop()
    return "\n".join(out).strip()


def _parse_tech_bullets(section: str) -> list[str]:
    return [line[2:].strip() for line in section.splitlines()
            if line.strip().startswith("- ") and line[2:].strip()]


def _parse_tasks(section: str) -> list[tuple[bool, str, str | None]]:
    tasks = []
    for line in section.splitlines():
        m = TASK_RE.match(line.strip())
        if not m:
            continue
        done = m.group(1).lower() == "x"
        label = m.group(2).strip()
        key = m.group(3).strip() if m.group(3) else None
        if label == TASK_FALLBACK_LINE and key is None:
            continue
        tasks.append((done, label, key))
    return tasks


def _parse_narrative(section: str) -> str | None:
    if section.startswith(AUTO_NARRATIVE_MARKER):
        return None
    return section or None


def _frontmatter_str(text: str, key: str) -> str | None:
    m = re.search(rf"^{key}:\s*(\S+)", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def _extract_callout(text: str, callout: str) -> str:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith(callout):
            body = []
            for nxt in lines[i + 1:]:
                if nxt.strip().startswith("> [!") or nxt.strip().startswith("#"):
                    break
                body.append(nxt)
            return "\n".join(body).strip()
    return ""


# ── per-file parsers ─────────────────────────────────────────────
def _extract_and_store_evidences(text, conn, host_id, host_name, proj_path, vuln_id=None):
    """Extract pasted images from MD text, copy to project Evidencias/, rewrite to ![[hash_file]]."""
    if not text:
        return text
    ev_dir = os.path.join(proj_path, "Varreduras", f"nmap-{host_name}", "Evidencias")

    def replacer(match):
        raw_link = match.group(1) or match.group(2)
        filename = os.path.basename(raw_link.split("|")[0])          # strip |500 sizing
        if re.match(r"^[0-9a-f]{8}_", filename):                     # already processed
            return match.group(0)
        if not re.search(r"\.(png|jpe?g|gif|svg|webp|bmp|ico)$", filename, re.I):
            return match.group(0)                                    # not an image — leave untouched
        orig_path = VAULT_INDEX.get(filename)
        if not orig_path or not os.path.exists(orig_path):
            return match.group(0)                                    # not found in vault
        with open(orig_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        stored_name = f"{file_hash[:8]}_{filename}"
        dst = os.path.join(ev_dir, stored_name)
        os.makedirs(ev_dir, exist_ok=True)
        if not os.path.exists(dst):
            shutil.copy2(orig_path, dst)
        conn.execute(
            "INSERT OR IGNORE INTO user_evidences "
            "(host_id, vuln_id, original_name, stored_name, sha256) VALUES (?, ?, ?, ?, ?)",
            (host_id, vuln_id, filename, stored_name, file_hash),
        )
        sizing = f"|{raw_link.split('|', 1)[1]}" if "|" in raw_link else ""
        return f"![[{stored_name}{sizing}]]"

    return re.sub(r"!\[\[(.*?)\]\]|!\[.*?\]\((.*?)\)", replacer, text)


def _ingest_tasks(conn, host_id: int, tasks: list[tuple[bool, str, str | None]]):
    cur = conn.cursor()
    for done, label, key in tasks:
        if key:
            cur.execute("UPDATE tasks SET is_done = ? WHERE host_id = ? AND task_key = ?",
                        (int(done), host_id, key))
        else:
            cur.execute("SELECT id FROM tasks WHERE host_id = ? AND kind = 'manual' AND label = ?",
                        (host_id, label))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE tasks SET is_done = ? WHERE id = ?", (int(done), row["id"]))
            else:
                key = "manual_" + hashlib.sha1(label.encode("utf-8")).hexdigest()[:10]
                cur.execute(
                    "INSERT OR IGNORE INTO tasks (host_id, task_key, label, is_done, kind) "
                    "VALUES (?, ?, ?, ?, 'manual')",
                    (host_id, key, label, int(done)),
                )


def _parse_host_md(conn, host_id, host_name, host_dir, proj_path):
    """Parse a host's MD file and update the DB with user edits.""" 
    host_md = os.path.join(host_dir, f"{host_name}.md")
    if not os.path.exists(host_md):
        return
    with open(host_md, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    cur = conn.cursor()

    # manual techs — diff bullets vs auto set from endpoints
    auto: set[str] = set()
    cur.execute("SELECT tech_stack FROM endpoints WHERE host_id = ?", (host_id,))
    for r in cur.fetchall():
        try:
            auto.update(json.loads(r["tech_stack"] or "[]"))
        except Exception:
            pass
    tech_section = _extract_section(text, TECH_HEADING)
    if tech_section:
        manual = [t for t in _parse_tech_bullets(tech_section) if t not in auto]
        cur.execute("UPDATE hosts SET manual_techs = ? WHERE id = ?",
                    (json.dumps(manual, ensure_ascii=False), host_id))

    # narrative — skip untouched auto-generated marker
    nav = _parse_narrative(_extract_section(text, NARRATIVE_HEADING))
    if nav is not None:
        nav = _extract_and_store_evidences(nav, conn, host_id, host_name, proj_path)
        cur.execute("UPDATE hosts SET narrative = ? WHERE id = ?", (nav, host_id))

    # task states
    prog = _extract_section(text, PROGRESS_HEADING)
    if prog:
        _ingest_tasks(conn, host_id, _parse_tasks(prog))


def _ingest_vuln(conn, host_id, host_name, proj_path, vuln_id, text):
    cur = conn.cursor()
    cur.execute("SELECT status FROM vulnerabilities WHERE id = ?", (vuln_id,))
    row = cur.fetchone()
    if row and row["status"] == "false_positive":
        return  # skip ingest for false positives
    updates = {}
    for callout, col in VULN_CALLOUTS.items():
        body = _extract_callout(text, callout)
        if body and body not in VULN_PLACEHOLDERS:
            updates[col] = _extract_and_store_evidences(
                body, conn, host_id, host_name, proj_path, vuln_id)

    # capture images pasted anywhere in the vuln file (e.g., Evidência block)
    _extract_and_store_evidences(text, conn, host_id, host_name, proj_path, vuln_id)

    status = _frontmatter_str(text, "status")
    if status:
        updates["status"] = status
    if updates:
        sets = ", ".join(f"{col} = ?" for col in updates)
        cur.execute(f"UPDATE vulnerabilities SET {sets} WHERE id = ?", (*updates.values(), vuln_id))


def _parse_vulns_dir(conn, host_id, host_name, proj_path, vulns_dir):
    if not os.path.isdir(vulns_dir):
        return
    for fname in sorted(os.listdir(vulns_dir)):
        if not fname.endswith(".md"):
            continue
        with open(os.path.join(vulns_dir, fname), "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        m = re.search(r"^vuln_id:\s*(\d+)", text, re.MULTILINE)
        if not m:
            continue  # legacy file without id — skipped until re-rendered
        _ingest_vuln(conn, host_id, host_name, proj_path, int(m.group(1)), text)


# ── entry point ──────────────────────────────────────────────────
def parse_vault_to_db(proj_path, obsdir, proj_name, target_name=None):
    global VAULT_INDEX
    VAULT_INDEX = {f: os.path.join(r, f) for r, _, files in os.walk(obsdir) for f in files}

    base = _vault_base(obsdir, proj_name)
    if not os.path.isdir(base):
        return
    with db.get_connection(proj_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, host FROM hosts WHERE is_alive = 1 AND in_scope = 1")
        for row in cur.fetchall():
            host_name = row["host"]
            if target_name and host_name != target_name:
                continue
            host_dir = os.path.join(base, host_name)
            _parse_host_md(conn, row["id"], host_name, host_dir, proj_path)
            _parse_vulns_dir(conn, row["id"], host_name, proj_path,
                             os.path.join(host_dir, "Vulnerabilidades"))
        console.print(" [dim]↳ Sync ingest: vault → DB concluído.[/dim]")
