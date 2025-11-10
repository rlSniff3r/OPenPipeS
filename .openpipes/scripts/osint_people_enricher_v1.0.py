#!/usr/bin/env python3
"""
osint_people_enricher_v1.0.py

Purpose:
- Python-based aggregator & enricher for people-focused OSINT (defensive).
- Entity resolution with fuzzy matching and scoring.
- File-searcher module: enumerates public documents (pdf, docx, xlsx, png, jpg, etc.) from given seeds (Wayback/GitHub/public buckets), downloads them, extracts metadata (author, creator, titles), extracts text, and searches for sensitive patterns (internal IPs, hostnames, usernames, paths).
- Writes results as JSON and updates Obsidian Markdown notes (frontmatter evidence entries) in the OpenPipeS structure.

Security model:
- Requires an authorization file supplied with --auth to run.
- Masks emails by default; unmask only if AUTH file contains ALLOW_UNMASK.
- Raw downloaded files are saved to a configurable raw dir and can be GPG-encrypted later (not implemented here).

Usage:
  python3 osint_people_enricher_v1.0.py --target example.com --auth /path/to/auth.txt --seeds seeds.txt

Outputs:
  $OBSDIR/Pentest/Alvos/<target>/OSINT/Pessoas/    (markdown notes)
  $OBSDIR/Pentest/Alvos/<target>/OSINT/files_raw/  (downloaded files)
  $OBSDIR/Pentest/Alvos/<target>/osint_people.json  (structured output)

Requirements (pip):
  requests, rapidfuzz, python-docx, openpyxl, pillow, pdfminer.six, pikepdf, exifread, PyYAML, dataclasses-json

This is a defensive tool. Do not use to target individuals outside the authorized scope.
"""

from __future__ import annotations
import argparse
import json
import os
import re
import sys
import shutil
import logging
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# third-party
try:
    import requests
    from rapidfuzz import fuzz
    from docx import Document
    import openpyxl
    from PIL import Image, ExifTags
    from pdfminer.high_level import extract_text as pdf_extract_text
    import pikepdf
    import exifread
    import yaml
except Exception as e:
    print("[!] Missing dependencies. Install requirements listed in the header.")
    raise

# ---------- Configuration & helpers ----------
LOG = logging.getLogger("osint_people_enricher")
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}")
IPV4_RE = re.compile(r"\b(?:(?:10|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}|(?:[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3})\b")
IPV4_GENERIC_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
HOSTNAME_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
USERNAME_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9._-]{2,30}\b")
PATH_RE = re.compile(r"(?:/[\w\-\.@]+){2,}")

SENSITIVE_EXTS = ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.txt', '.csv', '.png', '.jpg', '.jpeg', '.zip']

# ---------- Core classes ----------

class Config:
    def __init__(self, target: str, obsdir: Path, auth_file: Path, templates_dir: Path, seeds_file: Optional[Path]=None):
        self.target = target
        self.obsdir = obsdir
        self.auth_file = auth_file
        self.templates_dir = templates_dir
        self.seeds_file = seeds_file
        self.raw_dir = obsdir / 'Pentest' / 'Alvos' / target / 'OSINT' / 'files_raw'
        self.people_dir = obsdir / 'Pentest' / 'Alvos' / target / 'OSINT' / 'Pessoas'
        self.candidates_file = obsdir / 'Pentest' / 'Alvos' / target / 'osint' / 'people' / 'raw' / 'candidates.ndjson'
        self.output_struct = obsdir / 'Pentest' / 'Alvos' / target / 'OSINT' / 'osint_people.json'
        self.allow_unmask = False
        self._read_auth()

    def _read_auth(self):
        if not self.auth_file.exists():
            raise FileNotFoundError("Authorization file not found")
        txt = self.auth_file.read_text(encoding='utf-8', errors='ignore')
        if 'ALLOW_UNMASK' in txt:
            self.allow_unmask = True


# ---------- Utilities ----------

def safe_mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def mask_email(email: str) -> str:
    if not email or '@' not in email:
        return email
    user, domain = email.split('@', 1)
    return f"{user[:1]}***@{domain}"


def sha1_of_file(p: Path) -> str:
    h = hashlib.sha1()
    with p.open('rb') as f:
        while True:
            b = f.read(8192)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ---------- Parsing & metadata extraction ----------

def extract_pdf_metadata_and_text(path: Path) -> Dict[str, Any]:
    meta = {}
    try:
        # metadata via pikepdf
        with pikepdf.Pdf.open(path) as pdf:
            md = pdf.docinfo
            for k, v in md.items():
                meta[str(k)] = str(v)
    except Exception as e:
        LOG.debug(f"pikepdf failed: {e}")

    text = ''
    try:
        text = pdf_extract_text(str(path))
    except Exception as e:
        LOG.debug(f"pdfminer failed: {e}")

    return {'metadata': meta, 'text': text}


def extract_docx_metadata_and_text(path: Path) -> Dict[str, Any]:
    meta = {}
    text = ''
    try:
        doc = Document(str(path))
        props = doc.core_properties
        for attr in ['author', 'title', 'subject', 'last_modified_by', 'comments']:
            val = getattr(props, attr, None)
            if val:
                meta[attr] = val
        text = '\n'.join(paragraph.text for paragraph in doc.paragraphs)
    except Exception as e:
        LOG.debug(f"docx parse failed: {e}")
    return {'metadata': meta, 'text': text}


def extract_xlsx_metadata_and_text(path: Path) -> Dict[str, Any]:
    meta = {}
    text_parts = []
    try:
        wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
        props = wb.properties
        for k in ['creator', 'lastModifiedBy', 'title', 'subject']:
            v = getattr(props, k, None)
            if v:
                meta[k] = v
        for sheet in wb.worksheets:
            for row in sheet.iter_rows(max_row=50, max_col=10, values_only=True):
                for cell in row:
                    if cell:
                        text_parts.append(str(cell))
    except Exception as e:
        LOG.debug(f"xlsx parse failed: {e}")
    return {'metadata': meta, 'text': '\n'.join(text_parts[:1000])}


def extract_image_metadata_and_text(path: Path) -> Dict[str, Any]:
    meta = {}
    try:
        img = Image.open(str(path))
        info = img._getexif() or {}
        # map to human tags
        for k, v in info.items():
            tag = ExifTags.TAGS.get(k, k)
            meta[tag] = v
    except Exception as e:
        LOG.debug(f"image parse failed: {e}")
    return {'metadata': meta, 'text': ''}


# ---------- Sensitive pattern search ----------

def find_sensitive_patterns(text: str) -> Dict[str, List[str]]:
    found = {'internal_ips': [], 'ips': [], 'hostnames': [], 'paths': [], 'usernames': [], 'uuids': []}
    if not text:
        return found
    for m in IPV4_RE.findall(text):
        if m not in found['internal_ips']:
            found['internal_ips'].append(m)
    for m in IPV4_GENERIC_RE.findall(text):
        if m not in found['ips']:
            found['ips'].append(m)
    for m in HOSTNAME_RE.findall(text):
        if m not in found['hostnames']:
            found['hostnames'].append(m)
    for m in PATH_RE.findall(text):
        if m not in found['paths']:
            found['paths'].append(m)
    for m in USERNAME_RE.findall(text):
        if m not in found['usernames']:
            found['usernames'].append(m)
    for m in UUID_RE.findall(text):
        if m not in found['uuids']:
            found['uuids'].append(m)
    return found


# ---------- File searcher (Wayback + GitHub + S3 heuristics) ----------

def wayback_file_urls(domain: str, limit: int = 500) -> List[str]:
    """Query the webarchive CDX API for likely document URLs. Conservative and passive."""
    urls = []
    try:
        q = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&filter=statuscode:200&collapse=urlkey&limit={limit}"
        r = requests.get(q, timeout=20)
        if r.status_code == 200:
            j = r.json()
            # first row may be header
            for row in j[1:]:
                u = row[0]
                if any(u.lower().endswith(ext) for ext in SENSITIVE_EXTS):
                    urls.append(u)
    except Exception as e:
        LOG.debug(f"wayback query failed: {e}")
    return urls


def github_raw_file_urls_for_org(org: str, token: Optional[str] = None, per_repo_limit: int = 50) -> List[str]:
    urls = []
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if token:
        headers['Authorization'] = f'token {token}'
    try:
        base = f'https://api.github.com/orgs/{org}/repos?per_page=100'
        r = requests.get(base, headers=headers, timeout=15)
        if r.status_code != 200:
            LOG.info('GitHub org query failed or rate-limited')
            return urls
        repos = r.json()
        for repo in repos:
            full = repo.get('full_name')
            # Fetch tree for repo
            tree_url = f'https://api.github.com/repos/{full}/git/trees/HEAD?recursive=1'
            rt = requests.get(tree_url, headers=headers, timeout=15)
            if rt.status_code == 200:
                tree = rt.json().get('tree', [])
                for entry in tree:
                    path = entry.get('path','')
                    if any(path.lower().endswith(ext) for ext in SENSITIVE_EXTS):
                        raw_url = f'https://raw.githubusercontent.com/{full}/HEAD/{path}'
                        urls.append(raw_url)
    except Exception as e:
        LOG.debug(f'github search failed: {e}')
    return urls


def public_bucket_candidate_urls(domain: str, common_names: List[str] = None) -> List[str]:
    # Heuristic: discover typical bucket names and test for common files. This is conservative.
    if common_names is None:
        common_names = [domain, domain.replace('.', '-'), 'www-' + domain]
    candidates = []
    for name in common_names:
        # s3 public index heuristics
        candidates.append(f'https://{name}.s3.amazonaws.com/')
        candidates.append(f'https://{name}.s3.amazonaws.com/robots.txt')
    return candidates


# ---------- Download + analyze ----------

def download_to(path: Path, url: str) -> bool:
    try:
        r = requests.get(url, stream=True, timeout=30)
        if r.status_code == 200:
            with path.open('wb') as fh:
                shutil.copyfileobj(r.raw, fh)
            return True
    except Exception as e:
        LOG.debug(f'download failed {url}: {e}')
    return False


def analyze_downloaded_file(path: Path) -> Dict[str, Any]:
    ext = path.suffix.lower()
    data = {'file': str(path), 'sha1': sha1_of_file(path), 'metadata': {}, 'text': '', 'found': {}}
    if ext == '.pdf':
        r = extract_pdf_metadata_and_text(path)
        data['metadata'] = r['metadata']
        data['text'] = r['text'][:200000]
    elif ext in ('.docx', '.doc'):
        r = extract_docx_metadata_and_text(path)
        data['metadata'] = r['metadata']
        data['text'] = r['text'][:200000]
    elif ext in ('.xlsx', '.xls'):
        r = extract_xlsx_metadata_and_text(path)
        data['metadata'] = r['metadata']
        data['text'] = r['text'][:200000]
    elif ext in ('.png', '.jpg', '.jpeg'):
        r = extract_image_metadata_and_text(path)
        data['metadata'] = r['metadata']
    else:
        # try to read text
        try:
            data['text'] = path.read_text(encoding='utf-8', errors='ignore')[:200000]
        except Exception:
            data['text'] = ''
    data['found'] = find_sensitive_patterns('\n'.join([json.dumps(data['metadata']), data.get('text','')]))
    return data


# ---------- Entity resolution & scoring ----------

def build_entities_from_candidates(candidates_path: Path) -> List[Dict[str, Any]]:
    entities: List[Dict[str, Any]] = []
    if not candidates_path.exists():
        LOG.info('candidates file not found; returning empty entities')
        return entities
    with candidates_path.open() as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            name = obj.get('name') or obj.get('login') or obj.get('author')
            email = obj.get('email')
            if not name and not email:
                continue
            # match existing entity by fuzzy name or exact email
            matched = None
            for ent in entities:
                if email and any(e.get('email') == email for e in ent.get('emails', [])):
                    matched = ent; break
                if name and ent.get('name'):
                    score = fuzz.token_sort_ratio(name, ent['name'])
                    if score > 85:
                        matched = ent; break
            if not matched:
                ent = {'name': name, 'emails': [], 'profiles': [], 'evidence': [], 'score': 30}
                entities.append(ent)
                matched = ent
            if email and email not in [e['value'] for e in matched['emails']]:
                matched['emails'].append({'value': email, 'source': obj.get('source','candidate'), 'confidence': obj.get('confidence',40)})
            # add profile links
            for k in ('github','profile_url','html_url'):
                if k in obj:
                    matched['profiles'].append({'url': obj[k], 'source': obj.get('source','github')})
            matched['evidence'].append({'module': obj.get('module','unknown'), 'raw': obj})
            # bump score
            matched['score'] = min(100, matched.get('score',30) + 10)
    return entities


# ---------- Writer to Obsidian notes ----------

def write_person_notes(entities: List[Dict[str, Any]], cfg: Config):
    safe_mkdir(cfg.people_dir)
    for ent in entities:
        name = ent.get('name','unknown')
        slug = re.sub(r'[^A-Za-z0-9_\-]', '_', name)[:80]
        md_path = cfg.people_dir / f"{slug}.md"
        # build frontmatter
        fm = {
            'type': 'person',
            'name': name,
            'role': ent.get('role',''),
            'org': cfg.target,
            'photo': ent.get('photo',''),
            'email': [],
            'evidence': [],
            'generated': datetime.utcnow().isoformat() + 'Z',
            'verified': False
        }
        for e in ent.get('emails', []):
            val = e['value']
            if not cfg.allow_unmask:
                val = mask_email(val)
            fm['email'].append({'value': val, 'confidence': e.get('confidence',40), 'source': e.get('source','')})
        # evidence
        for ev in ent.get('evidence', []):
            raw = ev.get('raw',{})
            fm['evidence'].append({
                'source': raw.get('source','unknown'),
                'type': raw.get('module', raw.get('type','unknown')),
                'value': raw.get('email') or raw.get('repo') or raw.get('name') or '',
                'note': raw.get('note',''),
                'timestamp': raw.get('timestamp',''),
                'confidence': raw.get('confidence',40)
            })
        # write file
        with md_path.open('w', encoding='utf-8') as fh:
            fh.write('---\n')
            yaml.safe_dump(fm, fh, sort_keys=False)
            fh.write('---\n\n')
            fh.write(f"# {name}\n\n")
            fh.write(f"**Auto-generated**: {fm['generated']}\n\n")
            fh.write('## Evidence (auto-collected)\n')
            for e in fm['evidence']:
                fh.write(f"- {e['source']} | {e['type']} | {e['value']} | confidence: {e['confidence']}\n")
        LOG.info(f'Wrote person note: {md_path}')


# ---------- File searcher orchestration ----------

def run_file_search_and_analyze(cfg: Config, github_token: Optional[str] = None, wayback_limit: int = 500):
    safe_mkdir(cfg.raw_dir)
    found_files = []
    # 1) wayback
    LOG.info('Querying Wayback for likely document URLs...')
    wb_urls = wayback_file_urls(cfg.target, limit=wayback_limit)
    LOG.info(f'Wayback returned {len(wb_urls)} candidate URLs')
    for u in wb_urls:
        try:
            p = cfg.raw_dir / hashlib.sha1(u.encode()).hexdigest()[:12]
            ext = Path(u).suffix or '.bin'
            p = p.with_suffix(ext)
            if download_to(p, u):
                LOG.info(f'Downloaded: {u} -> {p.name}')
                meta = analyze_downloaded_file(p)
                found_files.append({'url': u, 'path': str(p), 'meta': meta})
        except Exception as e:
            LOG.debug(f'failed process wayback url {u}: {e}')
    # 2) GitHub
    LOG.info('Searching GitHub org (heuristic) for raw files...')
    org = cfg.target
    gh_urls = github_raw_file_urls_for_org(org, token=github_token)
    for u in gh_urls:
        p = cfg.raw_dir / hashlib.sha1(u.encode()).hexdigest()[:12]
        ext = Path(u).suffix or '.bin'
        p = p.with_suffix(ext)
        if download_to(p, u):
            LOG.info(f'Downloaded GH: {u} -> {p.name}')
            meta = analyze_downloaded_file(p)
            found_files.append({'url': u, 'path': str(p), 'meta': meta})
    # 3) public bucket heuristics (lightweight)
    LOG.info('Testing public bucket heuristics...')
    bucket_candidates = public_bucket_candidate_urls(cfg.target)
    for u in bucket_candidates:
        try:
            r = requests.get(u, timeout=10)
            if r.status_code == 200:
                LOG.info(f'Public bucket likely accessible: {u}')
                # save index HTML
                p = cfg.raw_dir / hashlib.sha1(u.encode()).hexdigest()[:12]
                p = p.with_suffix('.html')
                p.write_bytes(r.content)
                found_files.append({'url': u, 'path': str(p), 'meta': {'metadata': {}, 'text': r.text}})
        except Exception as e:
            LOG.debug(f'bucket check failed: {e}')

    # write summary
    summary = {'generated': datetime.utcnow().isoformat() + 'Z', 'target': cfg.target, 'found': found_files}
    with cfg.output_struct.open('w', encoding='utf-8') as fh:
        json.dump(summary, fh, indent=2)
    LOG.info(f'Wrote file search summary: {cfg.output_struct}')
    return summary


# ---------- Main CLI ----------

def main(argv=None):
    p = argparse.ArgumentParser(description='OSINT People Enricher v1.0 (defensive)')
    p.add_argument('--target', '-t', required=True)
    p.add_argument('--obsdir', default=str(Path.home() / 'ObsidianVault'))
    p.add_argument('--auth', required=True, help='authorization file (must exist; include ALLOW_UNMASK to permit unmask)')
    p.add_argument('--templates', default=str(Path.home() / '.openpipes' / '.templates'))
    p.add_argument('--seeds', help='optional seeds file (domains, repos)')
    p.add_argument('--github-token', help='optional GitHub token to increase rate limits')
    args = p.parse_args(argv)

    cfg = Config(target=args.target, obsdir=Path(args.obsdir), auth_file=Path(args.auth), templates_dir=Path(args.templates), seeds_file=Path(args.seeds) if args.seeds else None)
    safe_mkdir(cfg.raw_dir)
    safe_mkdir(cfg.people_dir)

    # 1) Run file search + analysis
    summary = run_file_search_and_analyze(cfg, github_token=args.github_token)

    # 2) Build entities from candidates (if present)
    entities = build_entities_from_candidates(cfg.candidates_file) if cfg.candidates_file.exists() else []

    # 3) From file search results, try to associate extracted metadata to entities (matching author names, usernames, emails found in metadata)
    # simple matching: check author fields and text for names/emails
    for f in summary['found']:
        meta = f.get('meta', {})
        # author keys
        author = None
        for k in ('Author','author','creator','Creator','lastModifiedBy'):
            v = meta.get('metadata',{}).get(k)
            if v:
                author = v; break
        text = meta.get('text','')
        # find emails in metadata/text
        emails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", json.dumps(meta)))
        # try to attach evidence to entities
        for ent in entities:
            # match by name fuzzy
            if ent.get('name') and author and fuzz.token_sort_ratio(ent['name'], author) > 85:
                ent['evidence'].append({'module':'file_search','raw':{'file': f['url'], 'author': author}})
            # match by email exact
            for em in emails:
                for em_obj in ent.get('emails', []):
                    if em_obj.get('value') and em.lower() == em_obj['value'].lower():
                        ent['evidence'].append({'module':'file_search','raw':{'file': f['url'], 'email': em}})

    # 4) Write notes
    write_person_notes(entities, cfg)

    LOG.info('Done.')

if __name__ == '__main__':
    main()
