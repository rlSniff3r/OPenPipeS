#!/usr/bin/env python3
"""
osint_doc_finder.py - Document Finder with Web Search
Versão: 2.0 - COM BUSCA WEB REAL

Busca documentos públicos relacionados ao target através de:
- Wayback Machine (archive.org)
- Google Custom Search API
- GitHub Code Search
- Bing Search API
- Common Crawl (opcional)

E extrai metadados sensíveis usando exiftool.
"""

import os
import sys
import json
import subprocess
import logging
import hashlib
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
from datetime import datetime

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[ERROR] Missing 'requests'. Install: pip install requests")
    sys.exit(1)

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)

# Extensões de documentos interessantes
DOCUMENT_EXTENSIONS = (
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.csv', '.rtf', '.odt', '.ods', '.odp',
    '.zip', '.tar', '.gz', '.7z', '.rar'
)

# Padrões sensíveis para buscar no texto/metadata
SENSITIVE_PATTERNS = {
    'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'internal_ips': r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b',
    'urls': r'https?://[^\s<>"]+',
    'paths': r'(?:/[\w\-\.]+){3,}',
    'usernames': r'(?:username|user|login)[:\s=]+([a-zA-Z0-9._-]+)',
}


def create_session() -> requests.Session:
    """Cria sessão HTTP com retry strategy."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    # User agent realista
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    })
    
    return session


class WaybackMachineCollector:
    """Busca documentos arquivados no Wayback Machine."""
    
    def __init__(self):
        self.session = create_session()
        self.cdx_api = 'http://web.archive.org/cdx/search/cdx'
    
    def search_domain(self, domain: str, limit: int = 1000) -> List[Dict[str, str]]:
        """Busca URLs arquivadas de um domínio."""
        log.info(f"Searching Wayback Machine for: {domain}")
        
        results = []
        
        for ext in DOCUMENT_EXTENSIONS:
            try:
                params = {
                    'url': f'*.{domain}/*{ext}',
                    'output': 'json',
                    'fl': 'original,timestamp,statuscode',
                    'filter': 'statuscode:200',
                    'collapse': 'urlkey',
                    'limit': limit
                }
                
                response = self.session.get(self.cdx_api, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                
                # Skip header row
                for row in data[1:]:
                    if len(row) >= 3:
                        results.append({
                            'url': row[0],
                            'timestamp': row[1],
                            'status': row[2],
                            'source': 'wayback',
                            'wayback_url': f'https://web.archive.org/web/{row[1]}/{row[0]}'
                        })
                
                log.info(f"  Found {len(data)-1} {ext} files")
                time.sleep(0.5)  # Be respectful
                
            except Exception as e:
                log.error(f"Wayback search error for {ext}: {e}")
        
        log.info(f"Wayback total: {len(results)} documents")
        return results


class GoogleCustomSearchCollector:
    """Busca documentos via Google Custom Search API."""
    
    def __init__(self, api_key: Optional[str] = None, cx: Optional[str] = None):
        self.api_key = api_key or os.environ.get('GOOGLE_API_KEY')
        self.cx = cx or os.environ.get('GOOGLE_CX')
        self.session = create_session()
        self.base_url = 'https://www.googleapis.com/customsearch/v1'
    
    def search(self, query: str, num: int = 10) -> List[Dict[str, str]]:
        """Executa busca no Google Custom Search."""
        if not self.api_key or not self.cx:
            log.warning("Google Custom Search not configured (GOOGLE_API_KEY, GOOGLE_CX)")
            return []
        
        try:
            params = {
                'key': self.api_key,
                'cx': self.cx,
                'q': query,
                'num': num
            }
            
            response = self.session.get(self.base_url, params=params, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            items = data.get('items', [])
            
            results = []
            for item in items:
                results.append({
                    'url': item.get('link'),
                    'title': item.get('title'),
                    'snippet': item.get('snippet'),
                    'source': 'google'
                })
            
            return results
            
        except Exception as e:
            log.error(f"Google search error: {e}")
            return []
    
    def search_documents(self, domain: str, limit: int = 50) -> List[Dict[str, str]]:
        """Busca documentos de um domínio específico."""
        log.info(f"Searching Google for documents: {domain}")
        
        all_results = []
        
        # Buscar cada tipo de arquivo
        for ext in ['.pdf', '.docx', '.xlsx', '.pptx']:
            query = f'site:{domain} filetype:{ext[1:]}'
            results = self.search(query, num=min(10, limit))
            all_results.extend(results)
            time.sleep(1)  # Rate limiting
        
        log.info(f"Google total: {len(all_results)} documents")
        return all_results


class BingSearchCollector:
    """Busca documentos via Bing Search API."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get('BING_API_KEY')
        self.session = create_session()
        self.base_url = 'https://api.bing.microsoft.com/v7.0/search'
    
    def search_documents(self, domain: str, limit: int = 50) -> List[Dict[str, str]]:
        """Busca documentos via Bing."""
        if not self.api_key:
            log.warning("Bing Search not configured (BING_API_KEY)")
            return []
        
        log.info(f"Searching Bing for documents: {domain}")
        
        results = []
        
        for ext in ['.pdf', '.docx', '.xlsx']:
            try:
                query = f'site:{domain} filetype:{ext[1:]}'
                
                headers = {'Ocp-Apim-Subscription-Key': self.api_key}
                params = {'q': query, 'count': min(50, limit)}
                
                response = self.session.get(
                    self.base_url,
                    headers=headers,
                    params=params,
                    timeout=15
                )
                response.raise_for_status()
                
                data = response.json()
                
                for item in data.get('webPages', {}).get('value', []):
                    results.append({
                        'url': item.get('url'),
                        'title': item.get('name'),
                        'snippet': item.get('snippet'),
                        'source': 'bing'
                    })
                
                time.sleep(1)
                
            except Exception as e:
                log.error(f"Bing search error for {ext}: {e}")
        
        log.info(f"Bing total: {len(results)} documents")
        return results


class GitHubCodeSearch:
    """Busca documentos em repositórios GitHub."""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get('GITHUB_TOKEN')
        self.session = create_session()
        self.base_url = 'https://api.github.com'
        
        if self.token:
            self.session.headers.update({'Authorization': f'token {self.token}'})
    
    def search_code(self, query: str, limit: int = 100) -> List[Dict[str, str]]:
        """Busca código/documentos no GitHub."""
        if not self.token:
            log.warning("GitHub token not configured - skipping code search")
            return []
        
        log.info(f"Searching GitHub code: {query}")
        
        try:
            params = {
                'q': query,
                'per_page': min(100, limit)
            }
            
            response = self.session.get(
                f"{self.base_url}/search/code",
                params=params,
                timeout=15
            )
            response.raise_for_status()
            
            data = response.json()
            items = data.get('items', [])
            
            results = []
            for item in items:
                results.append({
                    'url': item.get('html_url'),
                    'path': item.get('path'),
                    'repo': item.get('repository', {}).get('full_name'),
                    'source': 'github'
                })
            
            log.info(f"GitHub total: {len(results)} files")
            return results
            
        except Exception as e:
            log.error(f"GitHub search error: {e}")
            return []
    
    def search_documents(self, org: str) -> List[Dict[str, str]]:
        """Busca documentos em uma organização GitHub."""
        results = []
        
        for ext in ['.pdf', '.docx', '.xlsx', '.md']:
            query = f'org:{org} extension:{ext[1:]}'
            results.extend(self.search_code(query, limit=50))
            time.sleep(2)
        
        return results


class DocumentDownloader:
    """Faz download de documentos encontrados."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = create_session()
    
    def download(self, url: str, max_size_mb: int = 50) -> Optional[Path]:
        """Faz download de um documento."""
        try:
            # HEAD request para verificar tamanho
            head = self.session.head(url, timeout=10, allow_redirects=True)
            
            content_length = head.headers.get('content-length')
            if content_length:
                size_mb = int(content_length) / (1024 * 1024)
                if size_mb > max_size_mb:
                    log.warning(f"File too large ({size_mb:.1f}MB): {url}")
                    return None
            
            # Download
            response = self.session.get(url, timeout=30, stream=True)
            response.raise_for_status()
            
            # Gerar nome de arquivo único
            url_hash = hashlib.sha256(url.encode()).hexdigest()[:12]
            parsed = urlparse(url)
            ext = Path(parsed.path).suffix or '.bin'
            filename = f"{url_hash}{ext}"
            filepath = self.output_dir / filename
            
            # Salvar
            with filepath.open('wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            log.info(f"Downloaded: {filename}")
            return filepath
            
        except Exception as e:
            log.error(f"Download failed for {url}: {e}")
            return None


class MetadataExtractor:
    """Extrai metadados de documentos usando exiftool."""
    
    def extract(self, filepath: Path) -> Dict[str, Any]:
        """Extrai metadados de forma segura."""
        try:
            result = subprocess.run(
                ['exiftool', '-json', '-G', str(filepath)],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if data and isinstance(data, list):
                    return data[0]
            
        except subprocess.TimeoutExpired:
            log.error(f"Timeout extracting metadata: {filepath}")
        except json.JSONDecodeError:
            log.error(f"Failed to parse exiftool output: {filepath}")
        except Exception as e:
            log.error(f"Metadata extraction error: {e}")
        
        return {}
    
    def find_sensitive_data(self, metadata: Dict, text: str = '') -> Dict[str, List[str]]:
        """Encontra padrões sensíveis em metadados e texto."""
        import re
        
        found = {key: [] for key in SENSITIVE_PATTERNS.keys()}
        
        # Combinar metadata e texto
        combined = json.dumps(metadata) + '\n' + text
        
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, combined, re.IGNORECASE)
            found[pattern_name] = list(set(matches))[:20]  # Limitar a 20
        
        return found


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target> <output_dir>")
        print()
        print("Environment variables:")
        print("  GOOGLE_API_KEY   - Google Custom Search API key")
        print("  GOOGLE_CX        - Google Custom Search Engine ID")
        print("  BING_API_KEY     - Bing Search API key")
        print("  GITHUB_TOKEN     - GitHub personal access token")
        sys.exit(1)
    
    target = sys.argv[1]
    outdir = Path(sys.argv[2])
    
    # Criar diretório de output
    outdir.mkdir(parents=True, exist_ok=True)
    raw_dir = outdir / 'raw_files'
    raw_dir.mkdir(exist_ok=True)
    
    log.info(f"Starting document search for: {target}")
    log.info("=" * 60)
    
    all_documents = []
    
    # 1. Wayback Machine
    log.info("Source 1/4: Wayback Machine")
    wayback = WaybackMachineCollector()
    wayback_docs = wayback.search_domain(target, limit=500)
    all_documents.extend(wayback_docs)
    
    # 2. Google Custom Search
    log.info("Source 2/4: Google Custom Search")
    google = GoogleCustomSearchCollector()
    google_docs = google.search_documents(target, limit=50)
    all_documents.extend(google_docs)
    
    # 3. Bing Search
    log.info("Source 3/4: Bing Search")
    bing = BingSearchCollector()
    bing_docs = bing.search_documents(target, limit=50)
    all_documents.extend(bing_docs)
    
    # 4. GitHub Code Search
    log.info("Source 4/4: GitHub")
    github = GitHubCodeSearch()
    github_docs = github.search_documents(target)
    all_documents.extend(github_docs)
    
    log.info("=" * 60)
    log.info(f"Total documents found: {len(all_documents)}")
    
    # Download e análise
    log.info("Downloading and analyzing documents...")
    
    downloader = DocumentDownloader(raw_dir)
    extractor = MetadataExtractor()
    
    analyzed_docs = []
    
    for idx, doc in enumerate(all_documents[:100], 1):  # Limitar a 100 downloads
        url = doc.get('url') or doc.get('wayback_url')
        if not url:
            continue
        
        log.info(f"[{idx}/{min(100, len(all_documents))}] Processing: {url}")
        
        # Download
        filepath = downloader.download(url)
        if not filepath:
            continue
        
        # Extrair metadados
        metadata = extractor.extract(filepath)
        
        # Buscar padrões sensíveis
        sensitive = extractor.find_sensitive_data(metadata)
        
        analyzed = {
            'url': url,
            'filepath': str(filepath),
            'filename': filepath.name,
            'size': filepath.stat().st_size,
            'source': doc.get('source'),
            'metadata': metadata,
            'sensitive_data': sensitive,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        analyzed_docs.append(analyzed)
        
        time.sleep(0.5)  # Rate limiting
    
    # Salvar resultados
    output_file = outdir / 'metadata.json'
    
    final_output = {
        'target': target,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'total_found': len(all_documents),
        'total_downloaded': len(analyzed_docs),
        'sources': {
            'wayback': len(wayback_docs),
            'google': len(google_docs),
            'bing': len(bing_docs),
            'github': len(github_docs)
        },
        'documents': analyzed_docs
    }
    
    with output_file.open('w', encoding='utf-8') as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)
    
    log.info("=" * 60)
    log.info(f"[✔] Document search complete!")
    log.info(f"Total documents found: {len(all_documents)}")
    log.info(f"Documents downloaded: {len(analyzed_docs)}")
    log.info(f"Results saved to: {output_file}")
    
    # Estatísticas de dados sensíveis
    total_emails = sum(len(d['sensitive_data']['emails']) for d in analyzed_docs)
    total_ips = sum(len(d['sensitive_data']['internal_ips']) for d in analyzed_docs)
    
    log.info("")
    log.info("Sensitive data found:")
    log.info(f"  - Emails: {total_emails}")
    log.info(f"  - Internal IPs: {total_ips}")


if __name__ == '__main__':
    main()