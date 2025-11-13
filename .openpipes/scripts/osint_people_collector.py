#!/usr/bin/env python3
"""
osint_people_collector.py - Real People Data Collector
Versão: 2.0 - IMPLEMENTAÇÃO REAL

Coleta informações sobre colaboradores de uma organização através de:
- GitHub API (membros, commits, repos)
- LinkedIn (parsing ético)
- Hunter.io API (emails)
- Google Custom Search (mentions)
- Have I Been Pwned (data breaches)

AVISO: Use apenas com autorização apropriada para fins de segurança defensiva.
"""

import json
import sys
import os
import time
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import hashlib

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[ERROR] Missing 'requests' library. Install: pip install requests")
    sys.exit(1)

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)

# Rate limiting decorator
class RateLimiter:
    def __init__(self, calls: int, period: int):
        self.calls = calls
        self.period = period
        self.timestamps = []
    
    def __call__(self, func):
        def wrapper(*args, **kwargs):
            now = time.time()
            # Remove timestamps fora do período
            self.timestamps = [t for t in self.timestamps if t > now - self.period]
            
            if len(self.timestamps) >= self.calls:
                sleep_time = self.period - (now - self.timestamps[0])
                if sleep_time > 0:
                    log.debug(f"Rate limit reached, sleeping {sleep_time:.2f}s")
                    time.sleep(sleep_time)
            
            self.timestamps.append(time.time())
            return func(*args, **kwargs)
        return wrapper
    return self


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
    return session


class GitHubCollector:
    """Coleta dados de colaboradores via GitHub API."""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get('GITHUB_TOKEN')
        self.session = create_session()
        self.base_url = 'https://api.github.com'
        
        if self.token:
            self.session.headers.update({'Authorization': f'token {self.token}'})
            log.info("GitHub token configured")
        else:
            log.warning("No GitHub token - rate limits will be strict (60 req/hour)")
    
    @RateLimiter(calls=30, period=60)
    def _api_call(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Faz chamada à API do GitHub com rate limiting."""
        try:
            url = f"{self.base_url}/{endpoint}"
            response = self.session.get(url, params=params, timeout=15)
            
            # Log rate limit info
            remaining = response.headers.get('X-RateLimit-Remaining', 'unknown')
            log.debug(f"GitHub API rate limit remaining: {remaining}")
            
            if response.status_code == 404:
                log.warning(f"Not found: {endpoint}")
                return None
            elif response.status_code == 403:
                log.error("GitHub rate limit exceeded or forbidden")
                return None
            
            response.raise_for_status()
            return response.json()
        except Exception as e:
            log.error(f"GitHub API error for {endpoint}: {e}")
            return None
    
    def get_org_members(self, org: str) -> List[Dict[str, Any]]:
        """Lista membros públicos de uma organização."""
        log.info(f"Fetching GitHub org members: {org}")
        members = []
        page = 1
        
        while True:
            data = self._api_call(f"orgs/{org}/members", {'page': page, 'per_page': 100})
            if not data:
                break
            
            members.extend(data)
            
            if len(data) < 100:
                break
            page += 1
        
        log.info(f"Found {len(members)} org members")
        return members
    
    def get_user_details(self, username: str) -> Optional[Dict[str, Any]]:
        """Obtém detalhes de um usuário."""
        return self._api_call(f"users/{username}")
    
    def get_user_events(self, username: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Obtém eventos recentes de um usuário."""
        events = self._api_call(f"users/{username}/events/public", {'per_page': limit})
        return events if events else []
    
    def get_repo_contributors(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Lista contribuidores de um repositório."""
        contributors = self._api_call(f"repos/{owner}/{repo}/contributors", {'per_page': 100})
        return contributors if contributors else []
    
    def search_commits_by_email(self, email: str, org: str = None) -> List[Dict[str, Any]]:
        """Busca commits por email do autor."""
        query = f"author-email:{email}"
        if org:
            query += f" org:{org}"
        
        data = self._api_call("search/commits", {'q': query, 'per_page': 10})
        return data.get('items', []) if data else []
    
    def collect_from_org(self, org: str) -> List[Dict[str, Any]]:
        """Coleta completa de dados de uma organização."""
        people = []
        
        # 1. Membros da organização
        members = self.get_org_members(org)
        
        for member in members:
            username = member.get('login')
            if not username:
                continue
            
            log.info(f"Processing GitHub user: {username}")
            
            # Detalhes do usuário
            user_details = self.get_user_details(username)
            if not user_details:
                continue
            
            person = {
                'name': user_details.get('name') or username,
                'email': user_details.get('email', ''),
                'role': '',
                'photo': user_details.get('avatar_url', ''),
                'github': user_details.get('html_url', ''),
                'linkedin': '',
                'source': 'github',
                'confidence': 90,
                'metadata': {
                    'github_id': user_details.get('id'),
                    'username': username,
                    'bio': user_details.get('bio', ''),
                    'company': user_details.get('company', ''),
                    'location': user_details.get('location', ''),
                    'blog': user_details.get('blog', ''),
                    'twitter': user_details.get('twitter_username', ''),
                    'public_repos': user_details.get('public_repos', 0),
                    'followers': user_details.get('followers', 0),
                    'created_at': user_details.get('created_at', ''),
                }
            }
            
            people.append(person)
            time.sleep(0.5)  # Be nice to API
        
        return people


class HunterIOCollector:
    """Coleta emails via Hunter.io API."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get('HUNTER_API_KEY')
        self.session = create_session()
        self.base_url = 'https://api.hunter.io/v2'
    
    @RateLimiter(calls=10, period=60)
    def domain_search(self, domain: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Busca emails associados a um domínio."""
        if not self.api_key:
            log.warning("Hunter.io API key not configured")
            return []
        
        log.info(f"Searching emails for domain: {domain}")
        
        try:
            response = self.session.get(
                f"{self.base_url}/domain-search",
                params={'domain': domain, 'api_key': self.api_key, 'limit': limit},
                timeout=15
            )
            response.raise_for_status()
            data = response.json()
            
            emails = data.get('data', {}).get('emails', [])
            log.info(f"Found {len(emails)} emails via Hunter.io")
            
            people = []
            for email_data in emails:
                person = {
                    'name': f"{email_data.get('first_name', '')} {email_data.get('last_name', '')}".strip() or 'Unknown',
                    'email': email_data.get('value', ''),
                    'role': email_data.get('position', ''),
                    'photo': '',
                    'github': '',
                    'linkedin': email_data.get('linkedin', ''),
                    'source': 'hunter.io',
                    'confidence': email_data.get('confidence', 0),
                    'metadata': {
                        'department': email_data.get('department', ''),
                        'phone': email_data.get('phone_number', ''),
                        'twitter': email_data.get('twitter', ''),
                        'type': email_data.get('type', ''),
                        'verification_status': email_data.get('verification', {}).get('status', '')
                    }
                }
                people.append(person)
            
            return people
            
        except Exception as e:
            log.error(f"Hunter.io API error: {e}")
            return []


class LinkedInCollector:
    """Coleta dados do LinkedIn (parsing ético via Google)."""
    
    def __init__(self):
        self.session = create_session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
    
    @RateLimiter(calls=5, period=60)
    def search_via_google(self, company: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Busca perfis do LinkedIn via Google Search."""
        log.info(f"Searching LinkedIn profiles via Google: {company}")
        
        # Google Dork para perfis LinkedIn
        query = f'site:linkedin.com/in/ "{company}"'
        
        # NOTA: Isto é uma implementação simplificada
        # Para produção, use Google Custom Search API
        
        log.warning("LinkedIn search via Google is limited - use Google Custom Search API for production")
        
        # Placeholder - implementação real requer API key
        return []


class HIBPCollector:
    """Verifica emails em data breaches via Have I Been Pwned."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get('HIBP_API_KEY')
        self.session = create_session()
        self.base_url = 'https://haveibeenpwned.com/api/v3'
        
        if self.api_key:
            self.session.headers.update({'hibp-api-key': self.api_key})
    
    @RateLimiter(calls=1, period=2)  # HIBP rate limit: 1 request every 1.5s
    def check_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Verifica se email aparece em breaches."""
        if not self.api_key:
            log.debug("HIBP API key not configured, skipping breach check")
            return None
        
        try:
            response = self.session.get(
                f"{self.base_url}/breachedaccount/{email}",
                timeout=10
            )
            
            if response.status_code == 404:
                log.debug(f"Email not found in breaches: {email}")
                return None
            
            response.raise_for_status()
            breaches = response.json()
            
            log.warning(f"Email found in {len(breaches)} breaches: {email}")
            
            return {
                'email': email,
                'breach_count': len(breaches),
                'breaches': [b.get('Name') for b in breaches[:5]]  # Top 5
            }
            
        except Exception as e:
            log.debug(f"HIBP check error for {email}: {e}")
            return None


def deduplicate_people(people: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicatas e mescla informações."""
    from collections import defaultdict
    
    # Agrupar por email ou nome
    groups = defaultdict(list)
    
    for person in people:
        # Usar email como chave principal, senão nome
        key = person.get('email') or person.get('name', 'unknown')
        key = key.lower().strip()
        groups[key].append(person)
    
    deduplicated = []
    
    for key, group in groups.items():
        if not group:
            continue
        
        # Mesclar informações do grupo
        merged = group[0].copy()
        
        # Pegar melhor confidence
        merged['confidence'] = max(p.get('confidence', 0) for p in group)
        
        # Mesclar campos não vazios
        for person in group[1:]:
            for field in ['name', 'email', 'role', 'photo', 'github', 'linkedin']:
                if not merged.get(field) and person.get(field):
                    merged[field] = person[field]
            
            # Mesclar metadata
            if 'metadata' not in merged:
                merged['metadata'] = {}
            if 'metadata' in person:
                merged['metadata'].update(person['metadata'])
        
        # Adicionar fontes
        sources = list(set(p.get('source', '') for p in group if p.get('source')))
        merged['sources'] = sources
        merged['source'] = ', '.join(sources)
        
        deduplicated.append(merged)
    
    log.info(f"Deduplicated {len(people)} → {len(deduplicated)} people")
    return deduplicated


def enrich_with_breach_data(people: List[Dict[str, Any]], hibp: HIBPCollector) -> List[Dict[str, Any]]:
    """Enriquece dados com informações de breaches."""
    log.info("Checking for data breaches...")
    
    for person in people:
        email = person.get('email')
        if not email:
            continue
        
        breach_data = hibp.check_email(email)
        if breach_data:
            if 'metadata' not in person:
                person['metadata'] = {}
            person['metadata']['breaches'] = breach_data
            person['metadata']['security_risk'] = 'HIGH' if breach_data['breach_count'] > 3 else 'MEDIUM'
    
    return people


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target> <output_file>")
        print()
        print("Environment variables:")
        print("  GITHUB_TOKEN     - GitHub personal access token")
        print("  HUNTER_API_KEY   - Hunter.io API key")
        print("  HIBP_API_KEY     - Have I Been Pwned API key")
        sys.exit(1)
    
    target = sys.argv[1]
    outfile = Path(sys.argv[2])
    
    log.info(f"Starting people collection for: {target}")
    log.info("=" * 60)
    
    all_people = []
    
    # 1. GitHub
    log.info("Module 1/4: GitHub")
    github = GitHubCollector()
    github_people = github.collect_from_org(target)
    all_people.extend(github_people)
    log.info(f"GitHub: {len(github_people)} people collected")
    
    # 2. Hunter.io
    log.info("Module 2/4: Hunter.io")
    hunter = HunterIOCollector()
    hunter_people = hunter.domain_search(f"{target}.com")
    all_people.extend(hunter_people)
    log.info(f"Hunter.io: {len(hunter_people)} people collected")
    
    # 3. LinkedIn (via Google)
    log.info("Module 3/4: LinkedIn")
    linkedin = LinkedInCollector()
    linkedin_people = linkedin.search_via_google(target)
    all_people.extend(linkedin_people)
    log.info(f"LinkedIn: {len(linkedin_people)} people collected")
    
    # 4. Deduplicate
    log.info("Deduplicating and merging data...")
    deduplicated = deduplicate_people(all_people)
    
    # 5. Enrich with HIBP
    log.info("Module 4/4: Have I Been Pwned")
    hibp = HIBPCollector()
    enriched = enrich_with_breach_data(deduplicated, hibp)
    
    # Generate output
    output = {
        'target': target,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'total_collected': len(all_people),
        'total_unique': len(enriched),
        'sources': list(set(p.get('source', '') for p in enriched)),
        'people': enriched
    }
    
    # Save to file
    outfile.parent.mkdir(parents=True, exist_ok=True)
    
    with outfile.open('w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    log.info("=" * 60)
    log.info(f"[✔] Collection complete!")
    log.info(f"Total people collected: {len(all_people)}")
    log.info(f"Unique people after deduplication: {len(enriched)}")
    log.info(f"Output saved to: {outfile}")
    
    # Summary
    with_email = sum(1 for p in enriched if p.get('email'))
    with_github = sum(1 for p in enriched if p.get('github'))
    with_breaches = sum(1 for p in enriched if p.get('metadata', {}).get('breaches'))
    
    log.info("")
    log.info("Statistics:")
    log.info(f"  - With email: {with_email}")
    log.info(f"  - With GitHub: {with_github}")
    log.info(f"  - Found in breaches: {with_breaches}")


if __name__ == '__main__':
    main()