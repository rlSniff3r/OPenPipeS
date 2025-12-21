#!/usr/bin/env python3
import sys
import json
import argparse
import re
from urllib.parse import urlparse
import os

# Configurações de Extensões por Tecnologia
TECH_MAP = {
    'PHP': ['.php'],
    'ASP': ['.asp', '.aspx'],
    'JSP': ['.jsp', '.do', '.action'],
    'ColdFusion': ['.cfm'],
    'Perl': ['.pl', '.cgi'],
    'Python': ['.py']
}

BACKUP_EXTS = ['.bak', '.old', '.orig', '_backup', '.swp']

def generate_smart_wordlist(urls_file, tech_file):
    """Gera wordlist contextual baseada em arquivos reais e tecnologia detectada."""
    
    # 1. Carregar Tecnologias
    detected_techs = []
    try:
        with open(tech_file, 'r') as f:
            for line in f:
                data = json.loads(line)
                # O httpx retorna techs numa lista ou string, dependendo da versão
                # Normaliza para lista de strings
                tech_entry = data.get('tech', [])
                if isinstance(tech_entry, list):
                    detected_techs.extend(tech_entry)
                else:
                    detected_techs.append(tech_entry)
    except Exception:
        pass # Se falhar, segue sem tech específica
    
    detected_techs = set(detected_techs)
    
    # Determina quais extensões focar
    target_exts = set()
    for tech, exts in TECH_MAP.items():
        # Verifica se alguma tech detectada bate com nossa lista (ex: "PHP/8.1" contém "PHP")
        if any(tech in t for t in detected_techs):
            target_exts.update(exts)
            
    # 2. Processar URLs
    wordlist = set()
    
    try:
        with open(urls_file, 'r') as f:
            urls = f.read().splitlines()
    except FileNotFoundError:
        return

    for url in urls:
        parsed = urlparse(url)
        path = parsed.path
        if not path or path == '/': continue
        
        filename = os.path.basename(path)
        if not filename: continue
        
        # Regra 1: Adicionar o filename puro (ex: "login")
        base_name, ext = os.path.splitext(filename)
        if base_name: 
            wordlist.add(base_name)
        
        # Regra 2: Backup Extensions (index.html -> index.html.bak)
        for bak in BACKUP_EXTS:
            wordlist.add(filename + bak)
            if ext: # Se tinha extensão, tenta backup na base (index.bak)
                wordlist.add(base_name + bak)

        # Regra 3: Tech Swap (index.html -> index.php - SE tiver PHP detectado)
        if target_exts:
            for new_ext in target_exts:
                if ext != new_ext:
                    wordlist.add(base_name + new_ext)
        
        # Regra 4: Permutações de Ano (Só para palavras chave)
        if re.search(r'(admin|login|config|db|backup|teste)', base_name, re.IGNORECASE):
            import datetime
            year = datetime.datetime.now().year
            wordlist.add(f"{base_name}_{year}")
            wordlist.add(f"{base_name}{year}")
            wordlist.add(f"{base_name}_{year-1}")

    # Output limpo
    for w in sorted(wordlist):
        if len(w) > 2: # Ignora lixo curto
            print(w)

def deduplicate_for_screenshots(json_file):
    """Deduplica URLs para o GoWitness baseado em Título e Path."""
    unique_urls = {} # Key: Hash Lógico, Value: URL Data
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f) # Assumindo array de JSON objects do httpx
    except Exception as e:
        sys.stderr.write(f"Error loading JSON: {e}\n")
        return

    # Contadores para limitar paths repetitivos
    path_counters = {} 

    for item in data:
        url = item.get('url')
        title = item.get('title', 'No Title')
        status = item.get('status_code', 0)
        
        # Filtro 1: Status Code Irrelevante (exceto se tiver título interessante)
        if status in [404, 500, 502, 503] and title == 'No Title':
            continue

        parsed = urlparse(url)
        path_structure = os.path.dirname(parsed.path)
        
        # Filtro 2: Path Limiter (Max 3 screenshots por diretório base)
        # Ex: /blog/post1, /blog/post2, /blog/post3 -> O quarto é ignorado
        path_key = f"{parsed.netloc}{path_structure}"
        path_counters[path_key] = path_counters.get(path_key, 0) + 1
        
        if path_counters[path_key] > 3:
            continue

        # Filtro 3: Title Uniqueness (Se o título é identico, ignora)
        # Usa Título + Status como chave única
        unique_key = f"{title}_{status}"
        
        if unique_key not in unique_urls:
            unique_urls[unique_key] = url
            print(url)

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')
    
    # Subcomando Wordlist
    wl_parser = subparsers.add_parser('wordlist')
    wl_parser.add_argument('--urls', required=True)
    wl_parser.add_argument('--tech', required=True)
    
    # Subcomando Dedupe
    dd_parser = subparsers.add_parser('dedupe')
    dd_parser.add_argument('--json', required=True)
    
    args = parser.parse_args()
    
    if args.command == 'wordlist':
        generate_smart_wordlist(args.urls, args.tech)
    elif args.command == 'dedupe':
        deduplicate_for_screenshots(args.json)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
