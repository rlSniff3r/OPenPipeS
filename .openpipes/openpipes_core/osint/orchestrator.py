import sys
import os
import json
import re
import requests
from pathlib import Path
from rich.console import Console
from rich.table import Table

# Importa as nossas Engines isoladas
from openpipes_core.osint import engine_apollo
from openpipes_core.osint import engine_hunter
from openpipes_core.osint import engine_tomba

console = Console()


def load_secrets():
    """
    Lê o secrets.conf e traduz os arrays do Bash para listas do Python.
    Isso é mágico porque mantém a compatibilidade com a infraestrutura shell!
    """
    secrets_path = os.path.join(str(Path.home()), ".openpipes", "secrets.conf")
    secrets = {
        "apollo": [],
        "hunter": [],
        "tomba": [],
    }
    
    if not os.path.exists(secrets_path):
        console.print("[yellow][!] secrets.conf não encontrado. Orquestrador rodará sem chaves.[/yellow]")
        return secrets

    with open(secrets_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Regex Ninja: Busca por APOLLO_KEYS=("chave1" "chave2")
    apollo_match = re.search(r'APOLLO_KEYS=\((.*?)\)', content, re.DOTALL)
    if apollo_match:
        # Pega tudo dentro dos parênteses, divide por espaços e arranca as aspas
        raw_keys = apollo_match.group(1).split()
        secrets["apollo"] = [k.strip("'\"") for k in raw_keys if k.strip("'\"")]

    # Regex do Hunter ficaria aqui no futuro!
    hunter_match = re.search(r'HUNTER_KEYS=\((.*?)\)', content, re.DOTALL)
    if hunter_match:
        raw_keys = hunter_match.group(1).split()
        secrets["hunter"] = [k.strip("'\"") for k in raw_keys if k.strip("'\"")]
    
    # Regex do Tomba
    tomba_match = re.search(r'TOMBA_KEYS=\((.*?)\)', content, re.DOTALL)
    if tomba_match:
        raw_keys = tomba_match.group(1).split()
        secrets["tomba"] = [k.strip("'\"") for k in raw_keys if k.strip("'\"")]
    
    return secrets


def deduplicate(results):
    """
    A faxina fina! Remove contatos duplicados cruzando as bases.
    Prioriza o E-mail como identificador único. Se não tiver e-mail, usa Nome+Sobrenome.
    """
    seen = {}
    for p in results:
        email = p.get("email", "").strip().lower()
        fname = p.get("first_name", "").strip().lower()
        lname = p.get("last_name", "").strip().lower()
        
        # Define a chave de identidade do contato
        if email:
            uid = email
        else:
            uid = f"{fname}_{lname}"
            
        if not uid or uid == "_":
            continue # Pula "fantasmas" que não têm nem nome nem e-mail
            
        if uid not in seen:
            seen[uid] = p
            
    return list(seen.values())


def check_api_status(secrets):
    """Monta um painel mostrando as chaves mascaradas e o saldo de créditos"""
    table = Table(title="Painel de APIs OSINT")
    table.add_column("Serviço", style="cyan", justify="left")
    table.add_column("Chave (Mascarada)", style="dim", justify="center")
    table.add_column("Status / Créditos", style="green", justify="right")

    # ── Checagem do Hunter.io ──
    hunter_keys = secrets.get("hunter", [])
    if not hunter_keys:
        table.add_row("Hunter.io", "Não configurada", "[dim]N/A[/dim]")
    
    for key in hunter_keys:
        masked = f"{key[:4]}...{key[-4:]}"
        try:
            # O Hunter tem um endpoint específico para checar a conta!
            res = requests.get(f"https://api.hunter.io/v2/account?api_key={key}", timeout=10)
            if res.status_code == 200:
                calls = res.json().get("data", {}).get("calls", {})
                used = calls.get("used", 0)
                avail = calls.get("available", 0)
                # Alerta vermelho se estiver perto de acabar
                color = "red" if used >= avail else "green"
                table.add_row("Hunter.io", masked, f"[{color}]{used}/{avail} usados[/{color}]")
            else:
                table.add_row("Hunter.io", masked, f"[red]Erro {res.status_code}[/red]")
        except Exception:
            table.add_row("Hunter.io", masked, "[red]Falha na conexão[/red]")

    # ── Checagem do Tomba.io ──
    tomba_keys = secrets.get("tomba", [])
    if not tomba_keys:
        table.add_row("Tomba.io", "Não configurada", "[dim]N/A[/dim]")
    
    for key_pair in tomba_keys:
        try:
            api_key, api_secret = key_pair.split(":", 1)
            masked = f"{api_key[:4]}...{api_key[-4:]}"
        except ValueError:
            table.add_row("Tomba.io", "Formato Inválido", "[red]Erro de Formato[/red]")
            continue
            
        try:
            headers = {
                "X-Tomba-Key": api_key,
                "X-Tomba-Secret": api_secret,
                "Accept": "application/json",
                "User-Agent": "Tomba-Python/1.0.3"
            }
            res = requests.get("https://api.tomba.io/v1/usage", headers=headers, timeout=10)
            
            if res.status_code == 200:
                json_resp = res.json()
                
                # Se a API retornou uma lista na raiz, pegamos o primeiro item
                if isinstance(json_resp, list) and len(json_resp) > 0:
                    json_resp = json_resp[0]
                    
                requests_used, requests_limit = 0, 0
                
                # Navegação hiper-segura: só usa .get() se for um dicionário de verdade
                if isinstance(json_resp, dict):
                    data = json_resp.get("data")
                    
                    # Se o "data" também for uma lista, pegamos o primeiro
                    if isinstance(data, list) and len(data) > 0:
                        data = data[0]
                        
                    if isinstance(data, dict):
                        usage = data.get("usage")
                        limits = data.get("limits")
                        
                        if isinstance(usage, dict):
                            requests_used = usage.get("requests", 0)
                        if isinstance(limits, dict):
                            requests_limit = limits.get("requests", 0)
                
                color = "red" if requests_used >= requests_limit else "green"
                table.add_row("Tomba.io", masked, f"[{color}]{requests_used}/{requests_limit} usados[/{color}]")
            else:
                table.add_row("Tomba.io", masked, f"[red]HTTP {res.status_code}[/red]")
                
        except Exception as e:
            error_msg = str(e).split('\n')[0][:30]
            table.add_row("Tomba.io", masked, f"[red]Erro: {error_msg}[/red]")

    # ── Checagem do Apollo.io ──
    apollo_keys = secrets.get("apollo", [])
    if not apollo_keys:
        table.add_row("Apollo.io", "Não configurada", "[dim]N/A[/dim]")
        
    for key in apollo_keys:
        masked = f"{key[:4]}...{key[-4:]}"
        # A API free do Apollo não tem endpoint simples de créditos, então apenas validamos que existe.
        table.add_row("Apollo.io", masked, "[blue]Pronta para uso[/blue]")

    console.print(table)


def main():
    secrets = load_secrets()

    # Intercepta a flag de status
    if len(sys.argv) == 2 and sys.argv[1] == "--status":
        check_api_status(secrets)
        sys.exit(0)

    if len(sys.argv) < 3:
        console.print("[bold red]Uso: python -m openpipes_core.osint.orchestrator <domain> <out_json>[/bold red]")
        sys.exit(1)

    domain = sys.argv[1]
    out_json = sys.argv[2]
    
    # 1. Carrega as armas do Cofre
    secrets = load_secrets()
    all_results = []
    
    # 2. Aciona o Motor do Apollo
    apollo_keys = secrets.get("apollo", [])
    if apollo_keys:
        apollo_data = engine_apollo.run(domain, apollo_keys)
        all_results.extend(apollo_data)
    else:
        console.print("[dim]  [Orchestrator] Nenhuma chave APOLLO encontrada no secrets.conf.[/dim]")

    # 3. Aciona Motor do Hunter
    hunter_keys = secrets.get("hunter", [])
    if hunter_keys:
        hunter_data = engine_hunter.run(domain, hunter_keys)
        all_results.extend(hunter_data)
    else:
        console.print("[dim]  [Orchestrator] Nenhuma chave HUNTER encontrada no secrets.conf.[/dim]")
    
    # 4. Aciona Tomba
    tomba_keys = secrets.get("tomba", [])
    if tomba_keys:
        tomba_data = engine_tomba.run(domain, tomba_keys)
        all_results.extend(tomba_data)
    else:
        console.print("[dim]  [Orchestrator] Nenhuma chave TOMBA encontrada no secrets.conf.[/dim]")
    
    # 5. Consolida e limpa a sujeira
    final_results = deduplicate(all_results)
    
    console.print(f"[bold green]  [Orchestrator] OSINT Consolidado: {len(final_results)} contatos únicos mapeados.[/bold green]")
    
    # 6. Entrega a bandeja de prata para o parser
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    main()