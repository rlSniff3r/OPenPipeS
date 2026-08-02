import os
import json
import re
import requests
from pathlib import Path
from typing import Optional
from rich.console import Console

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll, Container
from textual.widgets import Header, Footer, DataTable, Button, Select, Input, Label, TabbedContent, TabPane, Rule

import db

HOME = str(Path.home())
CACHE_DIR = os.path.join(HOME, ".openpipes_cache")
SECRETS_FILE = os.path.join(HOME, ".openpipes", "secrets.conf")

# ================= FUNÇÕES DO SEU SCRIPT ORIGINAL =================

def _normalize_name(name: str) -> str:
    name = name.lower().strip()
    name = re.sub(r'[^a-z0-9]+', '_', name)
    return name.strip('_')

def _load_cache() -> dict[str, dict]:
    """Lê os templates JSON do cache."""
    cache = {}
    if not os.path.exists(CACHE_DIR):
        return cache
    for fname in os.listdir(CACHE_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(CACHE_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            key = fname.replace(".json", "")
            cache[key] = data
        except Exception:
            continue
    return cache

def _get_openai_key() -> Optional[str]:
    """Lê a API key do secrets.conf."""
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

def _get_nvd_api_key():
    """Read NVD API key from secrets.conf (supports export KEY=\"value\" format)."""
    secrets = os.path.expanduser("~/.openpipes/secrets.conf")
    if os.path.exists(secrets):
        with open(secrets) as f:
            for line in f:
                line = line.strip()
                # Match both "NVD_API_KEY=..." and "export NVD_API_KEY=..."
                if line.startswith("NVD_API_KEY=") or line.startswith("export NVD_API_KEY="):
                    key = line.split("=", 1)[1].strip()
                    # Strip surrounding quotes if present
                    key = key.strip('"').strip("'")
                    return key
    return None

def _extract_cve_id(text: str) -> str | None:
    """Extract a CVE ID (CVE-YYYY-NNNN) from a string, or None."""
    m = re.search(r"CVE-\d{4}-\d{4,7}", text or "")
    return m.group(0) if m else None

def _extract_cwe(references: list) -> str:
    """Extrai o ID da CWE baseando-se na URL."""
    if not references:
        return ""
    for ref in references:
        match = re.search(r'/definitions/(\d+)\.html', ref)
        if match:
            return f"CWE-{match.group(1)}"
    return ""

def _calculate_cvss(cvss_vector: str) -> tuple:
    """Usa a biblioteca cvss para gerar score e severidade."""
    if not cvss_vector:
        return None, None
    try:
        from cvss import CVSS3
        c = CVSS3(cvss_vector)
        score = c.scores()[0]
        severity = c.severities()[0]
        sev_map = {"CRITICAL": "Crítica", "HIGH": "Alta",
                   "MEDIUM": "Média", "LOW": "Baixa", "NONE": "Info"}
        return score, sev_map.get(severity.upper(), severity)
    except Exception:
        pass
    return None, None

def _get_proj_path():
    """Busca o caminho do projeto atual."""
    config_file = os.path.join(HOME, ".openpipes", "config.sh")
    if os.path.exists(config_file):
        try:
            import subprocess
            cmd = f"source {config_file} && echo -n \"$proj_path\""
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
            if result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
    return os.getcwd()

# ================= APLICAÇÃO TEXTUAL =================

class VulnEnricherApp(App):
    CSS = """
    Screen { padding: 1; }
    DataTable { height: 1fr; border: solid $primary; margin-bottom: 1; }
    .action-panel { height: auto; border: round $secondary; padding: 1; margin-bottom: 1;}
    .controls { height: auto; margin-bottom: 1; align: left middle; }
    .btn-row { layout: horizontal; align: left middle; height: auto; margin-top: 1; }
    Button { margin-right: 1; }
    Label.bold { text-style: bold; color: $accent; }
    """
    
    def __init__(self):
        super().__init__()
        self.proj_path = _get_proj_path()
        self.cache_data = _load_cache()
        
        # Variáveis de estado para a aba 1 (Enriquecimento)
        self.pending_vulns = []
        self.selected_vuln_id = None
        self.selected_vuln_data = None
        self.selected_cve_id = None
        
    def compose(self) -> ComposeResult:
        yield Header()
        
        with TabbedContent():
            # ======= ABA 1: ENRIQUECIMENTO PENDENTE =======
            with TabPane("Enriquecimento de Vulnerabilidades", id="tab-enrich"):
                yield Label(f"Projeto atual: {self.proj_path}\n", classes="bold")
                yield DataTable(id="table-pending", cursor_type="row")
                
                # Painel de ações que aparece quando você clica numa linha
                with Vertical(id="panel-enrich", classes="action-panel"):
                    yield Label("Selecione uma vulnerabilidade acima para resolver.", id="enrich-info", classes="bold")
                    yield Label("Cache sugerido:")
                    yield Select([], id="select-cache-match")
                    
                    with Horizontal(classes="btn-row"):
                        yield Button("Aplicar Cache Selecionado", id="btn-apply-cache", variant="success")
                        yield Button("Gerar com OpenAI", id="btn-openai", variant="primary")
                        yield Button("Gerar com NVD", id="btn-nvd", variant="primary")
                        yield Label("", id="enrich-status")
            
            # ======= ABA 2: INSERÇÃO MANUAL =======
            with TabPane("Inserir Vulnerabilidade Manual", id="tab-manual"):
                yield Label("1. Selecione o Host Alvo (Apenas hosts ativos):")
                yield Select([], id="select-host")
                
                yield Label("\n2. Selecione a Vulnerabilidade (Cache):")
                # Carrega as chaves do cache como opções
                cache_options = [(k, k) for k in sorted(self.cache_data.keys())]
                yield Select(cache_options, id="select-vuln")
                
                yield Label("\n3. Selecione o Endpoint (Opcional):")
                yield Select([("Nenhum (Aplicar ao Host inteiro)", "SKIP")], id="select-endpoint", value="SKIP")
                
                with Horizontal(classes="btn-row"):
                    yield Button("Inserir Vulnerabilidade", id="btn-insert-manual", variant="success")
                    yield Label("", id="manual-status")

        yield Footer()

    def on_mount(self) -> None:
        """Inicializa as tabelas e dados quando o TUI abre."""
        # Esconde o painel de ações de enriquecimento no início
        self.query_one("#panel-enrich").display = False
        self.query_one("#btn-nvd").display = False
        self.load_pending_vulns()
        self.load_active_hosts()

    # ================= LOGICA DA ABA 1: ENRIQUECIMENTO =================

    def _normalize_nvd_data(self, cve_id: str, cve: dict) -> dict:
    """Map NVD API JSON to the project's cache JSON format."""
    # Description (English)
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS v3.1 vector (fall back to v3.0)
    vector = ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            vector = metrics[key][0].get("cvssData", {}).get("vectorString", "")
            break

    # CWEs
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)

    # References
    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

    return {
        "title": cve_id,
        "cvssv3": vector,
        "description": description,
        "observation": ", ".join(cwes),
        "remediation": "",
        "references": refs,
        "cve_id": cve_id,
    }


    def load_pending_vulns(self):
        """Carrega vulnerabilidades do nuclei que precisam de enriquecimento[cite: 3]."""
        dt = self.query_one("#table-pending", DataTable)
        dt.clear(columns=True)
        dt.add_columns("ID", "Título/Nome", "Descrição", "Status")
        self.pending_vulns = []
        
        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, vuln_name, description, title
                    FROM vulnerabilities
                    WHERE source_tool = 'nuclei'
                      AND (enriched_by IS NULL OR enriched_by = '')
                """)
                rows = cursor.fetchall()
                
                for r in rows:
                    vuln_id = r["id"]
                    v_name = r["vuln_name"] or r["title"]
                    desc = str(r["description"] or "")[:50] + "..."
                    self.pending_vulns.append({"id": vuln_id, "name": v_name, "desc": r["description"]})
                    
                    dt.add_row(str(vuln_id), str(v_name), desc, "Pendente", key=str(vuln_id))
                    
        except Exception as e:
            dt.add_row("Erro", str(e), "", "")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Quando o usuário clica numa linha pendente."""
        if event.control.id != "table-pending": return
        
        self.selected_vuln_id = int(event.row_key.value)
        self.selected_vuln_data = next((v for v in self.pending_vulns if v["id"] == self.selected_vuln_id), None)
        
        if not self.selected_vuln_data: return
        
        # Mostra o painel
        self.query_one("#panel-enrich").display = True
        self.query_one("#enrich-info", Label).update(f"Resolvendo: {self.selected_vuln_data['name']}")
        self.query_one("#enrich-status", Label).update("")
        
        # Faz o fuzzy match exato do seu script original[cite: 3]
        vuln_name = self.selected_vuln_data["name"]
        normalized = _normalize_name(vuln_name)
        vuln_keywords = set(re.sub(r'[^a-z0-9]+', ' ', normalized).split())
        
        candidates = []
        for cache_key in self.cache_data.keys():
            cache_keywords = set(re.sub(r'[^a-z0-9]+', ' ', cache_key).split())
            overlap = len(vuln_keywords & cache_keywords)
            denom = max(len(vuln_keywords), len(cache_keywords))
            score = overlap / denom if denom > 0 else 0
            candidates.append((score, cache_key))
            
        candidates.sort(reverse=True, key=lambda x: x[0])

        # Detect CVE → show/hide NVD button
        self.selected_cve_id = (
            _extract_cve_id(self.selected_vuln_data["name"])
            or _extract_cve_id(self.selected_vuln_data.get("desc", ""))
        )
        nvd_btn = self.query_one("#btn-nvd", Button)
        if self.selected_cve_id:
            nvd_btn.display = True
            nvd_btn.label = f"Gerar com NVD ({self.selected_cve_id})"
        else:
            nvd_btn.display = False

        
        # Atualiza o dropdown com os candidatos ordenados por relevância
        select = self.query_one("#select-cache-match", Select)
        options = [(f"[{score:.2f}] {key}", key) for score, key in candidates]
        select.set_options(options)
        if options:
            select.value = options[0][1] # Seleciona o de maior score por padrão

    def apply_enrichment(self, cached_data: dict, source: str):
        """Aplica os dados gerados (Cache ou OpenAI) no banco de dados[cite: 2, 3]."""
        if not self.selected_vuln_id: return
        
        cvss_vector = cached_data.get("cvssv3", "")
        score, severity = _calculate_cvss(cvss_vector)
        cwe_id = _extract_cwe(cached_data.get("references", []))
        
        try:
            with db.get_connection(self.proj_path) as conn:
                with db.transaction(conn):
                    cursor = conn.cursor()
                    # Mantem a CVE original se o cache nao possuir[cite: 3]
                    cursor.execute("SELECT cve_id FROM vulnerabilities WHERE id = ?", (self.selected_vuln_id,))
                    existing = cursor.fetchone()
                    new_cve = cached_data.get("cve_id", "")
                    if not new_cve and existing and existing["cve_id"]:
                        new_cve = existing["cve_id"]
                        
                    cursor.execute("""
                        UPDATE vulnerabilities SET
                            title = ?, cvss_vector = ?, cvss_score = ?, severity = ?,
                            description = ?, impact = ?, remediation = ?,
                            reference_urls = ?, cwe_id = ?, cve_id = ?, enriched_by = ?
                        WHERE id = ?
                    """, (
                        cached_data.get("title", self.selected_vuln_data["name"]),
                        cvss_vector, score, severity or "Média",
                        cached_data.get("description", self.selected_vuln_data["desc"]),
                        cached_data.get("observation", ""),
                        cached_data.get("remediation", ""),
                        json.dumps(cached_data.get("references", [])),
                        cwe_id, new_cve, source, self.selected_vuln_id
                    ))
            
            # Remove da tabela visual
            dt = self.query_one("#table-pending", DataTable)
            dt.remove_row(str(self.selected_vuln_id))
            self.query_one("#panel-enrich").display = False
            
        except Exception as e:
            self.query_one("#enrich-status", Label).update(f"[red]Erro no DB: {e}[/red]")

    @work(exclusive=True, thread=True)
    def fetch_openai_enrichment(self, vuln_name: str, description: str):
        """Roda a IA em background (thread) para não travar o TUI."""
        api_key = _get_openai_key()
        if not api_key:
            self.call_from_thread(self.query_one("#enrich-status", Label).update, "[red]Erro: OPENAI_API_KEY não encontrada em secrets.conf.[/red]")
            return
    
        @work(exclusive=True, thread=True)
    def fetch_nvd_enrichment(self, cve_id: str):
        """Fetch CVE data from NVD API in background, cache it, auto-apply."""
        api_key = _get_nvd_api_key()
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        if api_key:
            url += f"&apiKey={api_key}"

        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 403:
                self.call_from_thread(
                    self.query_one("#enrich-status", Label).update,
                    "[red]NVD rate limit (403). Adicione NVD_API_KEY em secrets.conf para mais cota.[/red]",
                )
                return
            if r.status_code == 404:
                self.call_from_thread(
                    self.query_one("#enrich-status", Label).update,
                    f"[yellow]CVE {cve_id} não encontrado na NVD.[/yellow]",
                )
                return
            r.raise_for_status()

            vulns = r.json().get("vulnerabilities", [])
            if not vulns:
                self.call_from_thread(
                    self.query_one("#enrich-status", Label).update,
                    f"[yellow]NVD retornou vazio para {cve_id}.[/yellow]",
                )
                return

            cve = vulns[0]["cve"]
            normalized = self._normalize_nvd_data(cve_id, cve)

            # Store in cache folder
            cache_dir = Path.home() / ".openpipes_cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_path = cache_dir / f"{cve_id.lower()}.json"
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(normalized, f, indent=2, ensure_ascii=False)

            # Update in-memory cache + auto-apply
            self.cache_data[cve_id] = normalized
            self.call_from_thread(self.apply_enrichment, normalized, 'nvd')

        except Exception as e:
            self.call_from_thread(
                self.query_one("#enrich-status", Label).update,
                f"[red]Erro na API NVD: {e}[/red]",
            )

            
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
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    parsed_json = json.loads(json_match.group())
                    # Chama a função de atualização na thread principal do UI
                    self.call_from_thread(self.apply_enrichment, parsed_json, 'openai')
                    return
            self.call_from_thread(self.query_one("#enrich-status", Label).update, "[yellow]Falha ao obter JSON válido da OpenAI.[/yellow]")
        except Exception as e:
            self.call_from_thread(self.query_one("#enrich-status", Label).update, f"[red]Erro na API OpenAI: {e}[/red]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Controla os botões das duas abas."""
        # Botões da Aba 1 (Enriquecimento)
        if event.button.id == "btn-apply-cache":
            selected_cache_key = self.query_one("#select-cache-match", Select).value
            if selected_cache_key and selected_cache_key in self.cache_data:
                self.apply_enrichment(self.cache_data[selected_cache_key], 'cache')
                
        elif event.button.id == "btn-openai":
            if self.selected_vuln_data:
                self.query_one("#enrich-status", Label).update("[yellow]⏳ Solicitando IA da OpenAI. Aguarde...[/yellow]")
                # Dispara a Thread
                self.fetch_openai_enrichment(self.selected_vuln_data["name"], self.selected_vuln_data["desc"])

        elif event.button.id == "btn-nvd":          # ← ADD
            if self.selected_cve_id:
                self.query_one("#enrich-status", Label).update(f"[yellow]⏳ Consultando NVD ({self.selected_cve_id}). Aguarde...[/yellow]")
                self.fetch_nvd_enrichment(self.selected_cve_id)

        # Botão da Aba 2 (Inserção Manual)
        elif event.button.id == "btn-insert-manual":
            self.insert_manual_vulnerability()

    # ================= LOGICA DA ABA 2: INSERÇÃO MANUAL =================

    def load_active_hosts(self):
        """Popula o select de hosts apenas com os ativos (is_alive = 1)[cite: 3]."""
        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, host FROM hosts WHERE is_alive = 1 ORDER BY host")
                options = [(f"{r['host']} (ID: {r['id']})", str(r["id"])) for r in cursor.fetchall()]
                self.query_one("#select-host", Select).set_options(options)
        except Exception:
            pass

    def on_select_changed(self, event: Select.Changed) -> None:
        """Ao trocar o Host, carrega os endpoints vinculados a ele dinamicamente[cite: 3]."""
        if event.control.id == "select-host" and event.value:
            host_id = event.value
            try:
                with db.get_connection(self.proj_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id, url FROM endpoints WHERE host_id = ? LIMIT 500", (host_id,))
                    options = [("Nenhum (Aplicar ao Host inteiro)", "SKIP")]
                    for r in cursor.fetchall():
                        options.append((str(r["url"])[:80], str(r["id"])))
                    self.query_one("#select-endpoint", Select).set_options(options)
                    self.query_one("#select-endpoint", Select).value = "SKIP"
            except Exception:
                pass

    def insert_manual_vulnerability(self):
        """Lógica de inserção manual convertida do script original[cite: 2, 3]."""
        host_id_str = self.query_one("#select-host", Select).value
        cache_key = self.query_one("#select-vuln", Select).value
        ep_id_str = self.query_one("#select-endpoint", Select).value
        
        status_lbl = self.query_one("#manual-status", Label)
        
        if not host_id_str or not cache_key:
            status_lbl.update("[red]⚠ Selecione um host e uma vulnerabilidade.[/red]")
            return
            
        host_id = int(host_id_str)
        endpoint_id = int(ep_id_str) if ep_id_str != "SKIP" else None
        
        vuln_data = self.cache_data.get(cache_key, {})
        cvss_vector = vuln_data.get("cvssv3", "")
        score, severity = _calculate_cvss(cvss_vector)
        cwe_id = _extract_cwe(vuln_data.get("references", []))
        
        try:
            with db.get_connection(self.proj_path) as conn:
                with db.transaction(conn):
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO vulnerabilities
                            (host_id, endpoint_id, title, severity, cvss_score, cvss_vector,
                             cwe_id, description, impact, remediation, reference_urls,
                             source_tool, enriched_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual', 'user')
                    """, (
                        host_id, endpoint_id, vuln_data.get("title", ""),
                        severity or "Média", score, cvss_vector,
                        cwe_id,
                        vuln_data.get("description", ""),
                        vuln_data.get("observation", ""),
                        vuln_data.get("remediation", ""),
                        json.dumps(vuln_data.get("references", [])),
                    ))
                    vuln_id = cursor.lastrowid
                    
            status_lbl.update(f"[green]✔ Vulnerabilidade '{cache_key}' inserida com sucesso (ID={vuln_id}).[/green]")
        except Exception as e:
            status_lbl.update(f"[red]Erro ao inserir: {e}[/red]")

console = Console()

def run_enricher(proj_path: str, re_enrich: bool = False):
    """Wrapper called from cli.py."""
    if re_enrich:
        console.print("[yellow]⚠ Re-enrich: limpando marcas de enriquecimento...[/yellow]")
        with db.get_connection(proj_path) as conn:
            conn.execute("UPDATE vulnerabilities SET enriched_by = '' WHERE source_tool = 'nuclei'")
    app = VulnEnricherApp()
    app.run()


def run_manual(proj_path: str):
    """Wrapper called from cli.py."""
    app = VulnEnricherApp()
    app.run()


def run_edit(proj_path: str, vuln_id: int):
    """Edit an existing vulnerability: pre-filled form → UPDATE DB."""
    from pathlib import Path
    from vuln_create import JSONFormApp

    app = JSONFormApp(edit_vuln_id=vuln_id)
    result = app.run()

    if not result or not os.path.exists(result):
        console.print("[yellow]⚠ Edição cancelada ou arquivo não encontrado.[/yellow]")
        return

    with open(result, "r", encoding="utf-8") as f:
        data = json.load(f)

    vid = data.get("vuln_id")
    if not vid:
        console.print("[red]✖ JSON sem vuln_id. Nada para editar.[/red]")
        return

    cvss_vector = data.get("cvssv3", "")
    score, severity = _calculate_cvss(cvss_vector)
    cwe_id = _extract_cwe(data.get("references", []))

    try:
        with db.get_connection(proj_path) as conn:
            with db.transaction(conn):
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE vulnerabilities SET
                        title = ?, cvss_vector = ?, cvss_score = ?, severity = ?,
                        description = ?, impact = ?, remediation = ?,
                        reference_urls = ?, cwe_id = ?, enriched_by = 'user'
                    WHERE id = ?
                """, (
                    data.get("title", ""),
                    cvss_vector,
                    score,
                    severity or "Média",
                    data.get("description", ""),
                    data.get("observation", ""),
                    data.get("remediation", ""),
                    json.dumps(data.get("references", [])),
                    cwe_id,
                    vid,
                ))
        console.print(f" [dim]↳ Vulnerabilidade {vid} atualizada com sucesso.[/dim]")
    except Exception as e:
        console.print(f"[red]✖ Erro ao atualizar: {e}[/red]")

    # Cleanup the temp edit JSON
    try:
        os.remove(result)
    except Exception:
        pass


if __name__ == "__main__":
    app = VulnEnricherApp()
    app.run()