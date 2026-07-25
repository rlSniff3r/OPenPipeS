import os
import shutil
import subprocess
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Header, Footer, DataTable, Button, Label, Rule

import db

HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")


def _get_proj_path():
    """Lê o caminho do projeto no config.sh."""
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$proj_path\""
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        return r.stdout.strip() or None
    except Exception:
        return None


def _get_env_vars():
    """Lê as variáveis de ambiente necessárias para o cleanup."""
    if not os.path.exists(CONFIG_FILE):
        return None, None, None
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$obsdir|$proj_name|$NMAP_DIR\""
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        parts = r.stdout.strip().split("|")
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]
    except Exception:
        pass
    return None, None, None


class ScopeManagerApp(App):
    CSS = """
    Screen {
        layout: horizontal;
        padding: 1;
    }
    
    #left-pane {
        width: 65%;
        height: 100%;
        border-right: solid $primary;
        padding-right: 1;
    }
    
    #right-pane {
        width: 35%;
        height: 100%;
        padding-left: 1;
        align: center top;
    }
    
    DataTable {
        height: 1fr;
        border: solid $secondary;
    }
    
    .panel-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
        content-align: center middle;
    }
    
    .metric {
        margin-bottom: 1;
    }
    
    Button {
        width: 100%;
        margin-top: 1;
    }
    
    #cleanup-btn {
        margin-top: 2;
        background: $error;
        color: $text;
    }
    """

    BINDINGS = [
        ("q", "quit", "Sair"),
        ("space", "toggle_scope", "Inverter Escopo do Host"),
    ]

    def __init__(self):
        super().__init__()
        self.proj_path = _get_proj_path()
        self.selected_host_id = None
        self.selected_host_name = None
        self.selected_host_scope = None

    def compose(self) -> ComposeResult:
        yield Header()
        
        with Horizontal():
            with Vertical(id="left-pane"):
                yield Label("🎯 Gerenciador de Escopo de Varredura", classes="panel-title")
                yield DataTable(id="hosts-table", cursor_type="row")
            
            with Vertical(id="right-pane"):
                yield Label("📊 Métricas em Tempo Real", classes="panel-title")
                yield Label("Total de Hosts: --", id="lbl-total", classes="metric")
                yield Label("No Escopo: --", id="lbl-in", classes="metric")
                yield Label("Fora do Escopo: --", id="lbl-out", classes="metric")
                
                yield Rule()
                
                yield Label("Selecione um host na tabela...", id="lbl-action-title", classes="panel-title")
                yield Button("Inverter Escopo (Espaço)", id="toggle-btn", variant="primary", disabled=True)
                
                yield Rule()
                yield Label("Operações de Disco:")
                yield Button("Limpar Vaults & Inputs (Fora do Escopo)", id="cleanup-btn")
                yield Label("", id="lbl-cleanup-status")

        yield Footer()

    def on_mount(self) -> None:
        if not self.proj_path:
            self.query_one("#lbl-action-title", Label).update("[red]Erro: Projeto não configurado.[/red]")
            return
        
        dt = self.query_one("#hosts-table", DataTable)
        dt.add_columns("Host", "Vivo", "Escopo")
        
        self.load_data()

    def load_data(self) -> None:
        """Carrega e renderiza os hosts do banco de dados."""
        dt = self.query_one("#hosts-table", DataTable)
        dt.clear()
        
        in_count = 0
        out_count = 0
        total_count = 0
        
        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, host, is_alive, in_scope FROM hosts
                    ORDER BY in_scope DESC, host
                """)
                hosts = cursor.fetchall()
                
                total_count = len(hosts)
                
                for h in hosts:
                    status = "🟢" if h["is_alive"] else "⚫"
                    scope = "✅" if h["in_scope"] else "❌"
                    
                    if h["in_scope"]:
                        in_count += 1
                    else:
                        out_count += 1
                        
                    dt.add_row(h["host"], status, scope, key=str(h["id"]))
                    
        except Exception as e:
            self.query_one("#lbl-action-title", Label).update(f"[red]Erro no BD: {e}[/red]")
            return

        self.query_one("#lbl-total", Label).update(f"Total de Hosts: {total_count}")
        self.query_one("#lbl-in", Label).update(f"No Escopo: [green]{in_count}[/green]")
        self.query_one("#lbl-out", Label).update(f"Fora do Escopo: [red]{out_count}[/red]")

    def _refresh_selection(self) -> None:
        """Re-read the currently selected row and update the UI panel."""
        dt = self.query_one("#hosts-table", DataTable)
        if dt.cursor_row is None:
            return
        row_key = dt.get_row_key_at(dt.cursor_row)
        if row_key is None:
            return
        self.selected_host_id = int(row_key.value)

        with db.get_connection(self.proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT host, in_scope FROM hosts WHERE id = ?", (self.selected_host_id,))
            row = cursor.fetchone()
            if row:
                self.selected_host_name = row["host"]
                self.selected_host_scope = row["in_scope"]
                lbl = self.query_one("#lbl-action-title", Label)
                btn = self.query_one("#toggle-btn", Button)
                lbl.update(f"Host: [bold]{self.selected_host_name}[/bold]")
                btn.disabled = False
                if self.selected_host_scope:
                    btn.label = "Remover do Escopo ❌"
                    btn.variant = "warning"
                else:
                    btn.label = "Adicionar ao Escopo ✅"
                    btn.variant = "success"

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Quando o usuário clica ou foca em um host."""
        self._refresh_selection()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "toggle-btn":
            self.action_toggle_scope()
        elif event.button.id == "cleanup-btn":
            self.run_cleanup()

    def action_toggle_scope(self) -> None:
        """Inverte o valor in_scope no banco para o host selecionado."""
        if not self.selected_host_id:
            return
            
        new_val = 0 if self.selected_host_scope else 1
        try:
            with db.get_connection(self.proj_path) as conn:
                with db.transaction(conn):
                    cursor = conn.cursor()
                    cursor.execute("UPDATE hosts SET in_scope = ? WHERE id = ?", (new_val, self.selected_host_id))
            
            self.load_data()
            self._refresh_selection()
            
        except Exception as e:
            self.query_one("#lbl-action-title", Label).update(f"[red]Erro ao atualizar: {e}[/red]")

    def run_cleanup(self) -> None:
        """Executa a limpeza dos vaults e arquivos de input para hosts fora do escopo."""
        obsdir, proj_name, nmap_dir = _get_env_vars()
        if not obsdir or not proj_name or not nmap_dir:
            self.query_one("#lbl-cleanup-status", Label).update("[red]Erro ao ler config.sh[/red]")
            return

        target_files = [
            "httpx_targets.txt", "httpx_ports.txt",
            "katana_urls.txt", "ferox_urls.txt",
            "js_urls.txt", "gf_urls.txt",
            "screenshot_urls.txt", "nuclei_urls.txt",
            "alive_urls.txt", "context_wordlist.txt",
        ]

        removed_vaults = 0
        removed_files = 0

        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT host FROM hosts WHERE is_alive = 1 AND in_scope = 0")
                for row in cursor.fetchall():
                    host = row["host"]
                    
                    vault_path = os.path.join(obsdir, proj_name, "Pentest", "Alvos", host)
                    if os.path.exists(vault_path):
                        shutil.rmtree(vault_path)
                        removed_vaults += 1
                        
                    target_dir = os.path.join(nmap_dir, f"nmap-{host}")
                    for fname in target_files:
                        fpath = os.path.join(target_dir, fname)
                        if os.path.exists(fpath):
                            os.remove(fpath)
                            removed_files += 1

            status = f"[green]Limpeza concluída![/green]\nVaults removidos: {removed_vaults}\nArquivos removidos: {removed_files}"
            self.query_one("#lbl-cleanup-status", Label).update(status)
            
        except Exception as e:
            self.query_one("#lbl-cleanup-status", Label).update(f"[red]Erro na limpeza: {e}[/red]")


# === Wrapper for CLI integration ===

def run_scope_manager(proj_path: str):
    """Wrapper called from cli.py."""
    app = ScopeManagerApp()
    app.run()


if __name__ == "__main__":
    app = ScopeManagerApp()
    app.run()
