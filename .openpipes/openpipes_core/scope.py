import os
import shutil
import subprocess
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Header, Footer, DataTable, Button, Label, Rule, Input

import db

HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")

def _get_proj_path():
    if not os.path.exists(CONFIG_FILE): return None
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$proj_path\""
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        return r.stdout.strip() or None
    except Exception: return None

def _get_env_vars():
    if not os.path.exists(CONFIG_FILE): return None, None, None
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$obsdir|$proj_name|$NMAP_DIR\""
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        parts = r.stdout.strip().split("|")
        if len(parts) >= 3: return parts[0], parts[1], parts[2]
    except Exception: pass
    return None, None, None


class ScopeManagerApp(App):
    CSS = """
    Screen { layout: horizontal; padding: 1; }
    #left-pane { width: 65%; height: 100%; border-right: solid $primary; padding-right: 1; }
    #right-pane { width: 35%; height: 100%; padding-left: 1; align: center top; }
    
    #search-input { margin-bottom: 1; width: 100%; }
    DataTable { height: 1fr; border: solid $secondary; }
    
    .panel-title { text-style: bold; color: $accent; margin-bottom: 1; content-align: center middle; }
    .metric { margin-bottom: 1; }
    
    Button { width: 100%; margin-top: 1; }
    #btn-select-all { margin-bottom: 1; background: $accent; }
    #scope-buttons { height: auto; layout: horizontal; }
    #scope-buttons Button { width: 1fr; margin: 0 1; }
    #cleanup-btn { margin-top: 2; background: $error; color: $text; }
    """

    BINDINGS = [
        ("q", "quit", "Sair"),
        ("space", "toggle_selection", "Marcar/Desmarcar Host"),
    ]

    def __init__(self):
        super().__init__()
        self.proj_path = _get_proj_path()
        self.selected_hosts = set()
        self.highlighted_row_key = None

    def compose(self) -> ComposeResult:
        yield Header()
        
        with Horizontal():
            with Vertical(id="left-pane"):
                yield Label("🎯 Gerenciador de Escopo de Varredura", classes="panel-title")
                yield Input(placeholder="🔍 Buscar host (ex: api, dev, .com)...", id="search-input")
                yield DataTable(id="hosts-table", cursor_type="row")
            
            with Vertical(id="right-pane"):
                yield Label("📊 Métricas em Tempo Real", classes="panel-title")
                yield Label("Total de Hosts: --", id="lbl-total", classes="metric")
                yield Label("No Escopo: --", id="lbl-in", classes="metric")
                yield Label("Fora do Escopo: --", id="lbl-out", classes="metric")
                
                yield Rule()
                
                yield Label("Nenhum host marcado.", id="lbl-action-title", classes="panel-title")
                yield Button("Selecionar Todos Visíveis", id="btn-select-all", variant="default")
                
                with Horizontal(id="scope-buttons"):
                    yield Button("Adicionar ✅", id="btn-add", variant="success")
                    yield Button("Remover ❌", id="btn-remove", variant="warning")
                
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
        dt.add_column("Sel", key="sel")
        dt.add_column("Host", key="host")
        dt.add_column("Vivo", key="alive")
        dt.add_column("Escopo", key="scope")
        
        self.load_data()

    def load_data(self) -> None:
        dt = self.query_one("#hosts-table", DataTable)
        search_text = self.query_one("#search-input", Input).value.strip().lower()
        saved_row = dt.cursor_row
        dt.clear()
        
        in_count, out_count, total_count = 0, 0, 0
        
        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, host, is_alive, in_scope FROM hosts
                    ORDER BY in_scope DESC, host
                """)
                hosts = cursor.fetchall()
            
            for h in hosts:
                # O Filtro em Tempo Real atua aqui!
                if search_text and search_text not in h["host"].lower():
                    continue
                
                total_count += 1
                host_id = h["id"]
                status = "🟢" if h["is_alive"] else "⚫"
                scope = "✅" if h["in_scope"] else "❌"
                sel = "[bold cyan][ x ][/bold cyan]" if host_id in self.selected_hosts else "[   ]"
                
                if h["in_scope"]: in_count += 1
                else: out_count += 1
                
                dt.add_row(sel, h["host"], status, scope, key=str(host_id))
                
        except Exception as e:
            self.query_one("#lbl-action-title", Label).update(f"[red]Erro no BD: {e}[/red]")
            return

        self.query_one("#lbl-total", Label).update(f"Hosts Listados: {total_count}")
        self.query_one("#lbl-in", Label).update(f"No Escopo: [green]{in_count}[/green]")
        self.query_one("#lbl-out", Label).update(f"Fora do Escopo: [red]{out_count}[/red]")

        if saved_row is not None and saved_row < dt.row_count:
            dt.move_cursor(row=saved_row, animate=False)

    def on_input_changed(self, event: Input.Changed) -> None:
        """Sempre que a barra de busca mudar, recarrega a tabela aplicando o filtro."""
        if event.input.id == "search-input":
            self.load_data()

    def _refresh_selection(self) -> None:
        lbl = self.query_one("#lbl-action-title", Label)
        if len(self.selected_hosts) > 0:
            lbl.update(f"Selecionados: [bold cyan]{len(self.selected_hosts)} hosts[/bold cyan]")
        elif self.highlighted_row_key:
            host_name = self.query_one("#hosts-table", DataTable).get_cell(self.highlighted_row_key, "host")
            lbl.update(f"Alvo único: [bold]{host_name}[/bold]")
        else:
            lbl.update("Nenhum host marcado.")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.highlighted_row_key = event.row_key
        self._refresh_selection()

    def action_toggle_selection(self) -> None:
        if not self.highlighted_row_key: return
        
        host_id = int(self.highlighted_row_key.value)
        dt = self.query_one("#hosts-table", DataTable)
        
        if host_id in self.selected_hosts:
            self.selected_hosts.remove(host_id)
            dt.update_cell(self.highlighted_row_key, "sel", "[   ]")
        else:
            self.selected_hosts.add(host_id)
            dt.update_cell(self.highlighted_row_key, "sel", "[bold cyan][ x ][/bold cyan]")
            
        if dt.cursor_row < dt.row_count - 1:
            dt.move_cursor(row=dt.cursor_row + 1, animate=False)
            
        self._refresh_selection()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-add":
            self.apply_scope(1)
        elif event.button.id == "btn-remove":
            self.apply_scope(0)
        elif event.button.id == "btn-select-all":
            self.toggle_all_visible()
        elif event.button.id == "cleanup-btn":
            self.run_cleanup()

    def toggle_all_visible(self) -> None:
        """Seleciona ou desseleciona todos os hosts que estão VISÍVEIS na tabela atualmente."""
        dt = self.query_one("#hosts-table", DataTable)
        visible_ids = [int(key.value) for key in dt.rows.keys()]
        if not visible_ids: return
        
        # Se TODOS os visíveis já estiverem selecionados, desseleciona. Se não, seleciona todos.
        all_selected = all(vid in self.selected_hosts for vid in visible_ids)
        
        if all_selected:
            for vid in visible_ids:
                self.selected_hosts.discard(vid)
        else:
            for vid in visible_ids:
                self.selected_hosts.add(vid)
                
        self.load_data()
        self._refresh_selection()

    def apply_scope(self, in_scope: int) -> None:
        target_ids = list(self.selected_hosts)
        
        if not target_ids and self.highlighted_row_key:
            target_ids = [int(self.highlighted_row_key.value)]
            
        if not target_ids: return
            
        try:
            with db.get_connection(self.proj_path) as conn:
                with db.transaction(conn):
                    cursor = conn.cursor()
                    ph = ",".join("?" for _ in target_ids)
                    cursor.execute(f"UPDATE hosts SET in_scope = ? WHERE id IN ({ph})", [in_scope] + target_ids)
            
            self.selected_hosts.clear()
            self.load_data()
            self._refresh_selection()
            
        except Exception as e:
            self.query_one("#lbl-action-title", Label).update(f"[red]Erro ao atualizar DB: {e}[/red]")

    def run_cleanup(self) -> None:
        obsdir, proj_name, nmap_dir = _get_env_vars()
        if not obsdir or not proj_name or not nmap_dir:
            self.query_one("#lbl-cleanup-status", Label).update("[red]Erro ao ler config.sh[/red]")
            return

        target_files = [
            "httpx_targets.txt", "httpx_ports.txt", "katana_urls.txt", "ferox_urls.txt",
            "js_urls.txt", "gf_urls.txt", "screenshot_urls.txt", "nuclei_urls.txt",
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

def interactive_scope(proj_path: str = None):
    """Wrapper called from cli.py."""
    app = ScopeManagerApp()
    app.run()


if __name__ == "__main__":
    app = ScopeManagerApp()
    app.run()
