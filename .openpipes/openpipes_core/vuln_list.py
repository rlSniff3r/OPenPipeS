"""VulnListApp — Textual TUI for managing vulnerabilities."""

import os
import re
import subprocess
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import (
    Header, Footer, DataTable, Button, Label, Input, Select, Rule, Static
)
from textual.screen import ModalScreen
import db

HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")


def _get_proj_path():
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$proj_path\""
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        return r.stdout.strip() or None
    except Exception:
        return None


SEV_EMOJI = {"Crítica": "🔴", "Alta": "🟠", "Média": "🟡", "Baixa": "🟢", "Info": "🔵"}
STATUS_EMOJI = {"open": "🟢", "false_positive": "⚪", "confirmed": "🔵", "fixed": "⚫"}


# ── Modal: Action Menu ──
class VulnActionScreen(ModalScreen):
    def __init__(self, vuln: dict):
        super().__init__()
        self.vuln = vuln

    CSS = """
    Screen { align: center middle; }
    #dialog {
        width: 50; height: auto; padding: 1;
        border: thick $primary; background: $surface;
    }
    #dialog-title { text-style: bold; content-align: center middle; margin-bottom: 1; }
    Button { width: 100%; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        v = self.vuln
        sev_icon = SEV_EMOJI.get(v["severity"], "⚪")
        status_icon = STATUS_EMOJI.get(v["status"], "⚪")
        yield Vertical(
            Label(f"{sev_icon} {v['title'][:60]}", id="dialog-title"),
            Label(f"Host: [bold]{v.get('host', 'N/A')}[/bold]\n"
                  f"Severidade: {sev_icon} {v['severity']}\n"
                  f"Status: {status_icon} {v['status']}\n"
                  f"Ferramenta: {v.get('source_tool', 'N/A')}"),
            Rule(),
            Button("🔄 Remarcar como Aberto" if v["status"] == "false_positive"
                   else "⚪ Marcar como Falso Positivo",
                   id="btn-fp", variant="warning" if v["status"] != "false_positive" else "success"),
            Button("✏️ Editar", id="btn-edit", variant="primary"),
            Button("👁️ Ver Detalhes", id="btn-details", variant="default"),
            Button("❌ Fechar", id="btn-close", variant="default"),
            id="dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {"btn-fp": "toggle_fp", "btn-edit": "edit",
                   "btn-details": "details", "btn-close": "close"}
        self.dismiss({"action": actions.get(event.button.id, "close"),
                       "vuln_id": self.vuln["id"]})


# ── Modal: Detail View ──
class VulnDetailScreen(ModalScreen):
    def __init__(self, vuln: dict):
        super().__init__()
        self.vuln = vuln

    CSS = """
    Screen { align: center middle; }
    #detail-box {
        width: 70; height: 70%; padding: 1;
        border: thick $primary; background: $surface;
    }
    #detail-content { height: 1fr; }
    Button { width: 100%; }
    """

    def compose(self) -> ComposeResult:
        v = self.vuln
        yield Vertical(
            Label(f"📋 {v['title']}", classes="panel-title"),
            Rule(),
            Static(
                f"[bold]Host:[/bold] {v.get('host', 'N/A')}\n"
                f"[bold]Severidade:[/bold] {SEV_EMOJI.get(v['severity'], '')} {v['severity']}\n"
                f"[bold]Status:[/bold] {STATUS_EMOJI.get(v['status'], '')} {v['status']}\n"
                f"[bold]Ferramenta:[/bold] {v.get('source_tool', 'N/A')}\n"
                f"[bold]CVSS:[/bold] {v.get('cvss_score', 'N/A')}\n"
                f"[bold]CWE:[/bold] {v.get('cwe_id', 'N/A')}\n\n"
                f"[bold]Descrição:[/bold]\n{v.get('description', 'N/A')}\n",
                id="detail-content",
            ),
            Button("❌ Fechar", id="btn-close", variant="default"),
            id="detail-box",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)


# ── Main App ──
class VulnListApp(App):
    CSS = """
    Screen { layout: vertical; padding: 1; }
    #filter-bar { height: 3; margin-bottom: 1; }
    #search-input { width: 1fr; }
    #severity-filter { width: 20; }
    DataTable { height: 1fr; border: solid $secondary; }
    #status-bar { height: 1; content-align: center middle; color: $text-muted; }
    .panel-title { text-style: bold; color: $accent; margin-bottom: 1; content-align: center middle; }
    """
    BINDINGS = [("q", "quit", "Sair"), ("r", "refresh", "Atualizar")]

    def __init__(self, proj_path: str = None, severity: str = None):
        super().__init__()
        self.proj_path = proj_path or _get_proj_path()
        self.severity = severity

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("🔍 Gerenciador de Vulnerabilidades", classes="panel-title")
        with Horizontal(id="filter-bar"):
            yield Input(placeholder="🔎 Buscar por host ou título...", id="search-input")
            yield Select(
                [("Todas", "all"), ("Crítica", "Crítica"), ("Alta", "Alta"),
                 ("Média", "Média"), ("Baixa", "Baixa"), ("Info", "Info")],
                prompt="Severidade", id="severity-filter",
                value=self.severity or "all",
            )
        yield DataTable(id="vuln-table", cursor_type="row")
        yield Label("[dim]SPACE/ENTER: Ações  |  R: Atualizar  |  Q: Sair[/dim]", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        if not self.proj_path:
            self.query_one("#status-bar", Label).update("[red]Erro: Projeto não configurado.[/red]")
            return
        dt = self.query_one("#vuln-table", DataTable)
        dt.add_columns("Status", "Severidade", "Título", "Host", "Ferramenta")
        self.load_data()

    def load_data(self) -> None:
        dt = self.query_one("#vuln-table", DataTable)
        dt.clear()
        search_text = self.query_one("#search-input", Input).value.strip().lower()
        sev_filter = self.query_one("#severity-filter", Select).value

        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                query = """
                    SELECT v.id, v.title, v.severity, v.status, v.source_tool,
                        v.cvss_score, v.description, v.cwe_id,
                        COALESCE(h.host, 'N/A') as host
                    FROM vulnerabilities v
                    LEFT JOIN hosts h ON h.id = v.host_id
                    WHERE 1=1
                """
                params = []
                if sev_filter and sev_filter != "all":
                    query += " AND v.severity = ?"
                    params.append(sev_filter)
                query += " ORDER BY v.severity ASC, v.created_at DESC"
                cursor.execute(query, params)
                rows = cursor.fetchall()

                for r in rows:
                    host = (r["host"] or "").lower()
                    title = (r["title"] or "").lower()
                    if search_text and search_text not in host and search_text not in title:
                        continue
                    dt.add_row(
                        STATUS_EMOJI.get(r["status"], "⚪"),
                        f"{SEV_EMOJI.get(r['severity'], '')} {r['severity']}",
                        (r["title"] or "")[:80], r["host"], r["source_tool"],
                        key=str(r["id"]),
                    )

                self.query_one("#status-bar", Label).update(
                    f"[dim]Total: {dt.row_count} vulnerabilidades  |  "
                    f"SPACE/ENTER: Ações  |  R: Atualizar  |  Q: Sair[/dim]"
                )
        except Exception as e:
            self.query_one("#status-bar", Label).update(f"[red]Erro: {e}[/red]")

    def _get_vuln(self, vuln_id: int) -> dict | None:
        with db.get_connection(self.proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT v.*, COALESCE(h.host, 'N/A') as host
                FROM vulnerabilities v
                LEFT JOIN hosts h ON h.id = v.host_id
                WHERE v.id = ?
            """, (vuln_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def _toggle_fp(self, vuln_id: int):
        with db.get_connection(self.proj_path) as conn:
            with db.transaction(conn):
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM vulnerabilities WHERE id = ?", (vuln_id,))
                row = cursor.fetchone()
                if not row:
                    return
                new_status = "false_positive" if row["status"] != "false_positive" else "open"
                cursor.execute("UPDATE vulnerabilities SET status = ? WHERE id = ?", (new_status, vuln_id))
        self.notify(f"✅ Status alterado para: {new_status}", timeout=3)
        self.load_data()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        vuln = self._get_vuln(int(event.row_key.value))
        if not vuln:
            return

        def handle(result):
            if not result:
                return
            a = result.get("action")
            if a == "toggle_fp":
                self._toggle_fp(result["vuln_id"])
            elif a == "details":
                v = self._get_vuln(result["vuln_id"])
                if v:
                    self.push_screen(VulnDetailScreen(v))
            elif a == "edit":
                from vuln_enricher import run_edit
                run_edit(self.proj_path, result["vuln_id"])
                self.load_data()
                self.notify("✏️ Vulnerabilidade atualizada", timeout=3)

        self.push_screen(VulnActionScreen(vuln), handle)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self.load_data()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "severity-filter":
            self.load_data()

    def action_refresh(self) -> None:
        self.load_data()
        self.notify("🔄 Atualizado", timeout=2)


# ── CLI Wrapper ──
def run_vuln_list(proj_path: str = None, severity: str = None):
    VulnListApp(proj_path=proj_path, severity=severity).run()


if __name__ == "__main__":
    run_vuln_list()
