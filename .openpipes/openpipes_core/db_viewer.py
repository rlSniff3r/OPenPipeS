import os
import subprocess
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll, Horizontal
from textual.widgets import Header, Footer, DataTable, Button, Select, Input, Label, TabbedContent, TabPane, Rule

# Importando o seu módulo de banco de dados real
import db

HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")

# Mesmas tabelas gerenciadas pelo seu init_db
TABLES = [
    "projects", "hosts", "ports", "endpoints", 
    "screenshots", "js_discoveries", "vulnerabilities", "execution_logs"
]

def _fzf_select(options, prompt="Select:", multi=False):
    """Fallback fzf selector — used by vuln_enricher, scope, backup."""
    import tempfile
    inp = "\n".join(options)
    mode = "--multi" if multi else ""
    try:
        result = subprocess.run(
            ["fzf", mode, "--prompt", prompt],
            input=inp, capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            return [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
    except Exception:
        pass
    return []


def _get_proj_path():
    if not os.path.exists(CONFIG_FILE):
        return os.getcwd() 
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$proj_path\""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        path = result.stdout.strip()
        return path if path else os.getcwd()
    except Exception:
        return os.getcwd()

class DatabaseManagerApp(App):
    CSS = """
    Screen { padding: 1; }
    DataTable { height: 1fr; border: solid $primary; margin-bottom: 1; }
    .controls { height: auto; margin-bottom: 1; align: center middle; }
    .form-container { padding: 1 2; }
    Input { margin-bottom: 1; }
    #delete-btn, #clear-cell-btn { display: none; margin-left: 1;}
    """
    
    BINDINGS = [("q", "quit", "Sair")]

    def __init__(self):
        super().__init__()
        self.proj_path = _get_proj_path()
        db.init_db(self.proj_path)
        
        self.current_table = "hosts"
        self.selected_row_id = None
        self.selected_col_name = None # Nova variável para rastrear a coluna clicada

    def compose(self) -> ComposeResult:
        yield Header()
        
        with TabbedContent():
            with TabPane("Listar / Modificar", id="tab-list"):
                with Horizontal(classes="controls"):
                    yield Label("Tabela: ", classes="label-inline")
                    yield Select([(t, t) for t in TABLES], id="table_select_list", value="hosts")
                    yield Button("Deletar Linha", id="delete-btn", variant="error")
                    yield Button("Limpar Célula", id="clear-cell-btn", variant="warning")
                
                # Mudamos o cursor para 'cell'
                yield DataTable(id="data-table", cursor_type="cell")
                yield Label(f"Projeto atual: {self.proj_path}", id="status-msg-list")

            with TabPane("Inserir Novo Registro", id="tab-insert"):
                with Horizontal(classes="controls"):
                    yield Label("Tabela: ", classes="label-inline")
                    yield Select([(t, t) for t in TABLES], id="table_select_insert", value="hosts")
                
                yield Rule()
                with VerticalScroll(id="dynamic-form", classes="form-container"):
                    pass 
                
                yield Button("Inserir no Banco de Dados", id="insert-btn", variant="success")
                yield Label("", id="status-msg-insert")

        yield Footer()

    def on_mount(self) -> None:
        self.load_table_data("hosts")
        self.build_dynamic_form("hosts")

    def on_select_changed(self, event: Select.Changed) -> None:
        if not event.value:
            return
            
        if event.control.id == "table_select_list":
            self.current_table = event.value
            self.load_table_data(self.current_table)
            self.query_one("#delete-btn").display = False
            self.query_one("#clear-cell-btn").display = False
        
        elif event.control.id == "table_select_insert":
            self.build_dynamic_form(event.value)

    # NOVO: Agora interceptamos o clique na CÉLULA, não apenas na linha
    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        table = self.query_one("#data-table", DataTable)
        
        # Pega o ID da linha e o nome da coluna a partir da célula clicada
        self.selected_row_id = event.cell_key.row_key.value
        self.selected_col_name = event.cell_key.column_key.value
        
        btn_del = self.query_one("#delete-btn", Button)
        btn_del.display = True
        btn_del.label = f"Deletar ID {self.selected_row_id}"

        btn_clear = self.query_one("#clear-cell-btn", Button)
        btn_clear.display = True
        btn_clear.label = f"Limpar coluna '{self.selected_col_name}'"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "delete-btn":
            self.delete_record()
        elif event.button.id == "clear-cell-btn":
            self.clear_cell()
        elif event.button.id == "insert-btn":
            self.insert_record()

    def load_table_data(self, table_name: str) -> None:
        dt = self.query_one("#data-table", DataTable)
        dt.clear(columns=True)
        self.query_one("#delete-btn").display = False
        self.query_one("#clear-cell-btn").display = False
        
        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 200")
                rows = cursor.fetchall()
                
                if not rows:
                    dt.add_column("Aviso", key="Aviso")
                    dt.add_row(f"A tabela '{table_name}' está vazia.")
                    return
                
                col_names = rows[0].keys()
                # Adiciona as colunas passando o nome também como 'key', para sabermos onde o usuário clicou
                for col in col_names:
                    dt.add_column(col, key=col)
                
                for row in rows:
                    str_row = [str(item) if item is not None else "NULL" for item in row]
                    dt.add_row(*str_row, key=str(row["id"]))
                    
        except Exception as e:
            dt.add_column("Erro", key="Erro")
            dt.add_row(str(e))

    def delete_record(self) -> None:
        if not self.selected_row_id:
            return
            
        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"DELETE FROM {self.current_table} WHERE id = ?", (self.selected_row_id,))
                
            self.query_one("#status-msg-list", Label).update(f"[green]✔ Registro ID {self.selected_row_id} deletado com sucesso.[/green]")
            self.load_table_data(self.current_table)
            
        except Exception as e:
            self.query_one("#status-msg-list", Label).update(f"[red]Erro ao deletar: {e}[/red]")

    # NOVO: Função para atualizar a célula para NULL
    def clear_cell(self) -> None:
        if not self.selected_row_id or not self.selected_col_name:
            return

        # Impede o usuário de quebrar o banco apagando o ID Primário
        if self.selected_col_name.lower() == "id":
            self.query_one("#status-msg-list", Label).update("[yellow]Operação bloqueada: Você não pode limpar a chave primária (id).[/yellow]")
            return

        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                # Faz o UPDATE definindo a coluna clicada como NULL
                cursor.execute(f"UPDATE {self.current_table} SET {self.selected_col_name} = NULL WHERE id = ?", (self.selected_row_id,))
                
            self.query_one("#status-msg-list", Label).update(f"[green]✔ Coluna '{self.selected_col_name}' esvaziada (NULL) no ID {self.selected_row_id}.[/green]")
            self.load_table_data(self.current_table)
            
        except Exception as e:
            # Algumas colunas do seu banco possuem regras NOT NULL (ex: module_name em execution_logs). 
            # Se o usuário tentar limpar, cai aqui.
            self.query_one("#status-msg-list", Label).update(f"[red]Erro ao limpar célula (possível restrição do banco): {e}[/red]")

    def build_dynamic_form(self, table_name: str) -> None:
        form = self.query_one("#dynamic-form")
        for child in form.children:
            child.remove()
            
        self.query_one("#status-msg-insert", Label).update("")

        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()

            for col in columns:
                col_name = col["name"]
                col_type = col["type"]
                col_default = col["dflt_value"]
                
                if col_name.lower() == "id":
                    continue

                label_text = f"{col_name} ({col_type})"
                if col_default is not None:
                    label_text += f" [Default: {col_default}]"

                form.mount(Label(label_text))
                form.mount(Input(id=f"input_{col_name}"))
                
        except Exception as e:
            form.mount(Label(f"[red]Erro ao ler esquema: {e}[/red]"))

    def insert_record(self) -> None:
        table_name = self.query_one("#table_select_insert", Select).value
        form = self.query_one("#dynamic-form")
        
        inputs = form.query(Input)
        columns = []
        values = []
        placeholders = []
        
        for ip in inputs:
            col_name = ip.id.replace("input_", "")
            val = ip.value.strip()
            
            if val:
                columns.append(col_name)
                values.append(val)
                placeholders.append("?")
                
        if not columns:
            self.query_one("#status-msg-insert", Label).update("[yellow]Nenhum dado preenchido.[/yellow]")
            return
            
        cols_str = ", ".join(columns)
        placeholders_str = ", ".join(placeholders)
        sql = f"INSERT INTO {table_name} ({cols_str}) VALUES ({placeholders_str})"
        
        try:
            with db.get_connection(self.proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute(sql, values)
                
            self.query_one("#status-msg-insert", Label).update(f"[green]✔ Registro inserido com sucesso em {table_name}.[/green]")
            for ip in inputs:
                ip.value = ""
                
        except Exception as e:
             self.query_one("#status-msg-insert", Label).update(f"[red]Erro: {e}[/red]")

if __name__ == "__main__":
    app = DatabaseManagerApp()
    app.run()