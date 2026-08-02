import json
import re
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll, Grid, Container
from textual.widgets import Input, Label, Button, Select, Rule
from cvss import CVSS3

# Dicionário com as opções do CVSS 3.1
CVSS_METRICS = {
    "AV": [("Network (N)", "N"), ("Adjacent (A)", "A"), ("Local (L)", "L"), ("Physical (P)", "P")],
    "AC": [("Low (L)", "L"), ("High (H)", "H")],
    "PR": [("None (N)", "N"), ("Low (L)", "L"), ("High (H)", "H")],
    "UI": [("None (N)", "N"), ("Required (R)", "R")],
    "S":  [("Unchanged (U)", "U"), ("Changed (C)", "C")],
    "C":  [("None (N)", "N"), ("Low (L)", "L"), ("High (H)", "H")],
    "I":  [("None (N)", "N"), ("Low (L)", "L"), ("High (H)", "H")],
    "A":  [("None (N)", "N"), ("Low (L)", "L"), ("High (H)", "H")],
}

class JSONFormApp(App):
    CSS = """
    Screen {
        padding: 1 2;
    }
    Input {
        margin-bottom: 1;
    }
    Button {
        margin-top: 1;
        margin-bottom: 1;
    }
    .cvss-grid {
        layout: grid;
        grid-size: 2;
        grid-gutter: 1 2;
        padding: 1;
        border: solid $primary;
        margin-bottom: 1;
    }
    #score-label {
        text-style: bold;
        color: $warning;
        margin-bottom: 1;
    }
    .score-success { color: $success !important; }
    .score-error { color: $error !important; }
    """

    def __init__(self, edit_vuln_id: int = None):
        super().__init__()
        self.edit_vuln_id = edit_vuln_id
        self.final_cvss_vector = ""

    def on_mount(self) -> None:
        """If editing, pre-fill all fields with current vuln data."""
        if not self.edit_vuln_id:
            return

        try:
            import db
            from pathlib import Path
            import subprocess

            # Resolve proj_path
            home = str(Path.home())
            config = os.path.join(home, ".openpipes", "config.sh")
            cmd = f"source {config} && echo -n \"$proj_path\""
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
            proj_path = r.stdout.strip()

            with db.get_connection(proj_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (self.edit_vuln_id,))
                row = cursor.fetchone()
                if not row:
                    return
                vuln = dict(row)

            # Pre-fill text fields
            self.query_one("#title", Input).value = vuln.get("title") or ""
            self.query_one("#description", Input).value = vuln.get("description") or ""
            self.query_one("#observation", Input).value = vuln.get("impact") or ""
            self.query_one("#remediation", Input).value = vuln.get("remediation") or ""

            # References (JSON array → single input)
            refs = json.loads(vuln.get("reference_urls") or "[]")
            if refs:
                self.query_one("#references", Input).value = refs[0]

            # Pre-fill CVSS selects from vector
            vector = vuln.get("cvss_vector") or ""
            if vector and vector.startswith("CVSS:3.1"):
                for part in vector.split("/")[1:]:
                    if ":" in part:
                        key, val = part.split(":", 1)
                        try:
                            self.query_one(f"#cvss_{key}", Select).value = val
                        except Exception:
                            pass
            self.calculate_cvss()
        except Exception:
            pass

    # ... compose() stays exactly the same ...

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            raw_title = self.query_one("#title").value.strip()

            data = {
                "title": raw_title,
                "cvssv3": self.final_cvss_vector,
                "description": self.query_one("#description").value,
                "observation": self.query_one("#observation").value,
                "remediation": self.query_one("#remediation").value,
                "references": [self.query_one("#references").value],
            }
            # Include vuln_id when editing
            if self.edit_vuln_id:
                data["vuln_id"] = self.edit_vuln_id

            cache_dir = Path.home() / ".openpipes_cache"
            cache_dir.mkdir(parents=True, exist_ok=True)

            if raw_title:
                safe_title = re.sub(r'[^a-z0-9]+', '_', raw_title.lower()).strip('_')
            else:
                safe_title = "vulnerabilidade_sem_titulo"

            # When editing, use a prefixed filename to avoid clobbering cache
            prefix = f"edit_{self.edit_vuln_id}_" if self.edit_vuln_id else ""
            filepath = cache_dir / f"{prefix}{safe_title}.json"

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Exit with the filepath so run_edit() can consume it
            self.exit(str(filepath))


    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("Preencha os dados da Vulnerabilidade:", id="main-title")
            yield Input(placeholder="Title", id="title")

            yield Rule()
            yield Label("Calculadora CVSS v3.1:")
            yield Label("Score: -- (Preencha todos os campos do CVSS)", id="score-label")
            
            with Container(classes="cvss-grid"):
                yield Select(CVSS_METRICS["AV"], prompt="Attack Vector (AV)", id="cvss_AV")
                yield Select(CVSS_METRICS["AC"], prompt="Attack Complexity (AC)", id="cvss_AC")
                yield Select(CVSS_METRICS["PR"], prompt="Privileges Required (PR)", id="cvss_PR")
                yield Select(CVSS_METRICS["UI"], prompt="User Interaction (UI)", id="cvss_UI")
                yield Select(CVSS_METRICS["S"], prompt="Scope (S)", id="cvss_S")
                yield Select(CVSS_METRICS["C"], prompt="Confidentiality (C)", id="cvss_C")
                yield Select(CVSS_METRICS["I"], prompt="Integrity (I)", id="cvss_I")
                yield Select(CVSS_METRICS["A"], prompt="Availability (A)", id="cvss_A")

            yield Rule()
            yield Input(placeholder="Description", id="description")
            yield Input(placeholder="Observation", id="observation")
            yield Input(placeholder="Remediation", id="remediation")
            yield Input(placeholder="Reference URL", id="references")
            
            yield Button("Salvar JSON e Sair", id="save", variant="success")

    def on_select_changed(self, event: Select.Changed) -> None:
        self.calculate_cvss()

    def calculate_cvss(self) -> None:
        metrics_keys = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        vector_parts = ["CVSS:3.1"]
        score_label = self.query_one("#score-label", Label)

        for m in metrics_keys:
            val = self.query_one(f"#cvss_{m}", Select).value
            if val == Select.BLANK or val is None:
                score_label.update("Score: -- (Preencha todos os campos do CVSS)")
                score_label.remove_class("score-success")
                self.final_cvss_vector = ""
                return
            vector_parts.append(f"{m}:{val}")

        vector_str = "/".join(vector_parts)

        try:
            c = CVSS3(vector_str)
            score = c.scores()[0]
            severity = c.severities()[0]
            
            score_label.update(f"Score: {score} [{severity}] - Vetor: {vector_str}")
            score_label.add_class("score-success")
            self.final_cvss_vector = vector_str
        except Exception:
            score_label.update("Erro ao calcular o CVSS.")
            score_label.add_class("score-error")
            self.final_cvss_vector = ""

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            raw_title = self.query_one("#title").value.strip()

            data = {
                "title": raw_title,
                "cvssv3": self.final_cvss_vector,
                "description": self.query_one("#description").value,
                "observation": self.query_one("#observation").value,
                "remediation": self.query_one("#remediation").value,
                "references": [self.query_one("#references").value],
            }
            # Include vuln_id when editing
            if self.edit_vuln_id:
                data["vuln_id"] = self.edit_vuln_id

            cache_dir = Path.home() / ".openpipes_cache"
            cache_dir.mkdir(parents=True, exist_ok=True)

            if raw_title:
                safe_title = re.sub(r'[^a-z0-9]+', '_', raw_title.lower()).strip('_')
            else:
                safe_title = "vulnerabilidade_sem_titulo"

            # When editing, use a prefixed filename to avoid clobbering cache
            prefix = f"edit_{self.edit_vuln_id}_" if self.edit_vuln_id else ""
            filepath = cache_dir / f"{prefix}{safe_title}.json"

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Exit with the filepath so run_edit() can consume it
            self.exit(str(filepath))

if __name__ == "__main__":
    app = JSONFormApp()
    resultado = app.run()
    if resultado:
        print(resultado)