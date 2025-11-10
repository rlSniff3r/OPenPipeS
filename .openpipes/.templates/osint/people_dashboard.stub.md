---
type: osint_people_dashboard
target: "{{targetName}}"
created: {{date}}
---

# 👥 Dashboard de Colaboradores — {{targetName}}

> **Resumo automático das pessoas mapeadas durante o OSINT corporativo.**
> Clique em cada nome para abrir o perfil completo e as evidências associadas.

---

## 📊 Sumário Geral

```dataviewjs
// Diretório atual (OSINT/Pessoas)
const pages = dv.pages('"Pentest/Alvos/{{targetName}}/OSINT/Pessoas"')
    .where(p => p.type && p.type === "osint_person");

if (pages.length === 0) {
    dv.paragraph("Nenhum colaborador identificado ainda.");
} else {
    dv.table(
        ["Nome", "Cargo", "E-mail", "LinkedIn", "GitHub", "Twitter", "Evidências"],
        pages.map(p => [
            dv.fileLink(p.file.path, p.name || p.file.name),
            p.title || "-",
            p.email || "-",
            p.linkedin ? `[🔗](${p.linkedin})` : "-",
            p.github ? `[💻](${p.github})` : "-",
            p.twitter ? `[🐦](${p.twitter})` : "-",
            (p.evidence && p.evidence.length > 0)
                ? p.evidence.length + " fontes"
                : "—"
        ])
    );
}
