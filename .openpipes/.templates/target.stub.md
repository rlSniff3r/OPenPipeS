---
tipo: target
targetName: {{targetName}}
t_IP: {{ip}}
t_openPorts: ["80", "443"]
t_endpoint:
  - "GET /api/cashout 200"
  - "POST /api/account 403"
  - "GET /aes 404"
tags: [alvo, host]
---

# 💥 Vulnerabilidades

## 🔴 Critical
## 🟠 High
## 🟡 Medium
## 🟢 Low

---

# 📘 Narrativa Técnica

O host possui xyz tecnologias.

<br>

---
# 🔢 Enumeração

🌐 -  [[endpoints.md|Endpoints encontrados]]
🧹 -  [[nmap.md|Nmap results]]
🛜 -  [[httpx.md|HTTPX results]]
📦 -  [[nuclei.md|Nuclei results]]
🧪 -  [[gf-summary.md|gf Summary]]
🪡 -  [[js-endpoints.md|js Endpoints]]

<br>

---
# 🚩 Progresso

- [ ] Validar serviços nas portas abertas
