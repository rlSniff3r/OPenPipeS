# 🚀 OPenPipeS - Guia Rápido de Uso

## 📥 Instalação em 3 passos

```bash
# 1. Clone e instale
git clone https://github.com/seu-usuario/OPenPipeS.git
cd OPenPipeS
make install

# 2. Recarregue o shell
source ~/.bashrc

# 3. Configure
openpipes  # [C] Configuração
```

---

## ⚙️ Configuração Inicial

Edite `~/.openpipes/config.sh`:

```bash
# Seus projetos ficam aqui
proj_dir="/home/kali/pentests"

# Nome do projeto atual
proj_name="cliente-abc"

# API Keys (opcional)
securitytrailskey="sua-chave"
OPENAI_API_KEY="sk-..."
```

---

## 🎯 Uso Básico

### Opção 1: Menu Interativo (Recomendado)

```bash
openpipes
```

### Opção 2: Scripts Diretos

```bash
# Reconhecimento
cd /home/kali/pentests/cliente-abc
echo "exemplo.com" > domains.txt
recon.sh -d domains.txt

# Scan
cd Varreduras
nwrapper.sh -f targets.txt

# Criar estrutura Obsidian
cria_Alvos_Obsidian.sh

# HTTPX
httpx-runner.sh

# Katana + Feroxbuster
katana-buster.sh

# Nuclei
nuclei-runner.sh

# JSFinder
jsfinder-runner.sh

# GF Summary
gf-summary.sh

# WHOIS
whois-enricher.sh
```

---

## 🔄 Pipeline Completo (Automático)

```bash
# Preparar ambiente
cd /home/kali/pentests/cliente-abc
echo -e "exemplo.com\noutro.com" > domains.txt

# Executar TUDO de uma vez
openpipes  # [P] Pipeline Completo

# OU via Makefile
make run  # e escolha [P]
```

---

## 📂 Estrutura de Arquivos

```
/home/kali/pentests/cliente-abc/
├── domains.txt              # ← VOCÊ CRIA ESTE!
├── Recon/                   # Reconhecimento
│   ├── exemplo.com/
│   │   ├── allsubs          # Subdomínios
│   │   ├── hosts-allsubs    # DNS resolution
│   │   └── allsubs.httpx.json
│   └── outro.com/
└── Varreduras/              # Scanning
    ├── targets.txt          # Gerado automaticamente
    ├── nmap-192.168.1.1/
    │   ├── initial
    │   ├── nmap.nmap
    │   └── nmap.gnmap
    └── nmap-exemplo.com/
```

---

## 📊 Obsidian Vault

```
~/.obsidianFixedMount/Pentest/
├── Dashboard_Global.md      # Dashboard principal
├── Tarefas.md               # Todas as tarefas
└── Alvos/
    ├── exemplo.com/
    │   ├── exemplo.com.md           # Nota principal
    │   ├── Dashboard_exemplo.com.md # Dashboard do alvo
    │   ├── Vulnerabilidades/
    │   │   └── 20250110120000_XSS.md
    │   ├── nmap.md
    │   ├── httpx.md
    │   ├── nuclei.md
    │   ├── endpoints.md
    │   ├── ferox-katana.md
    │   ├── js-endpoints.md
    │   └── gf-summary.md
    └── 192.168.1.1/
        └── ...
```

---

## 💥 Gerenciar Vulnerabilidades

### Criar Nova Vulnerabilidade

```bash
openpipes
# [V] Gerenciar Vulnerabilidades
# [1] Criar Nova Vulnerabilidade

# Interativo:
# 1. Selecione o alvo (fzf)
# 2. Selecione o template do cache (145 opções!)
# 3. Arquivo criado automaticamente!
```

### Enriquecer com IA

```bash
openpipes
# [V] Gerenciar Vulnerabilidades
# [2] Enriquecer Vulnerabilidade

# Interativo:
# 1. Selecione a vulnerabilidade
# 2. OpenAI GPT-4 gera:
#    - Descrição técnica
#    - CWE
#    - WSTG ID
#    - Links OWASP
#    - Referências
```

---

## 🔍 Comandos Úteis

```bash
# Ver status da instalação
openpipes  # [S] Status do Sistema
make status

# Ver configuração atual
openpipes  # [C] Configuração
make config

# Ver documentação
openpipes  # [H] Help
cat README.md

# Atualizar OPenPipeS
cd OPenPipeS
make update

# Backup da configuração
make backup

# Restaurar backup
make restore BACKUP=backups/openpipes-backup-20250110.tar.gz
```

---

## 🐛 Troubleshooting

### Problema: "openpipes: command not found"

```bash
source ~/.bashrc
echo $PATH | grep openpipes
# Se não aparecer:
echo 'export PATH="$PATH:$HOME/.openpipes/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Problema: "Configuração incompleta"

```bash
nano ~/.openpipes/config.sh
# Preencha proj_dir e proj_name!
```

### Problema: Ferramenta não instalada

```bash
# Verificar o que falta
openpipes  # [S] Status

# Reinstalar dependências
cd OPenPipeS
make install
```

### Problema: Obsidian não mostra os arquivos

```bash
# 1. Abra Obsidian
# 2. Open Folder as vault
# 3. Selecione: ~/.obsidianFixedMount
```

### Problema: OpenAI API falha

```bash
# Testar chave
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer sk-sua-chave"

# Configurar novamente
nano ~/.openpipes/config.sh
```

---

## 🎨 Personalização

### Adicionar Template de Vulnerabilidade

```bash
# 1. Criar JSON
cat > ~/.openpipes_cache/minha_vuln.json << 'EOF'
{
  "title": "Minha Vulnerabilidade",
  "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
  "description": "Descrição...",
  "observation": "Impacto...",
  "remediation": "Solução...",
  "references": [
    "https://owasp.org/...",
    "https://cwe.mitre.org/..."
  ]
}
EOF

# 2. Usar no OPenPipeS
openpipes  # [V] → [1] → Selecione "minha_vuln"
```

### Modificar Templates Obsidian

```bash
# Templates ficam em:
ls ~/.openpipes/.templates/

# Editar dashboard
nano ~/.openpipes/.templates/dashboard.stub.md

# Após editar, recriar alvos:
cd Varreduras
cria_Alvos_Obsidian.sh
```

---

## 📋 Checklist de Pentest

```markdown
- [ ] 1. Reconhecimento
  - [ ] DNS enumeration
  - [ ] Subdomain discovery
  - [ ] WHOIS/RDAP
  
- [ ] 2. Scanning
  - [ ] Port scan (nmap)
  - [ ] Service detection
  - [ ] OS fingerprinting
  
- [ ] 3. Enumeration
  - [ ] Web servers (httpx)
  - [ ] Endpoints (katana/ferox)
  - [ ] Technologies (httpx)
  
- [ ] 4. Vulnerability Assessment
  - [ ] Nuclei scan
  - [ ] Manual testing
  
- [ ] 5. Documentation
  - [ ] Create vulnerabilities
  - [ ] Enrich with AI
  - [ ] Generate report
```

---

## 🔗 Links Úteis

- **Obsidian**: https://obsidian.md/
- **ProjectDiscovery**: https://projectdiscovery.io/
- **OWASP WSTG**: https://owasp.org/www-project-web-security-testing-guide/
- **CWE**: https://cwe.mitre.org/
- **SecLists**: https://github.com/danielmiessler/SecLists

---

## 💡 Dicas Pro

1. **Use o Pipeline Completo** para reconhecimento inicial rápido
2. **Analise o GF Summary** antes de testar manualmente
3. **Enriqueça vulnerabilidades com IA** para economizar tempo
4. **Customize os templates** para seu estilo de relatório
5. **Use tags no Obsidian** para organizar ainda mais

---

## 🎓 Workflow Recomendado

```
1. domains.txt → [1] Recon → Recon/*
                    ↓
2. targets.txt → [2] Scan → Varreduras/nmap-*
                    ↓
3. [3] Criar Alvos → Obsidian/Pentest/Alvos/*
                    ↓
4. [4] HTTPX → endpoints.md, httpx.md
                    ↓
5. [5] Katana/Ferox → ferox-katana.md
                    ↓
6. [6] Nuclei → nuclei.md
                    ↓
7. [7] JSFinder → js-endpoints.md
                    ↓
8. [8] GF Summary → gf-summary.md
                    ↓
9. [9] WHOIS → Dashboard atualizado
                    ↓
10. Análise Manual + [V] Vulnerabilidades
                    ↓
11. Relatório Final
```

---

<div align="center">

**🔥 Happy Hacking! 🔥**

*Made with ❤️ by Rafael Luís da Silva*

</div>