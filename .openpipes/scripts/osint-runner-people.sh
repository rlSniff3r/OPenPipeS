#!/usr/bin/env bash
# =============================================================================
# Script: osint-runner-people.sh
# Descrição: Executa coleta OSINT sobre colaboradores da organização
# Autor: OPenPipeS Stack
# Versão: 1.1 - CORRIGIDO
# =============================================================================

set -euo pipefail

targetName="${1:-}"
obsdir="${OBSIDIAN_VAULT_DIR:-$HOME/ObsidianVault}"
tpldir="$HOME/.openpipes/.templates/osint"
peopleDir="$obsdir/Pentest/Alvos/$targetName/OSINT/People"

# Validação de argumentos
if [[ -z "$targetName" ]]; then
    echo "[ERROR] Uso: $0 <target_name>"
    exit 1
fi

mkdir -p "$peopleDir"
mkdir -p "$peopleDir/evidences"

echo "[INFO] Iniciando OSINT People Runner para: $targetName"

# 1. Busca básica de colaboradores (DuckDuckGo, Google, LinkedIn, GitHub)
echo "[INFO] Executando coleta de colaboradores..."
python3 /usr/local/bin/osint_people_collector.py "$targetName" "$peopleDir/raw_people.json"

# Validar se o arquivo foi criado
if [[ ! -f "$peopleDir/raw_people.json" ]]; then
    echo "[ERROR] Falha na coleta de colaboradores"
    exit 1
fi

# 2. Parser para criar perfis individuais
echo "[INFO] Parseando perfis individuais..."
python3 /usr/local/bin/osint_people_parser.py "$peopleDir/raw_people.json" "$peopleDir"

# 3. Coleta e análise de metadados de documentos públicos
echo "[INFO] Executando análise de metadados e busca de documentos..."
python3 /usr/local/bin/osint_doc_finder.py "$targetName" "$peopleDir/evidences/"

# 4. Geração dos perfis individuais com base no template
echo "[INFO] Gerando arquivos markdown dos perfis..."

# Função helper para sanitizar valores para sed
sanitize_for_sed() {
    echo "$1" | sed 's/[\/&]/\\&/g'
}

# Processar cada pessoa do JSON usando jq -c (compact)
if ! jq -e '.people | length > 0' "$peopleDir/raw_people.json" >/dev/null 2>&1; then
    echo "[WARN] Nenhuma pessoa encontrada no JSON"
else
    jq -c '.people[]' "$peopleDir/raw_people.json" | while IFS= read -r person; do
        # Extrair campos com fallback para valores vazios
        name=$(echo "$person" | jq -r '.name // "Unknown"')
        email=$(echo "$person" | jq -r '.email // ""')
        role=$(echo "$person" | jq -r '.role // ""')
        photo=$(echo "$person" | jq -r '.photo // ""')
        github=$(echo "$person" | jq -r '.github // ""')
        linkedin=$(echo "$person" | jq -r '.linkedin // ""')
        source=$(echo "$person" | jq -r '.source // ""')
        
        # Sanitizar nome para arquivo
        safe_name=$(echo "$name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g' | sed 's/__*/_/g')
        person_file="$peopleDir/people_${safe_name}.md"
        
        # Verificar se template existe
        if [[ ! -f "$tpldir/osint_person.stub.md" ]]; then
            echo "[WARN] Template não encontrado: $tpldir/osint_person.stub.md"
            # Criar template básico
            cat > "$person_file" << TEMPLATE_EOF
---
name: "$name"
email: "$email"
role: "$role"
photo: "$photo"
github: "$github"
linkedin: "$linkedin"
source: "$source"
generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
---

# $name

**Role:** $role
**Email:** $email
**Source:** $source

## Links
- GitHub: $github
- LinkedIn: $linkedin

## Evidence
TEMPLATE_EOF
        else
            # Usar template com substituição segura via perl
            perl -pe "
                s/\Q{{NAME}}\E/\Q$name\E/g;
                s/\Q{{EMAIL}}\E/\Q$email\E/g;
                s/\Q{{ROLE}}\E/\Q$role\E/g;
                s/\Q{{PHOTO}}\E/\Q$photo\E/g;
                s/\Q{{GITHUB}}\E/\Q$github\E/g;
                s/\Q{{LINKEDIN}}\E/\Q$linkedin\E/g;
                s/\Q{{SOURCE}}\E/\Q$source\E/g;
            " "$tpldir/osint_person.stub.md" > "$person_file"
        fi
        
        echo "[INFO]   → Criado perfil: $person_file"
    done
fi

# 5. Adicionar evidências aos perfis usando ID/hash ao invés de nome
echo "[INFO] Vinculando evidências aos perfis..."

for person_file in "$peopleDir"/people_*.md; do
    [[ ! -f "$person_file" ]] && continue
    
    # Extrair email do perfil para matching
    person_email=$(grep -Po '(?<=^email: ")[^"]*' "$person_file" 2>/dev/null || echo "")
    
    # Adicionar seção de evidências se não existir
    if ! grep -q "## 📂 Evidências Encontradas" "$person_file"; then
        echo -e "\n## 📂 Evidências Encontradas" >> "$person_file"
    fi
    
    # Buscar evidências relacionadas (por email ou nome base)
    if [[ -n "$person_email" ]]; then
        find "$peopleDir/evidences" -type f 2>/dev/null | while read -r evidence_file; do
            # Verificar se o arquivo de evidência menciona este email
            if grep -qi "$person_email" "$evidence_file" 2>/dev/null; then
                rel_path=$(realpath --relative-to="$peopleDir" "$evidence_file")
                echo "- [$rel_path]($rel_path)" >> "$person_file"
            fi
        done
    fi
done

# 6. Geração automática do resumo global
echo "[INFO] Gerando summary global..."
if command -v osint-summary-people.sh &>/dev/null; then
    osint-summary-people.sh "$targetName"
else
    echo "[WARN] osint-summary-people.sh não encontrado no PATH"
fi

echo "[✔] OSINT People Runner finalizado para: $targetName"
echo "[INFO] Resultados salvos em: $peopleDir"