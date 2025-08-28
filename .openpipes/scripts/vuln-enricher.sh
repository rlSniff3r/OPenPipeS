#!/bin/bash

# Diretório base do 
# Configs
source $HOME/.openpipes/config.sh
OPENAI_API_KEY="${OPENAI_API_KEY:-$(grep OPENAI_API_KEY ~/.bashrc | cut -d '=' -f2 | tr -d "'")}"
echo $OPENAI_API_KEY


# Diretório de cache
cache_dir="$HOME/.openpipes_cache"
mkdir -p "$cache_dir"
log_file="$cache_dir/enrichment.log"

# Função para extrair campo do frontmatter
extract_field() {
  grep "^$1:" "$2" | cut -d ':' -f2- | xargs
}

# Função para normalizar tipo de vulnerabilidade
normalize_tipo() {
  echo "$1" | iconv -t ascii//TRANSLIT | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g'
}

# Buscar vulnerabilidades
vulns=($(find "$obsdir/Pentest/Alvos" -type f -path "*/Vulnerabilidades/*.md"))
[[ ${#vulns[@]} -eq 0 ]] && echo "[!] Nenhuma vulnerabilidade encontrada." && exit 1

# Montar painel fzf
selection=$(printf '%s\n' "${vulns[@]}" | while read -r file; do
  alvo=$(basename "$(dirname "$(dirname "$file")")")
  nome=$(basename "$file")
  echo "$nome ($alvo) :: $file"
done | fzf --prompt="Selecione a vulnerabilidade: ")

[[ -z "$selection" ]] && echo "[!] Nenhuma seleção feita." && exit 1
filepath=$(echo "$selection" | awk -F ':: ' '{print $2}')

# Extrair e normalizar Tipo
tipo=$(extract_field "Tipo" "$filepath")
[[ -z "$tipo" ]] && echo "[!] Campo 'Tipo' não encontrado no frontmatter." && exit 1
normalized_tipo=$(normalize_tipo "$tipo")
cache_file="$cache_dir/${normalized_tipo}.json"

# Criar cache se não existir
if [[ ! -f "$cache_file" ]]; then
  read -p "[?] Nenhum cache encontrado para '$tipo'. Consultar OpenAI? (s/N): " confirm
  [[ ! "$confirm" =~ ^[sS]$ ]] && echo "[!] Abortado." && exit 0

  read -r -d '' prompt <<EOF
Para a vulnerabilidade '$tipo', retorne apenas o seguinte JSON bruto, sem comentários, explicações ou formatação adicional. Responda apenas com o JSON puro e em português técnico:

{
  "cwe": "...",
  "wstg_id": "...",
  "wstg_url": "...",
  "owasp_url": "...",
  "cheatsheet_url": "...",
  "descricao": "..."
}

Se algum campo não se aplicar, utilize string vazia.
EOF

  read -r -d '' system_prompt <<EOF
Você é um especialista técnico em segurança ofensiva. Suas respostas são objetivas, técnicas e direcionadas para profissionais da área. Sempre responda apenas com JSON bruto, sem markdown, listas, comentários ou qualquer explicação adicional.
EOF

  request_payload=$(cat <<EOF
{
  "model": "gpt-4o",
  "temperature": 0.3,
  "max_tokens": 500,
  "messages": [
    { "role": "system", "content": $(jq -Rs <<< "$system_prompt") },
    { "role": "user", "content": $(jq -Rs <<< "$prompt") }
  ]
}
EOF
)

  echo "[+] Consultando API OpenAI..."
  response=$(curl -s https://api.openai.com/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -d "$request_payload")

  json_content=$(echo "$response" | jq -r '.choices[0].message.content // empty')

  echo "$response" > "$cache_dir/ultima_resposta_api.json"

  # Verifica se JSON é válido e contém os campos obrigatórios
  if ! echo "$json_content" | jq -e 'has("cwe") and has("descricao")' >/dev/null 2>&1; then
    echo "[!] ❌ A resposta da API não contém JSON válido esperado."
    echo "[DEBUG] Conteúdo bruto recebido:"
    echo "$json_content"
    echo "[?] Deseja editar manualmente antes de salvar? (s/N): "
    read -r edit_confirm
    echo "$json_content" > "$cache_file.tmp"
    if [[ "$edit_confirm" =~ ^[sS]$ ]]; then
      ${EDITOR:-nano} "$cache_file.tmp"
    fi
    echo "[+] Salvando cache manual após revisão..."
    mv "$cache_file.tmp" "$cache_file"
  else
    echo "$json_content" > "$cache_file"
    echo "[+] Cache salvo com sucesso: $cache_file"
  fi
fi

# Carrega dados do cache JSON
cwe=$(jq -r '.cwe' "$cache_file")
wstg_id=$(jq -r '.wstg_id' "$cache_file")
wstg_url=$(jq -r '.wstg_url' "$cache_file")
owasp_url=$(jq -r '.owasp_url' "$cache_file")
cheatsheet_url=$(jq -r '.cheatsheet_url' "$cache_file")
descricao=$(jq -r '.descricao' "$cache_file")

# Verifica presença mínima
[[ "$cwe" == "null" || -z "$cwe" ]] && echo "[!] Campo CWE ausente no cache." && exit 1

# Atualiza frontmatter no arquivo
sed -i "s#^CWE:.*#CWE: $cwe#" "$filepath"
sed -i "s#^WSTG:.*#WSTG: $wstg_id#" "$filepath"
sed -i "s#^OWASP:.*#OWASP: $owasp_url#" "$filepath"
sed -i "s#^Cheatsheet:.*#Cheatsheet: $cheatsheet_url#" "$filepath"

# Inserir descrição após o primeiro ***
descricao_final="[$wstg_id]($wstg_url)

$descricao"

line=$(grep -n '^\*\*\*' "$filepath" | head -n1 | cut -d':' -f1)
[[ -z "$line" ]] && echo "[!] Separador '***' não encontrado no arquivo." && exit 1
insert_line=$((line + 1))

awk -v insert_line="$insert_line" -v text="$descricao_final" 'NR==insert_line {print text "\n"} {print}' "$filepath" > "$filepath.tmp" && mv "$filepath.tmp" "$filepath"

# Log
echo "$(date +%F_%T) - Tipo: $tipo - Enriquecido em $filepath" >> "$log_file"
echo "[✔] Vulnerabilidade '$tipo' enriquecida com sucesso."
