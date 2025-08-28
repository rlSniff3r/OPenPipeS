#!/bin/bash

set -euo pipefail

# Caminhos base

source $HOME/.openpipes/config.sh
venv="$HOME/.venv-jsfinder/bin/activate"
varreduraDir="$PWD"

# Flag --force
force=false
[[ "$*" == *"--force"* ]] && force=true

# Ativa ambiente virtual
echo "[*] Ativando ambiente virtual do LinkFinder..."
source "$venv"

# Percorre todos os diretórios nmap-*
for nmapFolder in "$varreduraDir"/nmap-*; do
    [ -d "$nmapFolder" ] || continue

    targetName="${nmapFolder##*/nmap-}"
    targetDir="$obsdir/Pentest/Alvos/$targetName"
    tmpDir="/tmp/jsfinder-$targetName"
    outputFile="$targetDir/js-endpoints.md"

    if [ -f "$outputFile" ] && [ "$force" = false ]; then
        echo "[!] $outputFile já existe. Use --force para sobrescrever. Pulando $targetName..."
        continue
    fi

    echo "[*] Processando alvo: $targetName"
    mkdir -p "$tmpDir"
    > "$outputFile"

    echo "[*] Coletando possíveis arquivos JS..."
    js_urls=()

    # 1. endpoints.md
    [ -f "$targetDir/endpoints.md" ] && js_urls+=($(grep -Eo 'https?://[^ ")]+\.js(\?[^\s)]*)?' "$targetDir/endpoints.md" || true))

    # 2. ferox-katana.md
    [ -f "$targetDir/ferox-katana.md" ] && js_urls+=($(grep -Eo 'https?://[^ ")]+\.js(\?[^\s)]*)?' "$targetDir/ferox-katana.md" || true))

    # 3. gf-summary.md
    [ -f "$targetDir/gf-summary.md" ] && js_urls+=($(grep -Eo 'https?://[^ ")]+\.js(\?[^\s)]*)?' "$targetDir/gf-summary.md" || true))

    # 4. httpx*.json
    for json in "$nmapFolder"/httpx*.json; do
        [ -f "$json" ] || continue

        if jq -e 'type=="array"' "$json" &>/dev/null; then
            urls=$(jq -r '.[] | select(.url | test("\\.js($|\\?)")) | .url' "$json")
        else
            urls=$(jq -r 'select(type == "object") | select(.url | test("\\.js($|\\?)")) | .url' "$json")
        fi

        js_urls+=($urls)
    done

    js_urls=($(printf "%s\n" "${js_urls[@]}" | sort -u))
    echo "[*] Total de arquivos JS encontrados: ${#js_urls[@]}"

    if [ "${#js_urls[@]}" -eq 0 ]; then
        echo "[!] Nenhum arquivo JS encontrado para $targetName. Pulando..."
        continue
    fi

    echo "# 🔍 JS Endpoints encontrados para $targetName" > "$outputFile"
    echo "" >> "$outputFile"

    for url in "${js_urls[@]}"; do
        jsFile="$tmpDir/$(basename "$url" | cut -d '?' -f1)"
        echo "[*] Baixando $url..."
        curl -s -L --max-time 15 "$url" -o "$jsFile" || { echo "[-] Falha ao baixar: $url" && continue; }

        echo "## Fonte: [$url]($url)" >> "$outputFile"
        echo "" >> "$outputFile"

        echo "\`\`\`" >> "$outputFile"
        linkfinder.py -i "$jsFile" -o cli >> "$outputFile"
        echo "\`\`\`" >> "$outputFile"
        echo "" >> "$outputFile"
    done

    echo "[✓] js-endpoints.md criado em: $outputFile"
    echo ""
done

echo "[✓] Todos os alvos foram processados!"

