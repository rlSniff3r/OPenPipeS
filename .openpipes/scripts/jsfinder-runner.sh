#!/bin/bash
set -euo pipefail
source $HOME/.openpipes/config.sh
venv="$HOME/.venv-jsfinder/bin/activate"
varreduraDir="$NMAP_DIR"

force=false
[[ "$*" == *"--force"* ]] && force=true

echo "[*] Ativando ambiente virtual do LinkFinder..."
source "$venv"

for nmapFolder in "$varreduraDir"/nmap-*; do
    [ -d "$nmapFolder" ] || continue
    targetName="${nmapFolder##*/nmap-}"
    tmpDir="/tmp/jsfinder-$targetName"
    outputFile="$nmapFolder/jsfinder-results.json"

    nmap_file="$nmapFolder/nmap.gnmap"
    if [[ ! -s "$nmap_file" ]]; then
        echo "[!] Pulando $targetName: nmap.gnmap está vazio ou não existe."
        continue
    fi

    if [ -f "$outputFile" ] && [ "$force" = false ]; then
        echo "[!] $outputFile já existe. Use --force para sobrescrever. Pulando $targetName..."
        continue
    fi

    echo "[*] Processando alvo: $targetName"
    mkdir -p "$tmpDir"

    echo "[*] Coletando possíveis arquivos JS..."
    js_urls=()

    # Source 1: httpx JSONs (raw tool output)
    for json in "$nmapFolder"/httpx*.json; do
        [ -f "$json" ] || continue
        if jq -e 'type=="array"' "$json" &>/dev/null; then
            urls=$(jq -r '.[] | select(.url | test("\\.js($|\\?)")) | .url' "$json")
        else
            urls=$(jq -r 'select(type == "object") | select(.url | test("\\.js($|\\?)")) | .url' "$json")
        fi
        js_urls+=($urls)
    done

    # Source 2: katana crawled URLs
    if [[ -f "$nmapFolder/crawled_all.txt" ]]; then
        crawled_js=$(grep -Eo 'https?://[^ ")]+\.js(\?[^\s)]*)?' "$nmapFolder/crawled_all.txt" || true)
        js_urls+=($crawled_js)
    fi

    # Source 3: feroxbuster consolidated URLs
    if [[ -f "$nmapFolder/ferox_consolidated.txt" ]]; then
        ferox_js=$(grep -Eo 'https?://[^ ")]+\.js(\?[^\s)]*)?' "$nmapFolder/ferox_consolidated.txt" || true)
        js_urls+=($ferox_js)
    fi

    # Source 4: alive_urls.txt (live httpx URLs)
    if [[ -f "$nmapFolder/alive_urls.txt" ]]; then
        alive_js=$(grep -Eo 'https?://[^ ")]+\.js(\?[^\s)]*)?' "$nmapFolder/alive_urls.txt" || true)
        js_urls+=($alive_js)
    fi

    # Source 5: gf-summary.json patterns (raw output)
    if [[ -f "$nmapFolder/gf-summary.json" ]]; then
        gf_js=$(jq -r '.gf_patterns | to_entries[] | .value[]' "$nmapFolder/gf-summary.json" 2>/dev/null | grep -Eo 'https?://[^ ")]+\.js(\?[^\s)]*)?' || true)
        js_urls+=($gf_js)
    fi

    js_urls=($(printf "%s\n" "${js_urls[@]}" | sort -u))
    echo "[*] Total de arquivos JS encontrados: ${#js_urls[@]}"

    if [ "${#js_urls[@]}" -eq 0 ]; then
        echo "[!] Nenhum arquivo JS encontrado para $targetName."
        continue
    fi

    # Build JSON results array
    results=()
    for url in "${js_urls[@]}"; do
        jsFile="$tmpDir/$(basename "$url" | cut -d '?' -f1)"
        echo "[*] Baixando $url..."
        curl -s -L --max-time 15 "$url" -o "$jsFile" || { echo "[-] Falha ao baixar: $url"; continue; }

        routes=$(linkfinder.py -i "$jsFile" -o cli 2>/dev/null | grep -Eo 'https?://[^ ")]+' | sort -u | jq -R -s 'split("\n") | map(select(length > 0))')
        results+=("$(jq -n --arg url "$url" --argjson routes "$routes" '{source_js_url: $url, discovered_routes: $routes}')")
    done

    # Write JSON output
    jq -n \
        --arg target "$targetName" \
        --argjson results "$(printf '%s\n' "${results[@]}" | jq -s '.')" \
        '{target: $target, generated_at: now, results: $results}' \
        > "$outputFile"

    echo "[✓] jsfinder-results.json criado em: $outputFile"
done
echo "[✓] Todos os alvos foram processados!"
