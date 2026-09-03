#!/bin/bash
#set -euo pipefail
source $HOME/.openpipes/config.sh
varreduraDir="$NMAP_DIR"
MAX_ROUNDS=5

force=false
[[ "$*" == *"--force"* ]] && force=true

echo "[*] Iniciando MEGAZORD JS Scanner no OPenPipeS..."

for nmapFolder in "$varreduraDir"/nmap-*; do
    [ -d "$nmapFolder" ] || continue
    targetName="${nmapFolder##*/nmap-}"
    outputFile="$nmapFolder/jsfinder-results.json"
    
    if [ -f "$outputFile" ] && [ "$force" = false ]; then
        echo "[!] $outputFile já existe. Pulando $targetName..."
        continue
    fi

    # Arquivo de seed alimentado pelo feeder.py
    seed_file="$nmapFolder/js_urls.txt"
    if [ ! -s "$seed_file" ]; then
        echo "[!] Nenhum JS alimentado para $targetName. Pulando..."
        continue
    fi

    echo "[*] Processando alvo: $targetName"
    BASE_URL="https://$targetName"
    tmpDir="/tmp/megazord-$targetName"
    mkdir -p "$tmpDir"
    
    cp "$seed_file" "$tmpDir/pendentes_round_1.txt"
    touch "$tmpDir/historico_js.txt" "$tmpDir/todas_rotas_api.txt" "$tmpDir/secrets_all.txt" "$tmpDir/params_all.txt" "$tmpDir/source_map.txt"

    # ==========================================
    # LOOP DE RODADAS RECURSIVAS
    # ==========================================
    ROUND=1
    while [ -s "$tmpDir/pendentes_round_${ROUND}.txt" ] && [ "$ROUND" -le "$MAX_ROUNDS" ]; do
        TOTAL_ROUND=$(wc -l < "$tmpDir/pendentes_round_${ROUND}.txt")
        cat "$tmpDir/pendentes_round_${ROUND}.txt" >> "$tmpDir/historico_js.txt"
        
        echo "    ↳ Rodada $ROUND ($TOTAL_ROUND arquivos)..."
        
        while read -r raw_url; do
            # 1. Limpeza ninja: Remove quebras de linha e espaços invisíveis (\r\n)
            url=$(echo "$raw_url" | tr -d '\r' | tr -d '\n' | xargs)
            [ -z "$url" ] && continue

            filename=$(echo -n "$url" | md5sum | awk '{print $1}')
            js_path="$tmpDir/R${ROUND}_${filename}.js"
            
            # 2. Faz o download
            curl -s -k -L --max-time 15 "$url" -o "$js_path"
            
            # 3. DEBUG & SAFEGUARD: Checa se o arquivo foi criado E tem conteúdo
            if [ ! -s "$js_path" ]; then
                echo "        [!] Falha no download ou arquivo vazio: $url"
                rm -f "$js_path" 2>/dev/null # Limpa o lixo
                continue
            fi
            
            # Analisa com jsluice
            jsluice urls "$js_path" 2>/dev/null | jq -r '.url' | \
            grep -ivE "^http|^https|.*\.css$|.*\.png$|.*\.pdf$|.*\.svg$" | \
            sed 's#^\.*/*##' | sed "s#^#$BASE_URL/#" > "$tmpDir/rotas_temp.txt"
            
            # Mapeia origem (para o DB)
            while read -r rota; do
                echo "$url|$rota" >> "$tmpDir/source_map.txt"
            done < "$tmpDir/rotas_temp.txt"

            cat "$tmpDir/rotas_temp.txt" >> "$tmpDir/todas_rotas_all.txt" 2>/dev/null

            # ==========================================
            # CAÇA AOS SEGREDOS (TRIPLA CAMADA)
            # ==========================================
            
            # Camada 1: Grep Secrets (Nomes de variáveis do React e padrões Hardcoded diretos)
            grep -hioE "(react_app_[a-z0-9_]+|api_key|apikey|secret|token|password)\s*[:=]\s*['\"][^'\"]+['\"]" "$js_path" >> "$tmpDir/secrets_all.txt"
            
            # Camada 2: Jsluice Secrets (Análise via AST)
            # Extraímos em formato JSONL, pegamos apenas onde há um 'match' e montamos o formato "[tipo] segredo"
            jsluice secrets "$js_path" 2>/dev/null | jq -r 'select(has("match")) | "[\(.kind)] \(.match)"' >> "$tmpDir/secrets_all.txt"

            # Camada 3: SecretFinder (Expressões regulares de alta entropia)
            # O SecretFinder cospe um banner e as strings no formato "[+] tipo: segredo", o grep filtra só as strings!
            SecretFinder.py -i "$js_path" -o cli 2>/dev/null | grep -E "^\[\+\]" >> "$tmpDir/secrets_all.txt"
            
            # Grep Parâmetros (Alimenta wordlists do Arjun/Ferox)
            grep -hioE '["'\''][a-zA-Z0-9_-]+["'\'']\s*:\s*[{]?['\''"a-zA-Z0-9]' "$js_path" | awk -F'['\''"]' '{print $2}' >> "$tmpDir/params_all.txt"
            
        done < "$tmpDir/pendentes_round_${ROUND}.txt"

        # Prepara a próxima rodada (Pega novos arquivos JS descobertos)
        NEXT_ROUND=$((ROUND+1))
        if [ -f "$tmpDir/todas_rotas_all.txt" ]; then
            grep -i "\.js$" "$tmpDir/todas_rotas_all.txt" | sort -u > "$tmpDir/encontrados_js.txt"
            grep -vFf "$tmpDir/historico_js.txt" "$tmpDir/encontrados_js.txt" > "$tmpDir/pendentes_round_${NEXT_ROUND}.txt"
        fi
        
        ROUND=$((ROUND+1))
    done

# ==========================================
    # FASE FINAL: PROCESSAMENTO E JSON (ANTI-ARG_MAX)
    # ==========================================
    sort -u "$tmpDir/source_map.txt" -o "$tmpDir/source_map.txt" 2>/dev/null
    sort -u "$tmpDir/secrets_all.txt" -o "$tmpDir/secrets_all.txt" 2>/dev/null
    sort -u "$tmpDir/params_all.txt" -o "$nmapFolder/js_parameters.txt" 2>/dev/null # Salva para o Context Wordlist

    # Filtra as rotas para testar BOLA/Open Doors
    grep -iv "\.js$" "$tmpDir/source_map.txt" | awk -F'|' '{print $2}' | sort -u > "$tmpDir/api_endpoints.txt"
    
    echo "    ↳ Testando $(wc -l < "$tmpDir/api_endpoints.txt" 2>/dev/null || echo 0) rotas de API via HTTPx..."
    httpx -l "$tmpDir/api_endpoints.txt" -status-code -mc 200,401,403,500 -silent > "$tmpDir/httpx_status.txt" 2>/dev/null
    
    # Extrai as que deram 200 OK
    grep "\[200\]" "$tmpDir/httpx_status.txt" | awk '{print $1}' > "$tmpDir/200_ok.txt" 2>/dev/null

    # Garante que os arquivos existam para o jq não quebrar
    touch "$tmpDir/source_map.txt" "$tmpDir/secrets_all.txt" "$tmpDir/200_ok.txt"

    # Converte os arquivos de texto para Arrays JSON independentes em disco (Resolve o "Argument list too long")
    jq -R -s 'split("\n") | map(select(length > 0))' "$tmpDir/source_map.txt" > "$tmpDir/json_routes.json"
    jq -R -s 'split("\n") | map(select(length > 0))' "$tmpDir/secrets_all.txt" > "$tmpDir/json_secrets.json"
    jq -R -s 'split("\n") | map(select(length > 0))' "$tmpDir/200_ok.txt" > "$tmpDir/json_broken.json"

    # MONTAGEM DO JSON: Lê os arrays do disco usando --slurpfile em vez de carregar em memória via bash
    jq -n \
      --arg target "$targetName" \
      --slurpfile routes "$tmpDir/json_routes.json" \
      --slurpfile secrets "$tmpDir/json_secrets.json" \
      --slurpfile open_apis "$tmpDir/json_broken.json" \
      '{
         target: $target, 
         js_discoveries: ($routes[0] // []), 
         secrets: ($secrets[0] // []), 
         broken_access: ($open_apis[0] // [])
      }' \
      > "$outputFile"

    echo "[✓] Resultados JSON gerados em: $outputFile"
    rm -rf "$tmpDir"
done