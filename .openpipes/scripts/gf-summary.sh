#!/bin/bash
# === CONFIG ===
source $HOME/.openpipes/config.sh
gf_dir="$HOME/.openpipes/.gf"
gf_filters=(xss sqli lfi rce idor redirect debug_logic interestingparams)
exts=("php" "json" "js" "bak" "zip" "env" "txt" "log" "conf")

# === VERIFICA DEPENDÊNCIAS ===
for bin in gf awk grep cut sort uniq sed jq; do
    if ! command -v "$bin" &>/dev/null; then
        echo "[!] Dependência ausente: $bin"
        exit 1
    fi
done

# === LOOP EM TODOS OS ALVOS ===
for nmap_folder in "$NMAP_DIR"/nmap-*; do
    [[ ! -d "$nmap_folder" ]] && continue
    target_name="${nmap_folder##*/nmap-}"

    # Novo padrão OPenPipeS: Lê diretamente do feeder (Single Source of Truth)
    seed_file="$nmap_folder/gf_urls.txt"
    if [ ! -s "$seed_file" ]; then
        echo "[!] Nenhuma URL alimentada (gf_urls.txt) para $target_name. Pulando..."
        continue
    fi

    echo "[*] Processando GF para $target_name..."
    tmpDir="/tmp/gf-$target_name"
    mkdir -p "$tmpDir"

    # === Agrupamento por extensão (Anti-ARG_MAX) ===
    echo "{}" > "$tmpDir/ext_data.json"
    for ext in "${exts[@]}"; do
        count=$(grep -cEi "\.${ext}(\?|$|/)" "$seed_file" || true)
        if [ "$count" -gt 0 ]; then
            # Injeta e salva no arquivo pra não estourar a memória
            jq --arg ext "$ext" --argjson cnt "$count" '. + {($ext): $cnt}' "$tmpDir/ext_data.json" > "$tmpDir/ext_data_tmp.json"
            mv "$tmpDir/ext_data_tmp.json" "$tmpDir/ext_data.json"
        fi
    done

    # === Filtros GF (Anti-ARG_MAX via Slurpfile) ===
    echo "{}" > "$tmpDir/gf_data.json"
    for filter in "${gf_filters[@]}"; do
        cat "$seed_file" | gf "$filter" | sort -u > "$tmpDir/${filter}.txt"
        
        # Só converte pra JSON se achou algo (economiza I/O e deixa o JSON limpo)
        if [ -s "$tmpDir/${filter}.txt" ]; then
            jq -R -s 'split("\n") | map(select(length > 0))' "$tmpDir/${filter}.txt" > "$tmpDir/${filter}.json"
            
            # Slurpfile pra dentro do objeto gf_data
            jq --arg f "$filter" --slurpfile m "$tmpDir/${filter}.json" '. + {($f): ($m[0] // [])}' "$tmpDir/gf_data.json" > "$tmpDir/gf_data_tmp.json"
            mv "$tmpDir/gf_data_tmp.json" "$tmpDir/gf_data.json"
        fi
    done

    # === Arquivos sensíveis ===
    grep -iE '\.(bak|zip|env|conf|log|sql|tar|gz|rar)(\?|$|/)' "$seed_file" | sort -u > "$tmpDir/sensitive.txt" || true
    jq -R -s 'split("\n") | map(select(length > 0))' "$tmpDir/sensitive.txt" > "$tmpDir/sensitive.json"

    # === Output: JSON Final ===
    json_output="$nmap_folder/gf-summary.json"
    jq -n \
        --arg target "$target_name" \
        --slurpfile exts "$tmpDir/ext_data.json" \
        --slurpfile gf "$tmpDir/gf_data.json" \
        --slurpfile sensitive "$tmpDir/sensitive.json" \
        '{target: $target, generated_at: now, extension_summary: ($exts[0] // {}), gf_patterns: ($gf[0] // {}), sensitive_files: ($sensitive[0] // [])}' \
        > "$json_output"

    echo "[✔] gf-summary.json gerado para: $target_name → $json_output"
    rm -rf "$tmpDir"
done

# GF-Summary terminou o scan. Antes de dar o exit 0 pro Python, vamos ver se a internet está viva:
if ! ping -c 2 8.8.8.8 &> /dev/null; then
    echo "[!] AVISO: Queda de conexão detectada durante ou após o scan!"
    exit 1  # Força o erro! O Python NÃO vai rodar o parser!
fi

exit 0 # Tudo certo, o Python pode marcar as URLs como lidas!