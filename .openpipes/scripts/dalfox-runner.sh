#!/bin/bash
source ~/.openpipes/config.sh

# ========================================================
# MAGIA NINJA: CONVERTER ARGS CUSTOMIZADOS PARA ARRAY
# ========================================================
extra_args=()
if [[ -n "${OP_TOOL_ARGS:-}" ]]; then
    eval "extra_args=($OP_TOOL_ARGS)"
fi
# ========================================================

echo -e "\n\e[34m[+]\e[0m Iniciando varredura XSS com Dalfox (Remote Payloads + Deep DOM)..."

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

for d in "$NMAP_DIR"/nmap-*/; do
    [ -d "$d" ] || continue
    
    target_name=$(basename "$d" | sed 's/nmap-//')

    # === FILTRO OP_TARGETS ===
    if [[ -n "${OP_TARGETS:-}" ]]; then
        # Verifica se o target atual está na lista separada por vírgulas
        if ! echo "$OP_TARGETS" | tr ',' '\n' | grep -Fqx "$target_name"; then
            continue # Pula se não estiver na lista!
        fi
        echo "[*] Alvo restrito acionado para: $target_name"
    fi
    # ==========================

    TARGET_FILE="${d}dalfox_targets.txt"
    OUT_FILE="${d}dalfox_output_get_${TIMESTAMP}.json" # Nome corrigido pro parser achar!

    if [ -s "$TARGET_FILE" ]; then
        echo "  → (GET) Analisando $target_name..."

        # Native file mode: comando 'file' para ler a wordlist
        dalfox file "$TARGET_FILE" \
            --follow-redirects \
            --stream-findings \
            --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36" \
            --ignore-return 302,403,404 \
            --workers 150 \
            --remote-payloads portswigger,payloadbox \
            --format json \
            -o "$OUT_FILE" \
            "${extra_args[@]}"
    fi

    POST_FILE="${d}dalfox_post_targets.txt"
    OUT_POST_FILE="${d}dalfox_output_post_${TIMESTAMP}.json" # Nome corrigido pro parser achar!
    
    if [ -s "$POST_FILE" ]; then
        echo "  → (POST) $target_name..."
        
        # O loop 'while' vitalício para o POST
        while IFS='|' read -r url data; do
            [ -z "$url" ] && continue
            
            # Comando 'url' para um alvo específico
            dalfox url "$url" \
                --data "$data" \
                --workers 30 \
                --remote-payloads portswigger,payloadbox \
                --format json \
                -o "$OUT_POST_FILE" \
                "${extra_args[@]}"
        done < "$POST_FILE"
    fi
done

echo -e "\e[32m[✔]\e[0m Dalfox finalizado."

# Dalfox terminou o scan. Antes de dar o exit 0 pro Python, vamos ver se a internet está viva:
if ! ping -c 2 8.8.8.8 &> /dev/null; then
    echo "[!] AVISO: Queda de conexão detectada durante ou após o scan!"
    exit 1  # Força o erro! O Python NÃO vai rodar o parser!
fi

exit 0 # Tudo certo, o Python pode marcar as URLs como lidas!