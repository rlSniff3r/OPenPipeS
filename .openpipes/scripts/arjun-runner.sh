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

echo -e "\n\e[34m[+]\e[0m Iniciando descoberta de parâmetros ocultos com Arjun..."

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

    TARGET_FILE="${d}arjun_targets.txt"
    OUT_FILE="${d}arjun_output_${TIMESTAMP}.json"
    
    # === INTEGRAÇÃO COM MEGAZORD ===
    # Pega a wordlist customizada do host se ela existir
    CONTEXT_WL="${d}context_wordlist.txt"
    wl_param=()
    if [ -s "$CONTEXT_WL" ]; then
        wl_param=(-w "$CONTEXT_WL")
        echo "  → Usando Wordlist Contextual do Megazord!"
    fi
    # ===============================

    if [ -s "$TARGET_FILE" ]; then
        echo "  → Analisando $target_name..."
        arjun -i "$TARGET_FILE" \
            -t 10 \
            --passive wayback,commoncrawl,otx \
            -m GET,POST \
            "${wl_param[@]}" \
            -oJ "$OUT_FILE" \
            "${extra_args[@]}"
    fi
done

echo -e "\e[32m[✔]\e[0m Arjun finalizado."

# Arjun terminou o scan. Antes de dar o exit 0 pro Python, vamos ver se a internet está viva:
if ! ping -c 2 8.8.8.8 &> /dev/null; then
    echo "[!] AVISO: Queda de conexão detectada durante ou após o scan!"
    exit 1  # Força o erro! O Python NÃO vai rodar o parser!
fi

exit 0 # Tudo certo, o Python pode marcar as URLs como lidas!