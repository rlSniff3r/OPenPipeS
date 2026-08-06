#!/bin/bash
source $HOME/.openpipes/config.sh

echo -e "\n\e[34m[+]\e[0m Iniciando varredura Nuclei (tech/port-aware)..."

for dir in "$NMAP_DIR"/nmap-*; do
    [[ ! -d "$dir" ]] && continue
    target_name="${dir##*/nmap-}"
    input_file="$dir/nuclei_urls.txt"

    if [[ ! -s "$input_file" ]]; then
        echo "[SKIP] $target_name: nuclei_urls.txt vazio ou ausente."
        continue
    fi

    echo "[*] Processando: $target_name"

    # ── PASS 1: genérico (base + tech, sem CVE) ──
    TAGS=$(cat "$dir/nuclei_tags.txt" 2>/dev/null || \
           echo "misconfig,exposure,default-login,takeover,panel,auth-bypass")
    if nuclei -l "$input_file" \
        -tags "$TAGS" \
        -pt http \
        -severity low,medium,high,critical \
        -et "fuzz" \
        -timeout 5 -retries 1 \
        -je "$dir/nuclei_pass1.json"; then
        echo "  [✔] pass 1 OK ($(wc -c < "$dir/nuclei_pass1.json" 2>/dev/null || echo 0) bytes)"
    else
        echo "  [✖] pass 1 FALHOU (exit $?)"
    fi

    # ── PASS 2: CVEs apenas para techs detectadas (AND via -tc) ──
    if [[ -s "$dir/nuclei_techs.txt" ]]; then
        TECHS=$(cat "$dir/nuclei_techs.txt")
        IFS=',' read -ra TECH_ARRAY <<< "$TECHS"

        # Build: contains(tags,"a") || contains(tags,"b") || ...
        TECH_COND=""
        for tech in "${TECH_ARRAY[@]}"; do
            [[ -z "$tech" ]] && continue
            if [[ -n "$TECH_COND" ]]; then
                TECH_COND+=" || "
            fi
            TECH_COND+="contains(tags,\"$tech\")"
        done

        if [[ -n "$TECH_COND" ]]; then
            echo "  [*] pass 2 (CVE): contains(tags,\"cve\") && ($TECH_COND)"
            if nuclei -l "$input_file" \
                -tc "contains(tags,\"cve\") && ($TECH_COND)" \
                -pt http \
                -severity low,medium,high,critical \
                -timeout 5 -retries 1 \
                -je "$dir/nuclei_pass2.json"; then
                echo "  [✔] pass 2 OK ($(wc -c < "$dir/nuclei_pass2.json" 2>/dev/null || echo 0) bytes)"
            else
                echo "  [✖] pass 2 FALHOU (exit $?)"
            fi
        fi
    else
        echo "  [*] pass 2 pulado (sem techs detectadas)"
    fi
done

echo -e "\e[32m[✔]\e[0m nuclei-runner concluído."
