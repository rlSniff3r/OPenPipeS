#!/usr/bin/env bash
set -euo pipefail

# Carregar configurações globais e segredos
source ~/.openpipes/config.sh

# --- Validações ---
if [[ -z "${TARGETS_DIR:-}" ]] || [[ -z "${NMAP_DIR:-}" ]] || [[ -z "${tpdir:-}" ]]; then
    echo "[ERRO] Variáveis de diretório não definidas no config.sh."
    exit 1
fi

if [[ ! -d "$NMAP_DIR" ]]; then
    echo "[ERRO] Diretório de varreduras não encontrado: $NMAP_DIR"
    exit 1
fi

TEMPLATES_DIR="$tpdir"
ALVOS_DIR="$TARGETS_DIR"
FORCE_UPDATE_ALL="false" # Variável de controle para o modo "All"

# --- Funções Auxiliares ---

# Função para aplicar o template e fazer os replaces
# Uso: aplicar_template_alvo "caminho_destino" "nome_alvo" "ip_alvo"
aplicar_template_alvo() {
    local dest="$1"
    local t_name="$2"
    local t_ip="$3"
    
    if [[ -f "$TEMPLATES_DIR/target.stub.md" ]]; then
        cp "$TEMPLATES_DIR/target.stub.md" "$dest"
        # Usando pipe | como delimitador para aceitar N/A e caminhos
        sed -i "s|{{targetName}}|$t_name|g" "$dest"
        sed -i "s|{{ip}}|$t_ip|g" "$dest"
        sed -i "s|{{proj_name}}|$proj_name|g" "$dest"
        sed -i "s|{{date}}|$(date +%Y-%m-%d)|g" "$dest"
        return 0
    else
        echo "[ERRO] Template target.stub.md sumiu!"
        return 1
    fi
}

echo -e "\033[0;34m[OPenPipeS] Gerador de Alvos v2.4 (Batch Mode)\033[0m"
echo -e "\033[0;33m[+] Lendo scans em: $NMAP_DIR\033[0m"

# Encontrar arquivos .nmap
mapfile -t nmap_files < <(find "$NMAP_DIR" -type f -name "*.nmap" 2>/dev/null)

if [[ ${#nmap_files[@]} -eq 0 ]]; then
    echo "[ERRO] Nenhum arquivo .nmap encontrado."
    exit 1
fi

# Loop principal por alvo
for nmap_file in "${nmap_files[@]}"; do
    # Extrair metadados
    target_dir=$(dirname "$nmap_file")
    targetName=$(basename "$target_dir" | sed 's/^nmap-//')
    
    # Fallback de nome
    if [[ "$targetName" == "initial" ]] || [[ "$targetName" == "Scans" ]]; then
        targetName=$(basename "$nmap_file" .nmap)
    fi

    # Extrair IP
    ip=$(grep -oP 'Nmap scan report for .* \(\K[0-9.]+(?=\))' "$nmap_file" | head -n1 || echo "")
    if [[ -z "$ip" ]]; then
        ip=$(grep -oP 'Nmap scan report for \K[0-9.]+' "$nmap_file" | head -n1 || echo "N/A")
    fi

    echo -e "\033[0;36m\n[>] Processando: $targetName ($ip)\033[0m"

    # Preparar diretórios
    CURRENT_TARGET_DIR="$ALVOS_DIR/$targetName"
    BACKUP_DIR="$CURRENT_TARGET_DIR/_Backups"
    mkdir -p "$CURRENT_TARGET_DIR/Vulnerabilidades"
    
    TARGET_NOTE="$CURRENT_TARGET_DIR/${targetName}.md"

    # ---------------------------------------------------------
    # 1. NOTA PRINCIPAL (Lógica Update/All/Skip)
    # ---------------------------------------------------------
    if [[ -f "$TARGET_NOTE" ]]; then
        echo -e "\033[0;33m    [!] Nota '$targetName.md' já existe.\033[0m"
        
        # Define a escolha baseada no estado anterior ou pergunta
        if [[ "$FORCE_UPDATE_ALL" == "true" ]]; then
            choice="y"
            # Feedback visual minimalista para saber que está automático
            echo -e "\033[0;35m        [AUTO] Atualizando automaticamente (Modo All)...\033[0m"
        else
            # Pergunta interativa: y (Sim), n (Não), a (Todos)
            read -t 10 -p "        Atualizar (com backup)? [y/N/a]: " input_choice || input_choice="n"
            echo "" 

            # Processar input especial 'a'
            if [[ "$input_choice" =~ ^[Aa]$ ]]; then
                FORCE_UPDATE_ALL="true"
                choice="y"
                echo -e "\033[0;36m        [!] Opção 'Todos' selecionada. Sem mais perguntas!\033[0m"
            else
                choice="$input_choice"
            fi
        fi

        # Executar ação baseada na escolha final
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            mkdir -p "$BACKUP_DIR"
            TIMESTAMP=$(date +%Y%m%d_%H%M%S)
            BKP_FILE="$BACKUP_DIR/${targetName}_bkp_$TIMESTAMP.md"
            
            cp "$TARGET_NOTE" "$BKP_FILE"
            echo -e "\033[0;35m        [BKP] Backup salvo em: _Backups/$(basename "$BKP_FILE")\033[0m"
            
            aplicar_template_alvo "$TARGET_NOTE" "$targetName" "$ip"
            echo -e "\033[0;32m        [OK] Nota atualizada com novo template.\033[0m"
        else
            echo -e "\033[0;37m        [SKIP] Mantendo arquivo original.\033[0m"
        fi
    else
        aplicar_template_alvo "$TARGET_NOTE" "$targetName" "$ip"
        echo -e "\033[0;32m    [+] Nota principal criada.\033[0m"
    fi

    # ---------------------------------------------------------
    # 2. DASHBOARD (Sempre atualiza)
    # ---------------------------------------------------------
    DASHBOARD_NOTE="$CURRENT_TARGET_DIR/Dashboard_${targetName}.md"
    if [[ -f "$TEMPLATES_DIR/dashboard.stub.md" ]]; then
        cp "$TEMPLATES_DIR/dashboard.stub.md" "$DASHBOARD_NOTE"
        sed -i "s|{{targetName}}|$targetName|g" "$DASHBOARD_NOTE"
        sed -i "s|{{ip}}|$ip|g" "$DASHBOARD_NOTE"
        sed -i "s|{{proj_name}}|$proj_name|g" "$DASHBOARD_NOTE"
        sed -i "s|{{date}}|$(date +%Y-%m-%d)|g" "$DASHBOARD_NOTE"
    fi

    # ---------------------------------------------------------
    # 3. SCAN NMAP (Log Estático)
    # ---------------------------------------------------------
    if [[ ! -f "$CURRENT_TARGET_DIR/nmap.md" ]]; then
        cat > "$CURRENT_TARGET_DIR/nmap.md" <<EOF
---
type: scan
scan_type: nmap
target: $targetName
ip: $ip
date: $(date +%Y-%m-%d)
tags: [scan, nmap]
---
# Nmap Scan - $targetName
> IP: $ip
> Data: $(date +%Y-%m-%d)

## Resultados
\`\`\`nmap
$(cat "$nmap_file")
\`\`\`

[[Dashboard_${targetName}|Voltar ao Dashboard]]
EOF
    fi

    # ---------------------------------------------------------
    # 4. INDEX DE VULNS
    # ---------------------------------------------------------
    if [[ ! -f "$CURRENT_TARGET_DIR/Vulnerabilidades/_index.md" ]]; then
        if [[ -f "$TEMPLATES_DIR/vuln.stub.md" ]]; then
             cp "$TEMPLATES_DIR/vuln.stub.md" "$CURRENT_TARGET_DIR/Vulnerabilidades/_index.md"
             sed -i "s|{{targetName}}|$targetName|g" "$CURRENT_TARGET_DIR/Vulnerabilidades/_index.md"
             sed -i "s|{{proj_name}}|$proj_name|g" "$CURRENT_TARGET_DIR/Vulnerabilidades/_index.md"
             sed -i "s|{{date}}|$(date +%Y-%m-%d)|g" "$CURRENT_TARGET_DIR/Vulnerabilidades/_index.md"
        fi
    fi

done

echo -e "\033[0;32m\n[✓] Processamento concluído.\033[0m"
