#!/bin/bash

source ~/colorCodes.sh

cat <<Banner
${CYAN}
███╗   ██╗██╗    ██╗██████╗  █████╗ ██████╗ ██████╗ ███████╗██████╗    ███████╗██╗  ██╗${NC}
████╗  ██║██║    ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗   ██╔════╝██║  ██║
██╔██╗ ██║██║ █╗ ██║██████╔╝███████║██████╔╝██████╔╝█████╗  ██████╔╝   ███████╗███████║
██║╚██╗██║██║███╗██║██╔══██╗██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗   ╚════██║██╔══██║
██║ ╚████║╚███╔███╔╝██║  ██║██║  ██║██║     ██║     ███████╗██║  ██║██╗███████║██║  ██║
╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝══╝╚══════╝╚═╝  ╚═╝

${BLUE}                       ⚡ NWRAPPER.SH  ⚡
        🔍  A nmap wrapper created by Rafael Luís da Silva  🚀${NC}

Banner

show_help() {
    cat <<EOF
Uso: $0 [opções] <alvo>

Opções:
  -h, --help           Mostra esta ajuda e sai
  -f <arquivo>         Arquivo contendo uma lista de alvos (um por linha)
  -t <alvos>           Lista de alvos separados por vírgula
                       Exemplo: -t 192.168.0.1,scanme.nmap.org

Sem opções, o script roda normalmente com um único alvo passado como argumento:
  $0 192.168.0.1
EOF
    exit 0
}

targets=()

# Processa parâmetros extras
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -f)
            if [[ -f "$2" ]]; then
                while IFS= read -r line; do
                    [[ -n "$line" ]] && targets+=("$line")
                done < "$2"
            else
                echo "Arquivo não encontrado: $2"
                exit 1
            fi
            shift 2
            ;;
        -t)
            IFS=' ' read -ra tmp <<< "$2"
            for t in "${tmp[@]}"; do
                targets+=("$t")
            done
            shift 2
            ;;
        -*)
            echo "Opção inválida: $1"
            show_help
            ;;
        *)
            # argumento "padrão" (alvo único, já suportado no script)
            targets+=("$1")
            shift
            ;;
    esac
done

# Se nenhum alvo foi definido, mostra ajuda
if [[ ${#targets[@]} -eq 0 ]]; then
    show_help
fi

# Loop pelos alvos, mas preservando a lógica original do script
for target in "${targets[@]}"; do
    echo -e "${BLUE}[+] Executando varredura para:${NC} $target"

    mkdir -p "nmap-${target}"

	cd nmap-${target}
	sudo nmap -PR -vv --script=whois-ip -sS --min-rate=1000 -p- ${target} -oN initial
	cat initial | grep open | cut -d "/" -f1 > openports.txt
	sudo nmap -PR -vv -O -sC -sV -p $(sed -z 's/\n/,/g;s/,$/\n/' openports.txt) ${target} -oA nmap
	rm -rf openports.txt
	cd ..
    # -------------------------------------------------------
done

for host in $(ls -lah | sed 's/ \{1,\}/ /g' | cut -d " " -f 10 | grep nmap);do httpx -p $(cat $host/nmap.nmap | grep tcp | cut -d "/" -f1 | tr ' ' -d | sed -z 's/\n/,/g;s/,$//g') -title -tech-detect -status-code -probe -ip -ss -o $host/httpx;done
