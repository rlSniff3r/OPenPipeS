#!/bin/bash

# Carrega Cores
source ~/colorCodes.sh

# Banner
cat <<Banner

${HI_RED}
██╗   ██╗ █████╗ ████████╗ █████╗ ███╗   ██╗ █████╗ ${NC}      ⠀⠀${HI_BLACK}⠀⠀⢠⣶⡄    ${NC}
██║  ██╔╝██╔══██╗╚══██╔══╝██╔══██╗████╗  ██║██╔══██╗⠀⠀⠀⠀ ⠀⠀${HI_BLACK}⠀⠀⣠⡿⣿⡃   ${NC}
██████╔╝ ███████║   ██║   ███████║██╔██╗ ██║███████║⠀⠀⠀⠀ ⠀${HI_BLACK}⠀⠀⣰⢿⣻⠇⠀  ${NC}
██╔══██╗ ██╔══██║   ██║   ██╔══██║██║╚██╗██║██╔══██║⠀⠀⠀⠀ ${HI_BLACK}⠀⠀⣰⣿⣿⠋⠀⠀ ${NC}
██║   ██╗██║  ██║   ██║   ██║  ██║██║ ╚████║██║  ██║⠀ ⠀${HI_BLACK}⠀⠀⣤⣶⣳⡽⠇⠀⠀⠀${NC}
╚═╝   ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ⠀${HI_BLACK}⠀⢀⠏⢻⣿⡇⠀⠀⠀⠀${NC}
                                                   ⠀⠀⠀⡰${HI_RED}⠃⡴${HI_BLACK}⠋⠉⠁⠀⠀⠀⠀${NC}
${RED}  ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗    ███████╗██╗  ██╗${NC}
        ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗   ██╔════╝██║  ██║
        ██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝   ███████╗███████║
        ██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗   ╚════██║██╔══██║
        ██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║██╗███████║██║  ██║
        ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝
    ⠀                             ⠀⠀⠀⠀⠀⠀⣠⠞${HI_RED}⣡⡾⠋⠀⠀⠀⠀⠀⠀${NC}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
         Made for OPenPipeS      ⠀⠀⠀⠀⠀⡠⢊${HI_RED}⣠⠞⠉⠀⠀⠀${NC}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
         ${RED}꒷꒦${HI_RED}꒷꒦꒷${RED}꒦꒷${HI_RED}꒦꒷        ⠠⠶⠥⠾⠋⠀${NC}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ${RED}                    🩸                         Created by
                🩸
                         🩸                              ${HI_BLACK}🥷${HI_RED}⚔️⠀${HI_BLACK}rlSniff3r${NC}
        ${HI_RED}   🩸
                     🩸
Banner

# ─────────────────────────────────────────────────────────────
# katana-buster.sh v1.0 (modificado)
# Executa Feroxbuster + Katana paralelamente em URLs construídas
# Gera arquivos integrados ao Obsidian: endpoints.md, ferox-katana.md etc.
# Adicionado: --dns-only e --ip-only
# ─────────────────────────────────────────────────────────────

# === PARSING SIMPLES DE FLAGS ===
DNS_ONLY=
IP_ONLY=

# Remover flags conhecidas dos parâmetros, deixando apenas alvos (se houver)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dns-only)
      DNS_ONLY=1
      shift
      ;;
    --ip-only)
      IP_ONLY=1
      shift
      ;;
    --) # fim dos options
      shift
      break
      ;;
    -*)
      # Não reconhece outras flags aqui — deixe para o resto do script (ou trate como alvo)
      break
      ;;
    *)
      # primeiro parâmetro não-flag: para a fase de parsing
      break
      ;;
  esac
done

# === CONFIGURAÇÃO GLOBAL ===
source $HOME/.openpipes/config.sh

cd $base_dir

# Carregar configuração centralizada
if [ -f "$OPENPIPES_CONFIG" ]; then
    source "$OPENPIPES_CONFIG"
fi

# Paralelismo (usa PARALLEL_KATANA do config, fallback 3)
threads=${PARALLEL_KATANA:-3}

wordlist="/usr/share/wordlists/dirb/big-parsed.txt"
web_ports_whitelist=(80 81 82 83 84 85 88 89 90 98 99 443 591 593 8000 8001 8008 8010 8080 8081 8082 8088 8180 8181 8222 8280 8281 8443 8500 8501 8530 8531 8800 8880 8888 9000 9080 9443 9800 9981 10000 11371 12443 16080 18080 20000 2443 3000 3001)

# === FUNÇÕES AUXILIARES ===
is_web_port() {
  local porta=$1
  for p in "${web_ports_whitelist[@]}"; do
    [[ "$porta" == "$p" ]] && return 0
  done
  return 1
}

get_http_ports_from_nmap_nmap() {
  local nmap_file="$1"
  grep -E '(http|https|ssl/http|http-proxy|httpd)' "$nmap_file" | grep '/tcp' | cut -d '/' -f1
}

# === FUNÇÃO PRINCIPAL PARA CADA ALVO ===
process_target() {
  targetdir="$1"
  targetName=${dir#nmap-}
#  ip=$(grep "Nmap scan report for" "$dir/nmap.nmap" | head -n1 | cut -d "(" -f2 | cut -d ")" -f1)
  ip=$(grep "Nmap scan report for" $dir/initial | sed 's/Nmap scan report for //g' |cut -d "(" -f2 | cut -d ")" -f1 | cut -d ":" -f2) 
  dns=$(echo $targetName)
  httpx_json="../Recon/${targetName}/allsubs.httpx.json"
  nmap_nmap_file="$targetdir/nmap.nmap" # [MODIFICADO]

  echo -e "${blue}[*] Processando $targetName ($ip)${nc}"
  echo "" > urls.txt

  # === 1. URLs válidas do httpx.json ===
  if [ -f "$httpx_json" ]; then
    jq -r '.[] | select(.url != null) | .url' "$httpx_json" >> urls.txt
  else
    echo -e "${yellow}[!] httpx.json ausente para $targetName – continuando com fallback.${nc}"
  fi

  # === 2. Coleta portas HTTP a partir do nmap.nmap === [MODIFICADO]
  if [[ -f "$nmap_nmap_file" ]]; then
    http_ports=($(get_http_ports_from_nmap_nmap "$nmap_nmap_file"))
  else
    http_ports=()
  fi

  # === 3. Fallback: aplica whitelist nas portas abertas (caso não tenha detectado nenhuma HTTP) === [MODIFICADO]
  if [[ ${#http_ports[@]} -eq 0 ]]; then
    ports_fallback=($(grep "$ip" "$targetdir/nmap.gnmap" | grep -oP '\d+/open' | cut -d/ -f1 | sort -n | uniq | while read -r port; do
      is_web_port "$port" && echo "$port"
    done))
  else
    ports_fallback=()
  fi

  # === 4. Construção manual de URLs === [MODIFICADO]
  # Determina se vamos incluir IPs e/ou DNS baseando-se nas flags globais
  include_ip=true
  include_dns=true
  if [[ -n "$DNS_ONLY" ]]; then
    include_ip=false
    include_dns=true
  fi
  if [[ -n "$IP_ONLY" ]]; then
    include_ip=true
    include_dns=false
  fi

  for port in "${http_ports[@]}" "${ports_fallback[@]}"; do
    if [[ "$port" == "80" ]]; then
      $include_ip && echo "http://$ip" >> urls.txt
      $include_dns && [[ -n "$dns" ]] && echo "http://$dns" >> urls.txt
    elif [[ "$port" == "443" ]]; then
      $include_ip && echo "https://$ip" >> urls.txt
      $include_dns && [[ -n "$dns" ]] && echo "https://$dns" >> urls.txt
    else
      $include_ip && echo "http://$ip:$port" >> urls.txt
      $include_ip && echo "https://$ip:$port" >> urls.txt
      $include_dns && [[ -n "$dns" ]] && {
        echo "http://$dns:$port" >> urls.txt
        echo "https://$dns:$port" >> urls.txt
      }
    fi
  done

  # [restante do seu código continua igual...]



  echo "Total de URLs a serem testadas:"
  cat urls.txt | sort -u > urls.tmp
  cat urls.tmp > urls.txt
  cat urls.txt

  echo -e "${BLUE}[*] Processando $targetName ($ip)${NC}"

  # === Diretório destino no Obsidian ===
  outdir=$obsdir/Pentest/Alvos/$targetName
  mkdir -p "$outdir"

  # === Deduplicar e salvar lista final ===
  cat urls.txt | sort -u > urls_unique.txt

  # === Arquivos temporários ===
#  tmp_ferox=$(mktemp)
#  tmp_katana=$(mktemp)
  endpoints_file=$outdir/endpoints.md

# Validar GNU Parallel
  if ! command -v parallel &> /dev/null; then
      echo -e "${RED}[!] GNU Parallel não encontrado${NC}"
      echo -e "${YELLOW}[*] Instale com: sudo apt install parallel${NC}"
      exit 1
  fi

  echo "" > tmp_ferox
  echo "" > tmp_katana

  echo -e "${GREEN}[+] Iniciando Feroxbuster ($targetName)${NC}"
  cat urls_unique.txt | \
    parallel -j "$threads" --line-buffer 'feroxbuster -u {} -w "'"$wordlist"'" -q -n' >> tmp_ferox 2>/dev/null

  echo -e "${green}[+] Iniciando Katana ($targetName)${nc}"
  cat urls_unique.txt | \
    parallel -j "$threads" --line-buffer 'katana -u {} -silent' >> tmp_katana 2>/dev/null

  # === Salvar arquivos ===
  echo "Total de Endpoints encontrados:"

  cat tmp_ferox | sed -z 's/http/\nhttp/g' | grep http | cut -d "," -f1 | cut -d ")" -f1 | sort -u
  cat tmp_ferox | sed -z 's/http/\nhttp/g' | grep http | cut -d "," -f1 | cut -d ")" -f1 | sort -u >> $targetdir/feroxbuster.md

  cat tmp_katana | sed -z 's/http/\nhttp/g' | grep http | cut -d "," -f1 | cut -d ")" -f1 | sort -u
  cat tmp_katana | sed -z 's/http/\nhttp/g' | grep http | cut -d "," -f1 | cut -d ")" -f1 | sort -u >> $targetdir/katana.md


  sort -u tmp_ferox > $outdir/feroxbuster.md
  sort -u tmp_katana > $outdir/katana.md

  # === Gerar endpoints.md ===
#  cat "$outdir/feroxbuster.txt" "$outdir/katana.txt" | \
#    grep -Eo 'https?://[^ ]+' | sort -u > "$endpoints_file"
#  cat $outdir/feroxbuster.txt $outdir/katana.txt
#  cat $outdir/feroxbuster.txt >> $endpoints_file
#  cat $outdir/katana.txt >> $endpoints_file

  # === Gerar ferox-katana.md ===
  {
    echo "# 🔍 Feroxbuster + Katana Summary - $targetName"
    echo ""
    echo "## 🌐 Feroxbuster URLs"
    echo '```'
    cat $targetdir/feroxbuster.md
    echo '```'
    echo ""
    echo "## 🕸 Katana URLs"
    echo '```'
    cat $targetdir/katana.md
    echo '```'
  } > $targetdir/ferox-katana.md

  cat $targetdir/ferox-katana.md | grep http | sed -z 's/http/\nhttp/g' | grep http | cut -d " " -f1 | sed 's-/$--g' | sort -u >> $endpoints_file
  cat $endpoints_file | sed 's-/$--g' | sort -u > ep_tmp
  cat ep_tmp > $endpoints_file
  cp $targetdir/ferox-katana.md $obsdir/Pentest/Alvos/$targetName/


  echo -e "${GREEN}[✓] Finalizado: $targetName${nc}"
}

# === LOOP PRINCIPAL EM CADA ALVO (nmap-*) ===
echo -e "${BLUE}==> Iniciando katana-buster.sh${NC}"

if [[ $# -eq 0 ]]; then
  # Sem argumentos: processa todos os nmap-*
  find . -maxdepth 1 -type d -name 'nmap-*' | sort | cut -d "/" -f2 | while read -r dir; do
    process_target "$dir"
  done
else
  # Com argumentos: processa somente os alvos passados
  for alvo in "$@"; do
    dir="nmap-$alvo"
    if [[ -d "$dir" ]]; then
      process_target "$dir"
    else
      echo -e "${RED}[!] Diretório não encontrado para alvo: $alvo (${dir})${NC}"
    fi
  done
fi

echo -e "${GREEN}[✔] Todos os alvos processados.${NC}"
