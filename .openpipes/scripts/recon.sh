#!/bin/bash

source "$HOME/colorCodes.sh"
source "$HOME/.openpipes/config.sh"
wordlist="$HOME/.openpipes/.templates/names.txt"

cat <<Banner
${CYAN}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗   ███████╗██╗  ██╗${NC}
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║   ██╔════╝██║  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║   ███████╗███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║   ╚════██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╗███████║██║  ██║
╚═╝  ╚═╝ ══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝══╝╚══════╝╚═╝  ╚═╝
                                                              
${BLUE}                     🔍  Domain & Subdomain Recon
                                 DNS • HTTPX • RDAP • Amass${NC}
                                       by Rafael Luis da Silva

Banner

# ==============================
# Função de ajuda
# ==============================
show_help() {
  echo -e "${YELLOW}Uso:${NC} $0 [opções]"
  echo
  echo "Opções:"
  echo "  -d, --domain-file <arquivo>   Especifica o arquivo contendo domínios (um por linha)."
  echo "  -h, --help                    Mostra esta ajuda."
  echo
  echo -e "⚠️ ${RED} Avoid listing subdomains as it will significantly reduce the attack surface.${NC}"
  echo
  exit 0
}

# ==============================
# Parsing dos argumentos
# ==============================
DOMAIN_FILE="$(pwd)/domains.txt"

if [[ $# -eq 0 ]]; then
  if [[ ! -f "$DOMAIN_FILE" ]]; then
    show_help
  fi
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain-file)
        shift
        DOMAIN_FILE="$(pwd)/$1"
        ;;
      -h|--help)
        show_help
        ;;
      *)
        echo -e "${RED}[!] Opção desconhecida:${NC} $1"
        show_help
        ;;
    esac
    shift
  done
fi

# ==============================
# Valida se o arquivo existe
# ==============================
if [[ ! -f "$DOMAIN_FILE" ]]; then
  echo -e "${RED}[!] Arquivo de domínios não encontrado:${NC} $DOMAIN_FILE"
  exit 1
fi

echo -e "${GREEN}[+] Usando lista de domínios:${NC} $DOMAIN_FILE"
echo -e "${YELLOW}⚠️  Avoid listing subdomains as it will significantly reduce the attack surface.${NC}"

mkdir -p Recon
for domain in $(cat $DOMAIN_FILE); do
  cd Recon
  mkdir $domain
  rdap $domain > $domain/$domain-rdap.txt
  for ip in $(host $domain | grep "has address" | cut -d " " -f4); do
    rdap $ip > $domain/$ip-rdap.txt
  done
  host -t txt $domain >> DNS-txt-all_domains; echo "" >> DNS-txt-all_domains
  host -t txt _dmarc.$domain >> DMARC-all_domains; echo "" >> DMARC-all_domains
  dnsrecon -d $domain -ak --threads 16 | tee $domain/$domain-dnsrecon
  dnsrecon -d $domain -D $wordlist --threads 16 -t brt | tee $domain/$domain-subbrute
  cat $domain/$domain-subbrute | grep "A " | cut -d " " -f4 > $domain/$domain-subbrute.txt
  curl "https://api.securitytrails.com/v1/domain/$domain/subdomains" -H "apikey: $securitytrailskey" | jq | tail -n +8 | head -n -2 | cut -d "\"" -f2 | sed "s/$/.$domain/g" > $domain/$domain-securitytrails
  amass enum --passive -d $domain -o $domain/$domain-amass
  cat $domain/$domain-amass $domain/$domain-subbrute.txt $domain/$domain-securitytrails | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | sort -u > $domain/allsubs
  for sub in $(cat $domain/allsubs); do
    host $sub | tee -a $domain/hosts-allsubs
    host -t cname $sub | tee -a $domain/cname-allsubs
  done
  httpx -l $domain/allsubs -p 80,443,4443,8080,8000,10443,8443 -title -tech-detect -status-code -probe -ip -json -o $domain/allsubs.httpx.json
  httpx -l $domain/allsubs -p 80,443,4443,8080,8000,10443,8443 -title -tech-detect -status-code -probe -ip -o $domain/allsubs.httpx
  cat $domain/hosts-allsubs | egrep "has address" | grep "$domain" | cut -d " " -f4 | sort -u > valid-subs.txt
  for ip in $(cat valid-subs.txt); do
    rdap $ip > $ip.rdap
    owner=$(cat $ip.rdap | grep "vCard fn" | head -n1 | cut -d ":" -f2 | xargs)
    echo "$ip => $owner" >> valid-subs.rdap
  done
  cd ..
done

mkdir -p Varreduras
cat Recon/*/hosts-allsubs | grep "has address" | cut -d " " -f1,4 | egrep "$(cat $DOMAIN_FILE | sed -z 's/\n/|/g' | sed 's/.$//g')" | sed -z 's/ /\n/g' | sort -u > Varreduras/targets.txt
