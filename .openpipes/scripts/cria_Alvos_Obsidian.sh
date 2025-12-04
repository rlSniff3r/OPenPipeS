#!/bin/bash

# Diretórios
source "$OPENPIPES_CONFIG"
tpdir="$HOME/.openpipes/.templates/"
obsdir="$HOME/.obsidianFixedMount/"

for host in $(ls $NMAP_DIR/ | grep nmap- 2>/dev/null); do
    # Verifica se há portas abertas
    open_ports=$(grep "/tcp" "$NMAP_DIR/$host"/*.nmap | grep "open")
    if [ -z "$open_ports" ]; then
        continue
    fi

    targetName="$(echo $host | sed 's/nmap-//')"
    tgtFileName="$(echo $targetName | cut -d ' ' -f2)"
    tgtDir="$obsdir/$proj_name/Pentest/Alvos/$targetName"
    vulnDir="$tgtDir/Vulnerabilidades"

    # Cria diretórios
    mkdir -p "$vulnDir"

    # Resolve IP via DNS
    t_IP=$(echo -n "t_IP:" $(cat $RECON_DIR/$proj_name/hosts-allsubs | grep "has address" | grep "$targetName" | awk '/has address/ {print $4}' | sort -u))
#    t_IP=$(echo -n "t_IP:" $(cat $RECON_DIR/$proj_name/hosts-allsubs | grep "has address" | grep $targeName | awk '/has address/ {print $4}' | sort -u))
#    t_IP=$(echo -n "t_IP:" $(host -t a $targetName 2>/dev/null | awk '/has address/ {print $4}' | sort -u))

    # Frontmatter YAML
    tipo="Tipo: target"
    tgtName="targetName: $targetName"
    t_openPorts="t_openPorts: $(echo "$open_ports" | cut -d "/" -f1 | sed -z 's/\n/","/g' | sed -z 's/..$/]/g' | sed -z 'i["')"

    # Lista de serviços com TTL correto e versão limpa
    t_Services="t_services: $(echo "$open_ports" | awk '
    {
        split($1, port, "/");
        svc = $3;
        ttl = "N/A";
        vers = "";
        for(i=4;i<=NF;++i) {
            if ($i == "ttl" && (i+1)<=NF) {
                ttl = $(i+1);
                for(j=i+2;j<=NF;++j) vers = vers" "$(j);
                break;
            }
        }
        gsub(/^ /, "", vers);
        print port[1]" "svc" syn-ack ttl "ttl" "vers;
    }' | sed -z 's/\n/","/g' | sed -z 's/..$/]/g' | sed -z 'i["')"

    # Gera progresso baseado nas portas abertas
    progresso=$(echo "$open_ports" | cut -d "/" -f1 | sort -n | awk '{print "- [ ] Enumerar porta "$1}')

    # Criação do arquivo Markdown do alvo
    alvoFile="$tgtDir/$tgtFileName.md"
    {
        echo "---"
        echo "$tipo"
        echo "$tgtName"
        echo "$t_IP"
        echo "$t_openPorts"
        echo "$t_Services"
        echo "tags: [alvo, host]"
        echo "---"
        echo ""
        # Insere o template, mas substitui a seção de progresso
        awk -v prog="$progresso" '
            BEGIN {in_prog=0}
            /^# 🚩 Progresso/ {print; print prog; in_prog=1; next}
            in_prog && /^- / {next}
            {print}
        ' "$tpdir/target.stub.md"
    } > "$alvoFile"

    # Cria Dashboard com nome substituído
    sed "s/{{targetName}}/$targetName/g" "$tpdir/dashboard.stub.md" > "$tgtDir/Dashboard_${targetName}.md"

    # Copia stub de vulnerabilidade
    # Extrai apenas o IP do campo t_IP
    resolved_ip=$(echo "$t_IP" | awk '{print $2}')

    # Atualiza o stub de vulnerabilidade com os dados reais
    sed -e "s/^targetName:.*/targetName: $targetName/" \
        -e "s/^t_IP:.*/t_IP: $resolved_ip/" \
        "$tpdir/vuln.stub.md" > "$vulnDir/VULN_$targetName.stub.md"

    # Copia o nmap.nmap para a pasta do Alvo e transforma em sintaxe MD
    cp $NMAP_DIR/$host/nmap.nmap $tgtDir/nmap.md
    sed -i "1 i\```" $tgtDir/nmap.md
    sed -i "$a\```" $tgtDir/nmap.md

    # Remove as vulnerabilidades STUB de todos os alvos
    rm -rf "$obsdir/$proj_name/Pentest/Alvos/*/Vulnerabilidades/*"

done 2>/dev/null
