#!/bin/bash

amass_ver="https://github.com/owasp-amass/amass/releases/download/v3.20.0/amass_linux_amd64.zip"
amass_path=$(which amass)
dnsrecon_ver="https://github.com/darkoperator/dnsrecon/archive/refs/tags/1.1.3.zip"
dnsrecon_dir=$(readlink -f $(which dnsrecon) | rev | sed 's-^[^/]*--' | rev)
path="$(which ls | rev | sed 's-^[^/]*--' | rev)"
scripts_dir="$HOME/.openpipes/scripts/"
config_file="$HOME/.openpipes/config.sh"

echo $path

echo "stty sane" > ~/.profile

. ~/.profile

echo "##############################################################"
echo " Copying .openpipes folder to your \$HOME ... "
echo "##############################################################"

cp -r .openpipes/ $HOME
cp -r .openpipes_cache/ $HOME

echo "##############################################################"
echo " Copying scripts to folder $path ... "
echo " Please enter sudo credentials ... "
echo "##############################################################"

sudo cp $scripts_dir/* $path

echo "##############################################################"
echo " Making scripts executable (chmod +x) ... "
echo "##############################################################"

for file in $(ls $scripts_dir/* | rev | cut -d "/" -f1 | rev);do 
    sudo chmod +x $path/$file;
done

echo "##############################################################"
echo " Downgrading amass to version 3.20.0 ... "
echo "##############################################################"

wget $amass_ver && unzip amass_linux_amd64.zip && sudo cp amass_linux_amd64/amass $amass_path

echo "##############################################################"
echo " Downgrading dnsrecon to version 1.1.3 ... "
echo "##############################################################"

wget $dnsrecon_ver && unzip 1.1.3.zip && sudo mv $dnsrecon_dir $dnsrecon_dir-original && sudo mkdir -p $dnsrecon_dir && sudo cp -r dnsrecon-1.1.3/* $dnsrecon_dir

echo "##############################################################"
echo " Updating repositories and installing RDAP ... "
echo "##############################################################"

sudo apt-get update && sudo apt install rdap -y

echo "##############################################################"
echo " Populating local cache with top 10 vulnerabilities  ... "
echo "##############################################################"

python3 .openpipes/populate-cache-json.py

echo "##############################################################"
echo " Enter your Security Trails API Key ... "
echo "##############################################################"

read -p "You can set your API Keys later in $HOME/.openpipes/config.sh: " sectrailskey
sed -i 's/securitytrailskey=.*/securitytrailskey='\""${sectrailskey}"\"'/' $config_file

echo "##############################################################"
echo " Enter your Open AI API Key ... "
echo "##############################################################"

read -p "You can set your API Keys later in $HOME/.openpipes/config.sh: " OPENAI_API_KEY
sed -i 's/OPENAI_API_KEY=.*/OPENAI_API_KEY='\""${OPENAI_API_KEY}"\"'/' $config_file

echo "##############################################################"
echo " Enter the directory path to your Projects directory ... "
echo "##############################################################"

read -p "Directory to host all your openPipes Projects: " proj_dir
sed -i 's-proj_dir=.*-proj_dir='\""${proj_dir}"\"'/' $config_file

echo "##############################################################"
echo " Enter the name of your first Project ... "
echo "##############################################################"

read -p "Name of your first Project (usually your target's business name): " proj_name
sed -i 's-proj_name=.*-proj_name='\""${proj_name}"\"'-' $config_file

echo "##############################################################"
echo " Enter domains you wish OPenPipeS to Recon one at a time ... "
echo " Obs.: Please note you need ONLY 2nd level domains, ex.: "
echo " example.com "
echo " tesla.com "
echo " terra.com.br "
echo " etc... "
echo "##############################################################"

proj_path=${proj_dir}/${proj_name}
domains=${proj_path}/domains.txt

read -p "Enter a domain to start the Reconnaissance: " domain
echo $domain > ${domains}

echo ""
echo "[+] Recon file ${domains} created, add as many domains as you want for the Recon phase."
echo "[+] added $domain to ${domains}"
echo ""

echo "##############################################################"
echo " Avoid using 3rd+ level domains (ex. sub.example.com) as "
echo " this will significantly reduce the mapped attack surface "
echo "##############################################################"

while [[ -n $domain ]]; do
    read -p "Enter another domain or press [ENTER] twice when you're done: " domain
    echo "[+] added $domain to ${domains}"
done

echo ""
echo "[✅] Arquivo ${domains} finalizado!"
echo "[📄] domains.txt"
cat ${domains}
echo ""

echo "##############################################################"
echo " Initial configuration of OPenPipeS finished!"
echo " Please, map your host's Obsidian Project folder to:"
echo " ${obsdir}"
echo ""
echo " The configuration file to OPenPipeS is at:"
echo " ${config_file}"
echo ""
echo " After setting up your Obsidian mount, plase use the"
echo " orquestrator to start the Recon and Enumeration of"
echo " the targets and start feeding your Obsidian's Dashboards"
echo " and files with the information gathered by OPenPipeS!"
echo "##############################################################"

# dependencies=("")