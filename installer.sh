#!/bin/bash

amass_ver="https://github.com/owasp-amass/amass/releases/download/v3.20.0/amass_linux_amd64.zip"
amass_path=$(which amass)
dnsrecon_ver="https://github.com/darkoperator/dnsrecon/archive/refs/tags/1.1.3.zip"
dnsrecon_dir=$(readlink -f $(which dnsrecon) | rev | sed 's-^[^/]*--' | rev)
path="$(which ls | rev | sed 's-^[^/]*--' | rev)"
scripts_dir="$HOME/.openpipes/scripts/"
config_file="$HOME/.openpipes/config.sh"

echo $path

echo "##############################################################"
echo "  Copying .openpipes folder to your \$HOME ... "
echo "##############################################################"

cp -r .openpipes/ $HOME
cp -r .openpipes_cache/ $HOME

echo "##############################################################"
echo "  Copying scripts to folder $path ... "
echo "  Please enter sudo credentials ... "
echo "##############################################################"

sudo cp $scripts_dir/* $path

echo "##############################################################"
echo "  Making scripts executable (chmod +x) ... "
echo "##############################################################"

for file in $(ls $scripts_dir/* | rev | cut -d "/" -f1 | rev);do 
    sudo chmod +x $path/$file;
done

echo "##############################################################"
echo "  Downgrading amass to version 3.20.0 ... "
echo "##############################################################"

wget $amass_ver && unzip amass_linux_amd64.zip && sudo cp amass_linux_amd64/amass $amass_path

echo "##############################################################"
echo "  Downgrading dnsrecon to version 1.1.3 ... "
echo "##############################################################"

wget $dnsrecon_ver && unzip 1.1.3.zip && sudo rm -rf $dnsrecon_dir/* && sudo mkdir -p $dnsrecon_dir && sudo cp -r dnsrecon-1.1.3/* $dnsrecon_dir

echo "##############################################################"
echo "  Updating repositories and installing RDAP ... "
echo "##############################################################"

sudo apt-get update && sudo apt install rdap -y

echo "##############################################################"
echo "  Populating local cache with top 10 vulnerabilities  ... "
echo "##############################################################"

python3 .openpipes/populate-cache-json.py

echo "##############################################################"
echo "  Enter your Security Trails API Key ... "
echo "##############################################################"

read -p "You can set your API Keys later in $HOME/.openpipes/config.sh: " sectrailskey
sed -i 's/securitytrailskey=.*/securitytrailskey='\""${sectrailskey}"\"'/' $config_file

echo "##############################################################"
echo "  Enter your Open AI API Key ... "
echo "##############################################################"

read -p "You can set your API Keys later in $HOME/.openpipes/config.sh: " OPENAI_API_KEY
sed -i 's/OPENAI_API_KEY=.*/OPENAI_API_KEY='\""${OPENAI_API_KEY}"\"'/' $config_file

echo "##############################################################"
echo "  Enter the directory path to your Projects directory ... "
echo "##############################################################"

read -p "Directory to host all your openPipes Projects: " proj_dir
sed -i 's-proj_dir=.*-proj_dir='\""${proj_dir}"\"'/' $config_file

echo "##############################################################"
echo "  Enter the name of your first Project ... "
echo "##############################################################"

read -p "Name of your first Project (usually your target's business name): " proj_name
sed -i 's-proj_name=.*-proj_name='\""${proj_name}"\"'-' $config_file

# dependencies=("")