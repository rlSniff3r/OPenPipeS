#!/bin/bash

amass_ver="https://github.com/owasp-amass/amass/releases/download/v3.20.0/amass_linux_amd64.zip"
amass_path=$(which amass)
dnsrecon_ver="https://github.com/darkoperator/dnsrecon/archive/refs/tags/1.1.3.zip"
dnsrecon_dir=$(readlink -f $(which dnsrecon) | rev | sed 's-^[^/]*--' | rev)
path="$(which ls | rev | sed 's-^[^/]*--' | rev)"
scripts_dir="$HOME/.openpipes/scripts/"

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

# dependencies=("")