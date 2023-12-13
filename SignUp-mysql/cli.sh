#!/bin/bash

sudo apt update
sudo apt upgrade
if ! command -v python3 &>/dev/null; then
    echo "Python3 is not installed. Installing Python3..."
    sudo apt install -y python3
fi
if ! command -v pip3 &>/dev/null; then
    echo "pip3 is not installed. Installing pip3..."
    sudo apt install -y python3-pip
fi
echo "Installing awscli............................................................................................................................"
pip3 install --upgrade awscli
echo 'export PATH="$PATH:/home/ubuntu/.local/bin"' >> ~/.bashrc
source $HOME/.bashrc
if [ $? -eq 0 ]; then
    echo "AWS CLI installed successfully."
else
    echo "AWS CLI installation failed."
fi
echo ""
echo ""
echo "Installing azure-cli........................................................................................................................"
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
echo 'export PATH="$PATH:/home/ubuntu/bin"' >> ~/.bashrc
source $HOME/.bashrc
if [ $? -eq 0 ]; then
    echo "Azure CLI installed successfully."
else
    echo "Azure CLI installation failed."
fi
echo ""
echo ""
echo "Installing gcloud............................................................................................................................"
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
sudo apt-get -y update && sudo apt-get install -y google-cloud-sdk
source $HOME/.bashrc
if [ $? -eq 0 ]; then
    echo "gcloud installed successfully."
else
    echo "gcloud installation failed."
fi

