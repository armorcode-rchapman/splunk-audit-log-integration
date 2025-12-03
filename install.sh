#!/bin/bash

if [ $(id -u) -ne 0 ]; then 
  echo Please run this script as root or using sudo!
  exit
fi

SERVICE_ACCOUNT="splunk"
LOG_DIRECTORY="/var/log/armorcode"
SERVICE_GROUP="splunk"


echo "Looking for Splunk user | $SERVICE_ACCOUNT"
if id -u $SERVICE_ACCOUNT &>/dev/null; then
    echo "$SERVICE_ACCOUNT account exists."
    if [ ! -d $LOG_DIRECTORY ]; then
        echo "Creating ArmorCode folder in /var/log"
        sudo mkdir -p $LOG_DIRECTORY
    else
        echo "$LOG_DIRECTORY exists skipping this step"
    fi

    echo "Setting file permissions"

    sudo chown "$SERVICE_ACCOUNT":"$SERVICE_GROUP" "$LOG_DIRECTORY"
    sudo chmod 740 $LOG_DIRECTORY
else
    echo "$SERVICE_ACCOUNT does not exist."
fi

