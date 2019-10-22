#!/bin/bash

# READ .env file
echo PWD IS $(pwd)
if [ -f ~/svs.env ]; then
    echo Reading Installation options from `realpath ~/svs.env`
    env_file=~/svs.env
elif [ -f ../svs.env ]; then
    echo Reading Installation options from `realpath ../svs.env`
    env_file=../svs.env
fi

if [ -n $env_file ]; then
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
else
    echo No .env file found
    SVS_NOSETUP="true"
fi

SERVICE_USERNAME=svs

if [[ $EUID -ne 0 ]]; then
    echo "This installer must be run as root"
    exit 1
fi

echo "Setting up SGX Verification Service Linux User..."
id -u $SERVICE_USERNAME 2> /dev/null || useradd $SERVICE_USERNAME

echo "Installing SGX Verification Service..."


COMPONENT_NAME=svs
PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
DB_SCRIPT_PATH=$PRODUCT_HOME/dbscripts
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME/
CERTS_PATH=$CONFIG_PATH/certs
CERTDIR_TOKENSIGN=$CERTS_PATH/tokensign
CERTDIR_TRUSTEDJWTCERTS=$CERTS_PATH/trustedjwt
CERTDIR_TRUSTEDJWTCAS=$CERTS_PATH/trustedca

for directory in $BIN_PATH $DB_SCRIPT_PATH $LOG_PATH $CONFIG_PATH $CERTS_PATH $CERTDIR_TOKENSIGN $CERTDIR_TRUSTEDJWTCERTS $CERTDIR_TRUSTEDJWTCAS; do
  # mkdir -p will return 0 if directory exists or is a symlink to an existing directory or directory and parents can be created
  mkdir -p $directory
  if [ $? -ne 0 ]; then
    echo_failure "Cannot create directory: $directory"
    exit 1
  fi
  chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $directory
  chmod 700 $directory
  chmod g+s $directory

done


cp $COMPONENT_NAME $BIN_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $BIN_PATH/*
chmod 700 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

mkdir -p $CONFIG_PATH/root-ca && chown svs:svs $CONFIG_PATH/root-ca
chmod 700 $CONFIG_PATH/root-ca
chmod g+s $CONFIG_PATH/root-ca

# make log files world readable
chmod 661 $LOG_PATH

# Install systemd script
cp svs.service $PRODUCT_HOME && chown $SERVICE_USERNAME:$SERVICE_USERNAME $PRODUCT_HOME/svs.service && chown $SERVICE_USERNAME:$SERVICE_USERNAME $PRODUCT_HOME

# Enable systemd service
systemctl disable svs.service > /dev/null 2>&1
systemctl enable $PRODUCT_HOME/svs.service
systemctl daemon-reload

# check if SVS_NOSETUP is defined
if [ "${SVS_NOSETUP,,}" == "true" ]; then
    echo "SVS_NOSETUP is true, skipping setup"
    echo "Installation completed successfully!"
else
    $COMPONENT_NAME setup all
    SETUPRESULT=$?
    if [ ${SETUPRESULT} == 0 ]; then
        systemctl start $COMPONENT_NAME
        echo "Waiting for daemon to settle down before checking status"
        sleep 3
        systemctl status $COMPONENT_NAME 2>&1 > /dev/null
        if [ $? != 0 ]; then
            echo "Installation completed with Errors - $COMPONENT_NAME daemon not started."
            echo "Please check errors in syslog using \`journalctl -u $COMPONENT_NAME\`"
            exit 1
        fi
        echo "$COMPONENT_NAME daemon is running"
        echo "Installation completed successfully!"
    else
        echo "Installation completed with errors"
    fi
fi

