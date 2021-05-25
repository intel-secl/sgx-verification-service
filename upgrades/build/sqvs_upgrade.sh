#!/bin/bash

SERVICE_NAME=sqvs
CURRENT_VERSION=v4.0.0
BACKUP_PATH=${BACKUP_PATH:-"/tmp/"}
LOG_FILE=${LOG_FILE:-"/tmp/$SERVICE_NAME-upgrade.log"}
echo "" > $LOG_FILE
./upgrade.sh -s $SERVICE_NAME -v $CURRENT_VERSION -b $BACKUP_PATH |& tee -a $LOG_FILE
