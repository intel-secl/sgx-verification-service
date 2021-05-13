#!/bin/bash

COMPONENT_NAME=sqvs
LOG_PATH=/var/log/$COMPONENT_NAME

echo "Starting $COMPONENT_NAME config upgrade to v3.6.0"
chmod 640 $LOG_PATH/*
chmod 740 $LOG_PATH
echo "Completed $COMPONENT_NAME config upgrade to v3.6.0"
