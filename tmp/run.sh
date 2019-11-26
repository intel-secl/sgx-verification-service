#!/bin/bash
make clean
svs uninstall
make installer
./out/svs-SKC_SVS_M8_WW47.04.bin
./test.sh
