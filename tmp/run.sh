#!/bin/bash
make clean
svs uninstall
make installer
./out/svs-v0.0.0.bin
./test.sh
