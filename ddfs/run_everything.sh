#!/bin/bash

set -e

make
sudo insmod ddfs.ko
sudo mount -t ddfs -o loop ../../ddfs.img ./ddfs.dir
sudo chown stryku:stryku ddfs.dir
ls -la
