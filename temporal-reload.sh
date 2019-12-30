#!/bin/bash

#sudo cp 40-intel-fpga.rules /etc/udev/rules.d
sudo modprobe vfio
sudo modprobe vfio-mdev

CURDIR=$(dirname $0)
${CURDIR}/rmdrv.sh
${CURDIR}/temporal-insdrv.sh
