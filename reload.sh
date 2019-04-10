#!/bin/bash

#sudo cp 40-intel-fpga.rules /etc/udev/rules.d
sudo modprobe vfio
sudo modprobe vfio-mdev

sudo rmmod intel-fpga-fme
sudo rmmod intel-fpga-afu
sudo rmmod intel-fpga-pci
sudo rmmod fpga-mgr-mod
sudo rmmod spi-nor-mod

sudo dmesg -C
CURDIR=$(dirname $0)
sudo insmod ${CURDIR}/spi-nor-mod.ko
sudo insmod ${CURDIR}/fpga-mgr-mod.ko
sudo insmod ${CURDIR}/intel-fpga-pci.ko
sudo insmod ${CURDIR}/intel-fpga-afu.ko
sudo insmod ${CURDIR}/intel-fpga-fme.ko
