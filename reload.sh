#!/bin/bash

sudo cp 40-intel-fpga.rules /etc/udev/rules.d
sudo modprobe vfio
sudo modprobe vfio-mdev

sudo rmmod intel-fpga-fme
sudo rmmod intel-fpga-afu
sudo rmmod intel-fpga-pci
sudo rmmod fpga-mgr-mod
sudo rmmod spi-nor-mod

sudo dmesg -C

sudo insmod spi-nor-mod.ko
sudo insmod fpga-mgr-mod.ko
sudo insmod intel-fpga-pci.ko
sudo insmod intel-fpga-afu.ko
sudo insmod intel-fpga-fme.ko
