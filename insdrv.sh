#!/bin/bash

sudo modprobe vfio
sudo modprobe vfio-mdev

sudo insmod spi-nor-mod.ko
sudo insmod fpga-mgr-mod.ko
sudo insmod intel-fpga-pci.ko
sudo insmod intel-fpga-afu.ko
sudo insmod intel-fpga-fme.ko
