KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD ?= $(pwd)

cflags-y +=  -Wno-unused-value -Wno-unused-label -I$(PWD)/include -I$(PWD)/include/uapi -I$(PWD)/include/intel
cflags-y += -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include/uapi -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include/intel
cflags-y += -I$(PWD)/build/include -I$(PWD)/build/include/uapi -I$(PWD)/build/include/intel

ccflags-y +=  -Wno-unused-value -Wno-unused-label -I$(PWD)/include -I$(PWD)/include/uapi -I$(PWD)/include/intel
ccflags-y += -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include/uapi -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include/intel
ccflags-y += -I$(PWD)/build/include -I$(PWD)/build/include/uapi -I$(PWD)/build/include/intel
ccflags-y += -DCONFIG_AS_AVX512

obj-m += fpga-mgr-mod.o
obj-m += intel-fpga-pci.o
obj-m += intel-fpga-fme.o
obj-m += intel-fpga-afu.o

fpga-mgr-mod-y := drivers/fpga/fpga-mgr.o

intel-fpga-pci-y := drivers/fpga/intel/uuid_mod.o
intel-fpga-pci-y += drivers/fpga/intel/pcie.o
intel-fpga-pci-y += drivers/fpga/intel/pcie_check.o
intel-fpga-pci-y += drivers/fpga/intel/feature-dev.o

intel-fpga-fme-y := drivers/fpga/intel/fme-pr.o
intel-fpga-fme-y += drivers/fpga/intel/fme-iperf.o
intel-fpga-fme-y += drivers/fpga/intel/fme-dperf.o
intel-fpga-fme-y += drivers/fpga/intel/fme-error.o
intel-fpga-fme-y += drivers/fpga/intel/fme-main.o
intel-fpga-fme-y += drivers/fpga/intel/backport.o

intel-fpga-afu-y := drivers/fpga/intel/afu.o
intel-fpga-afu-y += drivers/fpga/intel/region.o
intel-fpga-afu-y += drivers/fpga/intel/dma-region.o
intel-fpga-afu-y += drivers/fpga/intel/afu-error.o
intel-fpga-afu-y += drivers/fpga/intel/afu-check.o
intel-fpga-afu-y += drivers/fpga/intel/optimus/optimus.o
intel-fpga-afu-y += drivers/fpga/intel/optimus/optimus-common.o
intel-fpga-afu-y += drivers/fpga/intel/optimus/vaccel-common.o
intel-fpga-afu-y += drivers/fpga/intel/optimus/vaccel-direct.o
intel-fpga-afu-y += drivers/fpga/intel/optimus/vaccel-timeslc.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
