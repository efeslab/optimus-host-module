KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD ?= $(pwd)

cflags-y +=  -Wno-unused-value -Wno-unused-label -I$(PWD)/include -I$(PWD)/include/uapi -I$(PWD)/include/intel
cflags-y += -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include/uapi -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include/intel
cflags-y += -I$(PWD)/build/include -I$(PWD)/build/include/uapi -I$(PWD)/build/include/intel

ccflags-y +=  -Wno-unused-value -Wno-unused-label -I$(PWD)/include -I$(PWD)/include/uapi -I$(PWD)/include/intel
ccflags-y += -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include/uapi -I$(DESTDIR)/usr/src/intel-fpga-1.2.0-1/include/intel
ccflags-y += -I$(PWD)/build/include -I$(PWD)/build/include/uapi -I$(PWD)/build/include/intel
ccflags-y += -DCONFIG_AS_AVX512

obj-m := spi-nor-mod.o
obj-m += altera-asmip2.o
obj-m += avmmi-bmc.o
obj-m += fpga-mgr-mod.o
obj-m += intel-fpga-pci.o
obj-m += intel-fpga-fme.o
obj-m += intel-fpga-afu.o
obj-m += intel-fpga-pac-hssi.o
obj-m += intel-fpga-pac-iopll.o

spi-nor-mod-y := drivers/mtd/spi-nor/spi-nor.o

altera-asmip2-y := drivers/mtd/spi-nor/altera-asmip2.o
avmmi-bmc-y := drivers/misc/avmmi-bmc.o

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
intel-fpga-afu-y += drivers/fpga/intel/fisor/fisor.o

intel-fpga-pac-hssi-y := drivers/fpga/intel/intel-fpga-pac-hssi.o

intel-fpga-pac-iopll-y := drivers/fpga/intel/intel-fpga-pac-iopll.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
