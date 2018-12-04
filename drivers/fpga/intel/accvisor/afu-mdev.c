/*
 * Mediated virtual PCI serial host device driver
 *
 * Copyright (c) 2016, NVIDIA CORPORATION. All rights reserved.
 *     Author: Neo Jia <cjia@nvidia.com>
 *             Kirti Wankhede <kwankhede@nvidia.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Sample driver that creates mdev device that simulates serial port over PCI
 * card.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/uuid.h>
#include <linux/vfio.h>
#include <linux/iommu.h>
#include <linux/sysfs.h>
#include <linux/ctype.h>
#include <linux/file.h>
#include <linux/mdev.h>
#include <linux/pci.h>
#include <linux/serial.h>
#include <uapi/linux/serial_reg.h>
#include <linux/eventfd.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>

#include "afu.h"
#include "afu-mdev.h"

/*
 * #defines
 */

#define VERSION_STRING  "0.1"
#define DRIVER_AUTHOR   "Jiacheng Ma"

#define MAFU_CLASS_NAME  "mafu"

#define MAFU_NAME        "mafu"

#define MAFU_STRING_LEN		16

#define MAFU_CONFIG_SPACE_SIZE  0xff
#define MAFU_IO_BAR_SIZE        0x40
#define MAFU_MMIO_BAR_SIZE      0x100000

#define LOAD_LE16(addr, val)    ((val) = *(u16 *)(addr))
#define LOAD_LE32(addr, val)    ((val) = *(u32 *)(addr))
#define LOAD_LE64(addr, val)    ((val) = *(u64 *)(addr))

#define STORE_LE16(addr, val)   (*(u16 *)(addr) = (val))
#define STORE_LE32(addr, val)   (*(u32 *)(addr) = (val))
#define STORE_LE64(addr, val)   (*(u64 *)(addr) = (val))

#define CIRCULAR_BUF_INC_IDX(idx)    (idx = (idx + 1) & (MAX_FIFO_SIZE - 1))

#define MAFU_VFIO_PCI_OFFSET_SHIFT   40

#define MAFU_VFIO_PCI_OFFSET_TO_INDEX(off)   (off >> MAFU_VFIO_PCI_OFFSET_SHIFT)
#define MAFU_VFIO_PCI_INDEX_TO_OFFSET(index) \
				((u64)(index) << MAFU_VFIO_PCI_OFFSET_SHIFT)
#define MAFU_VFIO_PCI_OFFSET_MASK    \
				(((u64)(1) << MAFU_VFIO_PCI_OFFSET_SHIFT) - 1)
#define MAX_MAFUS	24

/*
 * Global Structures
 */

struct mdev_region_info {
	u64 start;
	u64 phys_start;
	u32 size;
	u64 vfio_offset;
};

#define VAI_ACCELERATOR_L 0x0
#define VAI_ACCELERATOR_H 0x8
#define VAI_PAGING_NOTIFY_MAP_ADDR 0x10
#define VAI_PAGING_NOTIFY_MAP 0x18

#define VAI_NOTIFY_DO_MAP 0x0
#define VAI_NOTIFY_DO_UNMAP 0x1

struct vai_paging_notifier {
    uint64_t va;
    uint64_t pa;
};

struct mdev_guest_info {
    struct kvm *kvm;

    u64 addr_space_start;
    u64 addr_space_size;

    u64 paging_notifier_gpa;
};

#if 0
struct mdev_gfn {
    gfn_t gfn;
    struct hlist_node hnode;
};
#endif

/* State of each mdev device */
struct mdev_state {
	int irq_fd;
	struct eventfd_ctx *intx_evtfd;
	struct eventfd_ctx *msi_evtfd;
	int irq_index;
	u8 *vconfig;
    u8 *vbar0;
	struct mutex ops_lock;
	struct mdev_device *mdev;
	struct mdev_region_info region_info[VFIO_PCI_NUM_REGIONS];
	u32 bar_mask[VFIO_PCI_NUM_REGIONS];
	struct list_head next;
	struct mutex rxtx_lock;
	struct vfio_device_info dev_info;

    struct fpga_afu *pafu;
    struct feature_afu_header *afu_hdr;
    int global_id;
    int local_id;

#if 0
#define NR_BKT (1 << 18)
    struct hlist_head ptable[NR_BKT];
#undef NR_BKT
#endif

    struct notifier_block group_notifier;
    struct mdev_guest_info guest;
};

/* support for iommu */
static int handle_mafu_page_map(struct mdev_state *ms,
            u64 gpa, u64 gva)
{
    struct kvm *kvm = ms->guest.kvm;
    gfn_t gfn = gpa >> PAGE_SHIFT;
    kvm_pfn_t pfn = gfn_to_pfn(kvm, gfn);
    struct iommu_domain *domain = ms->pafu->afu_iommu_domain;
    int flags = ms->pafu->afu_iommu_map_flags;

    /* add to IOMMU */
    if ((gva & 0xfff) != 0) {
        printk("vai: %s err gva not aligned\n", __func__);
        gva &= (~0xfff);
    }

    if (gva > ms->guest.addr_space_size) {
        printk("vai: %s err gva too large\n", __func__);
        return -EINVAL;
    }

    //gva += ms->guest.addr_space_start;
    if (iommu_iova_to_phys(domain, gva)) {
        iommu_unmap(domain, gva, PAGE_SIZE);
        printk("vai: %s clear already mapped\n", __func__);
    }

    printk("vai: iommu_map %llx ==> %llx ==> %llx\n", gva, gpa, pfn << PAGE_SHIFT);

    return iommu_map(ms->pafu->afu_iommu_domain, gva,
                        pfn << PAGE_SHIFT, PAGE_SIZE, flags);
}

static void handle_mafu_page_unmap(struct mdev_state *ms, u64 gva)
{
    kvm_pfn_t pfn;
    int r;
    struct iommu_domain *domain = ms->pafu->afu_iommu_domain;

    //gva += gva + ms->guest.addr_space_start;
    pfn = iommu_iova_to_phys(domain, gva);
    
    if (!pfn) {
        r = iommu_unmap(domain, gva, PAGE_SIZE);
        kvm_release_pfn_clean(pfn);
    }
    else {
        printk("vai: %s free a unmapped page\n", __func__);
    }
}

static int mafu_rw_gpa(struct mdev_state *ms, u64 gpa,
            void *buf, u64 len, bool write)
{
    struct kvm *kvm = ms->guest.kvm;
    int idx, ret;
    bool kthread = current->mm == NULL;

    if (kthread)
        use_mm(kvm->mm);

    idx = srcu_read_lock(&kvm->srcu);
    ret = write ? kvm_write_guest(kvm, gpa, buf, len) :
            kvm_read_guest(kvm, gpa, buf, len);
    srcu_read_unlock(&kvm->srcu, idx);

    if (kthread)
        unuse_mm(kvm->mm);

    return ret;
}

static int mafu_read_gpa(struct mdev_state *ms, u64 gpa,
            void *buf, u64 len)
{
    return mafu_rw_gpa(ms, gpa, buf, len, false);
}

static int mafu_write_gpa(struct mdev_state *ms, u64 gpa,
            void *buf, u64 len)
{
    return mafu_rw_gpa(ms, gpa, buf, len, true);
}

static struct mutex mdev_list_lock;
static struct list_head mdev_devices_list;
static int curr_global_id;

static void mafu_create_config_space(struct mdev_state *mdev_state)
{
	/* PCI dev ID */
	STORE_LE32((u32 *) &mdev_state->vconfig[0x0], 0xdeadbeef);

	/* Control: I/O+, Mem-, BusMaster- */
	STORE_LE16((u16 *) &mdev_state->vconfig[0x4], 0x0001);

	/* Status: capabilities list absent */
	STORE_LE16((u16 *) &mdev_state->vconfig[0x6], 0x0200);

	/* Rev ID */
	mdev_state->vconfig[0x8] =  0x10;

	/* programming interface class : 16550-compatible serial controller */
	mdev_state->vconfig[0x9] =  0x00;

	/* Sub class : 00 */
	mdev_state->vconfig[0xa] =  0x00;

	/* Base class : Simple Communication controllers */
	mdev_state->vconfig[0xb] =  0xff;

	/* base address registers */
	/* BAR0: MMIO */
	STORE_LE32((u32 *) &mdev_state->vconfig[0x10], 0x000000);
	mdev_state->bar_mask[0] = ~(MAFU_IO_BAR_SIZE) + 1;

	/* Subsystem ID */
	STORE_LE32((u32 *) &mdev_state->vconfig[0x2c], 0x32534348);

	mdev_state->vconfig[0x34] =  0x00;   /* Cap Ptr */
	mdev_state->vconfig[0x3d] =  0x01;   /* interrupt pin (INTA#) */
}

static int mafu_group_notifier(struct notifier_block *nb,
        long unsigned int action, void *data)
{
    struct mdev_state *ms = container_of(nb, struct mdev_state, group_notifier);

    if (action == VFIO_GROUP_NOTIFY_SET_KVM) {
        ms->guest.kvm = data;

        if (!data) {
            printk("mafu: failed to set KVM\n");
        }
    }

    return NOTIFY_OK;
}

#if 0
static char mybuf[128] __attribute__ ((aligned (8)));

static void afu_test_echo(struct feature_afu_header *afu_hdr)
{
    char *buf = (char*)(((uint64_t)mybuf)/64*64+64);
    u64 pa = virt_to_phys(buf);
    long count = 0;

    printk("alloc page va %llx pa %llx\n", (uint64_t)buf, pa);

    writeq(pa/64, &afu_hdr->guid.b[0]);

    while (buf[0] == 0 || count == 1000000000) {
        count++;
    }
    printk("fuck: %s\n", buf);
}
#endif

int mafu_create(struct kobject *kobj, struct mdev_device *mdev)
{
    struct mdev_state *mdev_state;
    struct device *pafu = mdev_parent_dev(mdev);
    struct feature_platform_data *pdata = dev_get_platdata(pafu);
    struct fpga_afu *afu = fpga_pdata_get_private(pdata);
    struct feature_header *hdr =
            get_feature_ioaddr_by_index(pafu, PORT_FEATURE_ID_UAFU);
    struct feature_afu_header *afu_hdr =
            (struct feature_afu_header *)(hdr + 1);

	u64 guidl;
	u64 guidh;

    char buf[256];

	mutex_lock(&pdata->lock);
	if (pdata->disable_count) {
		mutex_unlock(&pdata->lock);
		return -EBUSY;
	}

	guidl = readq(&afu_hdr->guid.b[0]);
	guidh = readq(&afu_hdr->guid.b[8]);
	mutex_unlock(&pdata->lock);

	scnprintf(buf, PAGE_SIZE, "%016llx%016llx", guidh, guidl);

    printk("mafu: %s, phy afu id %s\n", __func__, buf);

    //afu_test_echo(afu_hdr);

    if (!mdev)
        return -EINVAL;

    mdev_state = kzalloc(sizeof(struct mdev_state), GFP_KERNEL);
    if (mdev_state == NULL)
        return -ENOMEM;

    mdev_state->irq_index = -1;
    mutex_init(&mdev_state->rxtx_lock);
    mdev_state->vconfig = kzalloc(MAFU_CONFIG_SPACE_SIZE, GFP_KERNEL);
    mdev_state->vbar0 = kzalloc(MAFU_IO_BAR_SIZE, GFP_KERNEL);
    mdev_state->pafu = afu;

    mdev_state->global_id = curr_global_id;
    mdev_state->local_id = afu->curr_local_id;
    curr_global_id++;
    afu->curr_local_id++;

#define AFU_VM_ADDR_SIZE (16*1024*1024*1024llu)
    mdev_state->guest.addr_space_start = mdev_state->local_id * AFU_VM_ADDR_SIZE;
    mdev_state->guest.addr_space_size = AFU_VM_ADDR_SIZE;
    printk("vai: local id %x global id %x start %llx\n",
                mdev_state->local_id, mdev_state->global_id,
                mdev_state->guest.addr_space_start);

    if (mdev_state->vconfig == NULL) {
        kfree(mdev_state);
        return -ENOMEM;
    }

    mutex_init(&mdev_state->ops_lock);
    mdev_state->mdev = mdev;
    mdev_set_drvdata(mdev, mdev_state);

    /* TODO */
    mafu_create_config_space(mdev_state);

    mdev_state->afu_hdr = afu_hdr;

    mutex_lock(&mdev_list_lock);
    list_add(&mdev_state->next, &mdev_devices_list);
    mutex_unlock(&mdev_list_lock);

    return 0;
}

int mafu_remove(struct mdev_device *mdev)
{
	struct mdev_state *mds, *tmp_mds;
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	int ret = -EINVAL;

	mutex_lock(&mdev_list_lock);
	list_for_each_entry_safe(mds, tmp_mds, &mdev_devices_list, next) {
		if (mdev_state == mds) {
			list_del(&mdev_state->next);
			mdev_set_drvdata(mdev, NULL);
			kfree(mdev_state->vconfig);
            kfree(mdev_state->vbar0);
			kfree(mdev_state);
			ret = 0;
			break;
		}
	}
	mutex_unlock(&mdev_list_lock);

	return ret;
}

int mafu_open(struct mdev_device *mdev)
{
    unsigned long events;
    struct mdev_state *ms = mdev_get_drvdata(mdev);

    pr_info("mafu: %s\n", __func__);

    ms->group_notifier.notifier_call = mafu_group_notifier;

    events = VFIO_GROUP_NOTIFY_SET_KVM;
    vfio_register_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY, &events,
                    &ms->group_notifier);

    return 0;
}

void mafu_close(struct mdev_device *mdev)
{
    pr_info("mafu: %s\n", __func__);
}

static void handle_pci_cfg_write(struct mdev_state *mdev_state, u16 offset,
				 char *buf, u32 count)
{
	u32 cfg_addr, bar_mask;

	switch (offset) {
	case 0x04: /* device control */
	case 0x06: /* device status */
		/* do nothing */
		break;
	case 0x3c:  /* interrupt line */
		mdev_state->vconfig[0x3c] = buf[0];
		break;
	case 0x3d:
		/*
		 * Interrupt Pin is hardwired to INTA.
		 * This field is write protected by hardware
		 */
		break;
	case 0x10:  /* BAR0 */
		cfg_addr = *(u32 *)buf;
		pr_info("mafu: BAR0 addr 0x%x\n", cfg_addr);

		if (cfg_addr == 0xffffffff) {
			bar_mask = mdev_state->bar_mask[0];
			cfg_addr = (cfg_addr & bar_mask);
		}

		cfg_addr |= (mdev_state->vconfig[offset] & 0x3ul);
		STORE_LE32(&mdev_state->vconfig[offset], cfg_addr);
		break;
	case 0x14:  /* BAR1 */
	case 0x18:  /* BAR2 */
	case 0x1c:  /* BAR3 */
	case 0x20:  /* BAR4 */
    case 0x24:  /* BAR5 */
		STORE_LE32(&mdev_state->vconfig[offset], 0);
		break;
	default:
		pr_info("PCI config write @0x%x of %d bytes not handled\n",
			offset, count);
		break;
	}
}

static void handle_bar_write(unsigned int index, struct mdev_state *mdev_state,
                u16 offset, char *buf, u32 count)
{
    u32 data32;

    switch (offset) {
    case 0x10:
    case 0x14:
    {
        data32 = *(u32*)buf;
        STORE_LE32(&mdev_state->vbar0[offset], data32);
        mdev_state->guest.paging_notifier_gpa = 0;
        break;
    }
    case 0x18:
    {
        u32 cmd;
        struct vai_paging_notifier notifier;
        int ret;
        char *test_msg = "Hello world!";

        if (mdev_state->guest.paging_notifier_gpa == 0) {
            LOAD_LE64(&mdev_state->vbar0[VAI_PAGING_NOTIFY_MAP_ADDR],
                        mdev_state->guest.paging_notifier_gpa);
        }
        printk("vai: notifier: %llx\n", mdev_state->guest.paging_notifier_gpa);

        LOAD_LE32(&mdev_state->vbar0[offset], cmd);

        printk("vai: cmd: %s\n", cmd == 0 ? "map" : "unmap");

        ret = mafu_read_gpa(mdev_state, mdev_state->guest.paging_notifier_gpa,
                            &notifier, sizeof(notifier));

        printk("vai: notifier ret %d va %llx pa %llx\n", ret, notifier.va, notifier.pa);
        
        //mafu_write_gpa(mdev_state, notifier.pa, test_msg, strlen(test_msg));

        if (cmd == 0) {
            struct feature_afu_header *afu_hdr = mdev_state->afu_hdr;

            handle_mafu_page_map(mdev_state, notifier.pa, notifier.va);
            writeq(notifier.va/64, &afu_hdr->guid.b[0]);
            msleep(1000);
        }
        else {
            handle_mafu_page_unmap(mdev_state, notifier.va);
        }

        break;
    }
    default:
        break;
    }
}

static void handle_bar_read(unsigned int index, struct mdev_state *mdev_state,
                u16 offset, char *buf, u32 count)
{
    u32 data32;

    switch (offset) {
    case 0x0: /* addr low */
    case 0x4: /* addr high */
    {
        data32 = *(u32*)buf;
        LOAD_LE32(&mdev_state->vbar0[offset], data32);
        break;
    }
    default:
        break;
    }
}

static void dump_buffer(char *buf, uint32_t count)
{
	int i;
    uint32_t *x = (uint32_t*)buf;

    for (i=0; i<count; i+=4) {
        pr_info("buffer: %08x\n", *x);
        x = (uint32_t*)(buf+i);
    }
}

static void mdev_read_base(struct mdev_state *mdev_state)
{
	int index, pos;
	u32 start_lo, start_hi;
	u32 mem_type;

	pos = PCI_BASE_ADDRESS_0;

	for (index = 0; index <= VFIO_PCI_BAR5_REGION_INDEX; index++) {

		if (!mdev_state->region_info[index].size)
			continue;

		start_lo = (*(u32 *)(mdev_state->vconfig + pos)) &
			PCI_BASE_ADDRESS_MEM_MASK;
		mem_type = (*(u32 *)(mdev_state->vconfig + pos)) &
			PCI_BASE_ADDRESS_MEM_TYPE_MASK;

		switch (mem_type) {
		case PCI_BASE_ADDRESS_MEM_TYPE_64:
			start_hi = (*(u32 *)(mdev_state->vconfig + pos + 4));
			pos += 4;
			break;
		case PCI_BASE_ADDRESS_MEM_TYPE_32:
		case PCI_BASE_ADDRESS_MEM_TYPE_1M:
			/* 1M mem BAR treated as 32-bit BAR */
		default:
			/* mem unknown type treated as 32-bit BAR */
			start_hi = 0;
			break;
		}
		pos += 4;
		mdev_state->region_info[index].start = ((u64)start_hi << 32) |
							start_lo;
	}
}

static ssize_t mdev_access(struct mdev_device *mdev, char *buf, size_t count,
			   loff_t pos, bool is_write)
{
	struct mdev_state *mdev_state;
	unsigned int index;
	loff_t offset;
	int ret = 0;

	if (!mdev || !buf)
		return -EINVAL;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state) {
		pr_err("%s mdev_state not found\n", __func__);
		return -EINVAL;
	}

	mutex_lock(&mdev_state->ops_lock);

	index = MAFU_VFIO_PCI_OFFSET_TO_INDEX(pos);
	offset = pos & MAFU_VFIO_PCI_OFFSET_MASK;
	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:

		pr_info("%s: PCI config space %s at offset 0x%llx\n",
			 __func__, is_write ? "write" : "read", offset);

		if (is_write) {
			dump_buffer(buf, count);
			handle_pci_cfg_write(mdev_state, offset, buf, count);
		} else {
			memcpy(buf, (mdev_state->vconfig + offset), count);
			dump_buffer(buf, count);
		}

		break;

	case VFIO_PCI_BAR0_REGION_INDEX ... VFIO_PCI_BAR5_REGION_INDEX:
		if (!mdev_state->region_info[index].start)
			mdev_read_base(mdev_state);

        pr_info("%s: global id %d BAR %d %s at offset 0x%llx\n", __func__, mdev_state->global_id,
            index - VFIO_PCI_BAR0_REGION_INDEX, is_write ? "write" : "read",
            offset);

		if (is_write) {
			dump_buffer(buf, count);
			handle_bar_write(index, mdev_state, offset, buf, count);
		} else {
			handle_bar_read(index, mdev_state, offset, buf, count);
			dump_buffer(buf, count);
		}
		break;

	default:
		ret = -1;
		goto accessfailed;
	}

	ret = count;


accessfailed:
	mutex_unlock(&mdev_state->ops_lock);

	return ret;
}

ssize_t mafu_read(struct mdev_device *mdev, char __user *buf, size_t count,
            loff_t *ppos)
{
    unsigned int done = 0;
    int ret;

    while (count) {
       size_t filled;

       if (count >= 4 && (*ppos % 4 == 0)) {
           u32 val;

           ret = mdev_access(mdev, (char *)&val, sizeof(val),
                    *ppos, false);
           if (ret <= 0)
               goto read_err;

           if (copy_to_user(buf, &val, sizeof(val)))
               goto read_err;

           filled = 4;
       }
       else if (count >= 2 && (*ppos % 2 == 0)) {
           u16 val;

           ret = mdev_access(mdev, (char *)&val, sizeof(val),
                        *ppos, false);
           if (ret <= 0)
               goto read_err;

           if (copy_to_user(buf, &val, sizeof(val)))
               goto read_err;

           filled = 2;
       }
       else {
           u8 val;

           ret = mdev_access(mdev, (char *)&val, sizeof(val),
                   *ppos, false);
           if (ret <= 0)
               goto read_err;

           if (copy_to_user(buf, &val, sizeof(val)))
               goto read_err;

           filled = 1;
       }

       count -= filled;
       done += filled;
       *ppos += filled;
       buf += filled;
    }

    return done;

read_err:
    return -EFAULT;
}

ssize_t mafu_write(struct mdev_device *mdev, const char __user *buf,
		   size_t count, loff_t *ppos)
{
	unsigned int done = 0;
	int ret;

	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = mdev_access(mdev, (char *)&val, sizeof(val),
					  *ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = mdev_access(mdev, (char *)&val, sizeof(val),
					  *ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = mdev_access(mdev, (char *)&val, sizeof(val),
					  *ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 1;
		}
		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;
write_err:
	return -EFAULT;
}

static int mafu_get_device_info(struct mdev_device *mdev,
                struct vfio_device_info *dev_info)
{
    dev_info->flags = VFIO_DEVICE_FLAGS_PCI;
    dev_info->flags |= VFIO_DEVICE_FLAGS_RESET;
    dev_info->num_regions = VFIO_PCI_NUM_REGIONS;
    dev_info->num_irqs = VFIO_PCI_NUM_IRQS;

    return 0;
}

static int mafu_get_region_info(struct mdev_device *mdev,
                struct vfio_region_info *region_info,
                u16 *cap_type_id, void **cap_type)
{
    unsigned int size = 0;
    struct mdev_state *mdev_state;
    u32 bar_index;

    if (!mdev)
        return -EINVAL;

    mdev_state = mdev_get_drvdata(mdev);
    if (!mdev_state)
        return -EINVAL;

    bar_index = region_info->index;
    if (bar_index >= VFIO_PCI_NUM_REGIONS)
        return -EINVAL;

    mutex_lock(&mdev_state->ops_lock);

    switch (bar_index) {
    case VFIO_PCI_CONFIG_REGION_INDEX:
        size = MAFU_CONFIG_SPACE_SIZE;
        break;
    case VFIO_PCI_BAR0_REGION_INDEX:
        size = MAFU_IO_BAR_SIZE;
        break;
    case VFIO_PCI_BAR1_REGION_INDEX:
        size = MAFU_IO_BAR_SIZE;
        break;
    default:
        size = 0;
        break;
    }

    mdev_state->region_info[bar_index].size = size;
    mdev_state->region_info[bar_index].vfio_offset =
        MAFU_VFIO_PCI_INDEX_TO_OFFSET(bar_index);

    region_info->size = size;
    region_info->offset = MAFU_VFIO_PCI_INDEX_TO_OFFSET(bar_index);
    region_info->flags = VFIO_REGION_INFO_FLAG_READ |
        VFIO_REGION_INFO_FLAG_WRITE;

    mutex_unlock(&mdev_state->ops_lock);
    return 0;
}

int mafu_get_irq_info(struct mdev_device *mdev, struct vfio_irq_info *irq_info)
{
	switch (irq_info->index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
	case VFIO_PCI_MSI_IRQ_INDEX:
	case VFIO_PCI_REQ_IRQ_INDEX:
		break;

	default:
		return -EINVAL;
	}

	irq_info->flags = VFIO_IRQ_INFO_EVENTFD;
	irq_info->count = 1;

	if (irq_info->index == VFIO_PCI_INTX_IRQ_INDEX)
		irq_info->flags |= (VFIO_IRQ_INFO_MASKABLE |
				VFIO_IRQ_INFO_AUTOMASKED);
	else
		irq_info->flags |= VFIO_IRQ_INFO_NORESIZE;

	return 0;
}


static int mafu_set_irqs(struct mdev_device *mdev, uint32_t flags,
			 unsigned int index, unsigned int start,
			 unsigned int count, void *data)
{
	int ret = 0;
	struct mdev_state *mdev_state;

	if (!mdev)
		return -EINVAL;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -EINVAL;

	mutex_lock(&mdev_state->ops_lock);
	switch (index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
		{
			if (flags & VFIO_IRQ_SET_DATA_NONE) {
				pr_info("%s: disable INTx\n", __func__);
				if (mdev_state->intx_evtfd)
					eventfd_ctx_put(mdev_state->intx_evtfd);
				break;
			}

			if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
				int fd = *(int *)data;

				if (fd > 0) {
					struct eventfd_ctx *evt;

					evt = eventfd_ctx_fdget(fd);
					if (IS_ERR(evt)) {
						ret = PTR_ERR(evt);
						break;
					}
					mdev_state->intx_evtfd = evt;
					mdev_state->irq_fd = fd;
					mdev_state->irq_index = index;
					break;
				}
			}
			break;
		}
		}
		break;
	case VFIO_PCI_MSI_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			if (flags & VFIO_IRQ_SET_DATA_NONE) {
				if (mdev_state->msi_evtfd)
					eventfd_ctx_put(mdev_state->msi_evtfd);
				pr_info("%s: disable MSI\n", __func__);
				mdev_state->irq_index = VFIO_PCI_INTX_IRQ_INDEX;
				break;
			}
			if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
				int fd = *(int *)data;
				struct eventfd_ctx *evt;

				if (fd <= 0)
					break;

				if (mdev_state->msi_evtfd)
					break;

				evt = eventfd_ctx_fdget(fd);
				if (IS_ERR(evt)) {
					ret = PTR_ERR(evt);
					break;
				}
				mdev_state->msi_evtfd = evt;
				mdev_state->irq_fd = fd;
				mdev_state->irq_index = index;
			}
			break;
	}
	break;
	case VFIO_PCI_MSIX_IRQ_INDEX:
		pr_info("%s: MSIX_IRQ\n", __func__);
		break;
	case VFIO_PCI_ERR_IRQ_INDEX:
		pr_info("%s: ERR_IRQ\n", __func__);
		break;
	case VFIO_PCI_REQ_IRQ_INDEX:
		pr_info("%s: REQ_IRQ\n", __func__);
		break;
	}

	mutex_unlock(&mdev_state->ops_lock);
	return ret;
}

int mafu_reset(struct mdev_device *mdev)
{
	struct mdev_state *mdev_state;

	if (!mdev)
		return -EINVAL;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -EINVAL;

	pr_info("%s: called\n", __func__);

	return 0;
}

static long mafu_ioctl(struct mdev_device *mdev, unsigned int cmd,
			unsigned long arg)
{
	int ret = 0;
	unsigned long minsz;
	struct mdev_state *mdev_state;

	if (!mdev)
		return -EINVAL;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -ENODEV;

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
	{
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		ret = mafu_get_device_info(mdev, &info);
		if (ret)
			return ret;

		memcpy(&mdev_state->dev_info, &info, sizeof(info));

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_GET_REGION_INFO:
	{
		struct vfio_region_info info;
		u16 cap_type_id = 0;
		void *cap_type = NULL;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		ret = mafu_get_region_info(mdev, &info, &cap_type_id,
					   &cap_type);
		if (ret)
			return ret;

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}

	case VFIO_DEVICE_GET_IRQ_INFO:
	{
		struct vfio_irq_info info;

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if ((info.argsz < minsz) ||
		    (info.index >= mdev_state->dev_info.num_irqs))
			return -EINVAL;

		ret = mafu_get_irq_info(mdev, &info);
		if (ret)
			return ret;

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_SET_IRQS:
	{
		struct vfio_irq_set hdr;
		u8 *data = NULL, *ptr = NULL;
		size_t data_size = 0;

		minsz = offsetofend(struct vfio_irq_set, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		ret = vfio_set_irqs_validate_and_prepare(&hdr,
						mdev_state->dev_info.num_irqs,
						VFIO_PCI_NUM_IRQS,
						&data_size);
		if (ret)
			return ret;

		if (data_size) {
			ptr = data = memdup_user((void __user *)(arg + minsz),
						 data_size);
			if (IS_ERR(data))
				return PTR_ERR(data);
		}

		ret = mafu_set_irqs(mdev, hdr.flags, hdr.index, hdr.start,
				    hdr.count, data);

		kfree(ptr);
		return ret;
	}
	case VFIO_DEVICE_RESET:
		return mafu_reset(mdev);
	}
	return -ENOTTY;
}

static const struct file_operations vd_fops = {
    .owner  = THIS_MODULE,
};

const struct attribute_group *mafu_dev_groups[] = {
    NULL,
};

static struct attribute *mdev_dev_attrs[] = {
    NULL,
};

static const struct attribute_group mdev_dev_group = {
    .name = "vendor",
    .attrs = mdev_dev_attrs,
};

const struct attribute_group *mdev_dev_groups[] = {
    &mdev_dev_group,
    NULL,
};

static ssize_t
name_show(struct kobject *kobj, struct device *dev, char *buf)
{
    char name[MAFU_STRING_LEN];
    int i;
    const char *name_str[1] = {"Virtualized Accelerator"};

    for (i = 0; i < 2; i++) {
        snprintf(name, MAFU_STRING_LEN, "%s-%d",
                dev_driver_string(dev), i + 1);
        if (!strcmp(kobj->name, name))
            return sprintf(buf, "%s\n", name_str[i]);
    }

    return -EINVAL;
}
MDEV_TYPE_ATTR_RO(name);

static ssize_t
device_api_show(struct kobject *kobj, struct device *dev,
            char *buf)
{
    return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}
MDEV_TYPE_ATTR_RO(device_api);

static ssize_t
amafulable_instances_show(struct kobject *kobj,
            struct device *dev, char *buf)
{
    struct mdev_state *mds;
    int used = 0;

    list_for_each_entry(mds, &mdev_devices_list, next)
        used += 1;

    return sprintf(buf, "%d\n", MAX_MAFUS - used);
}
MDEV_TYPE_ATTR_RO(amafulable_instances);

static struct attribute *mdev_types_attrs[] = {
    &mdev_type_attr_name.attr,
    &mdev_type_attr_device_api.attr,
    &mdev_type_attr_amafulable_instances.attr,
    NULL,
};

static struct attribute_group mdev_type_group1 = {
    .name = "1",
    .attrs = mdev_types_attrs,
};

struct attribute_group *mdev_type_groups[] = {
    &mdev_type_group1,
    NULL,
};

struct mdev_parent_ops mdev_fops = {
    .owner = THIS_MODULE,
    .dev_attr_groups = mafu_dev_groups,
    .mdev_attr_groups = mdev_dev_groups,
    .supported_type_groups = mdev_type_groups,
    .create = mafu_create,
    .remove = mafu_remove,
    .open = mafu_open,
    .release = mafu_close,
    .read = mafu_read,
    .write = mafu_write,
    .ioctl = mafu_ioctl,
    /* FIXME */
};

int fpga_register_afu_mdev_device(struct platform_device *pdev)
{
    int ret;
    ret = mdev_register_device(&pdev->dev, &mdev_fops);

    mutex_init(&mdev_list_lock);
    INIT_LIST_HEAD(&mdev_devices_list);
    curr_global_id = 0;

    return ret;
}

void fpga_unregister_afu_mdev_device(struct platform_device *pdev)
{
	mdev_unregister_device(&pdev->dev);
}
