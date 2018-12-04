#ifndef _VAI_INTERNAL_H_
#define _VAI_INTERNAL_H_

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
#include <linux/platform_device.h>
#include <linux/iommu.h>

#define VERSION_STRING  "0.1"
#define DRIVER_AUTHOR   "Jiacheng Ma"

#define ACCVISOR_CLASS_NAME  "accvisor"

#define ACCVISOR_NAME        "accvisor"

#define CL(x) ((x)*64)

#define ACCVISOR_STRING_LEN		64

#define ACCVISOR_CONFIG_SPACE_SIZE  0xff
#define ACCVISOR_MMIO_BAR_SIZE      0x100000

#define LOAD_LE16(addr, val)   (val = *(u16 *)addr)
#define LOAD_LE32(addr, val)   (val = *(u32 *)addr)
#define LOAD_LE64(addr, val)   (val = *(u64 *)addr)

#define STORE_LE16(addr, val)   (*(u16 *)addr = val)
#define STORE_LE32(addr, val)   (*(u32 *)addr = val)
#define STORE_LE64(addr, val)   (*(u64 *)addr = val)

#define ACCVISOR_VFIO_PCI_OFFSET_SHIFT   40

#define ACCVISOR_VFIO_PCI_OFFSET_TO_INDEX(off)   (off >> ACCVISOR_VFIO_PCI_OFFSET_SHIFT)
#define ACCVISOR_VFIO_PCI_INDEX_TO_OFFSET(index) \
				((u64)(index) << ACCVISOR_VFIO_PCI_OFFSET_SHIFT)
#define ACCVISOR_VFIO_PCI_OFFSET_MASK    \
				(((u64)(1) << ACCVISOR_VFIO_PCI_OFFSET_SHIFT) - 1)

struct phys_accel_entry;

struct accvisor {
    struct device *pafu_device;
    u8 *pafu_mmio;
    struct list_head next;

    struct mutex vaccel_list_lock;
    struct list_head vaccel_devices_list;

    struct iommu_domain *domain;
    int iommu_map_flags;

    struct mutex reset_lock;

    u32 global_seq_id;
    u32 num_phys_accels;
    struct phys_accel_entry *phys_accels;
};

extern struct mutex accvisor_list_lock;
extern struct list_head accvisor_list;

#define ACCVISOR_BAR_0_SIZE 0x100
#define ACCVISOR_BAR_2_SIZE 0x100
#define ACCVISOR_BAR_0_MASK ~(ACCVISOR_BAR_0_SIZE - 1)
#define ACCVISOR_BAR_2_MASK ~(ACCVISOR_BAR_2_SIZE - 1)

enum {
    VACCEL_BAR_0,
    VACCEL_BAR_2,
    VACCEL_BAR_NUM
};

typedef enum {
    VACCEL_TYPE_DIRECT,
    VACCEL_TYPE_TIME_SLICING
} vaccel_mode_t;

struct phys_accel_entry {
    vaccel_mode_t mode;
    u32 mode_id;

    u32 accel_id;
    u32 mmio_start;
    u32 mmio_size;

    struct mutex instance_lock;
    u32 available_instance;
    u32 current_instance;
    struct list_head vaccel_list;

    /* TODO: pointer to some bar address? */
};

struct vaccel {
    u8 *vconfig;
    u8 *bar[VACCEL_BAR_NUM];

    vaccel_mode_t mode;
    u32 seq_id;

    u64 gva_start;
    u64 iova_start;
    u64 paging_notifier_gpa;

    struct mutex ops_lock;
    struct list_head next;
    struct list_head entry_next;

    struct kvm *kvm;
    struct mdev_device *mdev;
    struct notifier_block group_notifier;

    struct accvisor *accvisor;
    struct phys_accel_entry *phys_accel_entry;
};

struct vaccel_paging_notifier {
    uint64_t va;
    uint64_t pa;
};

#endif /* _VAI_INTERNAL_H_ */
