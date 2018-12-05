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

#define FISOR_CLASS_NAME  "fisor"

#define FISOR_NAME        "fisor"

#define CL(x) ((x)*64)

#define FISOR_STRING_LEN		64

#define FISOR_CONFIG_SPACE_SIZE  0xff
#define FISOR_MMIO_BAR_SIZE      0x100000

#define LOAD_LE16(addr, val)   (val = *(u16 *)addr)
#define LOAD_LE32(addr, val)   (val = *(u32 *)addr)
#define LOAD_LE64(addr, val)   (val = *(u64 *)addr)

#define STORE_LE16(addr, val)   (*(u16 *)addr = val)
#define STORE_LE32(addr, val)   (*(u32 *)addr = val)
#define STORE_LE64(addr, val)   (*(u64 *)addr = val)

#define FISOR_VFIO_PCI_OFFSET_SHIFT   40

#define FISOR_VFIO_PCI_OFFSET_TO_INDEX(off)   (off >> FISOR_VFIO_PCI_OFFSET_SHIFT)
#define FISOR_VFIO_PCI_INDEX_TO_OFFSET(index) \
				((u64)(index) << FISOR_VFIO_PCI_OFFSET_SHIFT)
#define FISOR_VFIO_PCI_OFFSET_MASK    \
				(((u64)(1) << FISOR_VFIO_PCI_OFFSET_SHIFT) - 1)

struct paccel;

struct fisor {
    struct device *pafu_device;
    u8 *pafu_mmio;
    struct list_head next;

    struct mutex vaccel_list_lock;
    struct list_head vaccel_devices_list;

    struct iommu_domain *domain;
    int iommu_map_flags;

    struct mutex reset_lock;

    struct task_struct *worker_kthread;
    struct list_head worker_task_list;
    struct mutex worker_lock;

    u32 global_seq_id;
    u32 npaccels;
    struct paccel *paccels;
};

extern struct mutex fisor_list_lock;
extern struct list_head fisor_list;

#define SIZE_64G (64*1024*1024*1024LLU)

#define FISOR_BAR_0_SIZE 0x100
#define FISOR_BAR_2_SIZE 0x100
#define FISOR_BAR_0_MASK ~(FISOR_BAR_0_SIZE - 1)
#define FISOR_BAR_2_MASK ~(FISOR_BAR_2_SIZE - 1)

#define FISOR_GUID_HI 0xd1d383aaca4c4c60
#define FISOR_GUID_LO 0xa0a013a421139e69
#define FISOR_MAGIC 0xfffff

enum {
    VACCEL_BAR_0,
    VACCEL_BAR_2,
    VACCEL_BAR_NUM
};

typedef enum {
    VACCEL_TYPE_DIRECT,
    VACCEL_TYPE_TIME_SLICING
} vaccel_mode_t;

struct paccel {
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
    struct list_head paccel_next;

    struct kvm *kvm;
    struct mdev_device *mdev;
    struct notifier_block group_notifier;

    struct fisor *fisor;
    struct paccel *paccel;
};

struct vaccel_paging_notifier {
    uint64_t va;
    uint64_t pa;
};

#endif /* _VAI_INTERNAL_H_ */
