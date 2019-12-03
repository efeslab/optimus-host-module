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
#include <linux/eventfd.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/platform_device.h>
#include <linux/iommu.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/hugetlb.h>

#define PGSHIFT_4K 12                                                                                                                                                                                                                                      
#define PGSHIFT_2M 21                                                                                                                                                                                                                                      
#define PGSHIFT_1G 30                                                                                                                                                                                                                                      

#define PGSIZE_4K (1UL << PGSHIFT_4K)                                                                                                                                                                                                                      
#define PGSIZE_2M (1UL << PGSHIFT_2M)                                                                                                                                                                                                                      
#define PGSIZE_1G (1UL << PGSHIFT_1G)                                                                                                                                                                                                                      

#define PGSIZE_FLAG_4K (1 << 0)                                                                                                                                                                                                                            
#define PGSIZE_FLAG_2M (1 << 1)                                                                                                                                                                                                                            
#define PGSIZE_FLAG_1G (1 << 2)                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                           
#define MAP_BEHAVISOR_MAP 0x0                                                                                                                                                                                                                              
#define MAP_BEHAVISOR_UNMAP 0x1

#define PAGE4K_ALIGNED(addr) IS_ALIGNED((unsigned long)(addr), PGSIZE_4K)
#define PAGE2M_ALIGNED(addr) IS_ALIGNED((unsigned long)(addr), PGSIZE_2M)
#define PAGE1G_ALIGNED(addr) IS_ALIGNED((unsigned long)(addr), PGSIZE_1G)

#define VERSION_STRING  "0.1"
#define DRIVER_AUTHOR   "Jiacheng Ma"

#define OPTIMUS_CLASS_NAME  "optimus"

#define OPTIMUS_NAME        "optimus"

#define CL(x) ((x)*64)

#define OPTIMUS_STRING_LEN		64

#define OPTIMUS_CONFIG_SPACE_SIZE  0xff

#define LOAD_LE16(addr, val)   (val = *(u16 *)addr)
#define LOAD_LE32(addr, val)   (val = *(u32 *)addr)
#define LOAD_LE64(addr, val)   (val = *(u64 *)addr)

#define STORE_LE16(addr, val)   (*(u16 *)addr = val)
#define STORE_LE32(addr, val)   (*(u32 *)addr = val)
#define STORE_LE64(addr, val)   (*(u64 *)addr = val)

#define OPTIMUS_VFIO_PCI_OFFSET_SHIFT   40

#define OPTIMUS_VFIO_PCI_OFFSET_TO_INDEX(off)   (off >> OPTIMUS_VFIO_PCI_OFFSET_SHIFT)
#define OPTIMUS_VFIO_PCI_INDEX_TO_OFFSET(index) \
				((u64)(index) << OPTIMUS_VFIO_PCI_OFFSET_SHIFT)
#define OPTIMUS_VFIO_PCI_OFFSET_MASK    \
				(((u64)(1) << OPTIMUS_VFIO_PCI_OFFSET_SHIFT) - 1)

//#define SCHED_ENABLE_WEIGHT

#ifdef SCHED_ENABLE_WEIGHT
#define SCHED_WEIGHT_BIT 4
#define SCHED_WEIGHT_MASK 0xf
#endif

struct paccel;
struct vaccel;

struct optimus {
    struct device *pafu_device;
    u8 *pafu_mmio;
    struct list_head next;

    struct mutex ops_lock;
    struct list_head vaccel_list;

    #ifdef SCHED_ENABLE_WEIGHT
    u64 weights;
    #endif

    struct iommu_domain *domain;
    int iommu_map_flags;

    atomic_t next_seq_id;

    u32 npaccels;
    struct paccel *paccels;

    struct task_struct *scheduler;
    int user_check_signal;
};

#define SIZE_64G (64*1024*1024*1024LLU)
#define SIZE_4K 4096LLU

#define OPTIMUS_BAR_0_SIZE 0x1000
#define OPTIMUS_BAR_2_SIZE 0x100
#define OPTIMUS_BAR_0_MASK ~(OPTIMUS_BAR_0_SIZE - 1)
#define OPTIMUS_BAR_2_MASK ~(OPTIMUS_BAR_2_SIZE - 1)

#define OPTIMUS_GUID_HI 0xd1d383aaca4c4c60
#define OPTIMUS_GUID_LO 0xa0a013a421139e69
#define OPTIMUS_MAGIC 0xfffff

#define OPTIMUS_TRANS_CTL 0x18
#define OPTIMUS_TRANS_CTL_IDLE 0
#define OPTIMUS_TRANS_CTL_BUSY 1
#define OPTIMUS_TRANS_CTL_FINISH 2
#define OPTIMUS_TRANS_CTL_ABORT 3
#define OPTIMUS_TRANS_CTL_PAUSE 4
#define OPTIMUS_TRANS_CTL_CONT 5
#define OPTIMUS_TRANS_CTL_REQUEST_PAUSE 6

#define OPTIMUS_TRANS_CTL_PAUSE_WAIT_MS 100

#define OPTIMUS_STATE_SZ 0x20

enum {
    VACCEL_BAR_0,
    VACCEL_BAR_2,
    VACCEL_BAR_NUM
};

typedef enum {
    VACCEL_TYPE_DIRECT,
    VACCEL_TYPE_TIME_SLICING
} optimus_mode_t;

struct paccel_ops {
    int (*vaccel_init)(struct vaccel *vaccel, struct paccel *paccel, struct mdev_device *mdev);
    int (*vaccel_uinit)(struct vaccel *vaccel);
    int (*dump)(struct paccel *paccel);
};

struct vaccel_ops {
    int (*open)(struct mdev_device *mdev);
    int (*close)(struct mdev_device *mdev);
    int (*handle_mmio_read)(struct vaccel *vaccel, u32 index, u32 offset, u64 *val);
    int (*handle_mmio_write)(struct vaccel *vaccel, u32 index, u32 offset, u64 val);
    int (*soft_reset)(struct vaccel *vaccel);
    int (*set_mux_offset)(struct vaccel *vaccel);
};

extern struct mutex optimus_list_lock;
extern struct list_head optimus_list;

extern struct paccel_ops paccel_direct_ops;
extern struct paccel_ops paccel_time_slicing_ops;
extern struct vaccel_ops vaccel_direct_ops;
extern struct vaccel_ops vaccel_time_slicing_ops;

typedef enum {
    PACCEL_TS_POLICY_RR,
    PACCEL_TS_POLICY_FAIR_ABORT,
    PACCEL_TS_POLICY_FAIR_NOTIFY
} paccel_ts_sched_policy_t;

#define PACCEL_TS_MAX_PERIOD_MS 1
#define PACCEL_PREEMPT_WAIT_CYCLE 0

struct paccel {
    struct optimus *optimus;
    optimus_mode_t mode;

    u32 mode_id;
    u32 accel_id;

    u32 mmio_start;
    u32 mmio_size;

    struct mutex ops_lock;

    union {
        struct {
            bool occupied;
        } direct;
        struct {
            u32 total;
            u32 occupied;
            paccel_ts_sched_policy_t policy;
            struct list_head children;
            struct vaccel *curr;
            u64 state_sz;
        } timeslc;
    };

    struct paccel_ops *ops;
};

typedef enum {
    VACCEL_TRANSACTION_IDLE,
    VACCEL_TRANSACTION_STARTED,
    VACCEL_TRANSACTION_HARDWARE
} vaccel_trans_stat_t;

struct vaccel {
    struct optimus *optimus;
    struct paccel *paccel;

    u8 *vconfig;
    u8 *bar[VACCEL_BAR_NUM];

    optimus_mode_t mode;
    u32 seq_id;

    bool enabled;

    u64 gva_start;
    u64 iova_start;
    u64 paging_notifier_gpa;

    struct mutex ops_lock;
    struct list_head next;

    struct kvm *kvm;
    struct mdev_device *mdev;
    struct notifier_block group_notifier;

    struct page *dummy_page;

    union {
        struct {
            u32 padding;
        } direct;
        struct {
            struct list_head paccel_next;
            vaccel_trans_stat_t trans_status;
            u64 start_time;
            u64 running_time;
            u32 weight;
        } timeslc;
    };

    struct vaccel_ops *ops;
};

struct vaccel_paging_notifier {
    uint64_t va;
    uint64_t pa;
};

struct vaccel_fast_paging_notifier {
    uint32_t num_pages;
    uint16_t behavior;
    uint16_t pgsize_flag;
    uint64_t gva_start_addr;
    uint64_t gpas[0];
};

void dump_buffer_32(char *buf, uint32_t count);
void dump_buffer_64(char *buf, uint32_t count);

int vaccel_read_gpa(struct vaccel *vaccel,
            u64 gpa, void *buf, u64 len);

struct paccel* kobj_to_paccel(struct kobject *kobj,
            struct optimus *optimus, struct mdev_device *mdev,
            optimus_mode_t *mode, u32 *mode_id);
struct optimus* mdev_to_optimus(struct mdev_device *mdev);
struct optimus* pdev_to_optimus(struct platform_device *pdev);
struct optimus* device_to_optimus(struct device *pafu);

void iommu_unmap_region(struct iommu_domain *domain,
                int flags, u64 start, u64 npages);
void iommu_protect_range(struct vaccel *vaccel);
int vaccel_iommu_page_map(struct vaccel *vaccel,
            u64 gpa, u64 gva, u64 pgsize);
void vaccel_iommu_page_unmap(struct vaccel *vaccel, u64 gva, u64 pgsize);

void dump_paccels(struct optimus *optimus);

void vaccel_create_config_space(struct vaccel *vaccel);
void do_paccel_soft_reset(struct paccel *paccel, bool lock);
void do_vaccel_bar_cleanup(struct vaccel *vaccel);
int vaccel_handle_bar2_write(struct vaccel *vaccel,
                u32 offset, u64 val);

int vaccel_group_notifier(struct notifier_block *nb,
            long unsigned int action, void *data);

int kthread_watch_time(void *optimus_param);

#define OPTIMUS_DBG

#ifdef OPTIMUS_DBG
extern int optimus_dbg;
extern unsigned long long tlb_opt_offset;

#define optimus_err(fmt, args...) \
    if (optimus_dbg) {pr_err("optimus: "fmt, ##args);}
#define optimus_info(fmt, args...) \
    if (optimus_dbg) {pr_info("optimus: "fmt, ##args);}

#define paccel_err(paccel, fmt, args...) \
    if (optimus_dbg) {pr_err("paccel[%d]: "fmt, paccel->accel_id, ##args);}
#define paccel_info(paccel, fmt, args...) \
    if (optimus_dbg) {pr_info("paccel[%d]: "fmt, paccel->accel_id, ##args);}

#define vaccel_err(vaccel, fmt, args...) \
    if (optimus_dbg) {pr_err("vaccel[%d]: "fmt, vaccel->seq_id, ##args);}
#define vaccel_info(vaccel, fmt, args...) \
    if (optimus_dbg) {pr_info("vaccel[%d]: "fmt, vaccel->seq_id, ##args);}

#endif

extern int optimus_timeslc_mask;

#endif /* _VAI_INTERNAL_H_ */
