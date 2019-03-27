#include "afu.h"
#include "fisor.h"

static int paccel_timeslc_dump(struct paccel *paccel)
{
    u32 accel_id = paccel->accel_id;
    u32 mmio_start = paccel->mmio_start;
    u32 mmio_size = paccel->mmio_size;
    u32 avail_inst = paccel->timeslc.total;
    u32 curr_inst = paccel->timeslc.occupied;

    paccel_info(paccel, "fisor: phys accelerator #%d, mmio %x, mmio_size %x, avail %d, curr %d\n",
                accel_id, mmio_start, mmio_size, avail_inst, curr_inst);

    return 0;
}
 

static int vaccel_time_slicing_init(struct vaccel *vaccel,
                struct paccel *paccel, struct mdev_device *mdev)
{
    struct fisor *fisor;

    if (!mdev || !vaccel || !paccel)
        return -EINVAL;

    fisor = paccel->fisor;
    if (!fisor)
        return -EINVAL;

    if (paccel->mode != VACCEL_TYPE_TIME_SLICING) {
        paccel_err(paccel, "invalid mode");
        return -EINVAL;
    }

    if (paccel->timeslc.total <= paccel->timeslc.occupied) {
        paccel_err(paccel, "too many vaccels");
        return -EINVAL;
    }

    vaccel->mode = VACCEL_TYPE_TIME_SLICING;
    vaccel->paccel = paccel;
    vaccel->fisor = fisor;
    vaccel->gva_start = 0;
    vaccel->mdev = mdev;
    vaccel->seq_id = atomic_fetch_add(1, &fisor->next_seq_id);
    vaccel->iova_start = vaccel->seq_id * SIZE_64G;
    vaccel->ops = &vaccel_time_slicing_ops;
    vaccel->paging_notifier_gpa = 0;
    vaccel->timeslc.trans_status = VACCEL_TRANSACTION_IDLE;
    mutex_init(&vaccel->ops_lock);

    /* create pcie config space */
    vaccel->vconfig = kzalloc(FISOR_CONFIG_SPACE_SIZE, GFP_KERNEL);
    if (!vaccel->vconfig) {
        kfree(vaccel);
        return -ENOMEM;
    }
    vaccel_create_config_space(vaccel);

    /* allocate bar */
    vaccel->bar[VACCEL_BAR_0] = kzalloc(FISOR_BAR_0_SIZE, GFP_KERNEL);
    vaccel->bar[VACCEL_BAR_2] = kzalloc(FISOR_BAR_2_SIZE, GFP_KERNEL);

    /* register to mdev */
    mdev_set_drvdata(mdev, vaccel);

    /* set occupied */
    mutex_lock(&paccel->ops_lock);
    paccel->timeslc.occupied++;
    list_add(&vaccel->timeslc.paccel_next, &paccel->timeslc.children);
    mutex_unlock(&paccel->ops_lock);

    return 0;
}

static int vaccel_time_slicing_uinit(struct vaccel *vaccel)
{
    struct mdev_device *mdev = vaccel->mdev;
    struct vaccel *d, *tmp_d;
    struct paccel *paccel = vaccel->paccel;
    int ret = -EINVAL;

    if (vaccel->mode != VACCEL_TYPE_TIME_SLICING) {
        vaccel_err(vaccel, "invalid mode");
        return -EINVAL;
    }

    mdev_set_drvdata(mdev, NULL);

    /* free all allocated regions */
    kfree(vaccel->vconfig);
    kfree(vaccel->bar[VACCEL_BAR_0]);
    kfree(vaccel->bar[VACCEL_BAR_2]);
    vaccel->vconfig = NULL;
    vaccel->bar[VACCEL_BAR_0] = NULL;
    vaccel->bar[VACCEL_BAR_2] = NULL;

    /* set occupied as false */
    mutex_lock(&paccel->ops_lock);
    paccel->timeslc.occupied--;
    list_for_each_entry_safe(d, tmp_d, &paccel->timeslc.children, timeslc.paccel_next) {
        if (vaccel == d) {
            list_del(&vaccel->timeslc.paccel_next);
            ret = 0;
            break;
        }
    }
    mutex_unlock(&paccel->ops_lock);

    return ret;
}

static bool fisor_hw_check_trans_finished(struct paccel *paccel)
{
    u8 *mmio_base;
    u64 data64;
    struct fisor *fisor;

    WARN_ON(paccel == NULL);
    WARN_ON(paccel->fisor == NULL);

    fisor = paccel->fisor;
    mmio_base = fisor->pafu_mmio + paccel->mmio_start;
    data64 = readq(&mmio_base[0x18]);

    if (data64 != 0)
        return true;
    else
        return false;
}

static int vaccel_time_slicing_submit(struct vaccel *vaccel)
{
    struct fisor *fisor = vaccel->fisor;
    struct paccel *paccel = vaccel->paccel;
    u8 *mmio_base = fisor->pafu_mmio + paccel->mmio_start;
    u64 mux_offset = vaccel->iova_start/CL(1) - vaccel->gva_start/CL(1);
    u64 vm_cfg_offset = vaccel->paccel->accel_id * 8 + 0x30;
    int idx;
    u64 data64;

    /* configure the accelerator with new address */
    writeq(mux_offset, &fisor->pafu_mmio[vm_cfg_offset]);

    /* reset the accelerator */
    do_paccel_soft_reset(paccel, false);

    /* fill all the registers again */
    for (idx=0x20; idx<0x1000; idx+=8) {
        data64 = *(u64*)(vaccel->bar[VACCEL_BAR_0]+idx);
        if (data64 != 0) {
            writeq(data64, &mmio_base[idx]);
        }
    }

    /* write transaction begin */
    writeq(1, &mmio_base[0x18]);

    /* cleanup the bar after transaction */
    do_vaccel_bar_cleanup(vaccel);

    return 0;
}

static void do_vaccel_time_slicing(struct fisor *fisor)
{
    struct paccel *paccels;
    u32 npaccels;
    int i;

    fisor_info("%s", __func__);

    mutex_lock(&fisor->ops_lock);

    paccels = fisor->paccels;
    npaccels = fisor->npaccels;

    for (i=0; i<npaccels; i++) {
        struct paccel *paccel = &paccels[i];
        struct vaccel *ptr = NULL, *round = NULL, *last = NULL;

        if (paccel->mode == VACCEL_TYPE_DIRECT) {
            continue;
        }

        mutex_lock(&paccel->ops_lock);

        last = list_last_entry(&paccel->timeslc.children,
                    struct vaccel, timeslc.paccel_next);
        ptr = paccel->timeslc.curr;
        if (ptr) {
            if (ptr->enabled == false) {
                fisor_info("slicing: curr vaccel %d not enabled",
                            ptr->seq_id);
                continue;
            }

            fisor_info("slicing: curr vaccel %d", ptr->seq_id);

            if (ptr->timeslc.trans_status ==
                        VACCEL_TRANSACTION_HARDWARE) {
                if (fisor_hw_check_trans_finished(paccel)) {
                    fisor_info("slicing: curr vaccel %d finished",
                                    ptr->seq_id);

                    /* the transaction is finished */
                    ptr->timeslc.trans_status = VACCEL_TRANSACTION_IDLE;
                    STORE_LE64((u64*)&ptr->bar[VACCEL_BAR_0][0x18], 0x2);

                    round = ptr;
                    if (ptr == last) {
                        ptr = list_first_entry(&paccel->timeslc.children,
                                    struct vaccel, timeslc.paccel_next);
                    }
                    else {
                        ptr = list_next_entry(ptr, timeslc.paccel_next);
                    }
                }
                else {
                    /* the transacetion is unfinished, skip */
                    fisor_info("slicing: curr vaccel %d still running",
                                    ptr->seq_id);
                    continue;
                }
            }
        }
        else {
            fisor_info("slicing: curr vaccel NULL");
            ptr = list_first_entry(&paccel->timeslc.children,
                        struct vaccel, timeslc.paccel_next);
            round = ptr;
        }

        do {
            if (ptr->timeslc.trans_status
                        == VACCEL_TRANSACTION_STARTED) {
                fisor_info("slicing: vaccel %d selected", ptr->seq_id);
                vaccel_time_slicing_submit(ptr);
                ptr->timeslc.trans_status = VACCEL_TRANSACTION_HARDWARE;
                paccel->timeslc.curr = ptr;
            }
            else {
                fisor_info("slicing: vaccel %d empty, skipped", ptr->seq_id);
                fisor_info("ptr: %#llx, round: %#llx\n", ptr, round);
            }

            if (ptr == last) {
                ptr = list_first_entry(&paccel->timeslc.children,
                            struct vaccel, timeslc.paccel_next);
                fisor_info("ptr: %#llx, round: %#llx\n", ptr, round);
            }
            else {
                ptr = list_next_entry(ptr, timeslc.paccel_next);
                fisor_info("ptr: %#llx, round: %#llx\n", ptr, round);
            }
        } while (ptr != round);

        mutex_unlock(&paccel->ops_lock);
    }

    mutex_unlock(&fisor->ops_lock);

    fisor_info("%s exit", __func__);
}

static int vaccel_time_slicing_handle_mmio_read(struct vaccel *vaccel,
            u32 index, u32 offset, u64 *val)
{
    struct fisor *fisor = vaccel->fisor;
    struct paccel *paccel = vaccel->paccel;

    if (vaccel->mode != VACCEL_TYPE_TIME_SLICING) {
        vaccel_err(vaccel, "wrong mode");
        return -EINVAL;
    }

    if (offset % 0x8 != 0) {
        vaccel_err(vaccel, "MMIO not 8 bytes aligned");
        return -EINVAL;
    }

    if (index == VFIO_PCI_BAR0_REGION_INDEX) {
        if (offset + 0x8 >= paccel->mmio_size) {
            vaccel_err(vaccel, "offset too large");
            return -EINVAL;
        }
        
        LOAD_LE64(&vaccel->bar[VACCEL_BAR_0][offset], *val);

        if (offset == 0x18) {
            /* if someone is reading this, we also do a round
             * of scheduling */
            do_vaccel_time_slicing(fisor);
        }
    } else {
        switch (offset) {
        default:
            LOAD_LE64(&vaccel->bar[VACCEL_BAR_2][offset], *val);
            break;
        }
    }

    return 0;
}

static int vaccel_time_slicing_handle_mmio_write(struct vaccel *vaccel,
            u32 index, u32 offset, u64 val)
{
    struct fisor *fisor = vaccel->fisor;
    struct paccel *paccel = vaccel->paccel;
    int ret;

    if (vaccel->mode != VACCEL_TYPE_TIME_SLICING) {
        vaccel_err(vaccel, "wrong mode");
        return -EINVAL;
    }

    if (offset % 0x8 != 0) {
        vaccel_err(vaccel, "MMIO not 8 bytes aligned");
        return -EINVAL;
    }

    if (index == VFIO_PCI_BAR0_REGION_INDEX) {

        if (offset + 0x8 > paccel->mmio_size) {
            vaccel_err(vaccel, "offset too large");
            return -EINVAL;
        }

        /* for time slicing device, we just store the value
         * in the bar */
        STORE_LE64(&vaccel->bar[VACCEL_BAR_0][offset], val);

        /* if offset == 0x18, it is transaction register */
        if (offset == 0x18) {
            if (vaccel->timeslc.trans_status == VACCEL_TRANSACTION_STARTED) {
                vaccel_info(vaccel, "previous transaction not finished");
            }
            vaccel->timeslc.trans_status = VACCEL_TRANSACTION_STARTED;
        }

        /* fisor follows a asyncchronized scheduling schema,
         * when a transaction started, fisor checks all pending
         * transactions, and decides which to run next. */
        do_vaccel_time_slicing(fisor);

    } else if (index == VFIO_PCI_BAR2_REGION_INDEX) {
        ret = vaccel_handle_bar2_write(vaccel, offset, val);
        if (ret)
            return ret;
    }

    return 0;
}

static int vaccel_time_slicing_open(struct mdev_device *mdev)
{
    unsigned long events;
    struct vaccel *vaccel = mdev_get_drvdata(mdev);

    vaccel_info(vaccel, "call: %s\n", __func__);

    vaccel->group_notifier.notifier_call = vaccel_group_notifier;

    events = VFIO_GROUP_NOTIFY_SET_KVM;
    vfio_register_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY, &events,
                &vaccel->group_notifier);

    /* set using to true, polling uses this information */
    vaccel->enabled = true;

    do_vaccel_bar_cleanup(vaccel);

    return 0;
}

static int vaccel_time_slicing_close(struct mdev_device *mdev)
{
    struct vaccel *vaccel = mdev_get_drvdata(mdev);
    struct paccel *paccel = vaccel->paccel;

    mutex_lock(&paccel->ops_lock);
    if (paccel->timeslc.curr == vaccel)
        paccel->timeslc.curr == NULL;
    mutex_unlock(&paccel->ops_lock);

    vaccel_info(vaccel, "call: %s\n", __func__);

    vaccel->enabled = false;
    vfio_unregister_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY,
                &vaccel->group_notifier);
    iommu_unmap_region(vaccel->fisor->domain,
                vaccel->fisor->iommu_map_flags,
                vaccel->iova_start,
                SIZE_64G >> PAGE_SHIFT);

    do_vaccel_bar_cleanup(vaccel);

    vaccel_info(vaccel, "closed");

    return 0;
}

static int vaccel_time_slicing_soft_reset(struct vaccel *vaccel)
{
    return 0;
}

struct paccel_ops paccel_time_slicing_ops = {
    .vaccel_init = vaccel_time_slicing_init,
    .vaccel_uinit = vaccel_time_slicing_uinit,
    .dump = paccel_timeslc_dump,
};

struct vaccel_ops vaccel_time_slicing_ops = {
    .open = vaccel_time_slicing_open,
    .close = vaccel_time_slicing_close,
    .soft_reset = vaccel_time_slicing_soft_reset,
    .handle_mmio_read = vaccel_time_slicing_handle_mmio_read,
    .handle_mmio_write = vaccel_time_slicing_handle_mmio_write,
};
