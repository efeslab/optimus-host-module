#include "afu.h"
#include "fisor.h"

static vaccel_time_slicing_init(struct vaccel *vaccel,
                struct paccel *paccel, struct mdev *mdev)
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

    if (paccel->tm.total <= paccel->tm.occupied) {
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
    vaccel->ops = &vaccel_direct_ops;
    vaccel->paging_notifier_gpa = 0;
    vaccel->tm.trans_status = VACCEL_TRANSACTION_IDLE;
    mutex_init(&vaccel->ops_lock);
    mutex_init(&vaccel->tm.trans_lock);

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
    paccel->tm.occupied++;
    list_add(&vaccel->paccel_next, &paccel->tm.children);
    mutex_unlock(&paccel->ops_lock);

    return 0;
}

static int vaccel_time_slicing_uinit(struct vaccel *vaccel)
{
    struct vaccel *d, *tmp_d;
    struct fisor *fisor = vaccel->fisor;
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
    paccel->tm.occupied--;
    list_for_each_entry_safe(d, tmp_d, &paccel->tm.children, paccel_next) {
        if (vaccel == d) {
            list_del(&vaccel->paccel_next);
            ret = 0;
            break;
        }
    }
    mutex_unlock(&paccel->ops_lock);

    return ret;
}

static void do_vaccel_time_slicing(struct fisor *fisor)
{
    
}

static int vaccel_time_slicing_handle_mmio_read(struct vaccel *vaccel,
            u32 index, u32 offset, u64 *val)
{
    struct fisor *fisor = vaccel->fisor;
    struct paccel *paccel = vaccel->paccel;
    int ret;

    if (vaccel->mode != VACCEL_TYPE_TIME_SLICING) {
        vaccel_err(vaccel, "wrong mode");
        return -EINVAL;
    }

    if (index % 0x8 != 0) {
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
            do_vaccel_bar_cleanup(fisor);
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

    if (index % 0x8 != 0) {
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
            if (vaccel->tm.trans_status == VACCEL_TRANSACTION_STARTED) {
                vaccel_info(vaccel, "previous transaction not finished");
            }
            vaccel->tm.trans_status = VACCEL_TRANSACTION_STARTED;
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

static int vaccel_time_slicing_submit(struct vaccel *vaccel)
{
    struct fisor *fisor = vaccel->fisor;
    struct paccel *paccel = vaccel->paccel;
    u8 mmio_base = fisor->pafu_mmio + paccel->mmio_start;
    u64 mux_offset = vaccel->iova_start/CL(1) - vaccel->gva_start/CL(1);
    u64 vm_cfg_offset = vaccel->paccel->accel_id * 8 + 0x30;
    int idx;
    u64 data64;

    /* configure the accelerator with new address */
    writeq(mux_offset, &fisor->pafu_mmio[vm_cfg_offset]);

    /* reset the accelerator */
    do_paccel_soft_reset(paccel);

    /* fill all the registers again */
    for (idx=0x20; idx<0x100; idx+=8) {
        data64 = *(u64*)(vaccel->bar[VACCEL_BAR_0]+idx);
        if (data64 != 0) {
            writeq(data64, &mmio_base[idx]);
        }
    }

    /* write transaction begin */
    writeq(1, &mmio_base[0x18]);

    /* cleanup the bar after transaction */




struct paccel_ops paccel_direct_ops = {
    .vaccel_init = vaccel_time_slicing_init,
    .vaccel_uinit = vaccel_time_slicing_uinit
};

struct vaccel_ops vaccel_time_slicing_ops = {
    .handle_mmio_read = vaccel_time_slicing_handle_mmio_read,
    .handle_mmio_write = vaccel_time_slicing_handle_mmio_write,
    .submit_to_hardware = vaccel_time_slicing_submit
};
