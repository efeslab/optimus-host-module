#include "afu.h"
#include "fisor.h"

static int vaccel_direct_init(struct vaccel *vaccel,
                struct paccel *paccel, struct mdev *mdev)
{
    struct fisor *fisor;

    if (!mdev || !vaccel || !paccel)
        return -EINVAL;

    fisor = paccel->fisor;
    if (!fisor)
        return -EINVAL;

    if (paccel->mode != VACCEL_TYPE_DIRECT) {
        paccel_err(paccel, "invalid mode");
        return -EINVAL;
    }

    if (paccel->sm.occupied) {
        paccel_err(paccel, "already occupied");
        return -EINVAL;
    }

    vaccel->mode = VACCEL_TYPE_DIRECT;
    vaccel->paccel = paccel;
    vaccel->fisor = fisor;
    vaccel->gva_start = 0;
    vaccel->mdev = mdev;
    vaccel->seq_id = atomic_fetch_add(1, &fisor->next_seq_id);
    vaccel->iova_start = vaccel->seq_id * SIZE_64G;
    vaccel->ops = &vaccel_direct_ops;
    vaccel->paging_notifier_gpa = 0;
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
    paccel->sm.occupied = true;
    mutex_unlock(&paccel->ops_lock);

    return 0;
}

static int vaccel_direct_uinit(struct vaccel *vaccel)
{
    struct paccel *paccel = vaccel->paccel;

    if (vaccel->mode != VACCEL_TYPE_DIRECT) {
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
    paccel->sm.occupied = false;
    mutex_unlock(&paccel->ops_lock);

    return 0;
}

static int vaccel_direct_handle_mmio_read(struct vaccel *vaccel,
        u32 index, u32 offset, u64 *val)
{
    struct fisor *fisor = vaccel->fisor;
    struct paccel *paccel = vaccel->paccel;
    int ret;
    u64 data64;

    if (vaccel->mode != VACCEL_TYPE_DIRECT) {
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

        offset = offset + paccel->mmio_start;
        data64 = readq(&fisor->pafu_mmio[offset]);
        *val = data64;
    } else {
        switch (offset) {
        default:
            LOAD_LE64(&vaccel->bar[VACCEL_BAR_2][offset], *val);
            break;
        }
    }

    return 0;
}

static int vaccel_direct_handle_mmio_write(struct vaccel *vaccel,
        u32 index, u32 offset, u64 val)
{
    struct fisor *fisor = vaccel->fisor;
    struct paccel *paccel = vaccel->paccel;
    int ret;

    if (vaccel->mode != VACCEL_TYPE_DIRECT) {
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

        offset = offset + paccel->mmio_start;
        writeq(val, &fisor->pafu_mmio[offset]);

    } else if (index == VFIO_PCI_BAR2_REGION_INDEX) {
        ret = vaccel_handle_bar2_write(vaccel, offset, val);
        if (ret)
            return ret;
    }

    return 0;
}

struct paccel_ops paccel_direct_ops = {
    .vaccel_init = vaccel_direct_init,
    .vaccel_uinit = vaccel_direct_uinit
};

struct vaccel_ops vaccel_direct_ops = {
    .handle_mmio_read = vaccel_direct_handle_mmio_read,
    .handle_mmio_write = vaccel_direct_handle_mmio_write,
    .submit_to_hardware = NULL
};
