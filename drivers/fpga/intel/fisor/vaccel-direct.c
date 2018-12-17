#include "afu.h"
#include "fisor.h"

static int paccel_direct_dump(struct paccel *paccel)
{
    u32 accel_id = paccel->accel_id;
    u32 mmio_start = paccel->mmio_start;
    u32 mmio_size = paccel->mmio_size;
    bool occupied = paccel->direct.occupied;

    paccel_info(paccel, "phys accelerator #%d, mmio %x, mmio_size %x, occupied %s\n",
                accel_id, mmio_start, mmio_size, occupied?"true":"false");

    return 0;
}

static int vaccel_direct_init(struct vaccel *vaccel,
                struct paccel *paccel, struct mdev_device *mdev)
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

    if (paccel->direct.occupied) {
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
    paccel->direct.occupied = true;
    mutex_unlock(&paccel->ops_lock);

    return 0;
}

static int vaccel_direct_uinit(struct vaccel *vaccel)
{
    struct mdev_device *mdev = vaccel->mdev;
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
    paccel->direct.occupied = false;
    mutex_unlock(&paccel->ops_lock);

    return 0;
}

static int vaccel_direct_handle_mmio_read(struct vaccel *vaccel,
        u32 index, u32 offset, u64 *val)
{
    struct fisor *fisor = vaccel->fisor;
    struct paccel *paccel = vaccel->paccel;
    u64 data64;

    if (vaccel->mode != VACCEL_TYPE_DIRECT) {
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

    if (offset % 0x8 != 0) {
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

static int vaccel_direct_open(struct mdev_device *mdev)
{
    unsigned long events;
    struct vaccel *vaccel = mdev_get_drvdata(mdev);
    struct paccel *paccel = vaccel->paccel;

    vaccel_info(vaccel, "vaccel: %s\n", __func__);

    vaccel->group_notifier.notifier_call = vaccel_group_notifier;

    events = VFIO_GROUP_NOTIFY_SET_KVM;
    vfio_register_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY, &events,
                &vaccel->group_notifier);

    /* set using to true */
    vaccel->enabled = true;

    do_paccel_soft_reset(paccel);

    return 0;
}

static int vaccel_direct_close(struct mdev_device *mdev)
{
    struct vaccel *vaccel = mdev_get_drvdata(mdev);

    vaccel_info(vaccel, "call: %s\n", __func__);

    vaccel->enabled = false;
    vfio_unregister_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY,
                &vaccel->group_notifier);
    iommu_unmap_region(vaccel->fisor->domain,
                vaccel->fisor->iommu_map_flags,
                vaccel->iova_start,
                SIZE_64G >> PAGE_SHIFT);

    return 0;
}

static int vaccel_direct_soft_reset(struct vaccel *vaccel)
{
    /* to soft reset we write a special register */
    do_paccel_soft_reset(vaccel->paccel);
    return 0;
}

struct paccel_ops paccel_direct_ops = {
    .vaccel_init = vaccel_direct_init,
    .vaccel_uinit = vaccel_direct_uinit,
    .dump = paccel_direct_dump,
};

struct vaccel_ops vaccel_direct_ops = {
    .open = vaccel_direct_open,
    .close = vaccel_direct_close,
    .soft_reset = vaccel_direct_soft_reset,
    .handle_mmio_read = vaccel_direct_handle_mmio_read,
    .handle_mmio_write = vaccel_direct_handle_mmio_write,
};
