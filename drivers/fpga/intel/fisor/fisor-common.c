#include "afu.h"
#include "fisor.h"

void dump_buffer_32(char *buf, uint32_t count)
{
	int i;
    uint32_t *x = (uint32_t*)buf;

    for (i = 0; i < count; i+=4) {
        x = (uint32_t*)(buf+i);
        fisor_info("buffer: %x\n", *x);
    }
}

void dump_buffer_64(char *buf, uint32_t count)
{
	int i;
    uint64_t *x = (uint64_t*)buf;

    for (i = 0; i < count; i+=8) {
        x = (uint64_t*)(buf+i);
        fisor_info("buffer: %llx\n", *x);
    }
}

struct paccel* kobj_to_paccel(struct kobject *kobj,
            struct fisor *fisor, struct mdev_device *mdev,
            fisor_mode_t *mode, u32 *mode_id)
{
    char name[FISOR_STRING_LEN];
    struct paccel *paccel = NULL;
    int i;

    for (i=0; i<fisor->npaccels; i++) {

        if (fisor->paccels[i].mode == VACCEL_TYPE_DIRECT) {
            snprintf(name, FISOR_STRING_LEN, "%s-direct-%d",
                        dev_driver_string(mdev_parent_dev(mdev)),
                        fisor->paccels[i].mode_id);
        }
        else {
            snprintf(name, FISOR_STRING_LEN, "%s-time_slicing-%d",
                        dev_driver_string(mdev_parent_dev(mdev)),
                        fisor->paccels[i].mode_id);
        }

        fisor_info("%s: scan %s\n", __func__, name);

        if (!strcmp(kobj->name, name)) {
            *mode = fisor->paccels[i].mode;
            *mode_id = fisor->paccels[i].mode_id;
            paccel = &fisor->paccels[i];
            return paccel;
        }
    }

    *mode = VACCEL_TYPE_DIRECT;
    *mode_id = -1;

    return NULL;
}

struct fisor* mdev_to_fisor(struct mdev_device *mdev)
{
    struct fisor *d, *tmp_d;
    struct fisor *ret = NULL;

    mutex_lock(&fisor_list_lock);
    list_for_each_entry_safe(d, tmp_d, &fisor_list, next) {
        if (d->pafu_device == mdev_parent_dev(mdev)) {
            fisor_info("%s: found fisor\n", __func__);
            ret = d;
            break;
        }
    }
    mutex_unlock(&fisor_list_lock);

    return ret;
}

void iommu_unmap_region(struct iommu_domain *domain,
                int flags, u64 start, u64 npages)
{
    long idx, idx_end;
    u64 cnt = 0;

    fisor_info("unmap iommu region start %llx pages %llx\n", start, npages);

    idx = start;
    idx_end = start + npages * PAGE_SIZE;
    for (; idx < idx_end; idx += PAGE_SIZE) {
        if (iommu_iova_to_phys(domain, idx)) {
            iommu_unmap(domain, idx, PAGE_SIZE);
            kvm_release_pfn_clean(pfn);
            cnt++;
        }
    }

    fisor_info("unmap %lld pages\n", cnt);
}

struct fisor* pdev_to_fisor(struct platform_device *pdev)
{
    struct device *pafu = &pdev->dev;
    struct fisor *d, *tmp_d;
    struct fisor *ret = NULL;

    mutex_lock(&fisor_list_lock);
    list_for_each_entry_safe(d, tmp_d, &fisor_list, next) {
        if (d->pafu_device == pafu) {
            fisor_info("%s: found fisor\n", __func__);
            ret = d;
            break;
        }
    }
    mutex_unlock(&fisor_list_lock);

    return ret;
}

struct fisor* device_to_fisor(struct device *pafu)
{
    struct fisor *d, *tmp_d;
    struct fisor *ret = NULL;

    mutex_lock(&fisor_list_lock);
    list_for_each_entry_safe(d, tmp_d, &fisor_list, next) {
        if (d->pafu_device == pafu) {
            fisor_info("%s: found fisor\n", __func__);
            ret = d;
            break;
        }
    }
    mutex_unlock(&fisor_list_lock);

    return ret;
}


