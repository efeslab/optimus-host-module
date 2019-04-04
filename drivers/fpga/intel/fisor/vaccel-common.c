#include "afu.h"
#include "fisor.h"

static u64 vaccel_kvm_host_page_size(struct kvm *kvm, gfn_t gfn)
{
    struct vm_area_struct *vma;
    unsigned long addr, size;

    size = PAGE_SIZE;

    addr = gfn_to_hva(kvm, gfn);
    if (kvm_is_error_hva(addr))
        return PAGE_SIZE;

    down_read(&current->mm->mmap_sem);
    vma = find_vma(current->mm, addr);
    if (!vma)
        goto out;

    size = vma_kernel_pagesize(vma);

out:
    up_read(&current->mm->mmap_sem);

    return size;
}

int vaccel_iommu_page_map(struct vaccel *vaccel,
            u64 gpa, u64 gva, u64 pgsize)
{
    struct kvm *kvm = vaccel->kvm;
    gfn_t gfn = gpa >> PAGE_SHIFT;
    kvm_pfn_t pfn, old_pfn;
    struct iommu_domain *domain = vaccel->fisor->domain;
    int flags = vaccel->fisor->iommu_map_flags;
    u64 host_pgsize = vaccel_kvm_host_page_size(kvm, gfn);

    fisor_info("%s: iommu map gva %llx to gpa %llx pgsize %llx\n",
                    __func__, gva, gpa, pgsize);

    if (host_pgsize < pgsize) {
        u64 off, ret;

        fisor_info("%s: host page size less than guest page size", __func__);
        for (off = 0; off < pgsize; off += PAGE_SIZE) {
            ret = vaccel_iommu_page_map(vaccel, gpa + off, gva + off, PAGE_SIZE);

            if (ret) {
                fisor_err("%s: map failed", __func__);
                break;
            }
        }
        return ret;
    }

    pfn = gfn_to_pfn(kvm, gfn);

    /* add to IOMMU */
    if (!IS_ALIGNED((unsigned long)(gva), pgsize)) {
        vaccel_info(vaccel, "%s: err gva not aligned\n", __func__);
        return -EFAULT;
    }

    if (!IS_ALIGNED((unsigned long)(vaccel->iova_start), pgsize)) {
        vaccel_info(vaccel, "%s: err iova_start not aligned\n", __func__);
        return -EFAULT;
    }

    if (gva >= vaccel->gva_start + SIZE_64G) {
        vaccel_info(vaccel, "%s: err gva too large\n", __func__);
        return -EINVAL;
    }

    gva = gva - vaccel->gva_start + vaccel->iova_start;
    old_pfn = (iommu_iova_to_phys(domain, gva) >> PAGE_SHIFT);
    if (old_pfn) {
        iommu_unmap(domain, gva, pgsize);
        kvm_release_pfn_clean(old_pfn);
        vaccel_info(vaccel, "%s: clear already mapped\n", __func__);
    }

    vaccel_info(vaccel, "iommu_map %llx ==> %llx ==> %llx\n", gva, gpa, pfn << PAGE_SHIFT);

    return iommu_map(vaccel->fisor->domain, gva,
                        pfn << PAGE_SHIFT, pgsize, flags);
}

void vaccel_iommu_page_unmap(struct vaccel *vaccel, u64 gva, u64 pgsize)
{
    kvm_pfn_t pfn;
    int r;
    struct iommu_domain *domain = vaccel->fisor->domain;

    if (!IS_ALIGNED((unsigned long)(gva), pgsize)) {
        vaccel_info(vaccel, "%s: err gva not aligned\n", __func__);
        return;
    }

    if (!IS_ALIGNED((unsigned long)(vaccel->iova_start), pgsize)) {
        vaccel_info(vaccel, "%s: err iova_start not aligned\n", __func__);
        return;
    }

    if (gva >= vaccel->gva_start + SIZE_64G) {
        vaccel_info(vaccel, "%s: err gva too large\n", __func__);
        return;
    }

    gva = gva - vaccel->gva_start + vaccel->iova_start;
    pfn = (iommu_iova_to_phys(domain, gva) >> PAGE_SHIFT);
    
    if (pfn) {
        r = iommu_unmap(domain, gva, pgsize);
        kvm_release_pfn_clean(pfn);
    }
    else {
        vaccel_info(vaccel, "%s: free a unmapped page\n", __func__);
    }
}

void vaccel_create_config_space(struct vaccel *vaccel)
{
    /* PCI dev ID */
	STORE_LE32((u32 *) &vaccel->vconfig[0x0], 0xdeadbeef);

	/* Control: I/O+, Mem-, BusMaster- */
	STORE_LE16((u16 *) &vaccel->vconfig[0x4],
                PCI_COMMAND_IO | PCI_COMMAND_MEMORY);

	/* Status: capabilities list absent */
	STORE_LE16((u16 *) &vaccel->vconfig[0x6], 0x0200);

	/* Rev ID */
	vaccel->vconfig[0x8] =  0x10;

	/* programming interface class */
	vaccel->vconfig[0x9] =  0x00;

	/* Sub class : 00 */
	vaccel->vconfig[0xa] =  0x00;

	/* Base class : Simple Communication controllers */
	vaccel->vconfig[0xb] =  0xff;

    /* BAR 0 */
    STORE_LE32((u32 *) &vaccel->vconfig[0x10], 
                FISOR_BAR_0_MASK |
                PCI_BASE_ADDRESS_SPACE_MEMORY |
                PCI_BASE_ADDRESS_MEM_TYPE_64);

    /* BAR 1: upper 32 bits of BAR 0 */
    STORE_LE32((u32 *) &vaccel->vconfig[0x14], 0);

    /* BAR 2 */
    STORE_LE32((u32 *) &vaccel->vconfig[0x18],
                FISOR_BAR_2_MASK |
                PCI_BASE_ADDRESS_SPACE_MEMORY |
                PCI_BASE_ADDRESS_MEM_TYPE_64);

    /* BAR 3: upper 32 bits of BAR 2 */
    STORE_LE32((u32 *) &vaccel->vconfig[0x1c], 0);

	/* Subsystem ID */
	STORE_LE32((u32 *) &vaccel->vconfig[0x2c], 0x32534348);

	vaccel->vconfig[0x34] = 0x00;   /* Cap Ptr */
	vaccel->vconfig[0x3d] = 0x01;   /* interrupt pin (INTA#) */
}

static int vaccel_rw_gpa(struct vaccel *vaccel, u64 gpa,
            void *buf, u64 len, bool write)
{
    struct kvm *kvm = vaccel->kvm;
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

int vaccel_read_gpa(struct vaccel *vaccel, u64 gpa, void *buf, u64 len)
{
    return vaccel_rw_gpa(vaccel, gpa, buf, len, false);
}

int vaccel_write_gpa(struct vaccel *vaccel, u64 gpa, void *buf, u64 len)
{
    return vaccel_rw_gpa(vaccel, gpa, buf, len, true);
}

int vaccel_handle_bar2_write(struct vaccel *vaccel, u32 offset, u64 val)
{
    struct fisor *fisor = vaccel->fisor;
    struct paccel *paccel = vaccel->paccel;

    STORE_LE64(&vaccel->bar[VACCEL_BAR_2][offset], val);

    switch (offset) {
    case 0x0: /* PAGING_NOTIFY_MAP_ADDR */
    {
        vaccel->paging_notifier_gpa = val;
        vaccel_info(vaccel, "set paging notifier addr gpa %llx", val);
        break;
    }
    case 0x8: /* PAGING_NOTIFY_MAP */
    {
        struct vaccel_paging_notifier notifier;
        int ret;
        int idx;

        if (vaccel->paging_notifier_gpa == 0) {
            vaccel_err(vaccel, "invalid paging notify gpa\n");
            return -EFAULT;
        }

        /* read the structure from guest */
        ret = vaccel_read_gpa(vaccel, vaccel->paging_notifier_gpa,
                                &notifier, sizeof(notifier));
        if (ret) {
            vaccel_err(vaccel, "%s: read gpa error", __func__);
            return ret;
        }

        vaccel_info(vaccel, "paging notifier: %llx, va %llx, pa %llx",
                    vaccel->paging_notifier_gpa, notifier.va, notifier.pa);

        /* we have to hold the srcu since the following function 
         * will go through address translation */
        idx = srcu_read_lock(&vaccel->kvm->srcu);
        if (val == 0) { /* 0 for map */
            vaccel_iommu_page_map(vaccel, notifier.pa, notifier.va, PAGE_SIZE);
        } else {
            vaccel_iommu_page_unmap(vaccel, notifier.va, PAGE_SIZE);
        }
        srcu_read_unlock(&vaccel->kvm->srcu, idx);

        break;
    }
    case 0x38: /* FAST_PAGING_MAP */
    {
        int ret, idx, i, full_size;
        uint64_t notifier_gpa = val;
        uint64_t gva_iter;
        uint64_t pgsize;
        struct vaccel_fast_paging_notifier notifier, *notifier_full = NULL;

        ret = vaccel_read_gpa(vaccel, notifier_gpa, &notifier, sizeof(notifier));
        if (ret) {
            vaccel_err(vaccel, "%s: read gpa error", __func__);
            return ret;
        }

	    if (notifier.pgsize_flag == PGSIZE_FLAG_4K) {
            pgsize = PGSIZE_4K;
        }
        else if (notifier.pgsize_flag == PGSIZE_FLAG_2M) {
            pgsize = PGSIZE_2M;
        }
        else {
            pgsize = PGSIZE_1G;
        }

        if (!IS_ALIGNED((unsigned long)(notifier.gva_start_addr), pgsize)) {
            vaccel_err(vaccel, "%s: not page alligned", __func__);
            return -EFAULT;
        }

        if (notifier.behavior == 0) { /* 0 for map */
            full_size = sizeof(notifier) + sizeof(uint64_t) * notifier.num_pages;
            notifier_full = kmalloc(full_size, GFP_KERNEL);
            ret = vaccel_read_gpa(vaccel, notifier_gpa, notifier_full, full_size);
            if (ret) {
                vaccel_err(vaccel, "%s: read gpa error", __func__);
                return ret;
            }

            vaccel_info(vaccel, "fast paging map: %d pages, pgsize %#llx",
                        notifier.num_pages, pgsize);

            idx = srcu_read_lock(&vaccel->kvm->srcu);
            gva_iter = notifier.gva_start_addr;
            for (i = 0; i < notifier.num_pages; i++) {
                vaccel_iommu_page_map(vaccel, notifier_full->gpas[i], gva_iter, pgsize);
                gva_iter += pgsize;
            }
            srcu_read_unlock(&vaccel->kvm->srcu, idx);

            kfree(notifier_full);
            notifier_full = NULL;
        }
        else { /* 1 for unmap */
            vaccel_info(vaccel, "fast paging unmap: %d pages, pgsize %#llx",
                        notifier.num_pages, pgsize);

            idx = srcu_read_lock(&vaccel->kvm->srcu);
            gva_iter = notifier.gva_start_addr;
            for (i = 0; i < notifier.num_pages; i++) {
                vaccel_iommu_page_unmap(vaccel, gva_iter, pgsize);
                gva_iter += pgsize;
            }
            srcu_read_unlock(&vaccel->kvm->srcu, idx);
        }

        break;
    }
    case 0x10: /* MEM_BASE */
    {
        u64 mux_offset;
        u64 vm_cfg_offset;

        /* set gva start */
        vaccel->gva_start = val;

        /* calculate the offset for hardware fix */
        mux_offset = vaccel->iova_start/CL(1) -
                vaccel->gva_start/CL(1);
        vm_cfg_offset = paccel->accel_id * 8 + 0x30;
        writeq(mux_offset, &fisor->pafu_mmio[vm_cfg_offset]);

        break;
    }
    case 0x18: /* RESET */
    {
        vaccel->ops->soft_reset(vaccel);

        break;
    }
    default:
        vaccel_info(vaccel, "unimplemented MMIO");
        return -EINVAL;
    }

    return 0;
}

int vaccel_group_notifier(struct notifier_block *nb,
            long unsigned int action, void *data)
{
    struct vaccel *vaccel = container_of(nb, struct vaccel, group_notifier);

    if (action == VFIO_GROUP_NOTIFY_SET_KVM) {
        vaccel->kvm = data;

        if (!data) {
            vaccel_info(vaccel, "set KVM null\n");
            return NOTIFY_BAD;
        }
        else {
            vaccel_info(vaccel, "set KVM success\n");
        }
    }
    return NOTIFY_OK;
}

void do_paccel_soft_reset(struct paccel *paccel, bool lock)
{
    u64 reset_flags, new_reset_flags;
    struct fisor *fisor;

    WARN_ON(paccel->fisor == NULL);

    fisor = paccel->fisor;

    if (lock) {
        mutex_lock(&fisor->ops_lock);
    }

    reset_flags = readq(&fisor->pafu_mmio[0x18]);
    new_reset_flags = reset_flags |
            (1 << paccel->accel_id);
    writeq(new_reset_flags, &fisor->pafu_mmio[0x18]);
    writeq(reset_flags, &fisor->pafu_mmio[0x18]);

    if (lock) {
        mutex_unlock(&fisor->ops_lock);
    }
}   

void do_vaccel_bar_cleanup(struct vaccel *vaccel)
{
    WARN_ON(vaccel == NULL);
    WARN_ON(vaccel->bar == NULL);

    memset(vaccel->bar[VACCEL_BAR_0], 0, FISOR_BAR_0_SIZE);
    memset(vaccel->bar[VACCEL_BAR_2], 0, FISOR_BAR_2_SIZE);
}

