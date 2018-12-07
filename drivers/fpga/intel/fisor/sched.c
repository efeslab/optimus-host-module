#include "afu.h"
#include "fisor.h"

static void fisor_hw_trans_commit(struct vaccel *vaccel)
{
    int idx;
    u8* mmio_base;
    u64 data64;
    struct fisor *fisor;
    struct paccel *paccel;
    u64 mux_offset;
    u64 vm_cfg_offset;

    WARN_ON(vaccel == NULL);
    WARN_ON(vaccel->paccel == NULL);
    WARN_ON(vaccel->fisor == NULL);

    fisor = vaccel->fisor;
    paccel = vaccel->paccel;

    mmio_base = fisor->pafu_mmio + paccel->mmio_start;
    mux_offset = vaccel->iova_start/CL(1) - vaccel->gva_start/CL(1);
    vm_cfg_offset = vaccel->paccel->accel_id * 8 + 0x30;

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

    /* write transaction begin command */
    writeq(1, &mmio_base[0x18]);

    /* cleanup the bar after transaction
     * is it necessary? */
    do_vaccel_bar_cleanup(vaccel);
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

static int fisor_polling_do_sched_exit(void)
{
    if (kthread_should_stop()) {
        do_exit(0);
    }
    schedule();
}

static int fisor_polling_round(struct fisor *fisor) {
    struct paccel *paccels;
    u32 npaccels;
    int i;

    WARN_ON(fisor == NULL);
    WARN_ON(fisor->paccels == NULL);

    paccels = fisor->paccels;
    npaccels = fisor->npaccels;

    for (i=0; i<npaccels; i++) {
        struct paccel *paccel = &fisor->paccels[i];
        struct vaccel *ptr = NULL, *round = NULL;

        fisor_polling_do_sched_exit();

        /* TODO: this is pretty dangerous */
        mutex_lock(&paccel->instance_lock);

        if (paccel->mode == VACCEL_TYPE_DIRECT)
            continue;

        ptr = paccel->curr_vaccel;

        if (ptr) {
            /* Check the current status.
             * If it is running, check the TCR */

            if (ptr->is_using == false) {
                continue;
            }

            if (ptr->trans_status
                    == VACCEL_TRANSACTION_RUNNING) {
                if (fisor_hw_check_trans_finished(paccel)) {
                    /* the transaction is finished */
                    ptr->trans_status = VACCEL_TRANSACTION_IDLE;
                    STORE_LE64((u64*)&ptr->bar[VACCEL_BAR_0][0x18], 0xffff);
                    /* free transaction lock */
                    mutex_unlock(&ptr->trans_lock);
                    ptr = list_next_entry(ptr, paccel_next);
                }
                else {    
                    /* the transaction is unfinished, skip */
                    continue;
                }
            }
        }
        else {
            ptr = list_first_entry(&paccel->vaccel_list,
                            struct vaccel, paccel_next);
        }

        /* check whether any vaccel has pending transaction */
        round = ptr;
        do {
            if (ptr->trans_status
                    == VACCEL_TRANSACTION_COMMITTED) {
                /* acquire this lock until transaction end */
                mutex_lock(&ptr->trans_lock);
                fisor_hw_trans_commit(ptr);
                ptr->trans_status = VACCEL_TRANSACTION_RUNNING;

                ptr = list_next_entry(ptr, paccel_next);
                if (ptr == NULL) {
                    ptr = list_first_entry(&paccel->vaccel_list,
                                struct vaccel, paccel_next);
                }
            }
        } while (ptr != round);

        mutex_unlock(&paccel->instance_lock);
    }

    return 0;
}

static int fisor_polling(void *data)
{
    struct fisor *fisor = data;
    while (1) {
        fisor_polling_round(fisor);
    }
    return 0;
}

static int fisor_create_polling_thread(struct fisor *fisor)
{
    fisor->worker_kthread =
            kthread_create(fisor_polling, fisor, "fisor_polling");

    if (fisor->worker_kthread)
        return 0;
    else
        return -1;
}

static int fisor_start_polling(struct fisor *fisor)
{
    if (fisor->worker_kthread) {
        wake_up_process(fisor->worker_kthread);
        return true;
    }
    else {
        return false;
    }
}

static void fisor_stop_polling(struct fisor *fisor)
{
    if (fisor->worker_kthread) {
        kthread_stop(fisor->worker_kthread);
    }

    fisor->worker_kthread = NULL;
}


