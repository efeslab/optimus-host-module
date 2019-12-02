#include "afu.h"
#include "optimus.h"

static int paccel_timeslc_dump(struct paccel *paccel)
{
    u32 accel_id = paccel->accel_id;
    u32 mmio_start = paccel->mmio_start;
    u32 mmio_size = paccel->mmio_size;
    u32 avail_inst = paccel->timeslc.total;
    u32 curr_inst = paccel->timeslc.occupied;

    paccel_info(paccel, "optimus: phys accelerator #%d, mmio %x, mmio_size %x, avail %d, curr %d\n",
                accel_id, mmio_start, mmio_size, avail_inst, curr_inst);

    return 0;
}
 

static int vaccel_time_slicing_init(struct vaccel *vaccel,
                struct paccel *paccel, struct mdev_device *mdev)
{
    struct optimus *optimus;

    if (!mdev || !vaccel || !paccel)
        return -EINVAL;

    optimus = paccel->optimus;
    if (!optimus)
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
    vaccel->optimus = optimus;
    vaccel->gva_start = 0;
    vaccel->mdev = mdev;
    vaccel->seq_id = atomic_fetch_add(1, &optimus->next_seq_id);
    vaccel->iova_start = vaccel->seq_id * SIZE_64G;
    vaccel->ops = &vaccel_time_slicing_ops;
    vaccel->paging_notifier_gpa = 0;
    vaccel->timeslc.trans_status = VACCEL_TRANSACTION_IDLE;
    vaccel->timeslc.start_time = 0;
    vaccel->timeslc.running_time = 0;
    #ifdef SCHED_ENABLE_WEIGHT
    vaccel->timeslc.weight = 1;
    if (vaccel->seq_id == 0) {
        vaccel->timeslc.weight = 4;
    }
    if (vaccel->seq_id == 1) {
        vaccel->timeslc.weight = 2;
    }
    #endif
    mutex_init(&vaccel->ops_lock);

    /* create pcie config space */
    vaccel->vconfig = kzalloc(OPTIMUS_CONFIG_SPACE_SIZE, GFP_KERNEL);
    if (!vaccel->vconfig) {
        kfree(vaccel);
        return -ENOMEM;
    }
    vaccel_create_config_space(vaccel);

    /* allocate bar */
    vaccel->bar[VACCEL_BAR_0] = kzalloc(OPTIMUS_BAR_0_SIZE, GFP_KERNEL);
    vaccel->bar[VACCEL_BAR_2] = kzalloc(OPTIMUS_BAR_2_SIZE, GFP_KERNEL);

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

    vaccel_info(vaccel, "To be removed from paccel %d\n", paccel->accel_id);

    /* set occupied as false */
    mutex_lock(&paccel->ops_lock);
    list_for_each_entry_safe(d, tmp_d, &paccel->timeslc.children, timeslc.paccel_next) {
        if (vaccel == d) {
            list_del(&vaccel->timeslc.paccel_next);
            ret = 0;
            break;
        }
    }
    if (ret) {
        vaccel_err(vaccel, "uinit failed: not found in paccel list\n");
        mutex_unlock(&paccel->ops_lock);
        return ret;
    }
    paccel->timeslc.occupied--;
    mutex_unlock(&paccel->ops_lock);

    mdev_set_drvdata(mdev, NULL);

    /* free all allocated regions */
    kfree(vaccel->vconfig);
    kfree(vaccel->bar[VACCEL_BAR_0]);
    kfree(vaccel->bar[VACCEL_BAR_2]);
    vaccel->vconfig = NULL;
    vaccel->bar[VACCEL_BAR_0] = NULL;
    vaccel->bar[VACCEL_BAR_2] = NULL;

    return 0;
}

static bool optimus_hw_check_idle(struct paccel *paccel)
{
    u8 *mmio_base;
    u64 data64;
    struct optimus *optimus;

    WARN_ON(paccel == NULL);
    WARN_ON(paccel->optimus == NULL);

    optimus = paccel->optimus;
    mmio_base = optimus->pafu_mmio + paccel->mmio_start;
    data64 = readq(&mmio_base[OPTIMUS_TRANS_CTL]);

    if (data64 != OPTIMUS_TRANS_CTL_BUSY)
        return true;
    else
        return false;
}

static int vaccel_time_slicing_submit(struct vaccel *vaccel)
{
    struct optimus *optimus = vaccel->optimus;
    struct paccel *paccel = vaccel->paccel;
    u8 *mmio_base = optimus->pafu_mmio + paccel->mmio_start;
    u64 mux_offset = vaccel->iova_start/CL(1) - vaccel->gva_start/CL(1);
    u64 vm_cfg_offset = vaccel->paccel->accel_id * 8 + 0x30;
    int idx;
    u64 data64;

    /* configure the accelerator with new address */
    writeq(mux_offset, &optimus->pafu_mmio[vm_cfg_offset]);

    /* reset the accelerator */
    do_paccel_soft_reset(paccel, false);

    /* fill all the registers again */
    for (idx=0x20; idx<0x1000; idx+=8) {
        data64 = *(u64*)(vaccel->bar[VACCEL_BAR_0]+idx);
        if (data64 != 0) {
            writeq(data64, &mmio_base[idx]);
            //vaccel_info(vaccel, "Submit to hardware, offset = %#x, value = %lld\n", 
            //        idx, data64);
        }
    }

    /* write transaction begin or continue */
    data64 = *(u64*)(vaccel->bar[VACCEL_BAR_0] + OPTIMUS_TRANS_CTL);
    paccel_info(paccel, "%s: write %llu to transaction control\n",
            __func__, data64);
    writeq(data64, &mmio_base[OPTIMUS_TRANS_CTL]);

    // /* cleanup the bar after transaction */
    // do_vaccel_bar_cleanup(vaccel);

    return 0;
}

static int do_paccel_pause(struct paccel *paccel) {
    struct optimus *optimus = paccel->optimus;
    u8 *mmio_base = optimus->pafu_mmio + paccel->mmio_start;
    u64 data64;
    u64 start;

    u64 clock1, clock2;

    clock1 =rdtsc_ordered();

    /* Write pause request */
    writeq(OPTIMUS_TRANS_CTL_REQUEST_PAUSE, &mmio_base[OPTIMUS_TRANS_CTL]);

    start = jiffies;

    do {
        data64 = readq(&mmio_base[OPTIMUS_TRANS_CTL]);
    } while (data64 != OPTIMUS_TRANS_CTL_PAUSE &&
            jiffies < start + 50 * HZ / 1000);

    //clock2 = rdtsc_ordered();

    //printk("Clock difference %llu\n", clock2 - clock1);

    if (data64 != OPTIMUS_TRANS_CTL_PAUSE) {
        paccel_err(paccel, "Pause failed: no response (CTL: %llu)\n", data64);
        return -EIO;
    }

    do {
        clock2 = rdtsc_ordered();
    } while (clock2 - clock1 < PACCEL_PREEMPT_WAIT_CYCLE);

    return 0;
}

static inline void vaccel_record_stop(struct paccel *paccel, struct vaccel *vaccel)
{
    optimus_info("kthread: De-schedule vaccel %d on paccel %d \n",
            vaccel->seq_id, paccel->accel_id);
    vaccel->timeslc.start_time = 0;
    vaccel->timeslc.trans_status = VACCEL_TRANSACTION_IDLE;
    STORE_LE64((u64*)&vaccel->bar[VACCEL_BAR_0][OPTIMUS_TRANS_CTL],
            OPTIMUS_TRANS_CTL_FINISH);
    paccel->timeslc.curr = NULL;
}

static inline void vaccel_record_run(struct paccel *paccel, struct vaccel *vaccel)
{
    optimus_info("kthread: Schedule vaccel %d on paccel %d \n",
            vaccel->seq_id, paccel->accel_id);
    vaccel_time_slicing_submit(vaccel);
    vaccel->timeslc.start_time = jiffies;
    vaccel->timeslc.trans_status = VACCEL_TRANSACTION_HARDWARE;
    STORE_LE64((u64*)&vaccel->bar[VACCEL_BAR_0][OPTIMUS_TRANS_CTL],
            OPTIMUS_TRANS_CTL_BUSY);
    paccel->timeslc.curr = vaccel;
}

static inline void vaccel_record_abort(struct paccel *paccel, struct vaccel *vaccel)
{
    optimus_info("kthread: Abort vaccel %d on paccel %d \n",
            vaccel->seq_id, paccel->accel_id);
    vaccel->timeslc.start_time = 0;
    vaccel->timeslc.trans_status = VACCEL_TRANSACTION_IDLE;
    STORE_LE64((u64*)&vaccel->bar[VACCEL_BAR_0][OPTIMUS_TRANS_CTL],
            OPTIMUS_TRANS_CTL_ABORT);
    paccel->timeslc.curr = NULL;
}

static inline void vaccel_record_pause(struct paccel *paccel, struct vaccel *vaccel)
{
    optimus_info("kthread: Pause vaccel %d on paccel %d \n",
            vaccel->seq_id, paccel->accel_id);
    vaccel->timeslc.start_time = 0;
    vaccel->timeslc.trans_status = VACCEL_TRANSACTION_STARTED;
    STORE_LE64((u64*)&vaccel->bar[VACCEL_BAR_0][OPTIMUS_TRANS_CTL],
            OPTIMUS_TRANS_CTL_CONT);
    paccel->timeslc.curr = NULL;
}

static inline bool vaccel_should_continue(struct paccel *paccel, struct vaccel *curr, u64 duration)
{
    struct vaccel *next;

    if (duration <= PACCEL_TS_MAX_PERIOD_MS)
        return true;

    list_for_each_entry(next, &paccel->timeslc.children, timeslc.paccel_next) {
        if (next == curr)
            continue;

        if (next->timeslc.trans_status != VACCEL_TRANSACTION_STARTED)
            continue;

        #ifdef SCHED_ENABLE_WEIGHT
        if (next->timeslc.running_time * curr->timeslc.weight <
                (curr->timeslc.running_time + duration) * next->timeslc.weight)
        #else
        if (next->timeslc.running_time <
                curr->timeslc.running_time + duration)
        #endif
        {
            return false;
        }
        else {
            break;
        }
    }
    return true;
}

static void paccel_schedule_round_robin(struct paccel *paccel)
{
    struct vaccel *curr = NULL, *vaccel, *tmp_v;
    u64 run_duration;

    WARN_ON(paccel == NULL);

    if (paccel->mode != VACCEL_TYPE_TIME_SLICING) {
        optimus_err("%s: paccel %d is in the wrong mode\n",
                __func__, paccel->accel_id);
        return;
    }

    if (paccel->timeslc.curr != NULL) {

        curr = paccel->timeslc.curr;

        if (!curr->enabled) {
            paccel_err(paccel, "curr vaccel %d not enabled \n", curr->seq_id);
            vaccel_record_stop(paccel, curr);
            goto next_round;
        }

        if (curr->timeslc.trans_status != VACCEL_TRANSACTION_HARDWARE) {
            paccel_err(paccel, "curr vaccel %d not sched \n", curr->seq_id);
            vaccel_record_stop(paccel, curr);
            goto next_round;
        }

        /* If hw is still busy, continue (unlock in caller)*/
        if (!optimus_hw_check_idle(paccel)) {
            optimus_info("kthread: vaccel %d still runs on paccel %d \n",
                curr->seq_id, paccel->accel_id);
            return;
        }
        
        run_duration = (jiffies -
                curr->timeslc.start_time) * 1000 / HZ;

        curr->timeslc.running_time += run_duration;
        optimus_info("kthread: vaccel %d on paccel %d runs for %llu ms \n",
                curr->seq_id, paccel->accel_id, run_duration);
        vaccel_record_stop(paccel, curr);
        /* maintain linked list order */
        list_move_tail(&curr->timeslc.paccel_next,
            &paccel->timeslc.children);
    }

    next_round:
    // paccel_info(paccel, "has these vaccel: \n");

    list_for_each_entry_safe(vaccel, tmp_v, &paccel->timeslc.children, timeslc.paccel_next) {
    //    paccel_info(paccel, "vaccel %d \n", vaccel->seq_id);
        if (vaccel->timeslc.trans_status == VACCEL_TRANSACTION_STARTED) {
            vaccel_record_run(paccel, vaccel);
            return;
        }
    }

    // optimus_info("No job is runnable on paccel %d \n", paccel->accel_id);

}

static void paccel_schedule_fair_abort(struct paccel *paccel)
{
    struct vaccel *curr = NULL, *vaccel, *tmp_v;
    u64 run_duration;

    WARN_ON(paccel == NULL);

    if (paccel->mode != VACCEL_TYPE_TIME_SLICING) {
        optimus_err("%s: paccel %d is in the wrong mode\n",
                __func__, paccel->accel_id);
        return;
    }

    if (paccel->timeslc.curr != NULL) {

        curr = paccel->timeslc.curr;

        if (!curr->enabled) {
            paccel_err(paccel, "curr vaccel %d not enabled \n", curr->seq_id);
            vaccel_record_stop(paccel, curr);
            goto next_round;
        }

        if (curr->timeslc.trans_status != VACCEL_TRANSACTION_HARDWARE) {
            paccel_err(paccel, "curr vaccel %d not sched \n", curr->seq_id);
            vaccel_record_stop(paccel, curr);
            goto next_round;
        }

        run_duration = (jiffies -
                curr->timeslc.start_time) * 1000 / HZ;

        /* If hw is still busy, check max running period */
        if (!optimus_hw_check_idle(paccel)) {
            if (run_duration <= PACCEL_TS_MAX_PERIOD_MS) {
                optimus_info("kthread: vaccel %d still runs on paccel "
                        "%d, lasts %llu ms \n", curr->seq_id,
                        paccel->accel_id, run_duration);
                return;
            }
            else {
                optimus_info("kthread: vaccel %d runs on paccel %d "
                        "for %llu ms, timeout \n",curr->seq_id,
                        paccel->accel_id, run_duration);
                vaccel_record_abort(paccel, curr);
                do_paccel_soft_reset(paccel, false);
            }
        }
        else {
            optimus_info("kthread: vaccel %d on paccel %d runs for %llu ms \n",
                    curr->seq_id, paccel->accel_id, run_duration);
            vaccel_record_stop(paccel, curr);
        }

        curr->timeslc.running_time += run_duration;

        /* maintain linked list order */
        list_del(&curr->timeslc.paccel_next);
        list_for_each_entry(vaccel, &paccel->timeslc.children, timeslc.paccel_next) {
            if (vaccel->timeslc.running_time >
                    curr->timeslc.running_time)
                break;
        }
        if (&vaccel->timeslc.paccel_next == &paccel->timeslc.children) {
            list_add_tail(&curr->timeslc.paccel_next,
                    &paccel->timeslc.children);
        }
        else {
            list_add(&curr->timeslc.paccel_next,
                    vaccel->timeslc.paccel_next.prev);
        }
    }

    next_round:
    paccel_info(paccel, "has these vaccel: \n");

    list_for_each_entry_safe(vaccel, tmp_v, &paccel->timeslc.children, timeslc.paccel_next) {
        paccel_info(paccel, "vaccel %d: total running time %lld \n",
                vaccel->seq_id, vaccel->timeslc.running_time);
        if (vaccel->timeslc.trans_status == VACCEL_TRANSACTION_STARTED) {
            vaccel_record_run(paccel, vaccel);
            return;
        }
    }

    // optimus_info("No job is runnable on paccel %d \n", paccel->accel_id);

}

static void paccel_schedule_fair_notify(struct paccel *paccel)
{
    struct vaccel *curr = NULL, *vaccel, *tmp_v;
    u64 run_duration;

    WARN_ON(paccel == NULL);

    if (paccel->mode != VACCEL_TYPE_TIME_SLICING) {
        optimus_err("%s: paccel %d is in the wrong mode\n",
                __func__, paccel->accel_id);
        return;
    }

    if (paccel->timeslc.policy != PACCEL_TS_POLICY_FAIR_NOTIFY) {
        optimus_err("%s: paccel %d is in the wrong policy\n",
                __func__, paccel->accel_id);
        return;
    }

    if (paccel->timeslc.curr != NULL) {

        curr = paccel->timeslc.curr;

        if (!curr->enabled) {
            paccel_err(paccel, "curr vaccel %d not enabled \n", curr->seq_id);
            vaccel_record_stop(paccel, curr);
            goto next_round;
        }

        if (curr->timeslc.trans_status != VACCEL_TRANSACTION_HARDWARE) {
            paccel_err(paccel, "curr vaccel %d not sched \n", curr->seq_id);
            vaccel_record_stop(paccel, curr);
            goto next_round;
        }

        run_duration = (jiffies -
                curr->timeslc.start_time) * 1000 / HZ;

        /* If hw is still busy, check max running period */
        if (!optimus_hw_check_idle(paccel)) {
            if (vaccel_should_continue(paccel, curr, run_duration))
            {
                optimus_info("kthread: vaccel %d still runs on paccel "
                        "%d \n", curr->seq_id, paccel->accel_id);
                return;
            }
            else
            {
                optimus_info("kthread: vaccel %d runs on paccel %d "
                        "for %llu ms, timeout, preempt \n",
                        curr->seq_id, paccel->accel_id, run_duration);
                vaccel_record_pause(paccel, curr);
                do_paccel_pause(paccel);
            }
        }
        else {
            optimus_info("kthread: vaccel %d on paccel %d runs for %llu ms \n",
                    curr->seq_id, paccel->accel_id, run_duration);
            vaccel_record_stop(paccel, curr);
        }

        curr->timeslc.running_time += run_duration;

        /* maintain linked list order */
        list_del(&curr->timeslc.paccel_next);
        list_for_each_entry(vaccel, &paccel->timeslc.children, timeslc.paccel_next) {
            #ifdef SCHED_ENABLE_WEIGHT
            if (vaccel->timeslc.running_time * curr->timeslc.weight >
                    curr->timeslc.running_time * vaccel->timeslc.weight)
                break;
            #else
            if (vaccel->timeslc.running_time >
                    curr->timeslc.running_time)
                break;
            #endif
        }
        if (&vaccel->timeslc.paccel_next == &paccel->timeslc.children) {
            list_add_tail(&curr->timeslc.paccel_next,
                    &paccel->timeslc.children);
        }
        else {
            list_add(&curr->timeslc.paccel_next,
                    vaccel->timeslc.paccel_next.prev);
        }
    }

    next_round:
    paccel_info(paccel, "has these vaccel: \n");

    list_for_each_entry_safe(vaccel, tmp_v, &paccel->timeslc.children, timeslc.paccel_next) {
        paccel_info(paccel, "vaccel %d: total running time %lld \n", 
                vaccel->seq_id, vaccel->timeslc.running_time);
        if (vaccel->timeslc.trans_status == VACCEL_TRANSACTION_STARTED) {
            vaccel_record_run(paccel, vaccel);
            return;
        }
    }

    // optimus_info("No job is runnable on paccel %d \n", paccel->accel_id);

}

int kthread_watch_time(void *optimus_param)
{
    struct optimus *optimus = optimus_param;
    struct paccel *paccels = optimus->paccels;
    u32 npaccels = optimus->npaccels;
    int i;
    struct paccel *paccel;

    optimus_info("Time keeping (scheduling) kthread starts \n");

    while (1) {

        // optimus_info("Scheduling kthread wakes up \n");

        if (kthread_should_stop()) {
            break;
        }

        optimus->user_check_signal = 0;

        mutex_lock(&optimus->ops_lock);

        for (i = 0; i < npaccels; i++) {

            paccel = &paccels[i];

            if (paccel->mode == VACCEL_TYPE_DIRECT)
                continue;

            mutex_lock(&paccel->ops_lock);

            /* Make scheduling decision */
            switch (paccel->timeslc.policy) {
            case PACCEL_TS_POLICY_FAIR_ABORT:
            {
                paccel_schedule_fair_abort(paccel);
                break;
            }
            case PACCEL_TS_POLICY_FAIR_NOTIFY:
            {
                paccel_schedule_fair_notify(paccel);
                break;
            }
            default:
                paccel_schedule_round_robin(paccel);
            }

            mutex_unlock(&paccel->ops_lock);
        }

        mutex_unlock(&optimus->ops_lock);

        set_current_state(TASK_INTERRUPTIBLE);

        if (kthread_should_stop()) {
            set_current_state(TASK_RUNNING);
            break;
        }

        if (optimus->user_check_signal) {
            set_current_state(TASK_RUNNING);
            continue;
        }

        // optimus_info("Scheduling kthread sleeps \n");
        schedule_timeout(100000 * HZ);
    }

    optimus_info("Time keeping (scheduling) kthread exits \n");

    return 0;
}

static int vaccel_time_slicing_handle_mmio_read(struct vaccel *vaccel,
            u32 index, u32 offset, u64 *val)
{
    struct optimus *optimus = vaccel->optimus;
    struct paccel *paccel = vaccel->paccel;
    u64 data64;

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

        if (offset == OPTIMUS_STATE_SZ &&
                paccel->timeslc.policy == PACCEL_TS_POLICY_FAIR_NOTIFY) {
            vaccel_info(vaccel, "Read the saved state size (in # of pages) \n");
            *val = paccel->timeslc.state_sz;
            return 0;
        }

        if (offset == OPTIMUS_TRANS_CTL) {
            vaccel_info(vaccel, "Check hw transaction state \n");
            optimus->user_check_signal = 1;
            wake_up_process(optimus->scheduler);
            LOAD_LE64(&vaccel->bar[VACCEL_BAR_0][offset], *val);
            vaccel_info(vaccel, "buffer: %llu\n", *val);
        }
        else if (paccel->timeslc.curr == vaccel &&
                vaccel->timeslc.trans_status == VACCEL_TRANSACTION_HARDWARE) {
            offset = offset + paccel->mmio_start;
            data64 = readq(&optimus->pafu_mmio[offset]);
            *val = data64;
            //paccel_info(paccel, "Real MMIO read: offset 0x%x, value %llu\n",
            //        offset - paccel->mmio_start, data64);
        }
        else {
            LOAD_LE64(&vaccel->bar[VACCEL_BAR_0][offset], *val);
            //paccel_info(paccel, "Buffered MMIO read: offset 0x%x, value %llu\n",
            //        offset, *val);
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
    struct optimus *optimus = vaccel->optimus;
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
            vaccel_info(vaccel, "Commit transaction, wakeup scheduler\n");
            vaccel_info(vaccel, "buffer: %llu\n", val);
            optimus->user_check_signal = 1;
            wake_up_process(optimus->scheduler);
        }

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
    int idx;

    vaccel_info(vaccel, "call: %s\n", __func__);

    vaccel->enabled = false;
    vfio_unregister_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY,
                &vaccel->group_notifier);

    idx = srcu_read_lock(&vaccel->kvm->srcu);
    iommu_unmap_region(vaccel->optimus->domain,
                vaccel->optimus->iommu_map_flags,
                vaccel->iova_start,
                SIZE_64G >> PAGE_SHIFT);
    srcu_read_unlock(&vaccel->kvm->srcu, idx);

    do_vaccel_bar_cleanup(vaccel);

    vaccel_info(vaccel, "closed");

    return 0;
}

static int vaccel_time_slicing_soft_reset(struct vaccel *vaccel)
{
    struct paccel *paccel = vaccel->paccel;
    struct optimus *optimus = paccel->optimus;

    vaccel_info(vaccel, "call %s \n", __func__);

    mutex_lock(&optimus->ops_lock);
    mutex_lock(&paccel->ops_lock);

    if (vaccel->timeslc.trans_status ==
            VACCEL_TRANSACTION_STARTED) {
        vaccel->timeslc.trans_status = VACCEL_TRANSACTION_IDLE;
    }
    else if (vaccel->timeslc.trans_status ==
            VACCEL_TRANSACTION_HARDWARE) {
        do_paccel_soft_reset(paccel, false);
        /* TODO: record running time before interrupt */
        paccel->timeslc.curr = NULL;
        vaccel->timeslc.trans_status = VACCEL_TRANSACTION_IDLE;
    }

    mutex_unlock(&paccel->ops_lock);
    mutex_unlock(&optimus->ops_lock);

    do_vaccel_bar_cleanup(vaccel);

    return 0;
}

static int vaccel_time_slicing_set_mux_offset(struct vaccel* vaccel)
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
    .set_mux_offset = vaccel_time_slicing_set_mux_offset,
    .handle_mmio_read = vaccel_time_slicing_handle_mmio_read,
    .handle_mmio_write = vaccel_time_slicing_handle_mmio_write,
};
