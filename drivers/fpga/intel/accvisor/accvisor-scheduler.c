#include "afu.h"
#include "accvisor.h"

/* All MMIO access and interface emulation should be in this function,
 * however, currently we only use it to monitor the transaction of 
 * time-slicing devices */
static int accvisor_worker(void *args) {
    while (1) {
        if (kthread_should_stop()) {
            printk("fuck: who killed me?\n");
            do_exit(0);
        }

        msleep(200);
        schedule();

        printk("fuck: HARP, FPGA, and Intel.\n");
    }
}

static int accvisor_start_worker(struct accvisor *accvisor)
{
    accvisor->worker_kthread =
            kthread_create(accvisor_worker, accvisor, "accvisor_worker");

    if (accvisor->worker_kthread)
        return 0;
    else
        return -1;
}

static void accvisor_stop_worker(struct accvisor *accvisor)
{
    if (accvisor->worker_kthread) {
        kthread_stop(accvisor->worker_kthread);
    }

    accvisor->worker_kthread = NULL;
}


