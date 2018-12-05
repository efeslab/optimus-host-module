#include "afu.h"
#include "fisor.h"

/* All MMIO access and interface emulation should be in this function,
 * however, currently we only use it to monitor the transaction of 
 * time-slicing devices */
static int fisor_worker(void *args) {
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

static int fisor_start_worker(struct fisor *fisor)
{
    fisor->worker_kthread =
            kthread_create(fisor_worker, fisor, "fisor_worker");

    if (fisor->worker_kthread)
        return 0;
    else
        return -1;
}

static void fisor_stop_worker(struct fisor *fisor)
{
    if (fisor->worker_kthread) {
        kthread_stop(fisor->worker_kthread);
    }

    fisor->worker_kthread = NULL;
}


