#include "afu.h"
#include "fisor.h"

static int fisor_polling_round(struct fisor *fisor) {
    struct paccel *paccels = fisor->paccels;
    u32 npaccels = fisor->npaccels;
    int i;

    for (i=0; i<npaccels; i++) {
        struct paccel *paccel = &fisor->paccels[i];
        struct fisor *d, *tmp_d;

        if (paccel->mode == VACCEL_TYPE_DIRECT)
            continue;

        list_for_each_entry_safe(d, tmp_d, &paccel->vaccel_list, paccel_next) {
        
        }
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


