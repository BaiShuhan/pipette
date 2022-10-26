#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#ifdef CONFIG_FINE_GRAINED
#include <linux/ebio.h>
#endif

#include <asm/barrier.h>

#ifdef CONFIG_FINE_GRAINED
struct ebio *ebios_global;
EXPORT_SYMBOL(ebios_global);

DEFINE_PER_CPU(struct ebio_queue, ebio_queues);
EXPORT_PER_CPU_SYMBOL(ebio_queues);

struct ebio *ebio_alloc(gfp_t gfp_mask, unsigned int nr_iovecs)
{
        struct ebio_queue *ebio_queue;
        struct ebio *ebio;

        ebio_queue = &get_cpu_var(ebio_queues);
        ebio = &ebio_queue->ebios[ebio_queue->head];

	while (ebio_is_busy(ebio))
	{
		if (ebio_is_completed(ebio) && ebio_is_cached(ebio))
		{
			ebio_clear_completed(ebio);
			ebio_clear_cached(ebio);
			ebio_clear_busy(ebio);
		}
		else
		{
			DEFINE_WAIT(wait);
                        add_wait_queue(&ebio->ebio_waitqueue, &wait);
			wait_event(ebio->ebio_waitqueue, ebio_is_completed(ebio) && ebio_is_cached(ebio));
			finish_wait(&ebio->ebio_waitqueue, &wait);
		}
	}

        ebio_set_busy(ebio);
        ebio_queue->head = (ebio_queue->head + 1) % NR_EBIO_PER_CPU;
        put_cpu_var(ebio_queues);

        ebio->block = 0;
        INIT_LIST_HEAD(&ebio->list);
        init_waitqueue_head(&ebio->ebio_waitqueue);

        return ebio;
}

int init_ebio(struct device *dev)
{
        int cpu;

        get_online_cpus();

        ebios_global = kzalloc(sizeof(struct ebio) * num_online_cpus() * NR_EBIO_PER_CPU, GFP_KERNEL);
        if (ebios_global == NULL)
                panic("[FINE GRAINED ERROR] %s:%d cannot allocate ebios_global\n", __func__, __LINE__);

        printk(KERN_EMERG "[FINE_GRAINED %s] num_online_cpus() %d ebios_global: %p each ebio size: %lu total size: %lu\n",
                        __func__, num_online_cpus(), ebios_global, sizeof(struct ebio),
                        sizeof(struct ebio) * num_online_cpus() * NR_EBIO_PER_CPU);

        /* nvme command tag field check */
        BUG_ON(num_online_cpus() * NR_EBIO_PER_CPU > 0x8000);

        for_each_online_cpu(cpu) {
                struct ebio_queue *ebio_queue = per_cpu_ptr(&ebio_queues, cpu);
                ebio_queue->head = 0;
                ebio_queue->ebios = ebios_global + (NR_EBIO_PER_CPU * cpu);
                printk(KERN_EMERG "[FINE GRAINED %s] ebio_queue: %p cpu: %d head tag: %lu\n",
                                        __func__, ebio_queue, cpu, ebio_tag(ebio_queue->ebios));
        }

        put_online_cpus();
        return 0;
}
#endif
