#ifndef __EBIO_H_
#define __EBIO_H_

#include <linux/blk_types.h>
#include <linux/nvme.h>

#include <asm/bitops.h>

struct ebio;

struct ebio {
	sector_t block;
	struct list_head list;
	wait_queue_head_t ebio_waitqueue;
	unsigned long int flags;
	blk_status_t status;
} ____cacheline_internodealigned_in_smp;

extern struct ebio *ebios_global;

#define ebio_tag(ebio)	((ebio) - ebios_global)
#define tag_to_ebio(tag)	(&ebios_global[(tag)])
#define ebio_to_cpu(ebio)	(ebio_tag(ebio) / NR_EBIO_PER_CPU)

struct ebio_queue {
	unsigned int head;
	struct ebio *ebios;
};

#define NR_EBIO_PER_CPU 1024

enum ebioflags {
	EBIO_BUSY,
	EBIO_COMPLETED,
	EBIO_CACHED,
};

#define ebio_is_busy(ebio) test_bit(EBIO_BUSY, &ebio->flags)
#define ebio_set_busy(ebio) set_bit(EBIO_BUSY, &ebio->flags)
#define ebio_clear_busy(ebio) clear_bit(EBIO_BUSY, &ebio->flags)

#define ebio_is_completed(ebio)	test_bit(EBIO_COMPLETED, &ebio->flags)
#define ebio_set_completed(ebio) set_bit(EBIO_COMPLETED, &ebio->flags)
#define ebio_clear_completed(ebio) clear_bit(EBIO_COMPLETED, &ebio->flags)

#define ebio_is_cached(ebio) test_bit(EBIO_CACHED, &ebio->flags)
#define ebio_set_cached(ebio) set_bit(EBIO_CACHED, &ebio->flags)
#define ebio_clear_cached(ebio) clear_bit(EBIO_CACHED, &ebio->flags)

extern struct ebio *ebio_alloc(gfp_t gfp_mask, unsigned int nr_iovecs);
extern int init_ebio(struct device *dev);

extern int nvme_fine_granu_read(struct ebio *ebio);
extern int nvme_fine_granu_read_rw(struct ebio *ebio);  //for testing on non-CSD

extern enum reassign_result_type slabs_reassign(int src, int dst);

extern void record_read_info(unsigned long offset, size_t count, ssize_t hmb_offset);

extern void * host_mem_baddr;

extern unsigned int fine_granu_acc_cnt;
extern unsigned int fine_granu_reuse_acc_cnt;
extern unsigned int normal_acc_cnt;
extern unsigned int fine_granu_hit_cnt;
extern unsigned int fine_granu_cache_hit_cnt;
extern unsigned int page_cache_hit_cnt;
extern unsigned int FGCratio;
extern unsigned int PCratio;
extern int refThreshold;
extern int MinThreshold;
extern int MaxThreshold;
extern int ResetCnt;
extern unsigned int new_interhit;
extern unsigned int old_interhit;
extern unsigned int new_interratio;
extern unsigned int old_interratio;

extern unsigned int total_cnt_bytes;
extern unsigned int total_cnt;
extern struct mutex cnt_lock;
#endif
