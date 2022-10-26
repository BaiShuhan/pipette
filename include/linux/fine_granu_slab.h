#ifndef _FINE_GRANU_SLAB_H
#define _FINE_GRANU_SLAB_H

#include <linux/types.h>

/* Slab sizing definitions. */
#define POWER_SMALLEST 1
#define CHUNK_ALIGN_BYTES 32
/* slab class max is a 6-bit number, -1. */
#define MAX_NUMBER_OF_SLAB_CLASSES (63 + 1)
/* magic slab class for storing pages for reassignment */
#define SLAB_GLOBAL_PAGE_POOL 0
#define BUFFER_OFFSET 32
#define assert(x)                                               \
do {                                                            \
    if (unlikely(!(x))) {                                       \
	pr_err("Assertion failed\n");                           \
	BUG();                                                  \
    }                                                           \
} while (0)

typedef struct {
        int verbose;
        size_t maxbytes;
        int factor;                    /* chunk size growth factor */
        int chunk_size;
        int slab_chunk_size_max;          /* Upper end for chunks within slab pages. */
        int slab_page_size;               /* Slab's page units. */
} settings_t;

extern settings_t settings;

static inline void settings_init(size_t maxbytes, int factor, int chunk_size, int slab_chunk_size_max, int slab_page_size, int verbose) {
        settings.maxbytes = maxbytes; /* default is 64MB */
        settings.verbose = verbose;
        settings.factor = factor;
        settings.chunk_size = chunk_size;         /* space for a modest key and value */
        settings.slab_page_size = slab_page_size; /* chunks are split from 1MB pages. */
        settings.slab_chunk_size_max = slab_chunk_size_max;
}

typedef struct {
        unsigned int size;                /* sizes of chunks */
        unsigned int perslab;             /* how many chunks per slab */

        size_t *slots;                    /* pointer to array of free chunks' offset */
        unsigned int sl_total;            /* size of previous array */
        unsigned int sl_curr;             /* index of the first free slot */

        size_t end_page_offset;           /* offset of next free chunk at end of page, or 0 */
        unsigned int end_page_free;       /* number of chunks remaining at end of last alloced page */

	unsigned int evicted;             /* how many items evicted per slab */

        size_t *slab_list;                /* pointer to array of slab start offset */
        unsigned int list_size;           /* size of prev array */
        unsigned int slabs;               /* how many slabs were allocated for this class */

        size_t *killing;                  /* pointer to array of reassigned slabs */
        size_t *reassign;                 /* pointer to array of reassigned dst addr */
        unsigned int rebal_list_size;     /* size of prev array */

	unsigned int reassign_num;        /* how many slabs reassigned per class */
} slabclass_t;

extern slabclass_t slabclass[MAX_NUMBER_OF_SLAB_CLASSES];
extern int power_largest;
extern size_t mem_limit;
extern size_t mem_current;
extern size_t mem_avail;

/**
 * Determines the chunk sizes and initializes the slab class descriptors
 * accordingly.
 */
static inline void slabs_init(const size_t limit, const int factor, const uint32_t *slab_sizes) {
        int i = POWER_SMALLEST - 1;
        unsigned int size = settings.chunk_size;
        mem_limit = limit - settings.slab_page_size;
        mem_avail = mem_limit;
	    mem_current = settings.slab_page_size;

        memset(slabclass, 0, sizeof(slabclass));

        while (++i < MAX_NUMBER_OF_SLAB_CLASSES - 1) {
                if (slab_sizes != NULL) {
                        if (slab_sizes[i - 1] == 0)
                                break;
                        size = slab_sizes[i - 1];
                }
                else if (size >= (settings.slab_chunk_size_max - factor)) {
                        break;
                }
                /* Make sure items are always n-byte aligned */
                if (size % CHUNK_ALIGN_BYTES)
                        size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);

                slabclass[i].size = size;
                slabclass[i].perslab = settings.slab_page_size / slabclass[i].size;
                if (slab_sizes == NULL)
                        size += factor;
                if (settings.verbose > 1) {
                        printk(KERN_EMERG "slab class %3d: chunk size %9u perslab %7u\n",
                                i, slabclass[i].size, slabclass[i].perslab);
                }
        }

        power_largest = i;
        slabclass[power_largest].size = settings.slab_chunk_size_max;
        slabclass[power_largest].perslab = settings.slab_page_size / settings.slab_chunk_size_max;
        if (settings.verbose > 1) {
                printk(KERN_EMERG "slab class %3d: chunk size %9u perslab %7u\n",
                        i, slabclass[i].size, slabclass[i].perslab);
        }
}

/*
 * Figures out which slab class (chunk size) is required to store an item of
 * a given size.
 *
 * Given object size, return id to use when allocating/freeing memory for object
 * 0 means error: can't store such a large object
 */
static inline unsigned int slabs_clsid(const size_t size) {
        int res = POWER_SMALLEST;

        if (size == 0 || size > settings.slab_chunk_size_max)
                return 0;
        while (size > slabclass[res].size) {
                if (res++ == power_largest)     /* won't fit in the biggest slab */
                        return power_largest;
	}
        return res;
}

/* Initialize or increase the slab_list pointer array */
static int grow_slab_list(const unsigned int id) {
        slabclass_t *p = &slabclass[id];
        if ((p->reassign_num + p->slabs) == p->list_size) {
                size_t new_size = (p->list_size != 0) ? p->list_size * 2 : 16;
                void *new_list = krealloc(p->slab_list, new_size * sizeof(size_t), GFP_KERNEL);
                if (new_list == 0) return 0;
                p->list_size = new_size;
                p->slab_list = new_list;
        }
        return 1;
}

static size_t get_page_from_global_pool(void) {
        slabclass_t *p = &slabclass[SLAB_GLOBAL_PAGE_POOL];
        if (p->slabs < 1) {
                return -1;
        }
        size_t ret = p->slab_list[p->slabs - 1];
        p->slabs--;
        return ret;
}

static size_t memory_allocate(size_t size) {
        size_t ret;

        if (mem_current >= settings.slab_page_size) {
                ret = mem_current;

                if (size > mem_avail) {
                        return -1;
                }

                /* mem_current must be aligned!!! */
                if (size % CHUNK_ALIGN_BYTES) {
                        size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);
                }

                mem_current += size;

                if (size < mem_avail) {
                        mem_avail -= size;
                }
                else {
                        mem_avail = 0;
                }
        }

        return ret;
}

/* Initialize or reallocate a slab in a slabclass[id] */
static int do_slabs_newslab(const unsigned int id) {
        slabclass_t *p = &slabclass[id];
        slabclass_t *g = &slabclass[SLAB_GLOBAL_PAGE_POOL];
        int len = settings.slab_page_size;
        size_t offset;

        //pthread_mutex_lock(&slabs_lock);
        /* 
        if ((!mem_limit && len > mem_avail && p->slabs > 0 && g->slabs == 0)) {
                //printk(KERN_ERR "1 a slab of slab class %3d allocate failed\n", id);
                return 0;
        }
	*/

        if ((grow_slab_list(id) == 0) ||
                (((offset = get_page_from_global_pool()) == -1) &&
                ((offset = memory_allocate((size_t)len)) == -1))) {
                //printk(KERN_ERR "2 a slab of slab class %3d allocate failed\n", id);
                return 0;
        }

        p->end_page_offset = offset;
        p->end_page_free = p->perslab;

        p->slab_list[p->reassign_num+p->slabs++] = offset;
        
	//pthread_mutex_unlock(&slabs_lock);

        return 1;
}

/* Release the chunk structure (put it into the freelist offset array) */
static inline void do_slabs_free(size_t offset, unsigned int id) {
        slabclass_t *p;

        assert(id >= POWER_SMALLEST && id <= power_largest);
        if (id < POWER_SMALLEST || id > power_largest)
                return;

        p = &slabclass[id];

        if (p->sl_curr == p->sl_total) { /* need more space on the free list */
                int new_size = (p->sl_total != 0) ? p->sl_total * 2 : 16;  /* 16 is arbitrary */
                void *new_slots = krealloc(p->slots, new_size * sizeof(size_t), GFP_KERNEL);
                if (new_slots == 0)
                        return;
                p->slots = new_slots;
                p->sl_total = new_size;
        }
        p->slots[p->sl_curr++] = offset;
        return;
}

/* Assign a chunk data structure */
static inline size_t do_slabs_alloc(const size_t size) {
        slabclass_t *p;
        size_t ret = -1;
	int i, flag;

        unsigned int id = slabs_clsid(size);
        if (id < POWER_SMALLEST || id > power_largest) {
                //printk(KERN_ERR "a chunk of slab class %3d allocate failed\n", id);
                return -1;
        }

        p = &slabclass[id];
        assert(size <= p->size);

        /* fail unless we have space at the end of a recently allocated page,
           we have something on our freelist, or we could allocate a new page */
        if (!(p->end_page_free != 0 || p->sl_curr != 0 ||
                do_slabs_newslab(id) != 0)) {
                return -2;   /* We don't have more memory available */
	}
        else if (p->sl_curr != 0) {
                /* return off our freelist */
		if (p->reassign_num == 0)
			ret = p->slots[--p->sl_curr];
		else if (p->reassign_num > 0) {
			do {
				flag = 0;
				ret = p->slots[--p->sl_curr];
				for (i = 0; i < p->reassign_num; i++) {
					if (ret >= p->killing[i] && ret <= (p->killing[i] + settings.slab_page_size)) {
						flag = 1;
						break;
					}
				}
			} while (flag == 1 && p->sl_curr != 0);
			if (flag == 1) {
				if (p->end_page_free == 0)
                                        do_slabs_newslab(id);
				if (p->end_page_free != 0) {
					ret = p->end_page_offset;
					if (--p->end_page_free != 0)
						p->end_page_offset = p->end_page_offset + p->size;
				}
				else
					return -2;
			}
		}
	}
        else {
                /* if we recently allocated a whole page, return from that */
                assert(p->end_page_free != 0);
                ret = p->end_page_offset;
                if (--p->end_page_free != 0) {
                        p->end_page_offset = p->end_page_offset + p->size;
                }
        }

        return ret;
}

enum reassign_result_type {
    REASSIGN_OK = 0, REASSIGN_RUNNING, REASSIGN_BADCLASS, REASSIGN_NOSPARE, REASSIGN_FAILED
};

#endif
