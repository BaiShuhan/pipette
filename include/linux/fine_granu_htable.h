#ifndef _FINE_GRANU_HASH_H_
#define _FINE_GRANU_HASH_H_

#include <linux/types.h>
#include <linux/list.h>

#define LARGEST_ID (63 + 1)
#define ITEM_LINKED 1
#define assert(x)						\
do {								\
	if (unlikely(!(x))) {					\
		pr_err("Assertion failed\n");			\
		BUG();						\
	}							\
} while (0)
#define bucket_entry(_ptr, _type, _member) container_of(_ptr, _type, _member)

typedef struct _stritem {
    struct _stritem *next;
    struct _stritem *prev;
    uint8_t         it_flags;   /* ITEM_* above */
    uint32_t        slabs_clsid;/* which slab class we're in */
} item;

typedef struct {
    loff_t                 offset;
    unsigned int           max_data_len;
    unsigned int           refcount;
    ssize_t                hmb_offset;
    struct hlist_node      node;
    item                   thisit;
    unsigned int           slab_index;
    atomic_t               if_update;
    atomic_t               if_reassign;
    atomic_t               if_cached;
    atomic_t               bucket_waiters;
    wait_queue_head_t      bucket_waitqueue;
} bucket_t;

extern item *heads[LARGEST_ID];
extern item *tails[LARGEST_ID];

static void item_unlink_q(item *it) {
        item **head, **tail;

	assert(it->slabs_clsid < LARGEST_ID);

        head = &heads[it->slabs_clsid];
        tail = &tails[it->slabs_clsid];

        if (*head == it) {
                assert(it->prev == 0);
                *head = it->next;
        }

        if (*tail == it) {
                assert(it->next == 0);
                *tail = it->prev;
        }

        assert(it->next != it);
        assert(it->prev != it);

        if (it->next) it->next->prev = it->prev;
        if (it->prev) it->prev->next = it->next;

        return;
}

static void item_link_q(item *it) { /* item is the new head */
        item **head, **tail;

        assert(it->slabs_clsid < LARGEST_ID);

        head = &heads[it->slabs_clsid];
        tail = &tails[it->slabs_clsid];
        assert(it != *head);
        assert((*head && *tail) || (*head == 0 && *tail == 0));

        it->prev = 0;
        it->next = *head;
        if (it->next) it->next->prev = it;
        *head = it;
        if (*tail == 0) *tail = it;

        return;
}

static inline void do_item_unlink(item *it) {
        if ((it->it_flags & ITEM_LINKED) != 0)
        {
                it->it_flags &= ~ITEM_LINKED;
                item_unlink_q(it);
        }
}

static inline void do_item_link(item *it) {
        assert((it->it_flags & ITEM_LINKED) == 0);
        it->it_flags |= ITEM_LINKED;
        item_link_q(it);
}

static inline void do_item_update(item *it) {
        if ((it->it_flags & ITEM_LINKED) != 0)
        {
                item_unlink_q(it);
                item_link_q(it);
        }
}

#endif
