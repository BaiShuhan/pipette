// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ext4/readpage.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 * Copyright (C) 2015, Google, Inc.
 *
 * This was originally taken from fs/mpage.c
 *
 * The intent is the ext4_mpage_readpages() function here is intended
 * to replace mpage_readpages() in the general case, not just for
 * encrypted files.  It has some limitations (see below), where it
 * will fall back to read_block_full_page(), but these limitations
 * should only be hit when page_size != block_size.
 *
 * This will allow us to attach a callback function to support ext4
 * encryption.
 *
 * If anything unusual happens, such as:
 *
 * - encountering a page which has buffers
 * - encountering a page which has a non-hole after a hole
 * - encountering a page with non-contiguous blocks
 *
 * then this code just gives up and calls the buffer_head-based read function.
 * It does handle a page which has holes at the end - that is a common case:
 * the end-of-file on blocksize < PAGE_SIZE setups.
 *
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <linux/gfp.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/prefetch.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/cleancache.h>
#ifdef CONFIG_FINE_GRAINED
#include <linux/ebio.h>
#include <linux/fine_granu_htable.h>
#include <linux/fine_granu_slab.h>
#endif

#include "ext4.h"

#define NUM_PREALLOC_POST_READ_CTXS	128

#ifdef CONFIG_FINE_GRAINED
item *heads[LARGEST_ID];
EXPORT_SYMBOL_GPL(heads);

item *tails[LARGEST_ID];
EXPORT_SYMBOL_GPL(tails);

unsigned int total_cnt_bytes;
EXPORT_SYMBOL_GPL(total_cnt_bytes);

unsigned int total_cnt;
EXPORT_SYMBOL_GPL(total_cnt);

DEFINE_MUTEX(cnt_lock);
EXPORT_SYMBOL_GPL(cnt_lock);
#endif

static struct kmem_cache *bio_post_read_ctx_cache;
static mempool_t *bio_post_read_ctx_pool;

/* postprocessing steps for read bios */
enum bio_post_read_step {
	STEP_INITIAL = 0,
	STEP_DECRYPT,
	STEP_VERITY,
};

struct bio_post_read_ctx {
	struct bio *bio;
	struct work_struct work;
	unsigned int cur_step;
	unsigned int enabled_steps;
};

static void __read_end_io(struct bio *bio)
{
	struct page *page;
	struct bio_vec *bv;
	struct bvec_iter_all iter_all;

	bio_for_each_segment_all(bv, bio, iter_all) {
		page = bv->bv_page;

		/* PG_error was set if any post_read step failed */
		if (bio->bi_status || PageError(page)) {
			ClearPageUptodate(page);
			/* will re-read again later */
			ClearPageError(page);
		} else {
			SetPageUptodate(page);
		}
		unlock_page(page);
	}
	if (bio->bi_private)
		mempool_free(bio->bi_private, bio_post_read_ctx_pool);
	bio_put(bio);
}

static void bio_post_read_processing(struct bio_post_read_ctx *ctx);

static void decrypt_work(struct work_struct *work)
{
	struct bio_post_read_ctx *ctx =
		container_of(work, struct bio_post_read_ctx, work);

	fscrypt_decrypt_bio(ctx->bio);

	bio_post_read_processing(ctx);
}

static void verity_work(struct work_struct *work)
{
	struct bio_post_read_ctx *ctx =
		container_of(work, struct bio_post_read_ctx, work);

	fsverity_verify_bio(ctx->bio);

	bio_post_read_processing(ctx);
}

static void bio_post_read_processing(struct bio_post_read_ctx *ctx)
{
	/*
	 * We use different work queues for decryption and for verity because
	 * verity may require reading metadata pages that need decryption, and
	 * we shouldn't recurse to the same workqueue.
	 */
	switch (++ctx->cur_step) {
	case STEP_DECRYPT:
		if (ctx->enabled_steps & (1 << STEP_DECRYPT)) {
			INIT_WORK(&ctx->work, decrypt_work);
			fscrypt_enqueue_decrypt_work(&ctx->work);
			return;
		}
		ctx->cur_step++;
		/* fall-through */
	case STEP_VERITY:
		if (ctx->enabled_steps & (1 << STEP_VERITY)) {
			INIT_WORK(&ctx->work, verity_work);
			fsverity_enqueue_verify_work(&ctx->work);
			return;
		}
		ctx->cur_step++;
		/* fall-through */
	default:
		__read_end_io(ctx->bio);
	}
}

static bool bio_post_read_required(struct bio *bio)
{
	return bio->bi_private && !bio->bi_status;
}

/*
 * I/O completion handler for multipage BIOs.
 *
 * The mpage code never puts partial pages into a BIO (except for end-of-file).
 * If a page does not map to a contiguous run of blocks then it simply falls
 * back to block_read_full_page().
 *
 * Why is this?  If a page's completion depends on a number of different BIOs
 * which can complete in any order (or at the same time) then determining the
 * status of that page is hard.  See end_buffer_async_read() for the details.
 * There is no point in duplicating all that complexity.
 */
static void mpage_end_io(struct bio *bio)
{
	if (bio_post_read_required(bio)) {
		struct bio_post_read_ctx *ctx = bio->bi_private;

		ctx->cur_step = STEP_INITIAL;
		bio_post_read_processing(ctx);
		return;
	}
	__read_end_io(bio);
}

static inline bool ext4_need_verity(const struct inode *inode, pgoff_t idx)
{
	return fsverity_active(inode) &&
	       idx < DIV_ROUND_UP(inode->i_size, PAGE_SIZE);
}

static struct bio_post_read_ctx *get_bio_post_read_ctx(struct inode *inode,
						       struct bio *bio,
						       pgoff_t first_idx)
{
	unsigned int post_read_steps = 0;
	struct bio_post_read_ctx *ctx = NULL;

	if (IS_ENCRYPTED(inode) && S_ISREG(inode->i_mode))
		post_read_steps |= 1 << STEP_DECRYPT;

	if (ext4_need_verity(inode, first_idx))
		post_read_steps |= 1 << STEP_VERITY;

	if (post_read_steps) {
		ctx = mempool_alloc(bio_post_read_ctx_pool, GFP_NOFS);
		if (!ctx)
			return ERR_PTR(-ENOMEM);
		ctx->bio = bio;
		ctx->enabled_steps = post_read_steps;
		bio->bi_private = ctx;
	}
	return ctx;
}

static inline loff_t ext4_readpage_limit(struct inode *inode)
{
	if (IS_ENABLED(CONFIG_FS_VERITY) &&
	    (IS_VERITY(inode) || ext4_verity_in_progress(inode)))
		return inode->i_sb->s_maxbytes;

	return i_size_read(inode);
}

int ext4_mpage_readpages(struct address_space *mapping,
			 struct list_head *pages, struct page *page,
			 unsigned nr_pages, bool is_readahead)
{
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;

	struct inode *inode = mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	const unsigned blocks_per_page = PAGE_SIZE >> blkbits;
	const unsigned blocksize = 1 << blkbits;
	sector_t block_in_file;
	sector_t last_block;
	sector_t last_block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	struct block_device *bdev = inode->i_sb->s_bdev;
	int length;
	unsigned relative_block = 0;
	struct ext4_map_blocks map;

	map.m_pblk = 0;
	map.m_lblk = 0;
	map.m_len = 0;
	map.m_flags = 0;

	for (; nr_pages; nr_pages--) {
		int fully_mapped = 1;
		unsigned first_hole = blocks_per_page;

		if (pages) {
			page = lru_to_page(pages);

			prefetchw(&page->flags);
			list_del(&page->lru);
			if (add_to_page_cache_lru(page, mapping, page->index,
				  readahead_gfp_mask(mapping)))
				goto next_page;
		}

		if (page_has_buffers(page))
			goto confused;

		block_in_file = (sector_t)page->index << (PAGE_SHIFT - blkbits);
		last_block = block_in_file + nr_pages * blocks_per_page;
		last_block_in_file = (ext4_readpage_limit(inode) +
				      blocksize - 1) >> blkbits;
		if (last_block > last_block_in_file)
			last_block = last_block_in_file;
		page_block = 0;

		/*
		 * Map blocks using the previous result first.
		 */
		if ((map.m_flags & EXT4_MAP_MAPPED) &&
		    block_in_file > map.m_lblk &&
		    block_in_file < (map.m_lblk + map.m_len)) {
			unsigned map_offset = block_in_file - map.m_lblk;
			unsigned last = map.m_len - map_offset;

			for (relative_block = 0; ; relative_block++) {
				if (relative_block == last) {
					/* needed? */
					map.m_flags &= ~EXT4_MAP_MAPPED;
					break;
				}
				if (page_block == blocks_per_page)
					break;
				blocks[page_block] = map.m_pblk + map_offset +
					relative_block;
				page_block++;
				block_in_file++;
			}
		}

		/*
		 * Then do more ext4_map_blocks() calls until we are
		 * done with this page.
		 */
		while (page_block < blocks_per_page) {
			if (block_in_file < last_block) {
				map.m_lblk = block_in_file;
				map.m_len = last_block - block_in_file;

				if (ext4_map_blocks(NULL, inode, &map, 0) < 0) {
				set_error_page:
					SetPageError(page);
					zero_user_segment(page, 0,
							  PAGE_SIZE);
					unlock_page(page);
					goto next_page;
				}
			}
			if ((map.m_flags & EXT4_MAP_MAPPED) == 0) {
				fully_mapped = 0;
				if (first_hole == blocks_per_page)
					first_hole = page_block;
				page_block++;
				block_in_file++;
				continue;
			}
			if (first_hole != blocks_per_page)
				goto confused;		/* hole -> non-hole */

			/* Contiguous blocks? */
			if (page_block && blocks[page_block-1] != map.m_pblk-1)
				goto confused;
			for (relative_block = 0; ; relative_block++) {
				if (relative_block == map.m_len) {
					/* needed? */
					map.m_flags &= ~EXT4_MAP_MAPPED;
					break;
				} else if (page_block == blocks_per_page)
					break;
				blocks[page_block] = map.m_pblk+relative_block;
				page_block++;
				block_in_file++;
			}
		}
		if (first_hole != blocks_per_page) {
			zero_user_segment(page, first_hole << blkbits,
					  PAGE_SIZE);
			if (first_hole == 0) {
				if (ext4_need_verity(inode, page->index) &&
				    !fsverity_verify_page(page))
					goto set_error_page;
				SetPageUptodate(page);
				unlock_page(page);
				goto next_page;
			}
		} else if (fully_mapped) {
			SetPageMappedToDisk(page);
		}
		if (fully_mapped && blocks_per_page == 1 &&
		    !PageUptodate(page) && cleancache_get_page(page) == 0) {
			SetPageUptodate(page);
			goto confused;
		}

		/*
		 * This page will go to BIO.  Do we need to send this
		 * BIO off first?
		 */
		if (bio && (last_block_in_bio != blocks[0] - 1)) {
		submit_and_realloc:
			submit_bio(bio);
			bio = NULL;
		}
		if (bio == NULL) {
			struct bio_post_read_ctx *ctx;

			bio = bio_alloc(GFP_KERNEL,
				min_t(int, nr_pages, BIO_MAX_PAGES));
			if (!bio)
				goto set_error_page;
			ctx = get_bio_post_read_ctx(inode, bio, page->index);
			if (IS_ERR(ctx)) {
				bio_put(bio);
				bio = NULL;
				goto set_error_page;
			}
			bio_set_dev(bio, bdev);
			bio->bi_iter.bi_sector = blocks[0] << (blkbits - 9);
			bio->bi_end_io = mpage_end_io;
			bio->bi_private = ctx;
			bio_set_op_attrs(bio, REQ_OP_READ,
						is_readahead ? REQ_RAHEAD : 0);
		}

		length = first_hole << blkbits;
		if (bio_add_page(bio, page, length, 0) < length)
			goto submit_and_realloc;

		if (((map.m_flags & EXT4_MAP_BOUNDARY) &&
		     (relative_block == map.m_len)) ||
		    (first_hole != blocks_per_page)) {
			submit_bio(bio);
			bio = NULL;
		} else
			last_block_in_bio = blocks[blocks_per_page - 1];
		goto next_page;
	confused:
		if (bio) {
			submit_bio(bio);
			bio = NULL;
		}
		if (!PageUptodate(page))
			block_read_full_page(page, ext4_get_block);
		else
			unlock_page(page);
	next_page:
		if (pages)
			put_page(page);
	}
	BUG_ON(pages && !list_empty(pages));
	if (bio)
		submit_bio(bio);
	return 0;
}

int __init ext4_init_post_read_processing(void)
{
	bio_post_read_ctx_cache =
		kmem_cache_create("ext4_bio_post_read_ctx",
				  sizeof(struct bio_post_read_ctx), 0, 0, NULL);
	if (!bio_post_read_ctx_cache)
		goto fail;
	bio_post_read_ctx_pool =
		mempool_create_slab_pool(NUM_PREALLOC_POST_READ_CTXS,
					 bio_post_read_ctx_cache);
	if (!bio_post_read_ctx_pool)
		goto fail_free_cache;
	return 0;

fail_free_cache:
	kmem_cache_destroy(bio_post_read_ctx_cache);
fail:
	return -ENOMEM;
}

void ext4_exit_post_read_processing(void)
{
	mempool_destroy(bio_post_read_ctx_pool);
	kmem_cache_destroy(bio_post_read_ctx_cache);
}

#ifdef CONFIG_FINE_GRAINED
int ext4_fine_granu_mpage_readpage(struct inode *inode, pgoff_t page_offset, void **ret_ebio)
{
        struct ebio *ebio = NULL;

        const unsigned blkbits = inode->i_blkbits;
        const unsigned blocks_per_page = PAGE_SIZE >> blkbits;
        const unsigned blocksize = 1 << blkbits;
        sector_t block_in_file;
        sector_t last_block;
        sector_t last_block_in_file;
        sector_t blocks[MAX_BUF_PER_PAGE];
        unsigned page_block;
        unsigned relative_block = 0;
        struct ext4_map_blocks map;

        map.m_pblk = 0;
        map.m_lblk = 0;
        map.m_len = 0;
        map.m_flags = 0;

        int fully_mapped = 1;
        unsigned first_hole = blocks_per_page;

        block_in_file = page_offset << (PAGE_SHIFT - blkbits);
        last_block = block_in_file + blocks_per_page;
        last_block_in_file = (i_size_read(inode) + blocksize - 1) >> blkbits;
        if (last_block > last_block_in_file)
                last_block = last_block_in_file;
        page_block = 0;

        /*
         * Then do more ext4_map_blocks() calls until we are
         * done with this page.
         */
        while (page_block < blocks_per_page) {
                if (block_in_file < last_block) {
                        map.m_lblk = block_in_file;
                        map.m_len = last_block - block_in_file;

                        if (ext4_map_blocks(NULL, inode, &map, 0) < 0)
                            goto next_ebio;
                }
                if ((map.m_flags & EXT4_MAP_MAPPED) == 0) {
                        fully_mapped = 0;
                        if (first_hole == blocks_per_page)
                                first_hole = page_block;
                        page_block++;
                        block_in_file++;
                        continue;
                }

                for (relative_block = 0; ; relative_block++) {
                        if (relative_block == map.m_len) {
                                /* needed? */
                                map.m_flags &= ~EXT4_MAP_MAPPED;
                                break;
                        } else if (page_block == blocks_per_page)
                                break;
                        blocks[page_block] = map.m_pblk+relative_block;
                        page_block++;
                        block_in_file++;
                }
        }

        if (first_hole != blocks_per_page) {
                if (first_hole == 0)
                    goto next_ebio;
        }

        if (!ebio) {
                ebio = ebio_alloc(GFP_KERNEL, min_t(int, 1, BIO_MAX_PAGES));
                list_add_tail(&ebio->list, &current->plug->ebio_list);
                BUG_ON(!ebio);
                ebio->block = blocks[0];
        }

        if (((map.m_flags & EXT4_MAP_BOUNDARY) && (relative_block == map.m_len)) || (first_hole != blocks_per_page))
                ebio = NULL;

next_ebio:
        *ret_ebio = (void *)ebio;
        return 0;
}

static int ext4_fine_granu_readpage(struct inode *inode, pgoff_t page_offset, void **ebio)
{
    /* If the file has inline data, no need to do readpages. */
    if (ext4_has_inline_data(inode))
        return 0;

    return ext4_fine_granu_mpage_readpage(inode, page_offset, ebio);
}

static bucket_t * do_fine_granu_cache(struct inode *inode, pgoff_t page_offset, unsigned long offset, size_t count, bucket_t *bucket)
{
    loff_t file_offset;
    item *tail, *tmp_tail;
    bucket_t *new_bucket, *del_bucket;
    unsigned int id, index;

    file_offset = ((loff_t)page_offset << PAGE_SHIFT) + offset;

    if (bucket) {
        //the bucket is inside the htable
        if (bucket->hmb_offset != BUFFER_OFFSET) {
            id = slabs_clsid(bucket->max_data_len);
            if (slabclass[id].size < count) {
                bucket->hmb_offset = do_slabs_alloc(count);
                id = slabs_clsid(count);
                if (bucket->hmb_offset == -2) {
                    if (slabclass[id].slabs > 0) {
                        if (FGCratio >= PCratio) {
                            slabs_reassign(-1, 0);
                            bucket->hmb_offset = do_slabs_alloc(count);
                        }
                        else {
                            tail = tails[id];
                            del_bucket = bucket_entry(tail, bucket_t, thisit);
                            if (slabclass[id].reassign_num > 0) {
                                    do {
                                            if (del_bucket->slab_index < slabclass[id].reassign_num) {
                                                    tmp_tail = del_bucket->thisit.prev;
                                                    do_item_unlink(&del_bucket->thisit);
                                                    del_bucket = bucket_entry(tmp_tail, bucket_t, thisit);
                                            }
                                            else
                                                    tmp_tail = 0;
                                    } while (tmp_tail != 0);
                                    do_item_unlink(&del_bucket->thisit);
                            }
                            else
                                    do_item_unlink(tail);
                            do_slabs_free(del_bucket->hmb_offset, id);
                            slabclass[id].evicted++;
                            bucket->hmb_offset = do_slabs_alloc(count);
			    atomic_set(&del_bucket->if_cached, 2);
                        }
                    }
                    else {
                        slabs_reassign(-1, 0);
                        bucket->hmb_offset = do_slabs_alloc(count);
                    }
                    if (bucket->hmb_offset == -2) {
			//printk(KERN_EMERG "allocate a chunk error, store in TempBuf!\n");
                        bucket->hmb_offset = BUFFER_OFFSET;
			return bucket;
                    }
                }
                if (bucket->hmb_offset >= 0) {
                    do_item_unlink(&bucket->thisit);
                    bucket->max_data_len = count;
		    for (index = slabclass[id].reassign_num + slabclass[id].slabs - 1; index >= slabclass[id].reassign_num; index--) {
			    if (bucket->hmb_offset >= slabclass[id].slab_list[index] && bucket->hmb_offset <= (slabclass[id].slab_list[index] + settings.slab_page_size)) {
				    bucket->slab_index = index;
				    break;
			    }
		    }
                    bucket->thisit.slabs_clsid = id;
                    do_item_link(&bucket->thisit);
                }
            }
            else {
                bucket->max_data_len = count;
                if (slabclass[id].reassign_num > 0 && bucket->slab_index < slabclass[id].reassign_num) {
			bucket->hmb_offset = do_slabs_alloc(count);
			if (bucket->hmb_offset == -2) {
				if (slabclass[id].slabs > 0) {
					if (FGCratio >= PCratio) {
						slabs_reassign(-1, 0);
                                                bucket->hmb_offset = do_slabs_alloc(count);
                                        }
					else {
						tail = tails[id];
						del_bucket = bucket_entry(tail, bucket_t, thisit);
						if (slabclass[id].reassign_num > 0) {
							do {
								if (del_bucket->slab_index < slabclass[id].reassign_num) {
									tmp_tail = del_bucket->thisit.prev;
                                                                        do_item_unlink(&del_bucket->thisit);
                                                                        del_bucket = bucket_entry(tmp_tail, bucket_t, thisit);
                                                                }
                                                                else
									tmp_tail = 0;
                                                        } while (tmp_tail != 0);
                                                        do_item_unlink(&del_bucket->thisit);
                                                }
                                                else
							do_item_unlink(tail);
						do_slabs_free(del_bucket->hmb_offset, id);
                                                slabclass[id].evicted++;
                                                bucket->hmb_offset = do_slabs_alloc(count);
						atomic_set(&del_bucket->if_cached, 2);
					}
				}
				else {
					slabs_reassign(-1, 0);
					bucket->hmb_offset = do_slabs_alloc(count);
				}
				if (bucket->hmb_offset == -2) {
					//printk(KERN_EMERG "allocate a chunk error, store in TempBuf!\n");
                                        bucket->hmb_offset = BUFFER_OFFSET;
					return bucket;
                                }
			}
			if (bucket->hmb_offset >= 0) {
				for (index = slabclass[id].reassign_num + slabclass[id].slabs - 1; index >= slabclass[id].reassign_num; index--) {
					if (bucket->hmb_offset >= slabclass[id].slab_list[index] && bucket->hmb_offset <= (slabclass[id].slab_list[index] + settings.slab_page_size)) {
						bucket->slab_index = index;
						break;
					}
				}
				do_item_update(&bucket->thisit);
                        }
                }
                else
                    do_item_update(&bucket->thisit);
            }
        }
        else {
            bucket->hmb_offset = do_slabs_alloc(count);
            id = slabs_clsid(count);
            if (bucket->hmb_offset == -2) {
                if (slabclass[id].slabs > 0) {
                    if (FGCratio >= PCratio) {
                        slabs_reassign(-1, 0);
                        bucket->hmb_offset = do_slabs_alloc(count);
                    }
                    else {
                        tail = tails[id];
                        del_bucket = bucket_entry(tail, bucket_t, thisit);
                        if (slabclass[id].reassign_num > 0) {
                            do {
                                    if (del_bucket->slab_index < slabclass[id].reassign_num) {
                                            tmp_tail = del_bucket->thisit.prev;
                                            do_item_unlink(&del_bucket->thisit);
                                            del_bucket = bucket_entry(tmp_tail, bucket_t, thisit);
                                    }
                                    else
                                            tmp_tail = 0;
                            } while (tmp_tail != 0);
                            do_item_unlink(&del_bucket->thisit);
                        }
                        else
                                do_item_unlink(tail);
                        do_slabs_free(del_bucket->hmb_offset, id);
                        slabclass[id].evicted++;
                        bucket->hmb_offset = do_slabs_alloc(count);
			atomic_set(&del_bucket->if_cached, 2);
                    }
                }
                else {
                    slabs_reassign(-1, 0);
                    bucket->hmb_offset = do_slabs_alloc(count);
                }
                if (bucket->hmb_offset == -2) {
		    //printk(KERN_EMERG "allocate a chunk error, store in TempBuf!\n");
                    bucket->hmb_offset = BUFFER_OFFSET;
		    return bucket;
                }
            }
            if (bucket->hmb_offset >= 0) {
                bucket->max_data_len = count;
		for (index = slabclass[id].reassign_num + slabclass[id].slabs - 1; index >= slabclass[id].reassign_num; index--) {
			if (bucket->hmb_offset >= slabclass[id].slab_list[index] && bucket->hmb_offset <= (slabclass[id].slab_list[index] + settings.slab_page_size)) {
				bucket->slab_index = index;
				break;
			}
		}
                bucket->thisit.slabs_clsid = id;
                do_item_link(&bucket->thisit);
            }
        }
    }
    else {
        //the bucket is not inside the htable, add it
        new_bucket = (bucket_t *)kzalloc(sizeof(bucket_t), GFP_KERNEL);
        new_bucket->offset = file_offset;
        new_bucket->refcount += 1;
        new_bucket->hmb_offset = BUFFER_OFFSET;
	atomic_set(&new_bucket->if_update, 0);
	atomic_set(&new_bucket->if_reassign, 0);
        atomic_set(&new_bucket->if_cached, 0);
	atomic_set(&new_bucket->bucket_waiters, 0);
	init_waitqueue_head(&new_bucket->bucket_waitqueue);
	hlist_add_head(&new_bucket->node, &inode->fine_granu_htable[hash_min(new_bucket->offset, inode->htable_size)]);
        bucket = new_bucket;
    }

    return bucket;
}

ssize_t do_fine_granu_readpage(struct inode *inode, pgoff_t page_offset, unsigned long offset, size_t count, bucket_t *bucket, int flag)
{
    struct ebio *ebio = NULL;
    struct blk_plug plug;
    bucket_t *ret_bucket = bucket;
    ssize_t hmb_offset;

    blk_start_plug(&plug);
    ext4_fine_granu_readpage(inode, page_offset, (void *)&ebio);
    blk_finish_plug(&plug);
    //printk(KERN_EMERG "strLBN,%lld,offset,%lld,count,%lld\n", ebio->block, offset, count);  //for recording I/O traffic
   
    mutex_lock(&cnt_lock);
    total_cnt_bytes += count;
    total_cnt++;
    mutex_unlock(&cnt_lock);

    if (!flag)
    {
            ret_bucket = do_fine_granu_cache(inode, page_offset, offset, count, bucket);
	    hmb_offset = ret_bucket->hmb_offset;
    }
    else
            hmb_offset = ret_bucket->hmb_offset;
    
    //record_read_info(offset, count, hmb_offset);  //uncommented after enabling byte-addressable interface

    DEFINE_WAIT(wait);
    add_wait_queue(&ebio->ebio_waitqueue, &wait);
    wait_event(ebio->ebio_waitqueue, ebio_is_completed(ebio));
    finish_wait(&ebio->ebio_waitqueue, &wait);

    if(atomic_read(&ret_bucket->if_cached) == 0 && hmb_offset != BUFFER_OFFSET)
	    atomic_inc(&ret_bucket->if_cached);
    if (atomic_read(&ret_bucket->bucket_waiters))
	    wake_up_all(&ret_bucket->bucket_waitqueue);

    return hmb_offset;
}
EXPORT_SYMBOL_GPL(do_fine_granu_readpage);
#endif

