/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2014-2020,  Mellanox Technologies. All rights reserved.
 */
#ifndef RDMA_IB_PEER_MEM_H
#define RDMA_IB_PEER_MEM_H

#include <rdma/peer_mem.h>
#include <linux/kobject.h>
#include <linux/xarray.h>
#include <rdma/ib_umem.h>

struct ib_peer_memory_statistics {
	atomic64_t num_alloc_mrs;
	atomic64_t num_dealloc_mrs;
	atomic64_t num_reg_pages;
	atomic64_t num_dereg_pages;
	atomic64_t num_reg_bytes;
	atomic64_t num_dereg_bytes;
	unsigned long num_free_callbacks;
};

struct ib_peer_memory_client {
	struct kobject kobj;
	refcount_t usecnt;
	struct completion usecnt_zero;
	const struct peer_memory_client *peer_mem;
	struct list_head core_peer_list;
	struct ib_peer_memory_statistics stats;
	struct xarray umem_xa;
	u32 xa_cyclic_next;
	bool invalidation_required;
};

enum ib_umem_mapped_state {
	UMEM_PEER_UNMAPPED,
	UMEM_PEER_MAPPED,
	UMEM_PEER_INVALIDATED,
};

struct ib_umem_peer {
	struct ib_umem umem;
	struct kref kref;
	/* peer memory that manages this umem */
	struct ib_peer_memory_client *ib_peer_client;
	void *peer_client_context;
	umem_invalidate_func_t invalidation_func;
	void *invalidation_private;
	struct mutex mapping_lock;
	enum ib_umem_mapped_state mapped_state;
	u32 xa_id;
	struct scatterlist *first_sg;
	dma_addr_t first_dma_address;
	unsigned int first_dma_length;
	unsigned int first_length;
	struct scatterlist *last_sg;
	unsigned int last_dma_length;
	unsigned int last_length;
};

struct ib_umem *ib_peer_umem_get(struct ib_umem *old_umem, int old_ret,
				 unsigned long peer_mem_flags);
void ib_peer_umem_release(struct ib_umem *umem);

#endif
