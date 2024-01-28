// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2014-2020,  Mellanox Technologies. All rights reserved.
 */

#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <linux/sched/mm.h>
#include "ib_peer_mem.h"

static DEFINE_MUTEX(peer_memory_mutex);
static LIST_HEAD(peer_memory_list);
static struct kobject *peers_kobj;
#define PEER_NO_INVALIDATION_ID U32_MAX

static int ib_invalidate_peer_memory(void *reg_handle, u64 core_context);

struct peer_mem_attribute {
	struct attribute attr;
	ssize_t (*show)(struct ib_peer_memory_client *ib_peer_client,
			struct peer_mem_attribute *attr, char *buf);
	ssize_t (*store)(struct ib_peer_memory_client *ib_peer_client,
			 struct peer_mem_attribute *attr, const char *buf,
			 size_t count);
};
#define PEER_ATTR_RO(_name)                                                    \
	struct peer_mem_attribute peer_attr_ ## _name = __ATTR_RO(_name)

static ssize_t version_show(struct ib_peer_memory_client *ib_peer_client,
			    struct peer_mem_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n",
			 ib_peer_client->peer_mem->version);
}
static PEER_ATTR_RO(version);

static ssize_t num_alloc_mrs_show(struct ib_peer_memory_client *ib_peer_client,
				  struct peer_mem_attribute *attr, char *buf)
{
	return scnprintf(
		buf, PAGE_SIZE, "%llu\n",
		(u64)atomic64_read(&ib_peer_client->stats.num_alloc_mrs));
}
static PEER_ATTR_RO(num_alloc_mrs);

static ssize_t
num_dealloc_mrs_show(struct ib_peer_memory_client *ib_peer_client,
		     struct peer_mem_attribute *attr, char *buf)

{
	return scnprintf(
		buf, PAGE_SIZE, "%llu\n",
		(u64)atomic64_read(&ib_peer_client->stats.num_dealloc_mrs));
}
static PEER_ATTR_RO(num_dealloc_mrs);

static ssize_t num_reg_pages_show(struct ib_peer_memory_client *ib_peer_client,
				  struct peer_mem_attribute *attr, char *buf)
{
	return scnprintf(
		buf, PAGE_SIZE, "%llu\n",
		(u64)atomic64_read(&ib_peer_client->stats.num_reg_pages));
}
static PEER_ATTR_RO(num_reg_pages);

static ssize_t
num_dereg_pages_show(struct ib_peer_memory_client *ib_peer_client,
		     struct peer_mem_attribute *attr, char *buf)
{
	return scnprintf(
		buf, PAGE_SIZE, "%llu\n",
		(u64)atomic64_read(&ib_peer_client->stats.num_dereg_pages));
}
static PEER_ATTR_RO(num_dereg_pages);

static ssize_t num_reg_bytes_show(struct ib_peer_memory_client *ib_peer_client,
				  struct peer_mem_attribute *attr, char *buf)
{
	return scnprintf(
		buf, PAGE_SIZE, "%llu\n",
		(u64)atomic64_read(&ib_peer_client->stats.num_reg_bytes));
}
static PEER_ATTR_RO(num_reg_bytes);

static ssize_t
num_dereg_bytes_show(struct ib_peer_memory_client *ib_peer_client,
		     struct peer_mem_attribute *attr, char *buf)
{
	return scnprintf(
		buf, PAGE_SIZE, "%llu\n",
		(u64)atomic64_read(&ib_peer_client->stats.num_dereg_bytes));
}
static PEER_ATTR_RO(num_dereg_bytes);

static ssize_t
num_free_callbacks_show(struct ib_peer_memory_client *ib_peer_client,
			struct peer_mem_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%lu\n",
			 ib_peer_client->stats.num_free_callbacks);
}
static PEER_ATTR_RO(num_free_callbacks);

static struct attribute *peer_mem_attrs[] = {
			&peer_attr_version.attr,
			&peer_attr_num_alloc_mrs.attr,
			&peer_attr_num_dealloc_mrs.attr,
			&peer_attr_num_reg_pages.attr,
			&peer_attr_num_dereg_pages.attr,
			&peer_attr_num_reg_bytes.attr,
			&peer_attr_num_dereg_bytes.attr,
			&peer_attr_num_free_callbacks.attr,
			NULL,
};

static const struct attribute_group peer_mem_attr_group = {
	.attrs = peer_mem_attrs,
};

static ssize_t peer_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct peer_mem_attribute *peer_attr =
		container_of(attr, struct peer_mem_attribute, attr);

	if (!peer_attr->show)
		return -EIO;
	return peer_attr->show(container_of(kobj, struct ib_peer_memory_client,
					    kobj),
			       peer_attr, buf);
}

static const struct sysfs_ops peer_mem_sysfs_ops = {
	.show = peer_attr_show,
};

static void ib_peer_memory_client_release(struct kobject *kobj)
{
	struct ib_peer_memory_client *ib_peer_client =
		container_of(kobj, struct ib_peer_memory_client, kobj);

	kfree(ib_peer_client);
}

static struct kobj_type peer_mem_type = {
	.sysfs_ops = &peer_mem_sysfs_ops,
	.release = ib_peer_memory_client_release,
};

static int ib_memory_peer_check_mandatory(const struct peer_memory_client
						     *peer_client)
{
#define PEER_MEM_MANDATORY_FUNC(x) {offsetof(struct peer_memory_client, x), #x}
	int i;
	static const struct {
		size_t offset;
		char *name;
	} mandatory_table[] = {
		PEER_MEM_MANDATORY_FUNC(acquire),
		PEER_MEM_MANDATORY_FUNC(get_pages),
		PEER_MEM_MANDATORY_FUNC(put_pages),
		PEER_MEM_MANDATORY_FUNC(dma_map),
		PEER_MEM_MANDATORY_FUNC(dma_unmap),
	};

	for (i = 0; i < ARRAY_SIZE(mandatory_table); ++i) {
		if (!*(void **)((void *)peer_client +
				mandatory_table[i].offset)) {
			pr_err("Peer memory %s is missing mandatory function %s\n",
			       peer_client->name, mandatory_table[i].name);
			return -EINVAL;
		}
	}

	return 0;
}

void *
ib_register_peer_memory_client(const struct peer_memory_client *peer_client,
			       invalidate_peer_memory *invalidate_callback)
{
	struct ib_peer_memory_client *ib_peer_client;
	int ret;

	if (ib_memory_peer_check_mandatory(peer_client))
		return NULL;

	ib_peer_client = kzalloc(sizeof(*ib_peer_client), GFP_KERNEL);
	if (!ib_peer_client)
		return NULL;
	kobject_init(&ib_peer_client->kobj, &peer_mem_type);
	refcount_set(&ib_peer_client->usecnt, 1);
	init_completion(&ib_peer_client->usecnt_zero);
	ib_peer_client->peer_mem = peer_client;
	xa_init_flags(&ib_peer_client->umem_xa, XA_FLAGS_ALLOC);

	/*
	 * If the peer wants the invalidation_callback then all memory users
	 * linked to that peer must support invalidation.
	 */
	if (invalidate_callback) {
		*invalidate_callback = ib_invalidate_peer_memory;
		ib_peer_client->invalidation_required = true;
	}

	mutex_lock(&peer_memory_mutex);
	if (!peers_kobj) {
		/* Created under /sys/kernel/mm */
		peers_kobj = kobject_create_and_add("memory_peers", mm_kobj);
		if (!peers_kobj)
			goto err_unlock;
	}

	ret = kobject_add(&ib_peer_client->kobj, peers_kobj, peer_client->name);
	if (ret)
		goto err_parent;

	ret = sysfs_create_group(&ib_peer_client->kobj,
				 &peer_mem_attr_group);
	if (ret)
		goto err_parent;
	list_add_tail(&ib_peer_client->core_peer_list, &peer_memory_list);
	mutex_unlock(&peer_memory_mutex);
	return ib_peer_client;

err_parent:
	if (list_empty(&peer_memory_list)) {
		kobject_put(peers_kobj);
		peers_kobj = NULL;
	}
err_unlock:
	mutex_unlock(&peer_memory_mutex);
	kobject_put(&ib_peer_client->kobj);
	return NULL;
}
EXPORT_SYMBOL(ib_register_peer_memory_client);

void ib_unregister_peer_memory_client(void *reg_handle)
{
	struct ib_peer_memory_client *ib_peer_client = reg_handle;

	mutex_lock(&peer_memory_mutex);
	list_del(&ib_peer_client->core_peer_list);
	if (list_empty(&peer_memory_list)) {
		kobject_put(peers_kobj);
		peers_kobj = NULL;
	}
	mutex_unlock(&peer_memory_mutex);

	/*
	 * Wait for all umems to be destroyed before returning. Once
	 * ib_unregister_peer_memory_client() returns no umems will call any
	 * peer_mem ops.
	 */
	if (refcount_dec_and_test(&ib_peer_client->usecnt))
		complete(&ib_peer_client->usecnt_zero);
	wait_for_completion(&ib_peer_client->usecnt_zero);

	kobject_put(&ib_peer_client->kobj);
}
EXPORT_SYMBOL(ib_unregister_peer_memory_client);

static struct ib_peer_memory_client *
ib_get_peer_client(unsigned long addr, size_t size,
		   unsigned long peer_mem_flags, void **peer_client_context)
{
	struct ib_peer_memory_client *ib_peer_client;
	int ret = 0;

	mutex_lock(&peer_memory_mutex);
	list_for_each_entry(ib_peer_client, &peer_memory_list,
			    core_peer_list) {
		if (ib_peer_client->invalidation_required &&
		    (!(peer_mem_flags & IB_PEER_MEM_INVAL_SUPP)))
			continue;
		ret = ib_peer_client->peer_mem->acquire(addr, size, NULL, NULL,
							peer_client_context);
		if (ret > 0) {
			refcount_inc(&ib_peer_client->usecnt);
			mutex_unlock(&peer_memory_mutex);
			return ib_peer_client;
		}
	}
	mutex_unlock(&peer_memory_mutex);
	return NULL;
}

static void ib_put_peer_client(struct ib_peer_memory_client *ib_peer_client,
			       void *peer_client_context)
{
	if (ib_peer_client->peer_mem->release)
		ib_peer_client->peer_mem->release(peer_client_context);
	if (refcount_dec_and_test(&ib_peer_client->usecnt))
		complete(&ib_peer_client->usecnt_zero);
}

static void ib_peer_umem_kref_release(struct kref *kref)
{
	struct ib_umem_peer *umem_p =
		container_of(kref, struct ib_umem_peer, kref);

	mutex_destroy(&umem_p->mapping_lock);
	kfree(umem_p);
}

static void ib_unmap_peer_client(struct ib_umem_peer *umem_p,
				 enum ib_umem_mapped_state cur_state,
				 enum ib_umem_mapped_state to_state)
{
	struct ib_peer_memory_client *ib_peer_client = umem_p->ib_peer_client;
	const struct peer_memory_client *peer_mem = ib_peer_client->peer_mem;
	struct ib_umem *umem = &umem_p->umem;

	if (cur_state == UMEM_PEER_MAPPED &&
	    (to_state == UMEM_PEER_UNMAPPED ||
	     to_state == UMEM_PEER_INVALIDATED)) {
		/*
		 * In the invalidated state we will never touch the sg again,
		 * but the client might, so fix it anyhow.
		 */
		if (umem_p->last_sg) {
			umem_p->last_sg->length = umem_p->last_length;
			sg_dma_len(umem_p->last_sg) = umem_p->last_dma_length;
		}

		if (umem_p->first_sg) {
			umem_p->first_sg->dma_address =
				umem_p->first_dma_address;
			umem_p->first_sg->length = umem_p->first_length;
			sg_dma_len(umem_p->first_sg) = umem_p->first_dma_length;
		}

		if (to_state == UMEM_PEER_UNMAPPED) {
			peer_mem->dma_unmap(&umem_p->umem.sgt_append.sgt,
					    umem_p->peer_client_context,
					    umem_p->umem.ibdev->dma_device);
			peer_mem->put_pages(&umem_p->umem.sgt_append.sgt,
					    umem_p->peer_client_context);
		}

		memset(&umem->sgt_append.sgt, 0, sizeof(umem->sgt_append));
		atomic64_inc(&ib_peer_client->stats.num_dealloc_mrs);
	}

	if ((cur_state == UMEM_PEER_MAPPED && to_state == UMEM_PEER_UNMAPPED) ||
	    (cur_state == UMEM_PEER_INVALIDATED &&
	     to_state == UMEM_PEER_UNMAPPED)) {
		atomic64_add(umem->sgt_append.sgt.nents,
			     &ib_peer_client->stats.num_dereg_pages);
		atomic64_add(umem->length,
			     &ib_peer_client->stats.num_dereg_bytes);
	}
	umem_p->mapped_state = to_state;
}

/*
 * True if the client should do unmap itself after the invalidate callback
 * returns. Clients operating in this mode need to use this locking pattern:
 *
 * client_invalidate:
 *    mutex_lock(&client_lock)
 *     invalidate_callback():
 *       mutex_lock(mapping_lock)
 *       mutex_unlock(mapping_lock)
 *     client_dma_unmap()
 *     client_put_pages()
 *    mutex_unlock(&client_lock)
 *
 * ib_umem_stop_invalidation_notifier():
 *  mutex_lock(mapping_lock)
 *  mutex_unlock(mapping_lock)
 *  peer_mem->dma_unmap():
 *    mutex_lock(&client_lock)
 *     client_dma_unmap()
 *    mutex_unlock(&client_lock)
 *  peer_mem->put_pages():
 *    mutex_lock(&client_lock)
 *     client_put_pages()
 *    mutex_unlock(&client_lock)
 *
 * ib_peer_umem_release():
 *  peer_mem->release():
 *    mutex_lock(&client_lock)
 *    mutex_unlock(&client_lock)
 *
 * Noting that dma_unmap/put_pages can be called even though invalidate has
 * already done the unmap, and release() can be called concurrently with
 * invalidate. The client must protect itself against these races.
 */
static bool ib_peer_unmap_on_invalidate(struct ib_umem_peer *umem_p)
{
	const struct peer_memory_client *peer_mem =
		umem_p->ib_peer_client->peer_mem;
	const struct peer_memory_client_ex *peer_mem_ex;

	if (peer_mem->version[IB_PEER_MEMORY_VER_MAX - 1] == 0)
		return false;
	peer_mem_ex = container_of(peer_mem, const struct peer_memory_client_ex,
				   client);
	if (peer_mem_ex->ex_size <
	    offsetofend(struct peer_memory_client_ex, flags))
		return false;
	return peer_mem_ex->flags & PEER_MEM_INVALIDATE_UNMAPS;
}

static int ib_invalidate_peer_memory(void *reg_handle, u64 core_context)
{
	struct ib_peer_memory_client *ib_peer_client = reg_handle;
	struct ib_umem_peer *umem_p;

	/*
	 * The client is not required to fence against invalidation during
	 * put_pages() as that would deadlock when we call put_pages() here.
	 * Thus the core_context cannot be a umem pointer as we have no control
	 * over the lifetime. Since we won't change the kABI for this to add a
	 * proper kref, an xarray is used.
	 */
	xa_lock(&ib_peer_client->umem_xa);
	ib_peer_client->stats.num_free_callbacks += 1;
	umem_p = xa_load(&ib_peer_client->umem_xa, core_context);
	if (!umem_p)
		goto out_unlock;
	kref_get(&umem_p->kref);
	xa_unlock(&ib_peer_client->umem_xa);

	mutex_lock(&umem_p->mapping_lock);
	/*
	 * For flows that require invalidation the invalidation_func should not
	 * be NULL while the device can be doing DMA. The mapping_lock ensures
	 * that the device is ready to receive an invalidation before one is
	 * triggered here.
	 */
	if (umem_p->mapped_state == UMEM_PEER_MAPPED &&
	    umem_p->invalidation_func)
		umem_p->invalidation_func(&umem_p->umem,
					  umem_p->invalidation_private);
	if (ib_peer_unmap_on_invalidate(umem_p))
		ib_unmap_peer_client(umem_p, umem_p->mapped_state,
				     UMEM_PEER_INVALIDATED);
	else
		ib_unmap_peer_client(umem_p, umem_p->mapped_state,
				     UMEM_PEER_UNMAPPED);
	mutex_unlock(&umem_p->mapping_lock);
	kref_put(&umem_p->kref, ib_peer_umem_kref_release);
	return 0;

out_unlock:
	xa_unlock(&ib_peer_client->umem_xa);
	return 0;
}

void ib_umem_activate_invalidation_notifier(struct ib_umem *umem,
					    umem_invalidate_func_t func,
					    void *priv)
{
	struct ib_umem_peer *umem_p =
		container_of(umem, struct ib_umem_peer, umem);

	if (WARN_ON(!umem->is_peer))
		return;
	if (umem_p->xa_id == PEER_NO_INVALIDATION_ID)
		return;

	umem_p->invalidation_func = func;
	umem_p->invalidation_private = priv;
	/* Pairs with the lock in ib_peer_umem_get() */
	mutex_unlock(&umem_p->mapping_lock);

	/* At this point func can be called asynchronously */
}
EXPORT_SYMBOL(ib_umem_activate_invalidation_notifier);

/*
 * Caller has blocked DMA and will no longer be able to handle invalidate
 * callbacks. Callers using invalidation must call this function before calling
 * ib_peer_umem_release(). ib_umem_activate_invalidation_notifier() is optional
 * before doing this.
 */
void ib_umem_stop_invalidation_notifier(struct ib_umem *umem)
{
	struct ib_umem_peer *umem_p =
		container_of(umem, struct ib_umem_peer, umem);
	bool unmap_on_invalidate = ib_peer_unmap_on_invalidate(umem_p);
	enum ib_umem_mapped_state cur_state;

	if (umem_p->invalidation_func) {
		mutex_lock(&umem_p->mapping_lock);
		umem_p->invalidation_func = NULL;
	} else if (umem_p->xa_id != PEER_NO_INVALIDATION_ID) {
		mutex_lock(&umem_p->mapping_lock);
	} else {
		/*
		 * Haven't called ib_umem_activate_invalidation_notifier() yet,
		 * still have the lock
		 */
	}

	if (!unmap_on_invalidate) {
		ib_unmap_peer_client(umem_p, umem_p->mapped_state,
				     UMEM_PEER_UNMAPPED);
	} else {
		/* Block ib_invalidate_peer_memory() */
		cur_state = umem_p->mapped_state;
		umem_p->mapped_state = UMEM_PEER_UNMAPPED;
	}
	mutex_unlock(&umem_p->mapping_lock);

	if (unmap_on_invalidate)
		ib_unmap_peer_client(umem_p, cur_state, UMEM_PEER_UNMAPPED);

}
EXPORT_SYMBOL(ib_umem_stop_invalidation_notifier);

static void fix_peer_sgls(struct ib_umem_peer *umem_p, unsigned long peer_page_size)
{
	struct ib_umem *umem = &umem_p->umem;
	struct scatterlist *sg;
	int i;

	for_each_sg(umem_p->umem.sgt_append.sgt.sgl, sg,
		    umem_p->umem.sgt_append.sgt.nents, i) {
		if (i == 0) {
			unsigned long offset;

			umem_p->first_sg = sg;
			umem_p->first_dma_address = sg->dma_address;
			umem_p->first_dma_length = sg_dma_len(sg);
			umem_p->first_length = sg->length;

			offset = ALIGN_DOWN(umem->address, PAGE_SIZE) -
				 ALIGN_DOWN(umem->address, peer_page_size);
			sg->dma_address += offset;
			sg_dma_len(sg) -= offset;
			sg->length -= offset;
		}

		if (i == umem_p->umem.sgt_append.sgt.nents - 1) {
			unsigned long trim;

			umem_p->last_sg = sg;
			umem_p->last_dma_length = sg_dma_len(sg);
			umem_p->last_length = sg->length;

			trim = ALIGN(umem->address + umem->length,
				     peer_page_size) -
			       ALIGN(umem->address + umem->length, PAGE_SIZE);
			sg_dma_len(sg) -= trim;
			sg->length -= trim;
		}
	}
}

struct ib_umem *ib_peer_umem_get(struct ib_umem *old_umem, int old_ret,
				 unsigned long peer_mem_flags)
{
	struct ib_peer_memory_client *ib_peer_client;
	unsigned long peer_page_size;
	void *peer_client_context;
	struct ib_umem_peer *umem_p;
	int ret;

	ib_peer_client =
		ib_get_peer_client(old_umem->address, old_umem->length,
				   peer_mem_flags, &peer_client_context);
	if (!ib_peer_client)
		return ERR_PTR(old_ret);

	umem_p = kzalloc(sizeof(*umem_p), GFP_KERNEL);
	if (!umem_p) {
		ret = -ENOMEM;
		goto err_client;
	}

	kref_init(&umem_p->kref);
	umem_p->umem = *old_umem;
	memset(&umem_p->umem.sgt_append.sgt, 0, sizeof(umem_p->umem.sgt_append));
	umem_p->umem.is_peer = 1;
	umem_p->ib_peer_client = ib_peer_client;
	umem_p->peer_client_context = peer_client_context;
	mutex_init(&umem_p->mapping_lock);
	umem_p->xa_id = PEER_NO_INVALIDATION_ID;

	mutex_lock(&umem_p->mapping_lock);
	if (ib_peer_client->invalidation_required) {
		ret = xa_alloc_cyclic(&ib_peer_client->umem_xa, &umem_p->xa_id,
				      umem_p,
				      XA_LIMIT(0, PEER_NO_INVALIDATION_ID - 1),
				      &ib_peer_client->xa_cyclic_next,
				      GFP_KERNEL);
		if (ret < 0)
			goto err_umem;
	}

	/*
	 * We always request write permissions to the pages, to force breaking
	 * of any CoW during the registration of the MR. For read-only MRs we
	 * use the "force" flag to indicate that CoW breaking is required but
	 * the registration should not fail if referencing read-only areas.
	 */
	ret = ib_peer_client->peer_mem->get_pages(umem_p->umem.address,
						  umem_p->umem.length, 1,
						  !umem_p->umem.writable, NULL,
						  peer_client_context,
						  umem_p->xa_id);
	if (ret)
		goto err_xa;

	ret = ib_peer_client->peer_mem->dma_map(&umem_p->umem.sgt_append.sgt,
						peer_client_context,
						umem_p->umem.ibdev->dma_device,
						0, &umem_p->umem.sgt_append.sgt.nents);
	if (ret)
		goto err_pages;

	peer_page_size = ib_peer_client->peer_mem->get_page_size(peer_client_context);
	if (peer_page_size != PAGE_SIZE)
		fix_peer_sgls(umem_p, peer_page_size);

	umem_p->mapped_state = UMEM_PEER_MAPPED;
	atomic64_add(umem_p->umem.sgt_append.sgt.nents, &ib_peer_client->stats.num_reg_pages);
	atomic64_add(umem_p->umem.length, &ib_peer_client->stats.num_reg_bytes);
	atomic64_inc(&ib_peer_client->stats.num_alloc_mrs);

	/*
	 * If invalidation is allowed then the caller must call
	 * ib_umem_activate_invalidation_notifier() or ib_peer_umem_release() to
	 * unlock this mutex. This call should be done after the last read to
	 * sg_head, once the caller is ready for the invalidation function to be
	 * called.
	 */
	if (umem_p->xa_id == PEER_NO_INVALIDATION_ID)
		mutex_unlock(&umem_p->mapping_lock);

	/*
	 * On success the old umem is replaced with the new, larger, allocation
	 */
	kfree(old_umem);
	return &umem_p->umem;

err_pages:
	ib_peer_client->peer_mem->put_pages(&umem_p->umem.sgt_append.sgt,
					    umem_p->peer_client_context);
err_xa:
	if (umem_p->xa_id != PEER_NO_INVALIDATION_ID)
		xa_erase(&umem_p->ib_peer_client->umem_xa, umem_p->xa_id);
err_umem:
	mutex_unlock(&umem_p->mapping_lock);
	kref_put(&umem_p->kref, ib_peer_umem_kref_release);
err_client:
	ib_put_peer_client(ib_peer_client, peer_client_context);
	return ERR_PTR(ret);
}

void ib_peer_umem_release(struct ib_umem *umem)
{
	struct ib_umem_peer *umem_p =
		container_of(umem, struct ib_umem_peer, umem);

	/*
	 * If ib_umem_activate_invalidation_notifier() is called then
	 * ib_umem_stop_invalidation_notifier() must be called before release.
	 */
	WARN_ON(umem_p->invalidation_func);

	/* For no invalidation cases, make sure it is unmapped */
	ib_unmap_peer_client(umem_p, umem_p->mapped_state, UMEM_PEER_UNMAPPED);

	if (umem_p->xa_id != PEER_NO_INVALIDATION_ID)
		xa_erase(&umem_p->ib_peer_client->umem_xa, umem_p->xa_id);
	ib_put_peer_client(umem_p->ib_peer_client, umem_p->peer_client_context);
	umem_p->ib_peer_client = NULL;

	/* Must match ib_umem_release() */
	atomic64_sub(ib_umem_num_pages(umem), &umem->owning_mm->pinned_vm);
	mmdrop(umem->owning_mm);

	kref_put(&umem_p->kref, ib_peer_umem_kref_release);
}

/* Use it like this:
struct peer_memory_client_ex peer_memory_test = {
	.client = {
		.version = "1.0",
		.version[IB_PEER_MEMORY_VER_MAX-1] = 1,
	},
	.ex_size = sizeof(struct peer_memory_client_ex),
	.flags = PEER_MEM_INVALIDATE_UNMAPS,
};
*/
