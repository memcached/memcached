/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_PSYS_H
#define IPU_PSYS_H

#include <linux/cdev.h>
#include <linux/workqueue.h>

#include "ipu.h"
#include "ipu-pdata.h"
#include "ipu-fw-psys.h"
#include "ipu-platform-psys.h"

#define IPU_PSYS_PG_POOL_SIZE 16
#define IPU_PSYS_PG_MAX_SIZE 8192
#define IPU_MAX_PSYS_CMD_BUFFERS 32
#define IPU_PSYS_EVENT_CMD_COMPLETE IPU_FW_PSYS_EVENT_TYPE_SUCCESS
#define IPU_PSYS_EVENT_FRAGMENT_COMPLETE IPU_FW_PSYS_EVENT_TYPE_SUCCESS
#define IPU_PSYS_CLOSE_TIMEOUT_US   50
#define IPU_PSYS_CLOSE_TIMEOUT (100000 / IPU_PSYS_CLOSE_TIMEOUT_US)
#define IPU_PSYS_WORK_QUEUE		system_power_efficient_wq
#define IPU_MAX_RESOURCES 128

/* Opaque structure. Do not access fields. */
struct ipu_resource {
	u32 id;
	int elements;	/* Number of elements available to allocation */
	unsigned long *bitmap;	/* Allocation bitmap, a bit for each element */
};

enum ipu_resource_type {
	IPU_RESOURCE_DEV_CHN = 0,
	IPU_RESOURCE_EXT_MEM,
	IPU_RESOURCE_DFM
};

/* Allocation of resource(s) */
/* Opaque structure. Do not access fields. */
struct ipu_resource_alloc {
	enum ipu_resource_type type;
	struct ipu_resource *resource;
	int elements;
	int pos;
};

/*
 * This struct represents all of the currently allocated
 * resources from IPU model. It is used also for allocating
 * resources for the next set of PGs to be run on IPU
 * (ie. those PGs which are not yet being run and which don't
 * yet reserve real IPU resources).
 * Use larger array to cover existing resource quantity
 */

/* resource size may need expand for new resource model */
struct ipu_psys_resource_pool {
	u32 cells;	/* Bitmask of cells allocated */
	struct ipu_resource dev_channels[16];
	struct ipu_resource ext_memory[32];
	struct ipu_resource dfms[16];
	DECLARE_BITMAP(cmd_queues, 32);
	/* Protects cmd_queues bitmap */
	spinlock_t queues_lock;
};

/*
 * This struct keeps book of the resources allocated for a specific PG.
 * It is used for freeing up resources from struct ipu_psys_resources
 * when the PG is released from IPU (or model of IPU).
 */
struct ipu_psys_resource_alloc {
	u32 cells;	/* Bitmask of cells needed */
	struct ipu_resource_alloc
	 resource_alloc[IPU_MAX_RESOURCES];
	int resources;
};

struct task_struct;
struct ipu_psys {
	struct ipu_psys_capability caps;
	struct cdev cdev;
	struct device dev;

	struct mutex mutex;	/* Psys various */
	int ready; /* psys fw status */
	bool icache_prefetch_sp;
	bool icache_prefetch_isp;
	spinlock_t ready_lock;	/* protect psys firmware state */
	spinlock_t pgs_lock;	/* Protect pgs list access */
	struct list_head fhs;
	struct list_head pgs;
	struct list_head started_kcmds_list;
	struct ipu_psys_pdata *pdata;
	struct ipu_bus_device *adev;
	struct ia_css_syscom_context *dev_ctx;
	struct ia_css_syscom_config *syscom_config;
	struct ia_css_psys_server_init *server_init;
	struct task_struct *sched_cmd_thread;
	wait_queue_head_t sched_cmd_wq;
	atomic_t wakeup_count;  /* Psys schedule thread wakeup count */
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfsdir;
#endif

	/* Resources needed to be managed for process groups */
	struct ipu_psys_resource_pool resource_pool_running;

	const struct firmware *fw;
	struct sg_table fw_sgt;
	u64 *pkg_dir;
	dma_addr_t pkg_dir_dma_addr;
	unsigned int pkg_dir_size;
	unsigned long timeout;

	int active_kcmds, started_kcmds;
	void *fwcom;

	int power_gating;
};

struct ipu_psys_fh {
	struct ipu_psys *psys;
	struct mutex mutex;	/* Protects bufmap & kcmds fields */
	struct list_head list;
	struct list_head bufmap;
	wait_queue_head_t wait;
	struct ipu_psys_scheduler sched;
};

struct ipu_psys_pg {
	struct ipu_fw_psys_process_group *pg;
	size_t size;
	size_t pg_size;
	dma_addr_t pg_dma_addr;
	struct list_head list;
	struct ipu_psys_resource_alloc resource_alloc;
};

struct ipu_psys_kcmd {
	struct ipu_psys_fh *fh;
	struct list_head list;
	struct ipu_psys_buffer_set *kbuf_set;
	enum ipu_psys_cmd_state state;
	void *pg_manifest;
	size_t pg_manifest_size;
	struct ipu_psys_kbuffer **kbufs;
	struct ipu_psys_buffer *buffers;
	size_t nbuffers;
	struct ipu_fw_psys_process_group *pg_user;
	struct ipu_psys_pg *kpg;
	u64 user_token;
	u64 issue_id;
	u32 priority;
	u32 kernel_enable_bitmap[4];
	u32 terminal_enable_bitmap[4];
	u32 routing_enable_bitmap[4];
	u32 rbm[5];
	struct ipu_buttress_constraint constraint;
	struct ipu_psys_event ev;
	struct timer_list watchdog;
};

struct ipu_dma_buf_attach {
	struct device *dev;
	u64 len;
	void *userptr;
	struct sg_table *sgt;
	bool vma_is_io;
	struct page **pages;
	size_t npages;
};

struct ipu_psys_kbuffer {
	u64 len;
	void *userptr;
	u32 flags;
	int fd;
	void *kaddr;
	struct list_head list;
	dma_addr_t dma_addr;
	struct sg_table *sgt;
	struct dma_buf_attachment *db_attach;
	struct dma_buf *dbuf;
	bool valid;	/* True when buffer is usable */
};

#define inode_to_ipu_psys(inode) \
	container_of((inode)->i_cdev, struct ipu_psys, cdev)

#ifdef CONFIG_COMPAT
long ipu_psys_compat_ioctl32(struct file *file, unsigned int cmd,
			     unsigned long arg);
#endif

void ipu_psys_setup_hw(struct ipu_psys *psys);
void ipu_psys_subdomains_power(struct ipu_psys *psys, bool on);
void ipu_psys_handle_events(struct ipu_psys *psys);
int ipu_psys_kcmd_new(struct ipu_psys_command *cmd, struct ipu_psys_fh *fh);
void ipu_psys_run_next(struct ipu_psys *psys);
struct ipu_psys_pg *__get_pg_buf(struct ipu_psys *psys, size_t pg_size);
struct ipu_psys_kbuffer *
ipu_psys_lookup_kbuffer(struct ipu_psys_fh *fh, int fd);
int ipu_psys_mapbuf_locked(int fd, struct ipu_psys_fh *fh,
			   struct ipu_psys_kbuffer *kbuf);
struct ipu_psys_kbuffer *
ipu_psys_lookup_kbuffer_by_kaddr(struct ipu_psys_fh *fh, void *kaddr);
#ifdef IPU_PSYS_GPC
int ipu_psys_gpc_init_debugfs(struct ipu_psys *psys);
#endif
int ipu_psys_resource_pool_init(struct ipu_psys_resource_pool *pool);
void ipu_psys_resource_pool_cleanup(struct ipu_psys_resource_pool *pool);
struct ipu_psys_kcmd *ipu_get_completed_kcmd(struct ipu_psys_fh *fh);
long ipu_ioctl_dqevent(struct ipu_psys_event *event,
		       struct ipu_psys_fh *fh, unsigned int f_flags);

#endif /* IPU_PSYS_H */
