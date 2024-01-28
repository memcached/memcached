// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2013 - 2021 Intel Corporation

#include <asm/cacheflush.h>

#include <linux/slab.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/iova.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/dma-map-ops.h>

#include "ipu-dma.h"
#include "ipu-bus.h"
#include "ipu-mmu.h"

struct vm_info {
	struct list_head list;
	struct page **pages;
	void *vaddr;
	unsigned long size;
};

static struct vm_info *get_vm_info(struct ipu_mmu *mmu, void *vaddr)
{
	struct vm_info *info, *save;

	list_for_each_entry_safe(info, save, &mmu->vma_list, list) {
		if (info->vaddr == vaddr)
			return info;
	}

	return NULL;
}

/* Begin of things adapted from arch/arm/mm/dma-mapping.c */
static void __dma_clear_buffer(struct page *page, size_t size,
			       unsigned long attrs)
{
	/*
	 * Ensure that the allocated pages are zeroed, and that any data
	 * lurking in the kernel direct-mapped region is invalidated.
	 */
	void *ptr = page_address(page);

	memset(ptr, 0, size);
	if ((attrs & DMA_ATTR_SKIP_CPU_SYNC) == 0)
		clflush_cache_range(ptr, size);
}

static struct page **__dma_alloc_buffer(struct device *dev, size_t size,
					gfp_t gfp,
					unsigned long attrs)
{
	struct page **pages;
	int count = size >> PAGE_SHIFT;
	int array_size = count * sizeof(struct page *);
	int i = 0;

	pages = kvzalloc(array_size, GFP_KERNEL);
	if (!pages)
		return NULL;

	gfp |= __GFP_NOWARN;

	while (count) {
		int j, order = __fls(count);

		pages[i] = alloc_pages(gfp, order);
		while (!pages[i] && order)
			pages[i] = alloc_pages(gfp, --order);
		if (!pages[i])
			goto error;

		if (order) {
			split_page(pages[i], order);
			j = 1 << order;
			while (--j)
				pages[i + j] = pages[i] + j;
		}

		__dma_clear_buffer(pages[i], PAGE_SIZE << order, attrs);
		i += 1 << order;
		count -= 1 << order;
	}

	return pages;
error:
	while (i--)
		if (pages[i])
			__free_pages(pages[i], 0);
	kvfree(pages);
	return NULL;
}

static int __dma_free_buffer(struct device *dev, struct page **pages,
			     size_t size,
			     unsigned long attrs)
{
	int count = size >> PAGE_SHIFT;
	int i;

	for (i = 0; i < count; i++) {
		if (pages[i]) {
			__dma_clear_buffer(pages[i], PAGE_SIZE, attrs);
			__free_pages(pages[i], 0);
		}
	}

	kvfree(pages);
	return 0;
}

/* End of things adapted from arch/arm/mm/dma-mapping.c */

static void ipu_dma_sync_single_for_cpu(struct device *dev,
					dma_addr_t dma_handle,
					size_t size,
					enum dma_data_direction dir)
{
	struct ipu_mmu *mmu = to_ipu_bus_device(dev)->mmu;
	unsigned long pa = ipu_mmu_iova_to_phys(mmu->dmap->mmu_info,
						dma_handle);

	clflush_cache_range(phys_to_virt(pa), size);
}

static void ipu_dma_sync_sg_for_cpu(struct device *dev,
				    struct scatterlist *sglist,
				    int nents, enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sglist, sg, nents, i)
		clflush_cache_range(page_to_virt(sg_page(sg)), sg->length);
}

static void *ipu_dma_alloc(struct device *dev, size_t size,
			   dma_addr_t *dma_handle, gfp_t gfp,
			   unsigned long attrs)
{
	struct ipu_mmu *mmu = to_ipu_bus_device(dev)->mmu;
	struct page **pages;
	struct iova *iova;
	struct vm_info *info;
	int i;
	int rval;
	unsigned long count;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return NULL;

	size = PAGE_ALIGN(size);
	count = size >> PAGE_SHIFT;

	iova = alloc_iova(&mmu->dmap->iovad, count,
			  dma_get_mask(dev) >> PAGE_SHIFT, 0);
	if (!iova)
		goto out_kfree;

	pages = __dma_alloc_buffer(dev, size, gfp, attrs);
	if (!pages)
		goto out_free_iova;

	for (i = 0; iova->pfn_lo + i <= iova->pfn_hi; i++) {
		rval = ipu_mmu_map(mmu->dmap->mmu_info,
				   (iova->pfn_lo + i) << PAGE_SHIFT,
				   page_to_phys(pages[i]), PAGE_SIZE);
		if (rval)
			goto out_unmap;
	}

	info->vaddr = vmap(pages, count, VM_USERMAP, PAGE_KERNEL);
	if (!info->vaddr)
		goto out_unmap;

	*dma_handle = iova->pfn_lo << PAGE_SHIFT;

	info->pages = pages;
	info->size = size;
	list_add(&info->list, &mmu->vma_list);

	return info->vaddr;

out_unmap:
	for (i--; i >= 0; i--) {
		ipu_mmu_unmap(mmu->dmap->mmu_info,
			      (iova->pfn_lo + i) << PAGE_SHIFT, PAGE_SIZE);
	}
	__dma_free_buffer(dev, pages, size, attrs);

out_free_iova:
	__free_iova(&mmu->dmap->iovad, iova);
out_kfree:
	kfree(info);

	return NULL;
}

static void ipu_dma_free(struct device *dev, size_t size, void *vaddr,
			 dma_addr_t dma_handle,
			 unsigned long attrs)
{
	struct ipu_mmu *mmu = to_ipu_bus_device(dev)->mmu;
	struct page **pages;
	struct vm_info *info;
	struct iova *iova = find_iova(&mmu->dmap->iovad,
				      dma_handle >> PAGE_SHIFT);

	if (WARN_ON(!iova))
		return;

	info = get_vm_info(mmu, vaddr);
	if (WARN_ON(!info))
		return;

	if (WARN_ON(!info->vaddr))
		return;

	if (WARN_ON(!info->pages))
		return;

	list_del(&info->list);

	size = PAGE_ALIGN(size);

	pages = info->pages;

	vunmap(vaddr);

	ipu_mmu_unmap(mmu->dmap->mmu_info, iova->pfn_lo << PAGE_SHIFT,
		      (iova->pfn_hi - iova->pfn_lo + 1) << PAGE_SHIFT);

	__dma_free_buffer(dev, pages, size, attrs);

	mmu->tlb_invalidate(mmu);

	__free_iova(&mmu->dmap->iovad, iova);

	kfree(info);
}

static int ipu_dma_mmap(struct device *dev, struct vm_area_struct *vma,
			void *addr, dma_addr_t iova, size_t size,
			unsigned long attrs)
{
	struct ipu_mmu *mmu = to_ipu_bus_device(dev)->mmu;
	struct vm_info *info;
	size_t count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	size_t i;

	info = get_vm_info(mmu, addr);
	if (!info)
		return -EFAULT;

	if (!info->vaddr)
		return -EFAULT;

	if (vma->vm_start & ~PAGE_MASK)
		return -EINVAL;

	if (size > info->size)
		return -EFAULT;

	for (i = 0; i < count; i++)
		vm_insert_page(vma, vma->vm_start + (i << PAGE_SHIFT),
			       info->pages[i]);

	return 0;
}

static void ipu_dma_unmap_sg(struct device *dev,
			     struct scatterlist *sglist,
			     int nents, enum dma_data_direction dir,
			     unsigned long attrs)
{
	struct ipu_mmu *mmu = to_ipu_bus_device(dev)->mmu;
	struct iova *iova = find_iova(&mmu->dmap->iovad,
				      sg_dma_address(sglist) >> PAGE_SHIFT);

	if (!nents)
		return;

	if (WARN_ON(!iova))
		return;

	if ((attrs & DMA_ATTR_SKIP_CPU_SYNC) == 0)
		ipu_dma_sync_sg_for_cpu(dev, sglist, nents, DMA_BIDIRECTIONAL);

	ipu_mmu_unmap(mmu->dmap->mmu_info, iova->pfn_lo << PAGE_SHIFT,
		      (iova->pfn_hi - iova->pfn_lo + 1) << PAGE_SHIFT);

	mmu->tlb_invalidate(mmu);

	__free_iova(&mmu->dmap->iovad, iova);
}

static int ipu_dma_map_sg(struct device *dev, struct scatterlist *sglist,
			  int nents, enum dma_data_direction dir,
			  unsigned long attrs)
{
	struct ipu_mmu *mmu = to_ipu_bus_device(dev)->mmu;
	struct scatterlist *sg;
	struct iova *iova;
	size_t size = 0;
	u32 iova_addr;
	int i;

	for_each_sg(sglist, sg, nents, i)
		size += PAGE_ALIGN(sg->length) >> PAGE_SHIFT;

	dev_dbg(dev, "dmamap: mapping sg %d entries, %zu pages\n", nents, size);

	iova = alloc_iova(&mmu->dmap->iovad, size,
			  dma_get_mask(dev) >> PAGE_SHIFT, 0);
	if (!iova)
		return 0;

	dev_dbg(dev, "dmamap: iova low pfn %lu, high pfn %lu\n", iova->pfn_lo,
		iova->pfn_hi);

	iova_addr = iova->pfn_lo;

	for_each_sg(sglist, sg, nents, i) {
		int rval;

		dev_dbg(dev, "mapping entry %d: iova 0x%8.8x,phy 0x%16.16llx\n",
			i, iova_addr << PAGE_SHIFT,
			(unsigned long long)page_to_phys(sg_page(sg)));
		rval = ipu_mmu_map(mmu->dmap->mmu_info, iova_addr << PAGE_SHIFT,
				   page_to_phys(sg_page(sg)),
				   PAGE_ALIGN(sg->length));
		if (rval)
			goto out_fail;
		sg_dma_address(sg) = iova_addr << PAGE_SHIFT;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
		sg_dma_len(sg) = sg->length;
#endif /* CONFIG_NEED_SG_DMA_LENGTH */

		iova_addr += PAGE_ALIGN(sg->length) >> PAGE_SHIFT;
	}

	if ((attrs & DMA_ATTR_SKIP_CPU_SYNC) == 0)
		ipu_dma_sync_sg_for_cpu(dev, sglist, nents, DMA_BIDIRECTIONAL);

	mmu->tlb_invalidate(mmu);

	return nents;

out_fail:
	ipu_dma_unmap_sg(dev, sglist, i, dir, attrs);

	return 0;
}

/*
 * Create scatter-list for the already allocated DMA buffer
 */
static int ipu_dma_get_sgtable(struct device *dev, struct sg_table *sgt,
			       void *cpu_addr, dma_addr_t handle, size_t size,
			       unsigned long attrs)
{
	struct ipu_mmu *mmu = to_ipu_bus_device(dev)->mmu;
	struct vm_info *info;
	int n_pages;
	int ret = 0;

	info = get_vm_info(mmu, cpu_addr);
	if (!info)
		return -EFAULT;

	if (!info->vaddr)
		return -EFAULT;

	if (WARN_ON(!info->pages))
		return -ENOMEM;

	n_pages = PAGE_ALIGN(size) >> PAGE_SHIFT;

	ret = sg_alloc_table_from_pages(sgt, info->pages, n_pages, 0, size,
					GFP_KERNEL);
	if (ret)
		dev_dbg(dev, "IPU get sgt table fail\n");

	return ret;
}

const struct dma_map_ops ipu_dma_ops = {
	.alloc = ipu_dma_alloc,
	.free = ipu_dma_free,
	.mmap = ipu_dma_mmap,
	.map_sg = ipu_dma_map_sg,
	.unmap_sg = ipu_dma_unmap_sg,
	.sync_single_for_cpu = ipu_dma_sync_single_for_cpu,
	.sync_single_for_device = ipu_dma_sync_single_for_cpu,
	.sync_sg_for_cpu = ipu_dma_sync_sg_for_cpu,
	.sync_sg_for_device = ipu_dma_sync_sg_for_cpu,
	.get_sgtable = ipu_dma_get_sgtable,
};
