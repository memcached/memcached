// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2015 - 2020 Intel Corporation

#include <linux/dma-mapping.h>
#include <linux/module.h>

#include "ipu.h"
#include "ipu-cpd.h"

/* 15 entries + header*/
#define MAX_PKG_DIR_ENT_CNT		16
/* 2 qword per entry/header */
#define PKG_DIR_ENT_LEN			2
/* PKG_DIR size in bytes */
#define PKG_DIR_SIZE			((MAX_PKG_DIR_ENT_CNT) *	\
					 (PKG_DIR_ENT_LEN) * sizeof(u64))
#define PKG_DIR_ID_SHIFT		48
#define PKG_DIR_ID_MASK			0x7f
#define PKG_DIR_VERSION_SHIFT		32
#define PKG_DIR_SIZE_MASK		0xfffff
/* _IUPKDR_ */
#define PKG_DIR_HDR_MARK		0x5f4955504b44525f

/* $CPD */
#define CPD_HDR_MARK			0x44504324

/* Maximum size is 2K DWORDs */
#define MAX_MANIFEST_SIZE		(2 * 1024 * sizeof(u32))

/* Maximum size is 64k */
#define MAX_METADATA_SIZE		(64 * 1024)

#define MAX_COMPONENT_ID		127
#define MAX_COMPONENT_VERSION		0xffff

#define CPD_MANIFEST_IDX	0
#define CPD_METADATA_IDX	1
#define CPD_MODULEDATA_IDX	2

static inline struct ipu_cpd_ent *ipu_cpd_get_entries(const void *cpd)
{
	const struct ipu_cpd_hdr *cpd_hdr = cpd;

	return (struct ipu_cpd_ent *)((u8 *)cpd + cpd_hdr->hdr_len);
}

#define ipu_cpd_get_entry(cpd, idx) (&ipu_cpd_get_entries(cpd)[idx])
#define ipu_cpd_get_manifest(cpd) ipu_cpd_get_entry(cpd, CPD_MANIFEST_IDX)
#define ipu_cpd_get_metadata(cpd) ipu_cpd_get_entry(cpd, CPD_METADATA_IDX)
#define ipu_cpd_get_moduledata(cpd) ipu_cpd_get_entry(cpd, CPD_MODULEDATA_IDX)

static const struct ipu_cpd_metadata_cmpnt *
ipu_cpd_metadata_get_cmpnt(struct ipu_device *isp,
			   const void *metadata,
			   unsigned int metadata_size,
			   u8 idx)
{
	const struct ipu_cpd_metadata_extn *extn;
	const struct ipu_cpd_metadata_cmpnt *cmpnts;
	int cmpnt_count;

	extn = metadata;
	cmpnts = metadata + sizeof(*extn);
	cmpnt_count = (metadata_size - sizeof(*extn)) / sizeof(*cmpnts);

	if (idx > MAX_COMPONENT_ID || idx >= cmpnt_count) {
		dev_err(&isp->pdev->dev, "Component index out of range (%d)\n",
			idx);
		return ERR_PTR(-EINVAL);
	}

	return &cmpnts[idx];
}

static u32 ipu_cpd_metadata_cmpnt_version(struct ipu_device *isp,
					  const void *metadata,
					  unsigned int metadata_size, u8 idx)
{
	const struct ipu_cpd_metadata_cmpnt *cmpnt =
	    ipu_cpd_metadata_get_cmpnt(isp, metadata,
				       metadata_size, idx);

	if (IS_ERR(cmpnt))
		return PTR_ERR(cmpnt);

	return cmpnt->ver;
}

static int ipu_cpd_metadata_get_cmpnt_id(struct ipu_device *isp,
					 const void *metadata,
					 unsigned int metadata_size, u8 idx)
{
	const struct ipu_cpd_metadata_cmpnt *cmpnt =
	    ipu_cpd_metadata_get_cmpnt(isp, metadata,
				       metadata_size, idx);

	if (IS_ERR(cmpnt))
		return PTR_ERR(cmpnt);

	return cmpnt->id;
}

static const struct ipu6_cpd_metadata_cmpnt *
ipu6_cpd_metadata_get_cmpnt(struct ipu_device *isp,
			    const void *metadata,
			    unsigned int metadata_size,
			    u8 idx)
{
	const struct ipu_cpd_metadata_extn *extn = metadata;
	const struct ipu6_cpd_metadata_cmpnt *cmpnts = metadata + sizeof(*extn);
	int cmpnt_count;

	cmpnt_count = (metadata_size - sizeof(*extn)) / sizeof(*cmpnts);
	if (idx > MAX_COMPONENT_ID || idx >= cmpnt_count) {
		dev_err(&isp->pdev->dev, "Component index out of range (%d)\n",
			idx);
		return ERR_PTR(-EINVAL);
	}

	return &cmpnts[idx];
}

static u32 ipu6_cpd_metadata_cmpnt_version(struct ipu_device *isp,
					   const void *metadata,
					   unsigned int metadata_size, u8 idx)
{
	const struct ipu6_cpd_metadata_cmpnt *cmpnt =
	    ipu6_cpd_metadata_get_cmpnt(isp, metadata,
					metadata_size, idx);

	if (IS_ERR(cmpnt))
		return PTR_ERR(cmpnt);

	return cmpnt->ver;
}

static int ipu6_cpd_metadata_get_cmpnt_id(struct ipu_device *isp,
					  const void *metadata,
					  unsigned int metadata_size, u8 idx)
{
	const struct ipu6_cpd_metadata_cmpnt *cmpnt =
	    ipu6_cpd_metadata_get_cmpnt(isp, metadata,
					metadata_size, idx);

	if (IS_ERR(cmpnt))
		return PTR_ERR(cmpnt);

	return cmpnt->id;
}

static int ipu_cpd_parse_module_data(struct ipu_device *isp,
				     const void *module_data,
				     unsigned int module_data_size,
				     dma_addr_t dma_addr_module_data,
				     u64 *pkg_dir,
				     const void *metadata,
				     unsigned int metadata_size)
{
	const struct ipu_cpd_module_data_hdr *module_data_hdr;
	const struct ipu_cpd_hdr *dir_hdr;
	const struct ipu_cpd_ent *dir_ent;
	int i;
	u8 len;

	if (!module_data)
		return -EINVAL;

	module_data_hdr = module_data;
	dir_hdr = module_data + module_data_hdr->hdr_len;
	len = dir_hdr->hdr_len;
	dir_ent = (struct ipu_cpd_ent *)(((u8 *)dir_hdr) + len);

	pkg_dir[0] = PKG_DIR_HDR_MARK;
	/* pkg_dir entry count = component count + pkg_dir header */
	pkg_dir[1] = dir_hdr->ent_cnt + 1;

	for (i = 0; i < dir_hdr->ent_cnt; i++, dir_ent++) {
		u64 *p = &pkg_dir[PKG_DIR_ENT_LEN + i * PKG_DIR_ENT_LEN];
		int ver, id;

		*p++ = dma_addr_module_data + dir_ent->offset;

		if (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP)
			id = ipu6_cpd_metadata_get_cmpnt_id(isp, metadata,
							    metadata_size, i);
		else
			id = ipu_cpd_metadata_get_cmpnt_id(isp, metadata,
							   metadata_size, i);

		if (id < 0 || id > MAX_COMPONENT_ID) {
			dev_err(&isp->pdev->dev,
				"Failed to parse component id\n");
			return -EINVAL;
		}

		if (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP)
			ver = ipu6_cpd_metadata_cmpnt_version(isp, metadata,
							      metadata_size, i);
		else
			ver = ipu_cpd_metadata_cmpnt_version(isp, metadata,
							     metadata_size, i);

		if (ver < 0 || ver > MAX_COMPONENT_VERSION) {
			dev_err(&isp->pdev->dev,
				"Failed to parse component version\n");
			return -EINVAL;
		}

		/*
		 * PKG_DIR Entry (type == id)
		 * 63:56        55      54:48   47:32   31:24   23:0
		 * Rsvd         Rsvd    Type    Version Rsvd    Size
		 */
		*p = dir_ent->len | (u64)id << PKG_DIR_ID_SHIFT |
		    (u64)ver << PKG_DIR_VERSION_SHIFT;
	}

	return 0;
}

void *ipu_cpd_create_pkg_dir(struct ipu_bus_device *adev,
			     const void *src,
			     dma_addr_t dma_addr_src,
			     dma_addr_t *dma_addr, unsigned int *pkg_dir_size)
{
	struct ipu_device *isp = adev->isp;
	const struct ipu_cpd_ent *ent, *man_ent, *met_ent;
	u64 *pkg_dir;
	unsigned int man_sz, met_sz;
	void *pkg_dir_pos;
	int ret;

	man_ent = ipu_cpd_get_manifest(src);
	man_sz = man_ent->len;

	met_ent = ipu_cpd_get_metadata(src);
	met_sz = met_ent->len;

	*pkg_dir_size = PKG_DIR_SIZE + man_sz + met_sz;
	pkg_dir = dma_alloc_attrs(&adev->dev, *pkg_dir_size, dma_addr,
				  GFP_KERNEL,
				  0);
	if (!pkg_dir)
		return pkg_dir;

	/*
	 * pkg_dir entry/header:
	 * qword | 63:56 | 55   | 54:48 | 47:32 | 31:24 | 23:0
	 * N         Address/Offset/"_IUPKDR_"
	 * N + 1 | rsvd  | rsvd | type  | ver   | rsvd  | size
	 *
	 * We can ignore other fields that size in N + 1 qword as they
	 * are 0 anyway. Just setting size for now.
	 */

	ent = ipu_cpd_get_moduledata(src);

	ret = ipu_cpd_parse_module_data(isp, src + ent->offset,
					ent->len,
					dma_addr_src + ent->offset,
					pkg_dir,
					src + met_ent->offset, met_ent->len);
	if (ret) {
		dev_err(&isp->pdev->dev,
			"Unable to parse module data section!\n");
		dma_free_attrs(&isp->psys->dev, *pkg_dir_size, pkg_dir,
			       *dma_addr,
			       0);
		return NULL;
	}

	/* Copy manifest after pkg_dir */
	pkg_dir_pos = pkg_dir + PKG_DIR_ENT_LEN * MAX_PKG_DIR_ENT_CNT;
	memcpy(pkg_dir_pos, src + man_ent->offset, man_sz);

	/* Copy metadata after manifest */
	pkg_dir_pos += man_sz;
	memcpy(pkg_dir_pos, src + met_ent->offset, met_sz);

	dma_sync_single_range_for_device(&adev->dev, *dma_addr,
					 0, *pkg_dir_size, DMA_TO_DEVICE);

	return pkg_dir;
}
EXPORT_SYMBOL_GPL(ipu_cpd_create_pkg_dir);

void ipu_cpd_free_pkg_dir(struct ipu_bus_device *adev,
			  u64 *pkg_dir,
			  dma_addr_t dma_addr, unsigned int pkg_dir_size)
{
	dma_free_attrs(&adev->dev, pkg_dir_size, pkg_dir, dma_addr, 0);
}
EXPORT_SYMBOL_GPL(ipu_cpd_free_pkg_dir);

static int ipu_cpd_validate_cpd(struct ipu_device *isp,
				const void *cpd,
				unsigned long cpd_size, unsigned long data_size)
{
	const struct ipu_cpd_hdr *cpd_hdr = cpd;
	struct ipu_cpd_ent *ent;
	unsigned int i;
	u8 len;

	len = cpd_hdr->hdr_len;

	/* Ensure cpd hdr is within moduledata */
	if (cpd_size < len) {
		dev_err(&isp->pdev->dev, "Invalid CPD moduledata size\n");
		return -EINVAL;
	}

	/* Sanity check for CPD header */
	if ((cpd_size - len) / sizeof(*ent) < cpd_hdr->ent_cnt) {
		dev_err(&isp->pdev->dev, "Invalid CPD header\n");
		return -EINVAL;
	}

	/* Ensure that all entries are within moduledata */
	ent = (struct ipu_cpd_ent *)(((u8 *)cpd_hdr) + len);
	for (i = 0; i < cpd_hdr->ent_cnt; i++, ent++) {
		if (data_size < ent->offset ||
		    data_size - ent->offset < ent->len) {
			dev_err(&isp->pdev->dev, "Invalid CPD entry (%d)\n", i);
			return -EINVAL;
		}
	}

	return 0;
}

static int ipu_cpd_validate_moduledata(struct ipu_device *isp,
				       const void *moduledata,
				       u32 moduledata_size)
{
	const struct ipu_cpd_module_data_hdr *mod_hdr = moduledata;
	int rval;

	/* Ensure moduledata hdr is within moduledata */
	if (moduledata_size < sizeof(*mod_hdr) ||
	    moduledata_size < mod_hdr->hdr_len) {
		dev_err(&isp->pdev->dev, "Invalid moduledata size\n");
		return -EINVAL;
	}

	dev_info(&isp->pdev->dev, "FW version: %x\n", mod_hdr->fw_pkg_date);
	rval = ipu_cpd_validate_cpd(isp, moduledata +
				    mod_hdr->hdr_len,
				    moduledata_size -
				    mod_hdr->hdr_len, moduledata_size);
	if (rval) {
		dev_err(&isp->pdev->dev, "Invalid CPD in moduledata\n");
		return -EINVAL;
	}

	return 0;
}

static int ipu_cpd_validate_metadata(struct ipu_device *isp,
				     const void *metadata, u32 meta_size)
{
	const struct ipu_cpd_metadata_extn *extn = metadata;
	unsigned int size;

	/* Sanity check for metadata size */
	if (meta_size < sizeof(*extn) || meta_size > MAX_METADATA_SIZE) {
		dev_err(&isp->pdev->dev, "%s: Invalid metadata\n", __func__);
		return -EINVAL;
	}

	/* Validate extension and image types */
	if (extn->extn_type != IPU_CPD_METADATA_EXTN_TYPE_IUNIT ||
	    extn->img_type != IPU_CPD_METADATA_IMAGE_TYPE_MAIN_FIRMWARE) {
		dev_err(&isp->pdev->dev,
			"Invalid metadata descriptor img_type (%d)\n",
			extn->img_type);
		return -EINVAL;
	}

	/* Validate metadata size multiple of metadata components */
	if (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP)
		size = sizeof(struct ipu6_cpd_metadata_cmpnt);
	else
		size = sizeof(struct ipu_cpd_metadata_cmpnt);

	if ((meta_size - sizeof(*extn)) % size) {
		dev_err(&isp->pdev->dev, "%s: Invalid metadata size\n",
			__func__);
		return -EINVAL;
	}

	return 0;
}

int ipu_cpd_validate_cpd_file(struct ipu_device *isp,
			      const void *cpd_file, unsigned long cpd_file_size)
{
	const struct ipu_cpd_hdr *hdr = cpd_file;
	struct ipu_cpd_ent *ent;
	int rval;

	rval = ipu_cpd_validate_cpd(isp, cpd_file,
				    cpd_file_size, cpd_file_size);
	if (rval) {
		dev_err(&isp->pdev->dev, "Invalid CPD in file\n");
		return -EINVAL;
	}

	/* Check for CPD file marker */
	if (hdr->hdr_mark != CPD_HDR_MARK) {
		dev_err(&isp->pdev->dev, "Invalid CPD header\n");
		return -EINVAL;
	}

	/* Sanity check for manifest size */
	ent = ipu_cpd_get_manifest(cpd_file);
	if (ent->len > MAX_MANIFEST_SIZE) {
		dev_err(&isp->pdev->dev, "Invalid manifest size\n");
		return -EINVAL;
	}

	/* Validate metadata */
	ent = ipu_cpd_get_metadata(cpd_file);
	rval = ipu_cpd_validate_metadata(isp, cpd_file + ent->offset, ent->len);
	if (rval) {
		dev_err(&isp->pdev->dev, "Invalid metadata\n");
		return rval;
	}

	/* Validate moduledata */
	ent = ipu_cpd_get_moduledata(cpd_file);
	rval = ipu_cpd_validate_moduledata(isp, cpd_file + ent->offset,
					   ent->len);
	if (rval) {
		dev_err(&isp->pdev->dev, "Invalid moduledata\n");
		return rval;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ipu_cpd_validate_cpd_file);

unsigned int ipu_cpd_pkg_dir_get_address(const u64 *pkg_dir, int pkg_dir_idx)
{
	return pkg_dir[++pkg_dir_idx * PKG_DIR_ENT_LEN];
}
EXPORT_SYMBOL_GPL(ipu_cpd_pkg_dir_get_address);

unsigned int ipu_cpd_pkg_dir_get_num_entries(const u64 *pkg_dir)
{
	return pkg_dir[1];
}
EXPORT_SYMBOL_GPL(ipu_cpd_pkg_dir_get_num_entries);

unsigned int ipu_cpd_pkg_dir_get_size(const u64 *pkg_dir, int pkg_dir_idx)
{
	return pkg_dir[++pkg_dir_idx * PKG_DIR_ENT_LEN + 1] & PKG_DIR_SIZE_MASK;
}
EXPORT_SYMBOL_GPL(ipu_cpd_pkg_dir_get_size);

unsigned int ipu_cpd_pkg_dir_get_type(const u64 *pkg_dir, int pkg_dir_idx)
{
	return pkg_dir[++pkg_dir_idx * PKG_DIR_ENT_LEN + 1] >>
	    PKG_DIR_ID_SHIFT & PKG_DIR_ID_MASK;
}
EXPORT_SYMBOL_GPL(ipu_cpd_pkg_dir_get_type);
