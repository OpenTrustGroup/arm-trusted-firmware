/*
 * Copyright (c) 2015-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <string.h>

#include <libfdt.h>

#include <platform_def.h>

#include <arch_helpers.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <common/desc_image_load.h>
#include <common/fdt_fixup.h>
#include <common/fdt_wrappers.h>
#include <lib/optee_utils.h>
#if TRANSFER_LIST
#include <lib/transfer_list.h>
#endif
#include <lib/utils.h>
#include <plat/common/platform.h>

#include "qemu_private.h"

#define MAP_BL2_TOTAL		MAP_REGION_FLAT(			\
					bl2_tzram_layout.total_base,	\
					bl2_tzram_layout.total_size,	\
					MT_MEMORY | MT_RW | MT_SECURE)

#define MAP_BL2_RO		MAP_REGION_FLAT(			\
					BL_CODE_BASE,			\
					BL_CODE_END - BL_CODE_BASE,	\
					MT_CODE | MT_SECURE),		\
				MAP_REGION_FLAT(			\
					BL_RO_DATA_BASE,		\
					BL_RO_DATA_END			\
						- BL_RO_DATA_BASE,	\
					MT_RO_DATA | MT_SECURE)

#if USE_COHERENT_MEM
#define MAP_BL_COHERENT_RAM	MAP_REGION_FLAT(			\
					BL_COHERENT_RAM_BASE,		\
					BL_COHERENT_RAM_END		\
						- BL_COHERENT_RAM_BASE,	\
					MT_DEVICE | MT_RW | MT_SECURE)
#endif

/* Data structure which holds the extents of the trusted SRAM for BL2 */
static meminfo_t bl2_tzram_layout __aligned(CACHE_WRITEBACK_GRANULE);
#if TRANSFER_LIST
static struct transfer_list_header *bl2_tl;
#endif
#if __Nebula__
uint32_t tee_system_mode;
#endif

void bl2_early_platform_setup2(u_register_t arg0, u_register_t arg1,
			       u_register_t arg2, u_register_t arg3)
{
	meminfo_t *mem_layout = (void *)arg1;

	/* Initialize the console to provide early debug support */
	qemu_console_init();

	/* Setup the BL2 memory layout */
	bl2_tzram_layout = *mem_layout;

	plat_qemu_io_setup();
}

static void security_setup(void)
{
	/*
	 * This is where a TrustZone address space controller and other
	 * security related peripherals, would be configured.
	 */
}

static void update_dt(void)
{
#if TRANSFER_LIST
	struct transfer_list_entry *te;
#endif
	int ret;
	void *fdt = (void *)(uintptr_t)ARM_PRELOADED_DTB_BASE;

	ret = fdt_open_into(fdt, fdt, PLAT_QEMU_DT_MAX_SIZE);
	if (ret < 0) {
		ERROR("Invalid Device Tree at %p: error %d\n", fdt, ret);
		return;
	}

	if (dt_add_psci_node(fdt)) {
		ERROR("Failed to add PSCI Device Tree node\n");
		return;
	}

	if (dt_add_psci_cpu_enable_methods(fdt)) {
		ERROR("Failed to add PSCI cpu enable methods in Device Tree\n");
		return;
	}

	ret = fdt_pack(fdt);
	if (ret < 0)
		ERROR("Failed to pack Device Tree at %p: error %d\n", fdt, ret);

#if TRANSFER_LIST
	// create a TE
	te = transfer_list_add(bl2_tl, TL_TAG_FDT, fdt_totalsize(fdt), fdt);
	if (!te) {
		ERROR("Failed to add FDT entry to Transfer List\n");
		return;
	}
#endif
}

#ifdef __Nebula__
/* Get specific prop value by index from specific node. */
static uint64_t qemu_fdt_get_prop(const char *path, const char *prop, int index)
{
	int ret;
	int len;
	int offset;
	/* use 32bit-pointer to solve 64bit pointer misaligned issue */
	fdt32_t *vp;
	fdt64_t value;
	void *fdt = (void *)(uintptr_t)PLAT_QEMU_DT_BASE;

	ret = fdt_open_into(fdt, fdt, PLAT_QEMU_DT_MAX_SIZE);
	if (ret < 0) {
		ERROR("Invalid Device Tree at %p: error %d\n", fdt, ret);
		return 0;
	}

	offset = fdt_path_offset(fdt, path);
	if (offset < 0) {
		ERROR("Failed to find node '%s'\n", path);
		return 0;
	}
	vp = (fdt32_t *)fdt_getprop(fdt, offset, prop, &len);
	index <<= 1;
	value = vp[index + 1];
	value = (value << 32) | vp[index];

	return fdt64_to_cpu(value);
}

/* Set specific prop values to specific node. */
static void qemu_fdt_set_prop(void *fdt, const char *path,
		const char *prop, const uint64_t *value, const int len)
{
	int ret;
	int offset;

	ret = fdt_open_into(fdt, fdt, PLAT_QEMU_DT_MAX_SIZE);
	if (ret < 0) {
		ERROR("Invalid Device Tree at %p: error %d\n", fdt, ret);
		return;
	}

	offset = fdt_path_offset(fdt, path);
	if (offset < 0) {
		ERROR("Failed to find node '%s'\n", path);
		return;
	}

	ret = fdt_setprop(fdt, offset, prop, value, len);
	if (ret < 0) {
		ERROR("fdt_setprop failed at %p: error %d\n", fdt, ret);
		return;
	}

	ret = fdt_pack(fdt);
	if (ret < 0)
		ERROR("Failed to pack Device Tree at %p: error %d\n", fdt, ret);
}

/* Delete specific node from qemu fdt. */
static void qemu_fdt_del_node(void *fdt, const char *path)
{
	int ret;
	int offset;

	ret = fdt_open_into(fdt, fdt, PLAT_QEMU_DT_MAX_SIZE);
	if (ret < 0) {
		ERROR("Invalid Device Tree at %p: error %d\n", fdt, ret);
		return;
	}

	offset = fdt_path_offset(fdt, path);
	if (offset < 0) {
		ERROR("Failed to find node '%s'\n", path);
		return;
	}

	ret = fdt_del_node(fdt, offset);
	if (ret < 0) {
		ERROR("Delete '%s': error %d\n", path, ret);
		return;
	}

	ret = fdt_pack(fdt);
	if (ret < 0)
		ERROR("Failed to pack Device Tree at %p: error %d\n", fdt, ret);
}

/* Copy qemu fdt to specific location. */
static void qemu_fdt_copy(void *dst, void *src)
{
	int ret;

	ret = fdt_open_into(src, dst, PLAT_QEMU_DT_MAX_SIZE);
	if (ret < 0) {
		ERROR("Invalid Device Tree src %p dst %p: error %d\n", src, dst, ret);
		return;
	}

	ret = fdt_pack(dst);
	if (ret < 0)
		ERROR("Failed to pack Device Tree src %p dst %p: error %d\n", src, dst, ret);
}

char *
strrchr (const char *s, int c)
{
	char *rtnval = 0;

	do {
		if (*s == c)
			rtnval = (char*) s;
	} while (*s++);
	return (rtnval);
}

static void qemu_fdt_add_subnode(void *fdt, const char *name)
{
	char dupname[128];
	int parent = 0;
	char *basename;
	int ret;

	INFO("add_subnode: fdt=%p %s\n", fdt, name);
	ret = fdt_open_into(fdt, fdt, PLAT_QEMU_DT_MAX_SIZE);
	if (ret < 0) {
		ERROR("Invalid Device Tree at %p: error %d\n", fdt, ret);
		return;
	}

	memcpy(dupname, name, strlen(name)+1);
	basename = strrchr(dupname, '/');

	basename[0] = '\0';
	basename++;

	if (dupname[0]) {
		parent = fdt_path_offset(fdt, dupname);
		if (parent < 0)
			return;
	}

	ret = fdt_add_subnode(fdt, parent, basename);
	if (ret < 0)
		ERROR("Failed to add subnode. parent=%d %s\n", parent, name);

	ret = fdt_pack(fdt);
	if (ret < 0)
		ERROR("Failed to pack Device Tree at %p: error %d\n", fdt, ret);
}
#endif

#ifdef __Nebula__
void get_tee_system_mode(void)
{
	int offset;

	offset = fdt_path_offset((void*)(uintptr_t)PLAT_QEMU_DT_BASE, "/nebula/tee_system_mode@1");
	tee_system_mode = offset < 0 ? 0 : 1;
}
#endif


#ifdef __Nebula__

static const char *node[] = {
	[BL32_IMAGE_ID] = "/reserved-memory/tee-region",
	[BL33_IMAGE_ID] = "/reserved-memory/hee-region",
	[BL33_EXTRA1_IMAGE_ID] = "/reserved-memory/ree1-region",
	[BL33_EXTRA2_IMAGE_ID] = "/reserved-memory/ree2-region",
};

static int nbl_bl2_handle_pre_image_load(unsigned int image_id)
{
	uint64_t base, size, offset;
	bl_mem_params_node_t *bl_mem_params = get_bl_mem_params_node(image_id);

	switch (image_id) {
		case BL32_IMAGE_ID:        /* TEE */
		case BL33_IMAGE_ID:        /* HEE */
		case BL33_EXTRA1_IMAGE_ID: /* REE */
		case BL33_EXTRA2_IMAGE_ID: /* REE Rootfs */
			base = qemu_fdt_get_prop(node[image_id], "reg", 0);
			size = qemu_fdt_get_prop(node[image_id], "reg", 1);
			offset = qemu_fdt_get_prop(node[image_id], "offset", 0);
			INFO("%s base 0x%lx size 0x%lx offset 0x%lx\n", node[image_id], base, size, offset);
			bl_mem_params->ep_info.pc = base + offset;
			bl_mem_params->image_info.image_base = base + offset;
			break;
	}

	return 0;
}

/* Remove the not applicable nodes from the ree device tree */
static void remove_na_node_from_ree(void *fdt)
{
	qemu_fdt_del_node(fdt, "/secram"); /* Fix "virtual kernel memory layout" issue */
	qemu_fdt_del_node(fdt, "/okl-hyp/hee-interrupt-line");
	qemu_fdt_del_node(fdt, "/okl-hyp/hee-interrupt-line");
	qemu_fdt_del_node(fdt, "/okl-hyp/hee_fifo_vipc_irq");
	qemu_fdt_del_node(fdt, "/hee-link-shbuf");
	qemu_fdt_del_node(fdt, "/reserved-memory/hee-link-shbuf");
	qemu_fdt_del_node(fdt, "/hee-link-shbuf-2");
	qemu_fdt_del_node(fdt, "/reserved-memory/hee-link-shbuf-2");
	qemu_fdt_del_node(fdt, "/okl-hyp/hee-virq");
	qemu_fdt_del_node(fdt, "/okl-hyp/hee-pipe0");
	qemu_fdt_del_node(fdt, "/okl-hyp/hee-serial");
	qemu_fdt_del_node(fdt, node[BL32_IMAGE_ID]);
	qemu_fdt_del_node(fdt, node[BL33_IMAGE_ID]);
	qemu_fdt_del_node(fdt, node[BL33_EXTRA1_IMAGE_ID]);
	qemu_fdt_del_node(fdt, node[BL33_EXTRA2_IMAGE_ID]);
}

/* Remove the not applicable nodes from the hee device tree */
static void remove_na_node_from_hee(void *fdt)
{
	qemu_fdt_del_node(fdt, "/okl-hyp/ree-interrupt-line");
	qemu_fdt_del_node(fdt, "/okl-hyp/ree-link-shbuf");
	qemu_fdt_del_node(fdt, "/okl-hyp/ree-interrupt-line");
	qemu_fdt_del_node(fdt, "/okl-hyp/ree_fifo_vipc_irq");
	qemu_fdt_del_node(fdt, "/ree-link-shbuf");
	qemu_fdt_del_node(fdt, "/reserved-memory/ree-link-shbuf");
	qemu_fdt_del_node(fdt, "/ree-link-shbuf-2");
	qemu_fdt_del_node(fdt, "/reserved-memory/ree-link-shbuf-2");
	qemu_fdt_del_node(fdt, "/okl-hyp/ree-virq");
	qemu_fdt_del_node(fdt, "/okl-hyp/ree-pipe0");
	qemu_fdt_del_node(fdt, "/okl-hyp/ree-serial");
	qemu_fdt_del_node(fdt, "/pl011@9001000"); /* remove ree uart */
	qemu_fdt_del_node(fdt, "/pl011@9040000"); /* remove tee uart */
}

/* Remove the not applicable nodes from the tee device tree */
static void remove_na_node_from_tee(void *fdt)
{
	qemu_fdt_del_node(fdt, "/okl-hyp");
	qemu_fdt_del_node(fdt, "/emu-pipes");
	qemu_fdt_del_node(fdt, "/ree-link-shbuf");
	qemu_fdt_del_node(fdt, "/ree-link-shbuf-2");
	qemu_fdt_del_node(fdt, "/hee-link-shbuf");
	qemu_fdt_del_node(fdt, "/hee-link-shbuf-2");
	qemu_fdt_del_node(fdt, "/pl011@9000000"); /* remove hee uart */
	qemu_fdt_del_node(fdt, "/pl011@9001000"); /* remove ree uart */
}

static int nbl_bl2_handle_post_image_load(unsigned int image_id)
{
	fdt64_t value[2];
	uint64_t base, size, offset, initrd_start, initrd_end;
	bl_mem_params_node_t *bl_mem_params = get_bl_mem_params_node(image_id);

	switch (image_id) {
		case BL32_IMAGE_ID:        /* TEE */
		case BL33_IMAGE_ID:        /* HEE */
		case BL33_EXTRA1_IMAGE_ID: /* REE */
			base = qemu_fdt_get_prop(node[image_id], "reg", 0);
			size = qemu_fdt_get_prop(node[image_id], "reg", 1);
			value[0] = cpu_to_fdt64(base);
			value[1] = cpu_to_fdt64(size);
			qemu_fdt_copy((void*)(uintptr_t)base, (void*)(uintptr_t)PLAT_QEMU_DT_BASE);
			qemu_fdt_set_prop((void*)(uintptr_t)base, "/memory", "reg", value, sizeof(value));
			if (image_id == BL32_IMAGE_ID) {
				qemu_fdt_add_subnode((void*)(uintptr_t)base, "/nebula");
				qemu_fdt_add_subnode((void*)(uintptr_t)base, "/nebula/tee");
			}
			/* Assign device tree to x0 */
			INFO("base: 0x%lx\n", base);
			bl_mem_params->ep_info.args.arg0 = base;
			break;
		case BL33_EXTRA2_IMAGE_ID: /* REE Rootfs */
			base = qemu_fdt_get_prop(node[image_id], "reg", 0);
			offset = qemu_fdt_get_prop(node[image_id], "offset", 0);
			initrd_start = cpu_to_fdt64(base + offset);
			initrd_end = cpu_to_fdt64(base + offset + bl_mem_params->image_info.image_size);
			qemu_fdt_set_prop((void*)(uintptr_t)base, "/chosen", "linux,initrd-start", &initrd_start, sizeof(initrd_start));
			qemu_fdt_set_prop((void*)(uintptr_t)base, "/chosen", "linux,initrd-end", &initrd_end, sizeof(initrd_end));
			/* Remove all regions in ree device tree to avoid linux kernel complains. */
			remove_na_node_from_ree((void*)(uintptr_t)base);
			/* Remove unnecessary stuffs in hee device tree. */
			remove_na_node_from_hee((void*)(uintptr_t)qemu_fdt_get_prop(node[BL33_IMAGE_ID], "reg", 0));
			/* Remove unnecessary stuffs in tee device tree. */
			remove_na_node_from_tee((void*)(uintptr_t)qemu_fdt_get_prop(node[BL32_IMAGE_ID], "reg", 0));
			break;
	}

	return 0;
}
#endif /* __Nebula__ */

int bl2_plat_handle_pre_image_load(unsigned int image_id)
{
#ifdef __Nebula__
	nbl_bl2_handle_pre_image_load(image_id);
#endif
	return 0;
}

void bl2_platform_setup(void)
{
#if TRANSFER_LIST
	bl2_tl = transfer_list_init((void *)(uintptr_t)FW_HANDOFF_BASE,
				    FW_HANDOFF_SIZE);
	if (!bl2_tl) {
		ERROR("Failed to initialize Transfer List at 0x%lx\n",
		      (unsigned long)FW_HANDOFF_BASE);
	}
#endif
	security_setup();
	update_dt();

#ifdef __Nebula__
	get_tee_system_mode();
#endif

	/* TODO Initialize timer */
}

void qemu_bl2_sync_transfer_list(void)
{
#if TRANSFER_LIST
	transfer_list_update_checksum(bl2_tl);
#endif
}

void bl2_plat_arch_setup(void)
{
	const mmap_region_t bl_regions[] = {
		MAP_BL2_TOTAL,
		MAP_BL2_RO,
#if USE_COHERENT_MEM
		MAP_BL_COHERENT_RAM,
#endif
		{0}
	};

	setup_page_tables(bl_regions, plat_qemu_get_mmap());

#ifdef __aarch64__
	enable_mmu_el1(0);
#else
	enable_mmu_svc_mon(0);
#endif
}

/*******************************************************************************
 * Gets SPSR for BL32 entry
 ******************************************************************************/
static uint32_t qemu_get_spsr_for_bl32_entry(void)
{
#ifdef __aarch64__
	/*
	 * The Secure Payload Dispatcher service is responsible for
	 * setting the SPSR prior to entry into the BL3-2 image.
	 */
	return 0;
#else
	return SPSR_MODE32(MODE32_svc, SPSR_T_ARM, SPSR_E_LITTLE,
			   DISABLE_ALL_EXCEPTIONS);
#endif
}

/*******************************************************************************
 * Gets SPSR for BL33 entry
 ******************************************************************************/
static uint32_t qemu_get_spsr_for_bl33_entry(void)
{
	uint32_t spsr;
#ifdef __aarch64__
	unsigned int mode;

	/* Figure out what mode we enter the non-secure world in */
	mode = (el_implemented(2) != EL_IMPL_NONE) ? MODE_EL2 : MODE_EL1;

	/*
	 * TODO: Consider the possibility of specifying the SPSR in
	 * the FIP ToC and allowing the platform to have a say as
	 * well.
	 */
	spsr = SPSR_64(mode, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS);
#else
	spsr = SPSR_MODE32(MODE32_svc,
		    plat_get_ns_image_entrypoint() & 0x1,
		    SPSR_E_LITTLE, DISABLE_ALL_EXCEPTIONS);
#endif
	return spsr;
}

#if defined(SPD_spmd) && SPMD_SPM_AT_SEL2
static int load_sps_from_tb_fw_config(struct image_info *image_info)
{
	void *dtb = (void *)image_info->image_base;
	const char *compat_str = "arm,sp";
	const struct fdt_property *uuid;
	uint32_t load_addr;
	const char *name;
	int sp_node;
	int node;

	node = fdt_node_offset_by_compatible(dtb, -1, compat_str);
	if (node < 0) {
		ERROR("Can't find %s in TB_FW_CONFIG", compat_str);
		return -1;
	}

	fdt_for_each_subnode(sp_node, dtb, node) {
		name = fdt_get_name(dtb, sp_node, NULL);
		if (name == NULL) {
			ERROR("Can't get name of node in dtb\n");
			return -1;
		}
		uuid = fdt_get_property(dtb, sp_node, "uuid", NULL);
		if (uuid == NULL) {
			ERROR("Can't find property uuid in node %s", name);
			return -1;
		}
		if (fdt_read_uint32(dtb, sp_node, "load-address",
				    &load_addr) < 0) {
			ERROR("Can't read load-address in node %s", name);
			return -1;
		}
		if (qemu_io_register_sp_pkg(name, uuid->data, load_addr) < 0) {
			return -1;
		}
	}

	return 0;
}
#endif /*defined(SPD_spmd) && SPMD_SPM_AT_SEL2*/

static int qemu_bl2_handle_post_image_load(unsigned int image_id)
{
	int err = 0;
	bl_mem_params_node_t *bl_mem_params = get_bl_mem_params_node(image_id);
#if defined(SPD_opteed) || defined(AARCH32_SP_OPTEE) || defined(SPMC_OPTEE)
	bl_mem_params_node_t *pager_mem_params = NULL;
	bl_mem_params_node_t *paged_mem_params = NULL;
#endif
#if defined(SPD_spmd)
	bl_mem_params_node_t *bl32_mem_params = NULL;
#endif
#if TRANSFER_LIST
	struct transfer_list_header *ns_tl = NULL;
	struct transfer_list_entry *te = NULL;
#endif

	assert(bl_mem_params);

	switch (image_id) {
	case BL32_IMAGE_ID:
#if defined(SPD_opteed) || defined(AARCH32_SP_OPTEE) || defined(SPMC_OPTEE)
		pager_mem_params = get_bl_mem_params_node(BL32_EXTRA1_IMAGE_ID);
		assert(pager_mem_params);

		paged_mem_params = get_bl_mem_params_node(BL32_EXTRA2_IMAGE_ID);
		assert(paged_mem_params);

		err = parse_optee_header(&bl_mem_params->ep_info,
					 &pager_mem_params->image_info,
					 &paged_mem_params->image_info);
		if (err != 0) {
			WARN("OPTEE header parse error.\n");
		}
#endif

#if defined(SPMC_OPTEE)
		/*
		 * Explicit zeroes to unused registers since they may have
		 * been populated by parse_optee_header() above.
		 *
		 * OP-TEE expects system DTB in x2 and TOS_FW_CONFIG in x0,
		 * the latter is filled in below for TOS_FW_CONFIG_ID and
		 * applies to any other SPMC too.
		 */
		bl_mem_params->ep_info.args.arg2 = ARM_PRELOADED_DTB_BASE;
#elif defined(SPD_opteed)
		/*
		 * OP-TEE expect to receive DTB address in x2.
		 * This will be copied into x2 by dispatcher.
		 */
		bl_mem_params->ep_info.args.arg3 = ARM_PRELOADED_DTB_BASE;
#elif defined(AARCH32_SP_OPTEE)
		bl_mem_params->ep_info.args.arg0 =
					bl_mem_params->ep_info.args.arg1;
		bl_mem_params->ep_info.args.arg1 = 0;
		bl_mem_params->ep_info.args.arg2 = ARM_PRELOADED_DTB_BASE;
		bl_mem_params->ep_info.args.arg3 = 0;
#endif
		bl_mem_params->ep_info.spsr = qemu_get_spsr_for_bl32_entry();
		break;

	case BL33_IMAGE_ID:
#ifdef AARCH32_SP_OPTEE
		/* AArch32 only core: OP-TEE expects NSec EP in register LR */
		pager_mem_params = get_bl_mem_params_node(BL32_IMAGE_ID);
		assert(pager_mem_params);
		pager_mem_params->ep_info.lr_svc = bl_mem_params->ep_info.pc;
#endif

		bl_mem_params->ep_info.spsr = qemu_get_spsr_for_bl33_entry();

#if ARM_LINUX_KERNEL_AS_BL33
		/*
		 * According to the file ``Documentation/arm64/booting.txt`` of
		 * the Linux kernel tree, Linux expects the physical address of
		 * the device tree blob (DTB) in x0, while x1-x3 are reserved
		 * for future use and must be 0.
		 */
		bl_mem_params->ep_info.args.arg0 =
			(u_register_t)ARM_PRELOADED_DTB_BASE;
		bl_mem_params->ep_info.args.arg1 = 0U;
		bl_mem_params->ep_info.args.arg2 = 0U;
		bl_mem_params->ep_info.args.arg3 = 0U;
#elif TRANSFER_LIST
		if (bl2_tl) {
			// relocate the tl to pre-allocate NS memory
			ns_tl = transfer_list_relocate(bl2_tl,
					(void *)(uintptr_t)FW_NS_HANDOFF_BASE,
					bl2_tl->max_size);
			if (!ns_tl) {
				ERROR("Relocate TL to 0x%lx failed\n",
					(unsigned long)FW_NS_HANDOFF_BASE);
				return -1;
			}
			NOTICE("Transfer list handoff to BL33\n");
			transfer_list_dump(ns_tl);

			te = transfer_list_find(ns_tl, TL_TAG_FDT);

			bl_mem_params->ep_info.args.arg1 =
				TRANSFER_LIST_SIGNATURE |
				REGISTER_CONVENTION_VERSION_MASK;
			bl_mem_params->ep_info.args.arg3 = (uintptr_t)ns_tl;

			if (GET_RW(bl_mem_params->ep_info.spsr) == MODE_RW_32) {
				// aarch32
				bl_mem_params->ep_info.args.arg0 = 0;
				bl_mem_params->ep_info.args.arg2 = te ?
					(uintptr_t)transfer_list_entry_data(te)
					: 0;
			} else {
				// aarch64
				bl_mem_params->ep_info.args.arg0 = te ?
					(uintptr_t)transfer_list_entry_data(te)
					: 0;
				bl_mem_params->ep_info.args.arg2 = 0;
			}
		} else {
			// Legacy handoff
			bl_mem_params->ep_info.args.arg0 = 0xffff & read_mpidr();
		}
#else
		/* BL33 expects to receive the primary CPU MPID (through r0) */
#ifdef SPD_nebula
		/* The arg0 is stored device tree address, do not overwrite arg0 */
		/* The arg1 save tee system mode bl31 apply*/
		bl_mem_params->ep_info.args.arg1 = tee_system_mode;
#else
		/* BL33 expects to receive the primary CPU MPID (through r0) */
		bl_mem_params->ep_info.args.arg0 = 0xffff & read_mpidr();
#endif
#endif // ARM_LINUX_KERNEL_AS_BL33

		break;
#ifdef SPD_spmd
#if SPMD_SPM_AT_SEL2
	case TB_FW_CONFIG_ID:
		err = load_sps_from_tb_fw_config(&bl_mem_params->image_info);
		break;
#endif
	case TOS_FW_CONFIG_ID:
		/* An SPMC expects TOS_FW_CONFIG in x0/r0 */
		bl32_mem_params = get_bl_mem_params_node(BL32_IMAGE_ID);
		bl32_mem_params->ep_info.args.arg0 =
					bl_mem_params->image_info.image_base;
		break;
#endif
	case BL33_EXTRA1_IMAGE_ID:
		bl_mem_params->ep_info.spsr = qemu_get_spsr_for_bl33_entry();
		break;
	default:
		/* Do nothing in default case */
		break;
	}

	return err;
}

/*******************************************************************************
 * This function can be used by the platforms to update/use image
 * information for given `image_id`.
 ******************************************************************************/
int bl2_plat_handle_post_image_load(unsigned int image_id)
{
#ifdef __Nebula__
	nbl_bl2_handle_post_image_load(image_id);
#endif
	return qemu_bl2_handle_post_image_load(image_id);
}

uintptr_t plat_get_ns_image_entrypoint(void)
{
	return NS_IMAGE_OFFSET;
}
