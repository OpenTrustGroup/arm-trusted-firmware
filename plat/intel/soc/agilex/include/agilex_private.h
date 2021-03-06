/*
 * Copyright (c) 2019, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2019, Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef AGX_PRIVATE_H
#define AGX_PRIVATE_H

#define AGX_MMC_REG_BASE	0xff808000

#define EMMC_DESC_SIZE		(1<<20)
#define EMMC_INIT_PARAMS(base)			\
	{	.bus_width = MMC_BUS_WIDTH_4,	\
		.clk_rate = 50000000,		\
		.desc_base = (base),		\
		.desc_size = EMMC_DESC_SIZE,	\
		.flags = 0,			\
		.reg_base = AGX_MMC_REG_BASE,	\
		\
	}

typedef enum {
	BOOT_SOURCE_FPGA = 0,
	BOOT_SOURCE_SDMMC,
	BOOT_SOURCE_NAND,
	BOOT_SOURCE_RSVD,
	BOOT_SOURCE_QSPI,
} boot_source_type;

void enable_nonsecure_access(void);
void socfpga_io_setup(int boot_source);

#endif
