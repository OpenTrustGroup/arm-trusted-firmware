/*
 * Copyright (c) 2017-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SVE_H
#define SVE_H

#include <context.h>

#if (ENABLE_SME_FOR_NS || ENABLE_SVE_FOR_NS)
void sve_init_el2_unused(void);
void sve_enable_per_world(per_world_context_t *per_world_ctx);
void sve_disable_per_world(per_world_context_t *per_world_ctx);
#else
static inline void sve_init_el2_unused(void)
{
}
static inline void sve_enable_per_world(per_world_context_t *per_world_ctx)
{
}
static inline void sve_disable_per_world(per_world_context_t *per_world_ctx)
{
}
#endif /* ( ENABLE_SME_FOR_NS | ENABLE_SVE_FOR_NS ) */

// TODO: remove this workaround when FP registers are compatible with SVE/SME
#ifdef SPD_nebula
void init_per_world_context(per_world_context_t *per_world_ctx) {
	u_register_t cptr_el3;
	uint64_t sve_support;


	sve_support = read_id_aa64pfr0_el1() >> ID_AA64PFR0_SVE_SHIFT;
	sve_support &= ID_AA64PFR0_SVE_MASK;

	/* Enable access to FP registers for all ELs. */
	cptr_el3 = per_world_ctx->ctx_cptr_el3;
	if (sve_support) {
		cptr_el3 |= CPTR_EZ_BIT;
	}
	cptr_el3 &= ~(TFP_BIT);
	per_world_ctx->ctx_cptr_el3 = cptr_el3;
}
#endif

#endif /* SVE_H */
