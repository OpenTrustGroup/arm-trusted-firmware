/*
 * Copyright (c) 2016-2017, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arch_helpers.h>
#include <assert.h> /* for context_mgmt.h */
#include <bl31/bl31.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <plat/common/platform.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <bl31/interrupt_mgmt.h>
#include <string.h>
#include <lib/utils_def.h>
#include <drivers/arm/gicv3.h>
#include <lib/spinlock.h>
#include <lib/smccc.h>

#include "sm_err.h"
#include "smcall.h"
#include "../drivers/arm/gic/v3/gicv3_private.h"

/* macro to check if Hypervisor is enabled in the HCR_EL2 register */
#define HYP_ENABLE_FLAG		0x80000000

/* length of Trusty's input parameters (in bytes) */
#define TRUSTY_PARAMS_LEN_BYTES	(4096*2)

#define SMC_ENTITY_PLATFORM_MONITOR 61
#define SMC_FC_DEBUG_PUTC SMC_FASTCALL_NR(SMC_ENTITY_PLATFORM_MONITOR, 0x0)
#define SMC_FC_GET_REG_BASE SMC_FASTCALL_NR(SMC_ENTITY_PLATFORM_MONITOR, 0x1)
#define SMC_FC64_GET_REG_BASE SMC_FASTCALL64_NR(SMC_ENTITY_PLATFORM_MONITOR, 0x1)
#define SMC_GET_GIC_BASE_GICD 0
#define SMC_GET_GIC_BASE_GICC 1

#define TWO_MB_SHIFT U(21)
#define TWO_MB_MASK ((1UL << TWO_MB_SHIFT) - 1)

#define IS_FASTCALL(x) (x & (1U << 31))
#define ARM_GIC_ARCH  3
#define MAX_VMID 0xFF

struct trusty_stack {
	uint8_t space[PLATFORM_STACK_SIZE] __aligned(16);
	uint32_t end;
};

struct trusty_cpu_ctx {
	cpu_context_t	cpu_ctx;
	void		*saved_sp;
	uint32_t	saved_security_state;
	int		fiq_handler_active;
	uint64_t	fiq_handler_pc;
	uint64_t	fiq_handler_cpsr;
	uint64_t	fiq_handler_sp;
	uint64_t	fiq_pc;
	uint64_t	fiq_cpsr;
	uint64_t	fiq_sp_el1;
	gp_regs_t	fiq_gpregs;
	struct trusty_stack	secure_stack;
#if ENABLE_PAUTH
	uint64_t	suspend_apiakey[2];
	uint64_t 	resume_apiakey[2];
#endif
};

struct args {
	uint64_t	r0;
	uint64_t	r1;
	uint64_t	r2;
	uint64_t	r3;
	uint64_t	r4;
	uint64_t	r5;
	uint64_t	r6;
	uint64_t	r7;
};

struct trusty_cpu_ctx trusty_cpu_ctx[PLATFORM_CORE_COUNT];

struct args trusty_init_context_stack(void **sp, void *new_stack);
struct args trusty_context_switch_helper(void **sp, void *smc_params);

static uint32_t current_vmid = MAX_VMID;
static uint32_t current_vmid_ref_count;
spinlock_t vmid_lock;
static uint32_t last_vmid[PLATFORM_CORE_COUNT];

static uint64_t nbl_mem_base;
static uint64_t nbl_dt_base;

static uint32_t virtio_has_probed;

static struct trusty_cpu_ctx *get_trusty_ctx(void)
{
	return &trusty_cpu_ctx[plat_my_core_pos()];
}

static uint32_t is_hypervisor_mode(void)
{
	uint64_t hcr = read_hcr();

	return !!(hcr & HYP_ENABLE_FLAG);
}

static struct args trusty_context_switch(uint32_t security_state, uint64_t r0,
					 uint64_t r1, uint64_t r2, uint64_t r3)
{
	struct args ret;
	struct trusty_cpu_ctx *ctx = get_trusty_ctx();
	struct trusty_cpu_ctx *ctx_smc;
	assert(ctx->saved_security_state != security_state);

	ret.r7 = 0;
	if (is_hypervisor_mode()) {
		/* According to the ARM DEN0028A spec, VMID is stored in x7 */
		ctx_smc = cm_get_context(NON_SECURE);
		assert(ctx_smc);
		ret.r7 = SMC_GET_GP(ctx_smc, CTX_GPREG_X7);
	}
	/* r4, r5, r6 reserved for future use. */
	ret.r6 = 0;
	ret.r5 = 0;
	ret.r4 = 0;
	ret.r3 = r3;
	ret.r2 = r2;
	ret.r1 = r1;
	ret.r0 = r0;

#if ENABLE_PAUTH
	if (r0 == SMC_FC_CPU_RESUME) {
		write_apiakeylo_el1(ctx->suspend_apiakey[0]);
		write_apiakeyhi_el1(ctx->suspend_apiakey[1]);
		isb();
	}
#endif
	/*
	 * To avoid the additional overhead in PSCI flow, skip FP context
	 * saving/restoring in case of CPU suspend and resume, asssuming that
	 * when it's needed the PSCI caller has preserved FP context before
	 * going here.
	 */
	if (r0 != SMC_FC_CPU_SUSPEND && r0 != SMC_FC_CPU_RESUME)
		fpregs_context_save(get_fpregs_ctx(cm_get_context(security_state)));
	cm_el1_sysregs_context_save(security_state);

	ctx->saved_security_state = security_state;
	ret = trusty_context_switch_helper(&ctx->saved_sp, &ret);

	assert(ctx->saved_security_state == !security_state);

	cm_el1_sysregs_context_restore(security_state);
	if (r0 != SMC_FC_CPU_SUSPEND && r0 != SMC_FC_CPU_RESUME)
		fpregs_context_restore(get_fpregs_ctx(cm_get_context(security_state)));

	cm_set_next_eret_context(security_state);

	return ret;
}

#if ARM_GIC_ARCH == 3

#define MP_IPI_NS_NOP 15
#define MP_IPI_NS_NOP_UOS 13
#define MP_IPI_SIRQ 14

enum dequeue_action_t {
	DEQUEUE_ACTION_ENABLE_INT,
	DEQUEUE_ACTION_TRIGGER_INT,
};

typedef struct {
	uint32_t target_cpu;
	uint32_t interrupt_id;
	enum dequeue_action_t dequeue_action;
} interrupt_t;

#define INTLIST_MAX_LEN 64
uint32_t percpu_idx[PLATFORM_CORE_COUNT];
interrupt_t percpu_int_list[PLATFORM_CORE_COUNT][INTLIST_MAX_LEN];

spinlock_t int_list_lock;

void enqueue_int_on(int cpu, int id, enum dequeue_action_t action)
{
	int idx;

	spin_lock(&int_list_lock);
	idx = percpu_idx[cpu];

	if (idx < INTLIST_MAX_LEN) {

		percpu_int_list[cpu][idx].target_cpu = cpu;
		percpu_int_list[cpu][idx].interrupt_id = id;
		percpu_int_list[cpu][idx].dequeue_action = action;

		percpu_idx[cpu] = idx+1;
	}

	spin_unlock(&int_list_lock);
}

void enqueue_int(int id, enum dequeue_action_t action)
{
	enqueue_int_on(plat_my_core_pos(), id, action);
}

void dequeue_ints(void)
{
	uint32_t id;
	int cpu = plat_my_core_pos();
	int idx;

	/*
	 * Clear MP_IPI_NS_NOP pending bit
	 */

	if (last_vmid[cpu] == 1) {
		gicv3_clear_interrupt_pending(MP_IPI_NS_NOP, cpu);
	} else if (last_vmid[cpu] == 2) {
		gicv3_clear_interrupt_pending(MP_IPI_NS_NOP_UOS, cpu);
	}

	spin_lock(&int_list_lock);

	while (percpu_idx[cpu] > 0) {
		idx = percpu_idx[cpu] - 1;
		id = percpu_int_list[cpu][idx].interrupt_id;

		switch (percpu_int_list[cpu][idx].dequeue_action) {
		case DEQUEUE_ACTION_ENABLE_INT:
			plat_ic_enable_interrupt(id);
			break;
		case DEQUEUE_ACTION_TRIGGER_INT:
			if (id <= 15) {
				/* Currently only support for triggering secure ipi */
				plat_ic_raise_s_el1_sgi(id, read_mpidr());
			} else {
				/* The gicd interrupts are not supported */
			}
			break;
		}

		percpu_idx[cpu] = idx;
	};

	spin_unlock(&int_list_lock);
}

void trigger_ns_nop_ipi(void)
{
	int cpu = plat_my_core_pos();
	if(last_vmid[plat_my_core_pos()] == 1) {
		VERBOSE("(%d) %s: trigger MP_IPI_NS_NOP\n", cpu, __func__);
		plat_ic_raise_ns_sgi(MP_IPI_NS_NOP, read_mpidr());
	} else if (last_vmid[plat_my_core_pos()] == 2) {
		VERBOSE("(%d) %s: trigger MP_IPI_NS_NOP_UOS\n", cpu, __func__);
		plat_ic_raise_ns_sgi(MP_IPI_NS_NOP_UOS, read_mpidr());
	}
}

void trigger_sirq_ipi(void)
{
	int cpu = plat_my_core_pos();

	VERBOSE("(%d) %s: trigger MP_IPI_SIRQ\n", cpu, __func__);
	plat_ic_raise_s_el1_sgi(MP_IPI_SIRQ, read_mpidr());
}

void gic_configure_secure_irq(void)
{
	/* Reserve the IPI 14 for Nebula TEE irq routing*/
	plat_ic_set_interrupt_type(MP_IPI_SIRQ, INTR_TYPE_S_EL1);
	plat_ic_set_interrupt_priority(MP_IPI_SIRQ, 0);
	plat_ic_enable_interrupt(MP_IPI_SIRQ);
}

/*
 * All G1NS interrupts that happened in S-EL1 will be trapped to here
 */
static uint64_t trusty_g1ns_fiq_handler(uint32_t id,
				   uint32_t flags,
				   void *handle,
				   void *cookie)
{
	assert(is_caller_secure(flags));

	trigger_sirq_ipi();

	SMC_RET0(handle);
}
#endif

/*
 * All G1S interrupts that happened in NS-EL1 will be trapped to here
 */
static uint64_t trusty_fiq_handler(uint32_t id,
				   uint32_t flags,
				   void *handle,
				   void *cookie)
{
	int cpu = plat_my_core_pos();

	if (is_caller_secure(flags)) {
		/*
		 * Return to S-EL1 directly when the concurrent interrupts happened.
		 *
		 * Here is an example to explain why it have to return S-EL1 directly.
		 * When S-EL1 got the g1ns fiq(27), and then it trapped to EL3.
		 * In the mean time the g1s(29) happened.
		 * Then EL3 got the highest pending irq number is g1s(29), and
		 * EL3 treat it as a G1S interrupts that trapped from NS-EL1, but
		 * it is trapped from S-EL1 actually.
		 * So we have to return to S-EL1 if caller is secure.
		 */
		SMC_RET0(handle);
	}
	assert(!is_caller_secure(flags));

#if ARM_GIC_ARCH == 3
	/*
	 * The purpose of triggering MP_IPI_NS_NOP is letting REE entering
         * to TEE via NOP smc call instead of entering via fiq trap.
         *
	 * Here we got g1s interrupt (trap from non-secure el1)
	 * Then temporarily disable it, and add to queue.
         * It's for injecting irq to tee when switching into secure el1
	 */
	uint32_t el1_g1s_int_id;

	el1_g1s_int_id = plat_ic_get_pending_interrupt_id();
	VERBOSE("(%d) %s: el1_g1s_int_id %u\n", cpu, __func__, el1_g1s_int_id);
	if (el1_g1s_int_id < 1022) {
		/* Disable G1S interrupt, and put in list */
		enqueue_int(el1_g1s_int_id, DEQUEUE_ACTION_ENABLE_INT);
		plat_ic_disable_interrupt(el1_g1s_int_id);

		/* Trigger the MP_IPI_NS_NOP */
		trigger_ns_nop_ipi();
	}
	SMC_RET0(handle);
#else
	struct args ret;
	struct trusty_cpu_ctx *ctx = get_trusty_ctx();

	ret = trusty_context_switch(NON_SECURE, SMC_FC_FIQ_ENTER, 0, 0, 0);
	if (ret.r0) {
		SMC_RET0(handle);
	}

	if (ctx->fiq_handler_active) {
		INFO("%s: fiq handler already active\n", __func__);
		SMC_RET0(handle);
	}

	ctx->fiq_handler_active = 1;
	memcpy(&ctx->fiq_gpregs, get_gpregs_ctx(handle), sizeof(ctx->fiq_gpregs));
	ctx->fiq_pc = SMC_GET_EL3(handle, CTX_ELR_EL3);
	ctx->fiq_cpsr = SMC_GET_EL3(handle, CTX_SPSR_EL3);
	ctx->fiq_sp_el1 = read_ctx_reg(get_el1_sysregs_ctx(handle), CTX_SP_EL1);

	write_ctx_reg(get_el1_sysregs_ctx(handle), CTX_SP_EL1, ctx->fiq_handler_sp);
	cm_set_elr_spsr_el3(NON_SECURE, ctx->fiq_handler_pc, ctx->fiq_handler_cpsr);

	SMC_RET0(handle);
#endif
}

static uint64_t trusty_set_fiq_handler(void *handle, uint64_t cpu,
			uint64_t handler, uint64_t stack)
{
	struct trusty_cpu_ctx *ctx;

	if (cpu >= PLATFORM_CORE_COUNT) {
		ERROR("%s: cpu %ld >= %d\n", __func__, (unsigned long)cpu, PLATFORM_CORE_COUNT);
		return SM_ERR_INVALID_PARAMETERS;
	}

	ctx = &trusty_cpu_ctx[cpu];
	ctx->fiq_handler_pc = handler;
	ctx->fiq_handler_cpsr = SMC_GET_EL3(handle, CTX_SPSR_EL3);
	ctx->fiq_handler_sp = stack;

	SMC_RET1(handle, 0);
}

static uint64_t trusty_get_fiq_regs(void *handle)
{
	struct trusty_cpu_ctx *ctx = get_trusty_ctx();
	uint64_t sp_el0 = read_ctx_reg(&ctx->fiq_gpregs, CTX_GPREG_SP_EL0);

	SMC_RET4(handle, ctx->fiq_pc, ctx->fiq_cpsr, sp_el0, ctx->fiq_sp_el1);
}

static uint64_t trusty_fiq_exit(void *handle, uint64_t x1, uint64_t x2, uint64_t x3)
{
	struct args ret;
	struct trusty_cpu_ctx *ctx = get_trusty_ctx();

	if (!ctx->fiq_handler_active) {
		NOTICE("%s: fiq handler not active\n", __func__);
		SMC_RET1(handle, SM_ERR_INVALID_PARAMETERS);
	}

	ret = trusty_context_switch(NON_SECURE, SMC_FC_FIQ_EXIT, 0, 0, 0);
	if (ret.r0 != 1) {
		INFO("%s(%p) SMC_FC_FIQ_EXIT returned unexpected value, %ld\n",
		       __func__, handle, (unsigned long)ret.r0);
	}

	/*
	 * Restore register state to state recorded on fiq entry.
	 *
	 * x0, sp_el1, pc and cpsr need to be restored because el1 cannot
	 * restore them.
	 *
	 * x1-x4 and x8-x17 need to be restored here because smc_handler64
	 * corrupts them (el1 code also restored them).
	 */
	memcpy(get_gpregs_ctx(handle), &ctx->fiq_gpregs, sizeof(ctx->fiq_gpregs));
	ctx->fiq_handler_active = 0;
	write_ctx_reg(get_el1_sysregs_ctx(handle), CTX_SP_EL1, ctx->fiq_sp_el1);
	cm_set_elr_spsr_el3(NON_SECURE, ctx->fiq_pc, ctx->fiq_cpsr);

	SMC_RET0(handle);
}

/*
 * Return 1 to let trusty-pm knows there has remained secure timer
 */
static uint64_t get_secure_timer(void *handle)
{
	uint64_t ctl;
	uint64_t ret;

	ctl = read_cntps_ctl_el1();
	ret = ctl & 0x1;

#ifdef PLAT_MTK
	if (ret) {
		/*
		 * MTK workaround:
		 *    The trusty-pm linux driver will return NOTIFY_BAD for cpu_pm_enter
		 *    if there has remained secure timer.
		 *    The mcdi won't handle the failed case when cpu_pm_enter return error,
		 *    eventually the G1NS is being off forever.
		 *    So we should re-enable the G1NS in the gicv3 control register
		 */
		write_icc_igrpen1_el3(read_icc_igrpen1_el3() | IGRPEN1_EL3_ENABLE_G1NS_BIT);
	}
#endif

	SMC_RET4(handle, ret, 0, 0, 0);
}

static void nbl_register_boot_entry(uint64_t entry_offset)
{
	entry_point_info_t *ep_info = bl31_plat_get_next_image_ep_info(SECURE);

	ep_info->pc = (uintptr_t)(nbl_mem_base + entry_offset);
}

static void handle_ipi_fwd(uint64_t cpu_mask, uint64_t ipi_id)
{
	int cpu_num;

	/* Enqueue ipi into percpu interrupt list */
	for (cpu_num = 0; cpu_num < PLATFORM_CORE_COUNT; cpu_num++) {
		if (cpu_mask & (1 << cpu_num))
			enqueue_int_on(cpu_num, ipi_id, DEQUEUE_ACTION_TRIGGER_INT);
	}

	/* Asking linux to enqueue nop for all online cpus */
	if (virtio_has_probed)
		trusty_context_switch(SECURE, SM_ERR_IPI_FWD_SEND_NOP, 0, 0, 0);
}

static uintptr_t trusty_smc_handler(uint32_t smc_fid,
			 u_register_t x1,
			 u_register_t x2,
			 u_register_t x3,
			 u_register_t x4,
			 void *cookie,
			 void *handle,
			 u_register_t flags)
{
	struct args ret;
	uint32_t vmid = 0;
	int cpu = plat_my_core_pos();
	entry_point_info_t *ep_info = bl31_plat_get_next_image_ep_info(SECURE);
#if ARM_GIC_ARCH == 3
	uint32_t icc_igrpen1_val;
#endif

	/*
	 * Return success for SET_ROT_PARAMS if Trusty is not present, as
	 * Verified Boot is not even supported and returning success here
	 * would not compromise the boot process.
	 */
	if (!ep_info && (smc_fid == SMC_SC_SET_ROT_PARAMS)) {
		SMC_RET1(handle, 0);
	} else if (!ep_info) {
		SMC_RET1(handle, SMC_UNK);
	}

	if (is_caller_secure(flags)) {
		VERBOSE("(%d) %s:TEE smc fid 0x%x\n", cpu, __func__, smc_fid);
		if (smc_fid == SMC_SC_NS_RETURN) {
#if ARM_GIC_ARCH == 3
			gicv3_clear_interrupt_pending(MP_IPI_SIRQ, plat_my_core_pos());
#endif
			VERBOSE("(%d) %s: TEE smc fid 0x%x conext switch to REE\n", cpu, __func__, smc_fid);
			ret = trusty_context_switch(SECURE, x1, 0, 0, 0);
			VERBOSE("(%d) %s: TEE smc fid 0x%x return from REE smc fid 0x%lx\n", cpu, __func__, smc_fid, ret.r0);

			SMC_RET8(handle, ret.r0, ret.r1, ret.r2, ret.r3,
				 ret.r4, ret.r5, ret.r6, ret.r7);
		}
		if (smc_fid == SMC_FC_DEBUG_PUTC) {
			putchar((int)x1);
			SMC_RET1(handle, 0);
		}
		if (smc_fid == SMC_FC64_GET_REG_BASE) {
			if (x1 == SMC_GET_GIC_BASE_GICC)
				SMC_RET1(handle, GICC_BASE);
			if (x1 == SMC_GET_GIC_BASE_GICD)
				SMC_RET1(handle, GICD_BASE);
		}
		if (smc_fid == SMC_FC_IPI_FWD_ENQ_IPI) {
			handle_ipi_fwd(x1, x2);
			SMC_RET0(handle);
		}
		if (smc_fid == SMC_FC_PLAT_REGISTER_BOOT_ENTRY) {
			nbl_register_boot_entry(x1);
			SMC_RET0(handle);
		}
		if (smc_fid == SMC_FC_PLAT_ARITHMETIC) {
			//INFO("smc_fid 0x%x x1 0x%lu x2 0x%lu x3 0x%lu x4 0x%lu\n", smc_fid, x1, x2, x3, x4);
			switch (x2) {
				case '+': SMC_RET2(handle, SMC_OK, x1 + x3);
				case '-': SMC_RET2(handle, SMC_OK, x1 - x3);
				case '*': SMC_RET2(handle, SMC_OK, x1 * x3);
				case '/': SMC_RET2(handle, SMC_OK, x1 / x3);
				default: SMC_RET2(handle, SMC_UNK, 0);
			}
		}
		/*if (plat_smc_handler(smc_fid, x1, x2, x3, x4, cookie, handle, flags)) {
			SMC_RET0(handle);
		}*/
		INFO("%s (0x%x, 0x%lx, 0x%lx, 0x%lx, 0x%lx, %p, %p, 0x%lx) \
		     cpu %d, unknown smc\n",
		     __func__, smc_fid, x1, x2, x3, x4, cookie, handle, flags,
		     plat_my_core_pos());
		SMC_RET1(handle, SMC_UNK);
	} else {
		VERBOSE("(%d) %s: REE smc fid 0x%x\n", cpu, __func__, smc_fid);
		switch (smc_fid) {
		case SMC_FC64_SET_FIQ_HANDLER:
			return trusty_set_fiq_handler(handle, x1, x2, x3);
		case SMC_FC64_GET_FIQ_REGS:
			return trusty_get_fiq_regs(handle);
		case SMC_FC_FIQ_EXIT:
			return trusty_fiq_exit(handle, x1, x2, x3);
		case SMC_FC64_GET_TIMER:
			return get_secure_timer(handle);
		default:
			if (is_hypervisor_mode())
				vmid = SMC_GET_GP(handle, CTX_GPREG_X7);

			if (!IS_FASTCALL(smc_fid)) {
				spin_lock(&vmid_lock);
				if ((current_vmid != MAX_VMID) && (current_vmid != vmid)) {
					/* This message will cause SMC mechanism
					* abnormal in multi-guest environment.
					* Change it to WARN in case you need it.
					*/
					VERBOSE("Previous SMC not finished.\n");
					spin_unlock(&vmid_lock);
					SMC_RET1(handle, SM_ERR_BUSY);
				}

				current_vmid = vmid;
				current_vmid_ref_count++;
				spin_unlock(&vmid_lock);

				last_vmid[plat_my_core_pos()] = vmid;
			}

#if ARM_GIC_ARCH == 3
			/* Inject g1s pending interrupts */
			dequeue_ints();

			if (IS_FASTCALL(smc_fid)) {
				/* disable Grp1NS and Grp1S before calling to the fastcall */
				icc_igrpen1_val = read_icc_igrpen1_el3();
				write_icc_igrpen1_el3(0);
				isb();
			}
#endif
			VERBOSE("(%d) %s: REE smc fid 0x%x conext switch to TEE\n", cpu, __func__, smc_fid);
			ret = trusty_context_switch(NON_SECURE, smc_fid, x1,
				x2, x3);
			VERBOSE("(%d) %s: REE smc fid 0x%x return from TEE smc fid 0x%lx\n", cpu, __func__,
				smc_fid, ret.r0);

#if ARM_GIC_ARCH == 3
			if (IS_FASTCALL(smc_fid)) {
				/* restore icc_igrpen1_el3 after fastcall */
				write_icc_igrpen1_el3(icc_igrpen1_val);
				isb();
			}
#endif

			if (!IS_FASTCALL(smc_fid)) {
				spin_lock(&vmid_lock);
				current_vmid_ref_count--;
				if(current_vmid_ref_count == 0) {
					current_vmid = MAX_VMID;
				}
				spin_unlock(&vmid_lock);
			}

			if (smc_fid == SMC_SC_VIRTIO_START)
				virtio_has_probed = 1;

			SMC_RET1(handle, ret.r0);
		}
	}
}

static int32_t trusty_init(void)
{
	void el3_exit(void);
	entry_point_info_t *ep_info;
	struct args zero_args = {0};
	struct trusty_cpu_ctx *ctx = get_trusty_ctx();
	uint32_t cpu = plat_my_core_pos();
	int reg_width = GET_RW(read_ctx_reg(get_el3state_ctx(&ctx->cpu_ctx),
			       CTX_SPSR_EL3));
	uintptr_t gicr_base = gicv3_driver_data->rdistif_base_addrs[cpu];
	unsigned int saved_isenabler0_reg = mmio_read_32(gicr_base + GICR_ISENABLER0);
	unsigned int tmp_isenabler0_reg = 0;

	/*
	 * Get information about the Trusty image. Its absence is a critical
	 * failure.
	 */
	ep_info = bl31_plat_get_next_image_ep_info(SECURE);
	assert(ep_info);

	/*
	 * The fp registers were not saved here because they are not used yet
	 * and should be "zeros". The "TFP" bit status also stops us accessing
	 * the fp registers.
	 * See commit "trusty: delete the fp registers save&restore at init stage".
	 */
	cm_el1_sysregs_context_save(NON_SECURE);

	cm_set_context(&ctx->cpu_ctx, SECURE);
	cm_init_my_context(ep_info);

	/*
	 * Adjust secondary cpu entry point for 32 bit images to the
	 * end of exeption vectors
	 */
	if ((cpu != 0) && (reg_width == MODE_RW_32)) {
		INFO("trusty: cpu %d, adjust entry point to 0x%lx\n",
		     cpu, ep_info->pc + (1U << 5));
		cm_set_elr_el3(SECURE, ep_info->pc + (1U << 5));
	}

	cm_el1_sysregs_context_restore(SECURE);
	/*
	 * Skip fp registers restore as they are not used yet.
	 */
	cm_set_next_eret_context(SECURE);

	ctx->saved_security_state = ~0; /* initial saved state is invalid */
	trusty_init_context_stack(&ctx->saved_sp, &ctx->secure_stack.end);

	trusty_context_switch_helper(&ctx->saved_sp, &zero_args);

	cm_el1_sysregs_context_restore(NON_SECURE);
	/*
	 * We can touch fp registers now, restore them to avoid leaking
	 * TEE fp registers to non-secure world.
	 */
	fpregs_context_restore(get_fpregs_ctx(cm_get_context(NON_SECURE)));
	cm_set_next_eret_context(NON_SECURE);

#if ARM_GIC_ARCH == 3
	/*
	 * Configure SPD dedicated secure irq after initialized Nebula BL32
	 * otherwise the SPD irq will be initialized and disabled
	 * in the Nebula BL32's percpu initial flow
	 */
	gic_configure_secure_irq();

	/*
	 * Re-enable the SGI/PPI interrupts that already enabled before trusty_init()
	 */
	tmp_isenabler0_reg = mmio_read_32(gicr_base + GICR_ISENABLER0);
	tmp_isenabler0_reg |= saved_isenabler0_reg;
	mmio_write_32(gicr_base + GICR_ISENABLER0, tmp_isenabler0_reg);
#endif

	return 1;
}

static void trusty_cpu_suspend(void)
{
	struct args ret;

#if ARM_GIC_ARCH == 3
	uint32_t icc_igrpen1_val;

	icc_igrpen1_val = read_icc_igrpen1_el3();
	write_icc_igrpen0_el1(0);
	write_icc_igrpen1_el3(0);
	isb();
#endif

#if ENABLE_PAUTH
	struct trusty_cpu_ctx *ctx = get_trusty_ctx();

	ctx->suspend_apiakey[0] = read_apiakeylo_el1();
	ctx->suspend_apiakey[1] = read_apiakeyhi_el1();
#endif
	ret = trusty_context_switch(NON_SECURE, SMC_FC_CPU_SUSPEND, 0, 0, 0);
	if (ret.r0 != 0) {
		INFO("%s: cpu %u, SMC_FC_CPU_SUSPEND returned unexpected value, %ld\n",
		     __func__, plat_my_core_pos(), (unsigned long)ret.r0);
	}

#if ARM_GIC_ARCH == 3
	write_icc_igrpen1_el3(icc_igrpen1_val);
	isb();
#endif
}

static void trusty_cpu_resume(void)
{
	struct args ret;
	uint64_t cptr_el3;
#if ARM_GIC_ARCH == 3
	uint32_t icc_igrpen1_val;

	gic_configure_secure_irq();

	icc_igrpen1_val = read_icc_igrpen1_el3();
	write_icc_igrpen1_el3(0);
	isb();
#endif

#if ENABLE_PAUTH
	struct trusty_cpu_ctx *ctx = get_trusty_ctx();

	ctx->resume_apiakey[0] = read_apiakeylo_el1();
	ctx->resume_apiakey[1] = read_apiakeyhi_el1();
#endif

	cptr_el3 = read_cptr_el3();
	write_cptr_el3(per_world_context[CPU_CONTEXT_SECURE].ctx_cptr_el3);
	isb();
	ret = trusty_context_switch(NON_SECURE, SMC_FC_CPU_RESUME, 0, 0, 0);
	if (ret.r0 != 0) {
		INFO("%s: cpu %u, SMC_FC_CPU_RESUME returned unexpected value, %ld\n",
		     __func__, plat_my_core_pos(), (unsigned long)ret.r0);
	}
	write_cptr_el3(cptr_el3);
	isb();

#if ENABLE_PAUTH
	write_apiakeylo_el1(ctx->resume_apiakey[0]);
	write_apiakeyhi_el1(ctx->resume_apiakey[1]);
	isb();
#endif

#if ARM_GIC_ARCH == 3
	write_icc_igrpen1_el3(icc_igrpen1_val);
	isb();
#endif
}

static int32_t trusty_cpu_off_handler(u_register_t unused)
{
	trusty_cpu_suspend();

	return 0;
}

static void trusty_cpu_on_finish_handler(u_register_t unused)
{
	struct trusty_cpu_ctx *ctx = get_trusty_ctx();

	if (!ctx->saved_sp) {
		trusty_init();
	} else {
		trusty_cpu_resume();
	}
}

static void trusty_cpu_suspend_handler(u_register_t unused)
{
	trusty_cpu_suspend();
}

static void trusty_cpu_suspend_finish_handler(u_register_t unused)
{
	trusty_cpu_resume();
}

static const spd_pm_ops_t trusty_pm = {
	.svc_off = trusty_cpu_off_handler,
	.svc_suspend = trusty_cpu_suspend_handler,
	.svc_on_finish = trusty_cpu_on_finish_handler,
	.svc_suspend_finish = trusty_cpu_suspend_finish_handler,
};

static int32_t trusty_setup(void)
{
	entry_point_info_t *ep_info;
	uint32_t flags;
	int ret;

	/* Get trusty's entry point info */
	ep_info = bl31_plat_get_next_image_ep_info(SECURE);
	if (!ep_info) {
		INFO("Trusty image missing.\n");
		return -1;
	}

	nbl_mem_base = ep_info->pc & ~(TWO_MB_MASK);
	nbl_dt_base = nbl_mem_base;

	/* Trusty runs in AARCH64 mode */
	SET_PARAM_HEAD(ep_info, PARAM_EP, VERSION_1, SECURE | EP_ST_ENABLE);
	ep_info->spsr = SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS);

	/*
	 * arg0 = TZDRAM aperture available for BL32
	 * arg1 = BL32 boot params
	 * arg2 = BL32 boot params length
	 * arg3 = tee support parameter for BL32
	 */
	ep_info->args.arg0 = nbl_dt_base;
	ep_info->args.arg1 = ep_info->args.arg2;
	ep_info->args.arg2 = TRUSTY_PARAMS_LEN_BYTES;
	ep_info->args.arg3 = 1;

	/* register init handler */
	bl31_register_bl32_init(trusty_init);

	/* register power management hooks */
	psci_register_spd_pm_hook(&trusty_pm);

	/* register interrupt handler */
	flags = 0;
	set_interrupt_rm_flag(flags, NON_SECURE);
	ret = register_interrupt_type_handler(INTR_TYPE_S_EL1,
					      trusty_fiq_handler,
					      flags);
	if (ret)
		ERROR("trusty: failed to register fiq handler, ret = %d\n", ret);

#if ARM_GIC_ARCH == 3
	/* register interrupt handler (route sel1 g1ns fiq to el3) */
	flags = 0;
	set_interrupt_rm_flag(flags, SECURE);
	ret = register_interrupt_type_handler(INTR_TYPE_NS,
					      trusty_g1ns_fiq_handler,
					      flags);
	if (ret)
		ERROR("trusty: failed to register g1ns fiq handler, ret = %d\n", ret);
#endif

	return 0;
}

/* Define a SPD runtime service descriptor for fast SMC calls */
DECLARE_RT_SVC(
	trusty_fast,
	OEN_TOS_START,
	SMC_ENTITY_SECURE_MONITOR,
	SMC_TYPE_FAST,
	trusty_setup,
	trusty_smc_handler
);

/* Define a SPD runtime service descriptor for yielding SMC calls */
DECLARE_RT_SVC(
	trusty_std,
	OEN_TAP_START,
	SMC_ENTITY_SECURE_MONITOR,
	SMC_TYPE_YIELD,
	NULL,
	trusty_smc_handler
);

DECLARE_RT_SVC(
    trusty_fast_plat,
    OEN_TOS_START,
    SMC_ENTITY_PLATFORM_MONITOR,
    SMC_TYPE_FAST,
    NULL,
    trusty_smc_handler
);

DECLARE_RT_SVC(
    trusty_fast_plat_vm,
    OEN_TOS_START,
    SMC_ENTITY_PLAT,
    SMC_TYPE_FAST,
    NULL,
    trusty_smc_handler
);
