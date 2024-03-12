#
# Copyright (c) 2016, ARM Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

NEBULA_DIR		:=	services/spd/nebula
SPD_INCLUDES		:=	-I${NEBULA_DIR}

SPD_SOURCES		:=	services/spd/nebula/trusty.c		\
				services/spd/nebula/trusty_helpers.S

NEED_BL32		:=	yes

CTX_INCLUDE_FPREGS	:=	1

# TODO: use common rule to distinguish MTK platform
ifeq (${MACH_TYPE},ecarxp)
PLAT_MTK		:= 1
else
PLAT_MTK		:= $(shell echo ${MACH_TYPE} | grep -E "^mt[0-9]{4}$$")
endif

ifneq (${PLAT_MTK},)
CFLAGS += -DPLAT_MTK
endif
