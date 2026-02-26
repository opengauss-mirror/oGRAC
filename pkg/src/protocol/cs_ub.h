/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cs_ub.h
 *
 * IDENTIFICATION
 * pkg/src/protocol/cs_ub.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CS_UB_H
#define __CS_UB_H

#include <stdio.h>
#include <errno.h>
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t ub_init_ubsm_mem(void);
status_t ub_create_shm_region(uint32 host_id, uint32 inst_count);
status_t ub_delete_shm(uint32 host_id);
status_t ub_delete_shm_region(uint32 host_id);
	

#ifdef __cplusplus
}
#endif
#endif