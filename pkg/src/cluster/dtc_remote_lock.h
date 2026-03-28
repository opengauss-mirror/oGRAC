/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * dtc_remote_buffer.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_remote_buffer.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_REMOTE_LOCK_H
#define DTC_REMOTE_LOCK_H

#include "knl_session.h"
#include "dtc_remote_buffer.h"
#include "ub_dist_comm_queue.h"
#include "ub_dist_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t init_lock_comm_queue();
void drc_init_remote_lock(ub_rw_lock_t **ub_lock, ub_lock_config_t *config, ub_location_t *creator);

#ifdef __cplusplus
}
#endif
#endif
