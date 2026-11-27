/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef __OGSQL_INPUT_BIND_PARAM_H__
#define __OGSQL_INPUT_BIND_PARAM_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32 ogsql_get_param_count(const char *sql);
status_t ogsql_bind_params(ogconn_stmt_t stmt, uint32 param_count /* , uint32 *batch_count */);
status_t ogsql_bind_param_init(uint32 param_count);
void ogsql_bind_param_uninit(uint32 param_count);

/** @} */  // end group OGSQL_CMD

#ifdef __cplusplus
}
#endif

#endif  // end __OGSQL_INPUT_BIND_PARAM_H__