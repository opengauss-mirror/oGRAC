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
 * ogsql_wsr_analyse.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogsql/ogsql_wsr_analyse.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OGSQL_WSR_ANALYSE_H__
#define __OGSQL_WSR_ANALYSE_H__

#include "ogsql.h"
#include "ogsql_wsr_common.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t wsr_build_report_summary(wsr_options_t *wsr_opts, wsr_info_t *wsr_info);

#ifdef __cplusplus
}
#endif

#endif