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
 * ogbackup_query.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_query.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef OGBACKUP_QUERY_H
#define OGBACKUP_QUERY_H
#include <getopt.h>
#include "cm_defs.h"
#include "ogbackup_info.h"
#include "cm_file.h"
#include "bak_common.h"
#include "cm_defs.h"
#ifdef __cplusplus
extern "C" {
#endif

status_t ogbak_parse_query_args(int32 argc, char** argv, ogbak_param_t* ogbak_param);

status_t ogbak_do_query(ogbak_param_t* ogbak_param);

ogbak_cmd_t *ogbak_generate_query_incremental_mode_cmd(void);

#ifdef __cplusplus
}
#endif


#endif  // OGBACKUP_QUERY_H
