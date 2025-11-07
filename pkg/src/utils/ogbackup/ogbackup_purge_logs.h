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
 * ogbackup_purge_logs.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_purge_logs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef OGBACKUP_PURGE_LOGS_H
#define OGBACKUP_PURGE_LOGS_H

#include <getopt.h>
#include "cm_defs.h"
#include "ogbackup_info.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t ogbak_parse_purge_logs_args(int32 argc, char** argv, ogbak_param_t* ogbak_param);

status_t ogbak_do_purge_logs(ogbak_param_t* ogbak_param);

status_t fill_params_for_ograc_purge_logs(ogbak_param_t* ogbak_param, char *og_params[]);

ogbak_cmd_t *ogbak_generate_purge_logs_cmd(void);

#ifdef __cplusplus
}
#endif

#endif  // OGBACKUP_PURGE_LOGS_H
