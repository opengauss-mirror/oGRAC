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
 * ogbackup_prepare.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_prepare.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_OGBACKUP_PREPARE_H
#define OGRACDB_OGBACKUP_PREPARE_H

#include <getopt.h>
#include "cm_defs.h"
#include "ogbackup_info.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t ogbak_do_prepare(ogbak_param_t* ogbak_param);

status_t ogbak_do_restore(ogbak_param_t* ogbak_param);

status_t ogbak_do_recover(ogbak_param_t* ogbak_param);

status_t ogbak_do_restore_or_recover(ogbak_param_t* ogbak_param);

status_t ogbak_parse_prepare_args(int32 argc, char** argv, ogbak_param_t* ogbak_param);

status_t fill_params_for_ograc_recover(ogbak_param_t *ogbak_param, char *og_params[]);

status_t fill_params_for_ograc_reset_log(ogbak_param_t *ogbak_param, char *og_params[]);

status_t check_badblock_file_for_ograc_restore(ogbak_param_t *ogbak_param, const char *file_directory);

status_t get_statement_for_ograc_restore(char *file_directory, uint64_t option_len,
                                           char *option_str, char **statement);

status_t fill_params_for_ograc_restore(ogbak_param_t *ogbak_param, char *og_params[]);

status_t fill_options_for_ograc_restore(ogbak_param_t* ogbak_param, uint64_t* option_len, char** option_str);

ogbak_cmd_t *ogbak_generate_prepare_cmd(void);

#ifdef __cplusplus
}
#endif

#endif // OGRACDB_OGBACKUP_PREPARE_H