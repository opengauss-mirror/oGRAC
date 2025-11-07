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
 * ogbackup_backup.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_backup.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_OGBACKUP_BACKUP_H
#define OGRACDB_OGBACKUP_BACKUP_H

#include <getopt.h>
#include "cm_defs.h"
#include "ogbackup_info.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t convert_database_string_to_ograc(char *database, char *og_database);

status_t get_statement_for_ograc(ogbak_param_t* ogbak_param, uint64_t len, char *statement,
    char *databases, char *og_backup_dir);

status_t ogbak_do_backup(ogbak_param_t* ogbak_param);

status_t ogbak_parse_backup_args(int32 argc, char** argv, ogbak_param_t* ogbak_param);

ogbak_cmd_t *ogbak_generate_backup_cmd(void);

status_t fill_params_for_ograc_backup(ogbak_param_t* ogbak_param, char *og_params[]);

#ifdef __cplusplus
}
#endif

#endif // OGRACDB_OGBACKUP_BACKUP_H
