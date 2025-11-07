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
 * ogbackup_purge_logs.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_purge_logs.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogbackup_module.h"
#include "ogbackup_purge_logs.h"
#include "ogbackup_info.h"
#include "ogbackup_common.h"
#include "cm_defs.h"

const struct option ogbak_purge_logs_options[] = {
    {OGBAK_LONG_OPTION_PURGE_LOGS, no_argument, NULL, OGBAK_PARSE_OPTION_COMMON},
    {0, 0, 0, 0}
};

status_t ogbak_parse_purge_logs_args(int32 argc, char** argv, ogbak_param_t* ogbak_param)
{
    int opt_s;
    int opt_index = 0;
    optind = 1;
    while (optind < argc) {
        OG_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, OGBAK_SHORT_OPTION_EXP, ogbak_purge_logs_options, &opt_index);
        if (opt_s == OGBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case OGBAK_PARSE_OPTION_COMMON:
                break;
            case OGBAK_SHORT_OPTION_UNRECOGNIZED:
            case OGBAK_SHORT_OPTION_NO_ARG:
                printf("[ogbackup]Parse option arguments error!\n");
                return OG_ERROR;
            default:
                break;
        }
    }
    return OG_SUCCESS;
}

/**
 * 1. ogsql execute ALTER DATABASE DELETE ARCHIVELOG ABNORMAL
 * @param ogbak_param
 * @return
 */
status_t ogbak_do_purge_logs(ogbak_param_t* ogbak_param)
{
    status_t status;
    char *og_params[OGBACKUP_MAX_PARAMETER_CNT] = {0};
    printf("[ogbackup]ready to purge logs for oGRAC!\n");
    status = fill_params_for_ograc_purge_logs(ogbak_param, og_params);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]fill_params_for_ograc_purge_logs failed!\n");
        return OG_ERROR;
    }
    
    char *ogsql_binary_path = NULL;
    if (get_ogsql_binary_path(&ogsql_binary_path) != OG_SUCCESS) {
        CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
        return OG_ERROR;
    }

    status = ogbak_system_call(ogsql_binary_path, og_params, "oGRAC purge logs");
    // free space of heap
    CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ogsql_binary_path);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]oGRAC purge logs failed!\n");
        return OG_ERROR;
    }

    printf("[ogbackup]oGRAC purge logs success\n");
    return OG_SUCCESS;
}

status_t fill_params_for_ograc_purge_logs(ogbak_param_t* ogbak_param, char *og_params[])
{
    int param_index = 0;
    uint64_t len;
    errno_t ret;
    if (fill_params_for_ogsql_login(og_params, &param_index, OGBAK_OGSQL_EXECV_MODE) != OG_SUCCESS) {
        printf("[ogbackup]failed to fill params for ogsql login!\n");
        return OG_ERROR;
    }

    len = strlen(OGSQL_PURGE_LOGS) + strlen(OGSQL_STATEMENT_END_CHARACTER) + 1;
    // stetement not free here
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        printf("[ogbackup]failed to apply storage for purge logs!\n");
        return OG_ERROR;
    }
    ret = snprintf_s(statement, len, len - 1, "%s%s", OGSQL_PURGE_LOGS, OGSQL_STATEMENT_END_CHARACTER);
    if (ret == -1) {
        CM_FREE_PTR(statement);
        printf("[ogbackup]failed to concatenate strs for purge logs!\n");
        return OG_ERROR;
    }

    og_params[param_index++] = statement;
    // The last parameter must be NULL
    og_params[param_index++] = NULL;
    return OG_SUCCESS;
}

ogbak_cmd_t *ogbak_generate_purge_logs_cmd(void)
{
    ogbak_cmd_t* ogbak_cmd = (ogbak_cmd_t*)malloc(sizeof(ogbak_cmd_t));
    if (ogbak_cmd == NULL) {
        printf("[ogbackup]failed to malloc memory for purge_logs ogbak_cmd!\n");
        return (ogbak_cmd_t *)NULL;
    }
    ogbak_cmd->parse_args = ogbak_parse_purge_logs_args;
    ogbak_cmd->do_exec = ogbak_do_purge_logs;
    return ogbak_cmd;
}
