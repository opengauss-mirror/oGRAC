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
 * ogbackup_archivelog.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_archivelog.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogbackup_module.h"
#include "ogbackup_archivelog.h"
#include "ogbackup_info.h"
#include "ogbackup_common.h"

const struct option ogbak_archivelog_options[] = {
    {OGBAK_LONG_OPTION_ARCHIVELOG, no_argument, NULL, OGBAK_PARSE_OPTION_COMMON},
    {OGBAK_LONG_OPTION_LRP_LSN, no_argument, NULL, OGBAK_SHORT_OPTION_LRP_LSN},
    {OGBAK_LONG_OPTION_FORCE, no_argument, NULL, OGBAK_SHORT_OPTION_FORCE},
    {0, 0, 0, 0}
};

status_t ogbak_parse_archivelog_args(int32 argc, char** argv, ogbak_param_t* ogbak_param)
{
    int opt_s;
    int opt_index = 0;
    optind = 1;
    while (optind < argc) {
        OG_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, OGBAK_SHORT_OPTION_EXP, ogbak_archivelog_options, &opt_index);
        if (opt_s == OGBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case OGBAK_PARSE_OPTION_COMMON:
                break;
            case OGBAK_SHORT_OPTION_LRP_LSN:
                ogbak_param->is_get_lrp = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_FORCE:
                ogbak_param->is_force_archive = OG_TRUE;
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

static status_t ogbak_do_force_archive(char *og_params[], char *ogsql_binary_path)
{
    status_t status;
    if (check_ogracd_status() != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (start_ogracd_server() != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogbak_check_ogsql_online(OGSQL_CHECK_CONN_MAX_TIME_S) != OG_SUCCESS) {
        return OG_ERROR;
    }

    status = ogbak_system_call(ogsql_binary_path, og_params, "oGRAC force archive log");
    OG_RETURN_IFERR(stop_ogracd_server());
    if (status != OG_SUCCESS) {
        printf("[ogbackup]oGRAC force archive log failed!\n");
        return OG_ERROR;
    }
    printf("[ogbackup]oGRAC force archive log success\n");
    return OG_SUCCESS;
}

/**
 * 1. ogsql execute ALTER DATABASE ARCHIVELOG
 * @param ogbak_param
 * @return
 */
status_t ogbak_do_archivelog(ogbak_param_t* ogbak_param)
{
    status_t status;
    char *og_params[OGBACKUP_MAX_PARAMETER_CNT] = {0};
    if (ogbak_param->is_get_lrp == OG_TRUE && ogbak_param->is_force_archive == OG_TRUE) {
        printf("[ogbackup]--lrp-lsn and --force can not be specified at the same time.\n");
        return OG_ERROR;
    }
    printf("[ogbackup]ready to archive log for oGRAC!\n");
    status = fill_params_for_ograc_archive_log(ogbak_param, og_params);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]fill_params_for_ograc_archive_log failed!\n");
        return OG_ERROR;
    }
    
    char *ogsql_binary_path = NULL;
    if (get_ogsql_binary_path(&ogsql_binary_path) != OG_SUCCESS) {
        CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
        return OG_ERROR;
    }

    if (ogbak_param->is_force_archive == OG_TRUE) {
        status = ogbak_do_force_archive(og_params, ogsql_binary_path);
        CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
        CM_FREE_PTR(ogsql_binary_path);
        return status;
    }

    status = ogbak_system_call(ogsql_binary_path, og_params, "oGRAC archive log");
    // free space of heap
    CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ogsql_binary_path);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]oGRAC archive log failed!\n");
        return OG_ERROR;
    }

    printf("[ogbackup]oGRAC archive log success\n");
    return OG_SUCCESS;
}

status_t fill_params_for_ograc_archive_log(ogbak_param_t* ogbak_param, char *og_params[])
{
    int param_index = 0;
    uint64_t len;
    errno_t ret;
    if (fill_params_for_ogsql_login(og_params, &param_index, OGBAK_OGSQL_EXECV_MODE) != OG_SUCCESS) {
        printf("[ogbackup]failed to fill params for ogsql login!\n");
        return OG_ERROR;
    }
    if (ogbak_param->is_get_lrp == OG_TRUE) {
        len = strlen(OGSQL_GET_LRP_LSN_STATEMENT) + strlen(OGSQL_STATEMENT_END_CHARACTER) + 1;
    } else {
        len = strlen(OGSQL_ARCHIVELOG_STATEMENT_PREFIX) + strlen(OGSQL_STATEMENT_END_CHARACTER) + 1;
    }
    // stetement not free here
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        printf("[ogbackup]failed to apply storage for archive log!\n");
        OGBAK_RETURN_ERROR_IF_NULL(statement);
    }

    if (ogbak_param->is_get_lrp == OG_TRUE) {
        ret = snprintf_s(statement, len, len - 1, "%s%s", OGSQL_GET_LRP_LSN_STATEMENT, OGSQL_STATEMENT_END_CHARACTER);
        if (SECUREC_UNLIKELY(ret == -1)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return OG_ERROR;
        }
    } else {
        ret = snprintf_s(statement, len, len - 1, "%s%s",
                         OGSQL_ARCHIVELOG_STATEMENT_PREFIX, OGSQL_STATEMENT_END_CHARACTER);
    }
    
    if (ret == -1) {
        CM_FREE_PTR(statement);
        printf("[ogbackup]failed to concatenate strs for archive log!\n");
        return OG_ERROR;
    }
    og_params[param_index++] = statement;
    // The last parameter must be NULL
    og_params[param_index++] = NULL;
    return OG_SUCCESS;
}

ogbak_cmd_t *ogbak_generate_archivelog_cmd(void)
{
    ogbak_cmd_t* ogbak_cmd = (ogbak_cmd_t*)malloc(sizeof(ogbak_cmd_t));
    if (ogbak_cmd == NULL) {
        printf("[ogbackup]failed to malloc memory for archivelog ogbak_cmd!\n");
        return (ogbak_cmd_t *)NULL;
    }
    ogbak_cmd->parse_args = ogbak_parse_archivelog_args;
    ogbak_cmd->do_exec = ogbak_do_archivelog;
    return ogbak_cmd;
};
