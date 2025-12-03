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
 * ogbackup_prepare.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_prepare.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogbackup_module.h"
#include "ogbackup_prepare.h"
#include "ogbackup_info.h"
#include "ogbackup_common.h"
#include "cm_file.h"

const struct option ogbak_prepare_options[] = {
    {OGBAK_LONG_OPTION_PREPARE, no_argument, NULL, OGBAK_PARSE_OPTION_COMMON},
    {OGBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, OGBAK_SHORT_OPTION_TARGET_DIR},
    {OGBAK_LONG_OPTION_PARALLEL, required_argument, NULL, OGBAK_SHORT_OPTION_PARALLEL},
    {OGBAK_LONG_OPTION_DECOMPRESS, no_argument, NULL, OGBAK_SHORT_OPTION_DECOMPRESS},
    {OGBAK_LONG_OPTION_BUFFER, required_argument, NULL, OGBAK_SHORT_OPTION_BUFFER},
    {OGBAK_LONG_OPTION_PITR_TIME, required_argument, NULL, OGBAK_SHORT_OPTION_PITR_TIME},
    {OGBAK_LONG_OPTION_PITR_SCN, required_argument, NULL, OGBAK_SHORT_OPTION_PITR_SCN},
    {OGBAK_LONG_OPTION_PITR_CANCEL, no_argument, NULL, OGBAK_SHORT_OPTION_PITR_CANCEL},
    {OGBAK_LONG_OPTION_PITR_RESTORE, no_argument, NULL, OGBAK_SHORT_OPTION_PITR_RESTORE},
    {OGBAK_LONG_OPTION_PITR_RECOVER, no_argument, NULL, OGBAK_SHORT_OPTION_PITR_RECOVER},
    {OGBAK_LONG_OPTION_REPAIR_TYPE, required_argument, NULL, OGBAK_SHORT_OPTION_REPAIR_TYPE},
    {0, 0, 0, 0}
};

status_t ogbak_parse_prepare_args(int32 argc, char** argv, ogbak_param_t* ogbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        OG_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, OGBAK_SHORT_OPTION_EXP, ogbak_prepare_options, &opt_index);
        if (opt_s == OGBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case OGBAK_PARSE_OPTION_COMMON:
                break;
            case OGBAK_SHORT_OPTION_TARGET_DIR:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->target_dir));
                break;
            case OGBAK_SHORT_OPTION_PARALLEL:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->parallelism));
                break;
            case OGBAK_SHORT_OPTION_DECOMPRESS:
                ogbak_param->is_decompress = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_BUFFER:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->buffer_size));
                break;
            case OGBAK_SHORT_OPTION_PITR_TIME:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->pitr_time));
                break;
            case OGBAK_SHORT_OPTION_PITR_SCN:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->pitr_scn));
                break;
            case OGBAK_SHORT_OPTION_PITR_CANCEL:
                ogbak_param->is_pitr_cancel = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_PITR_RESTORE:
                ogbak_param->is_restore = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_PITR_RECOVER:
                ogbak_param->is_recover = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_REPAIR_TYPE:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->repair_type));
                break;
            case OGBAK_SHORT_OPTION_UNRECOGNIZED:
            case OGBAK_SHORT_OPTION_NO_ARG:
                printf("[ogbackup]Parse option arguments of prepare failed!\n");
                return OG_ERROR;
            default:
                break;
        }
    }
    return OG_SUCCESS;
}

/**
 * 1. ogsql execute RESTORE DATABASE
 * 2. ogsql execute RECOVER DATABASE

 * @param ogbak_param
 * @return
 */
status_t ogbak_do_prepare(ogbak_param_t* ogbak_param)
{
    status_t status;
    if (check_common_params(ogbak_param) != OG_SUCCESS) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(check_ogracd_status());
    OG_RETURN_IFERR(start_ogracd_server());
    OG_RETURN_IFERR(ogbak_check_ogsql_online(OGSQL_CHECK_CONN_MAX_TIME_S));

    bool32 action_flag = (ogbak_param->is_restore == OG_TRUE && ogbak_param->is_recover != OG_TRUE) ||
            (ogbak_param->is_recover == OG_TRUE && ogbak_param->is_restore != OG_TRUE) ? OG_TRUE : OG_FALSE;
    if (action_flag) {
        status = ogbak_do_restore_or_recover(ogbak_param);
        return status;
    }
    status = ogbak_do_restore(ogbak_param);
    if (status != OG_SUCCESS) {
        free_input_params(ogbak_param);
        OG_RETURN_IFERR(stop_ogracd_server());
        return OG_ERROR;
    }

    status = ogbak_do_recover(ogbak_param);
    free_input_params(ogbak_param);
    OG_RETURN_IFERR(stop_ogracd_server());
    return status;
}


status_t check_badblock_file_for_ograc_restore(ogbak_param_t *ogbak_param, const char *file_directory)
{
    if ((ogbak_param->repair_type.str != NULL) && (!cm_str_equal(ogbak_param->repair_type.str, "return_error"))) {
        uint64_t len = strlen(file_directory) + strlen(OGSQL_RESTORE_BAD_BLOCK_FILE) + 1;
        char *file_path = (char *)malloc(len);
        if (file_path == NULL) {
            printf("[ogbackup] failed to malloc for badblock_file_path!\n");
            return OG_ERROR;
        }
        errno_t ret = snprintf_s(file_path, len, len - 1, "%s%s", file_directory, OGSQL_RESTORE_BAD_BLOCK_FILE);
        if (ret == -1) {
            CM_FREE_PTR(file_path);
            printf("[ogbackup] failed to concatenate strs for badblock_file_path!\n");
            return OG_ERROR;
        }
        if (cm_file_exist(file_path)) {
            printf("[ogbackup] there exist %s, pelase remove it before restore with repair_type!\n", file_path);
            CM_FREE_PTR(file_path);
            return OG_ERROR;
        }
        CM_FREE_PTR(file_path);
    }
    return OG_SUCCESS;
}

static status_t fill_repair_type_for_ograc_restore(ogbak_param_t *ogbak_param, uint64_t *option_len, char **option_str)
{
    errno_t ret;
    if (ogbak_param->repair_type.str != NULL) {
        OGBAK_RETURN_ERROR_IF_NULL(*option_str);
        if (cm_str_equal(ogbak_param->repair_type.str, "return_error")) {
            ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s%s",
                             *option_str, OGSQL_RESTORE_REPAIR_TYPE, OGSQL_RESTORE_REPAIR_TYPE_RETURN_ERROR);
        } else if (cm_str_equal(ogbak_param->repair_type.str, "replace_checksum")) {
            ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s%s",
                             *option_str, OGSQL_RESTORE_REPAIR_TYPE, OGSQL_RESTORE_REPAIR_TYPE_REPLACE_CHECKUSM);
        } else if (cm_str_equal(ogbak_param->repair_type.str, "discard_badblock")) {
            ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s%s",
                             *option_str, OGSQL_RESTORE_REPAIR_TYPE, OGSQL_RESTORE_REPAIR_TYPE_DISCARD_BADBLOCK);
        } else {
            printf("[ogbackup]repair_type is illegal!\n");
            return OG_ERROR;
        }
        if (ret == -1) {
            printf("[ogbackup]fill_options_for_cantain_restore concatenate repair_type for option_str failed!\n");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t fill_options_for_ograc_restore(ogbak_param_t* ogbak_param, uint64_t* option_len, char** option_str)
{
    errno_t ret;
    char *parallelism = NULL;
    *option_len += ogbak_param->parallelism.str != NULL ?
                  strlen(OGSQL_PARALLELISM_OPTION) + ogbak_param->parallelism.len + 1 : 0;
    *option_len += ogbak_param->buffer_size.str != NULL ?
                  strlen(OGSQL_BUFFER_OPTION) + ogbak_param->buffer_size.len + 1 : 0;
    *option_len += ogbak_param->repair_type.str != NULL ?
                  strlen(OGSQL_RESTORE_REPAIR_TYPE) + ogbak_param->repair_type.len + 1 : 0;
    if (*option_len != 0) {
        *option_str = (char *)malloc(*option_len);
        if (*option_str == NULL) {
            printf("[ogbackup]fill_options_for_ograc_restore malloc for option_str failed!\n");
            return OG_ERROR;
        }
        ret = memset_s(*option_str, *option_len, 0, *option_len);
        if (ret != EOK) {
            CM_FREE_PTR(*option_str);
            printf("[ogbackup]failed to set memory for option_str\n");
            return OG_ERROR;
        }
    }
    if (ogbak_param->parallelism.str != NULL) {
        parallelism = ogbak_param->parallelism.str;
        OGBAK_RETURN_ERROR_IF_NULL(*option_str);
        ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s", OGSQL_PARALLELISM_OPTION, parallelism);
        if (ret == -1) {
            CM_FREE_PTR(*option_str);
            printf("[ogbackup]fill_options_for_cantain_restore concatenate parallel for option_str failed!\n");
            return OG_ERROR;
        }
    }

    if (ogbak_param->buffer_size.str != NULL) {
        OGBAK_RETURN_ERROR_IF_NULL(*option_str);
        ret = snprintf_s(*option_str, *option_len, *option_len - 1, "%s%s%s",
                         *option_str, OGSQL_BUFFER_OPTION, ogbak_param->buffer_size.str);
        if (ret == -1) {
            CM_FREE_PTR(*option_str);
            printf("[ogbackup]fill_options_for_cantain_restore concatenate buffer size for option_str failed!\n");
            return OG_ERROR;
        }
    }
    if (fill_repair_type_for_ograc_restore(ogbak_param, option_len, option_str) != OG_SUCCESS) {
        CM_FREE_PTR(*option_str);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t get_statement_for_ograc_restore(char *file_directory, uint64_t option_len,
                                           char *option_str, char **statement)
{
    errno_t ret;
    uint64_t len = strlen(OGSQL_RESTORE_STATEMENT_PREFIX) + strlen(file_directory) + option_len +
                    strlen(OGSQL_STATEMENT_QUOTE) + strlen(OGSQL_STATEMENT_END_CHARACTER) + 1;
    if (len > MAX_STATEMENT_LENGTH) {
        printf("[ogbackup] The requested memory size is wrong in fill params for oGRAC restore, please check!\n");
        return OG_ERROR;
    }
    // stetement free by outside caller
    *statement = (char *)malloc(len);
    if (*statement == NULL) {
        printf("[ogbackup] failed to malloc for statement when restore!\n");
        return OG_ERROR;
    }

    if (option_str != NULL) {
        ret = snprintf_s(*statement, len, len - 1, "%s%s%s%s%s", OGSQL_RESTORE_STATEMENT_PREFIX, file_directory,
                         OGSQL_STATEMENT_QUOTE, option_str, OGSQL_STATEMENT_END_CHARACTER);
    } else {
        ret = snprintf_s(*statement, len, len - 1, "%s%s%s%s", OGSQL_RESTORE_STATEMENT_PREFIX,
                         file_directory, OGSQL_STATEMENT_QUOTE, OGSQL_STATEMENT_END_CHARACTER);
    }
    if (ret == -1) {
        printf("[ogbackup] snprintf_s failed when fill params for oGRAC restore!\n");
        CM_FREE_PTR(*statement);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t fill_params_for_ograc_restore(ogbak_param_t* ogbak_param, char *og_params[])
{
    uint64_t option_len  = 0;
    int   param_index = 0;
    char *option_str  = NULL;
    char *statement = NULL;
    errno_t ret;
    if (fill_params_for_ogsql_login(og_params, &param_index, OGBAK_OGSQL_EXECV_MODE) != OG_SUCCESS) {
        printf("[ogbackup]failed to fill params for ogsql login!\n");
        return OG_ERROR;
    }
    uint64_t len = strlen(ogbak_param->target_dir.str) + strlen(OGRAC_BACKUP_DIR) + 1;
    if (len > OGRAC_BACKUP_FILE_LENGTH) {
        printf("[ogbackup]The requested memory size is wrong in fill params for oGRAC restore, please check!\n");
        return OG_ERROR;
    }
    char *file_directory = (char *)malloc(len);
    if (file_directory == NULL) {
        return OG_ERROR;
    }
    ret = snprintf_s(file_directory, len, len - 1, "%s%s", ogbak_param->target_dir.str, OGRAC_BACKUP_DIR);
    if (ret == -1) {
        CM_FREE_PTR(file_directory);
        printf("[ogbackup]failed to concatenate strs for file_directory!\n");
        return OG_ERROR;
    }
    if (cm_access_file((const char *)file_directory, F_OK) != OG_SUCCESS) {
        CM_FREE_PTR(file_directory);
        printf("[ogbackup]the backup directory not exist!\n");
        return OG_ERROR;
    }

    if (fill_options_for_ograc_restore(ogbak_param, &option_len, &option_str) != OG_SUCCESS) {
        CM_FREE_PTR(file_directory);
        return OG_ERROR;
    }

    if (check_badblock_file_for_ograc_restore(ogbak_param, file_directory) != OG_SUCCESS) {
        CM_FREE_PTR(file_directory);
        CM_FREE_PTR(option_str);
        return OG_ERROR;
    }

    if (get_statement_for_ograc_restore(file_directory, option_len, option_str, &statement) != OG_SUCCESS) {
        CM_FREE_PTR(file_directory);
        CM_FREE_PTR(option_str);
        return OG_ERROR;
    }

    og_params[param_index++] = statement;
    // The last parameter must be NULL
    og_params[param_index++] = NULL;
    CM_FREE_PTR(file_directory);
    CM_FREE_PTR(option_str);
    return OG_SUCCESS;
}

status_t fill_params_for_ograc_recover(ogbak_param_t* ogbak_param, char *og_params[])
{
    int param_index = 0;
    uint64_t len;
    errno_t ret;
    if (fill_params_for_ogsql_login(og_params, &param_index, OGBAK_OGSQL_EXECV_MODE) != OG_SUCCESS) {
        printf("[ogbackup]failed to fill params for ogsql login!\n");
        return OG_ERROR;
    }

    len = strlen(OGSQL_RECOVER_STATEMENT_PREFIX) + strlen(OGSQL_STATEMENT_END_CHARACTER) + 1;
    if (ogbak_param->pitr_time.str != NULL) {
        len += ogbak_param->pitr_time.len + strlen(OGSQL_PITR_TIME_OPTION) + strlen(OGSQL_STATEMENT_QUOTE);
    } else if (ogbak_param->pitr_scn.str != NULL) {
        len += ogbak_param->pitr_scn.len + strlen(OGSQL_PITR_SCN_OPTION);
    } else if (ogbak_param->is_pitr_cancel == OG_TRUE) {
        len += strlen(OGSQL_PITR_CANCEL_OPTION);
    }
    // stetement not free here
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        printf("[ogbackup]failed to apply storage for archive log!\n");
        OGBAK_RETURN_ERROR_IF_NULL(statement);
    }
    if (ogbak_param->pitr_time.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s%s%s", OGSQL_RECOVER_STATEMENT_PREFIX, OGSQL_PITR_TIME_OPTION,
                         ogbak_param->pitr_time.str, OGSQL_STATEMENT_QUOTE, OGSQL_STATEMENT_END_CHARACTER);
    } else if (ogbak_param->pitr_scn.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s%s", OGSQL_RECOVER_STATEMENT_PREFIX, OGSQL_PITR_SCN_OPTION,
                         ogbak_param->pitr_scn.str, OGSQL_STATEMENT_END_CHARACTER);
    } else if (ogbak_param->is_pitr_cancel == OG_TRUE) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", OGSQL_RECOVER_STATEMENT_PREFIX, OGSQL_PITR_CANCEL_OPTION,
                         OGSQL_STATEMENT_END_CHARACTER);
    } else {
        ret = snprintf_s(statement, len, len - 1, "%s%s", OGSQL_RECOVER_STATEMENT_PREFIX, OGSQL_STATEMENT_END_CHARACTER);
    }
    
    if (ret == -1) {
        CM_FREE_PTR(statement);
        return OG_ERROR;
    }
    og_params[param_index++] = statement;
    // The last parameter must be NULL
    og_params[param_index++] = NULL;
    return OG_SUCCESS;
}

status_t fill_params_for_ograc_reset_log(ogbak_param_t* ogbak_param, char *og_params[])
{
    int param_index = 0;
    uint64_t len;
    errno_t ret;
    if (fill_params_for_ogsql_login(og_params, &param_index, OGBAK_OGSQL_EXECV_MODE) != OG_SUCCESS) {
        printf("[ogbackup]failed to fill params for ogsql login!\n");
        return OG_ERROR;
    }
    len = strlen(OGSQL_RECOVER_RESET_LOG) + strlen(OGSQL_STATEMENT_END_CHARACTER) + 1;
 
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        printf("[ogbackup]failed to apply storage for reset log!\n");
        OGBAK_RETURN_ERROR_IF_NULL(statement);
    }
 
    ret = snprintf_s(statement, len, len - 1, "%s%s", OGSQL_RECOVER_RESET_LOG, OGSQL_STATEMENT_END_CHARACTER);
    if (ret == -1) {
        CM_FREE_PTR(statement);
        printf("[ogbackup]failed to concatenate strs for reset log!\n");
        return OG_ERROR;
    }
    og_params[param_index++] = statement;
    og_params[param_index++] = NULL;
    return OG_SUCCESS;
}

status_t ogbak_do_restore_or_recover(ogbak_param_t* ogbak_param)
{
    status_t status;
    if (ogbak_param->is_restore == OG_TRUE) {
        status = ogbak_do_restore(ogbak_param);
    } else {
        status = ogbak_do_recover(ogbak_param);
    }
    free_input_params(ogbak_param);
    OG_RETURN_IFERR(stop_ogracd_server());
    return status;
}

/**
 * 1. decode restore params from prepare
 * 2. ogsql execute restore
 * @param ogbak_param
 * @return
 */
status_t ogbak_do_restore(ogbak_param_t* ogbak_param)
{
    status_t status;
    char *og_params[OGBACKUP_MAX_PARAMETER_CNT] = {0};
    printf("[ogbackup]ready to restore oGRAC!\n");
    status = fill_params_for_ograc_restore(ogbak_param, og_params);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]fill_params_for_ograc_restore failed!\n");
        return OG_ERROR;
    }
    char *ogsql_binary_path = NULL;
    if (get_ogsql_binary_path(&ogsql_binary_path) != OG_SUCCESS) {
        CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
        return OG_ERROR;
    }
    status = ogbak_system_call(ogsql_binary_path, og_params, "oGRAC restore");
    // free space of heap
    CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ogsql_binary_path);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]oGRAC restore failed!\n");
        return OG_ERROR;
    }

    printf("[ogbackup]oGRAC restore success\n");
    return OG_SUCCESS;
}

/**
 * 1. decode recovery params from prepare
 * 2. ogsql execute recover
 * @param recover_param
 * @return
 */
status_t ogbak_do_recover(ogbak_param_t* ogbak_param)
{
    status_t status;
    char *og_params[OGBACKUP_MAX_PARAMETER_CNT] = {0};
    char *og_params_resetlog[OGBACKUP_MAX_PARAMETER_CNT] = {0};
    printf("[ogbackup]ready to recover oGRAC!\n");
    status = fill_params_for_ograc_recover(ogbak_param, og_params);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]fill_params_for_ograc_recover failed!\n");
        return OG_ERROR;
    }
    char *ogsql_binary_path = NULL;
    if (get_ogsql_binary_path(&ogsql_binary_path) != OG_SUCCESS) {
        CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
        return OG_ERROR;
    }
    status = ogbak_system_call(ogsql_binary_path, og_params, "oGRAC recover");
    // free space of heap
    CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
    if (status != OG_SUCCESS) {
        CM_FREE_PTR(ogsql_binary_path);
        printf("[ogbackup]oGRAC recover failed!\n");
        return OG_ERROR;
    }

    if (ogbak_param->pitr_time.str != NULL || ogbak_param->pitr_scn.str != NULL) {
        printf("[ogbackup]ready to reset log after recover!\n");
        status = fill_params_for_ograc_reset_log(ogbak_param, og_params_resetlog);
        if (status != OG_SUCCESS) {
            CM_FREE_PTR(ogsql_binary_path);
            printf("[ogbackup]fill_params_for_ograc_reset_log failed!\n");
            return OG_ERROR;
        }
 
        status = ogbak_system_call(ogsql_binary_path, og_params_resetlog, "oGRAC resetlog");
        if (status != OG_SUCCESS) {
            CM_FREE_PTR(og_params_resetlog[OGSQL_STATEMENT_INDEX]);
            CM_FREE_PTR(ogsql_binary_path);
            printf("[ogbackup]oGRAC reset log failed!\n");
            return OG_ERROR;
        }
    }
    CM_FREE_PTR(og_params_resetlog[OGSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ogsql_binary_path);
    printf("[ogbackup]oGRAC recover success\n");
    return OG_SUCCESS;
}

ogbak_cmd_t *ogbak_generate_prepare_cmd(void)
{
    ogbak_cmd_t* ogbak_cmd = (ogbak_cmd_t*)malloc(sizeof(ogbak_cmd_t));
    if (ogbak_cmd == NULL) {
        printf("[ogbackup]failed to malloc memory for prepare ogbak_cmd!\n");
        return (ogbak_cmd_t *)NULL;
    }
    ogbak_cmd->parse_args = ogbak_parse_prepare_args;
    ogbak_cmd->do_exec = ogbak_do_prepare;
    return ogbak_cmd;
};