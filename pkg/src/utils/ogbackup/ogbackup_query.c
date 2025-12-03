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
 * ogbackup_query.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_query.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogbackup_module.h"
#include "ogbackup_query.h"
#include "ogbackup_info.h"
#include "ogbackup_common.h"

const struct option ogbak_query_options[] = {
    {OGBAK_LONG_OPTION_QUERY, no_argument, NULL, OGBAK_PARSE_OPTION_COMMON},
    {OGBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, OGBAK_SHORT_OPTION_TARGET_DIR},
    {0, 0, 0, 0}
};

status_t ogbak_parse_query_args(int32 argc, char** argv, ogbak_param_t* ogbak_param)
{
    int opt_s;
    int opt_index = 0;
    optind = 1;
    while (optind < argc) {
        OG_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, OGBAK_SHORT_OPTION_EXP, ogbak_query_options, &opt_index);
        if (opt_s == OGBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case OGBAK_PARSE_OPTION_COMMON:
                break;
            case OGBAK_SHORT_OPTION_TARGET_DIR:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->target_dir));
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

static status_t ogbak_miner_parse_backup_info(const char *input_file, char **read_buf,
    uint32 buf_size, bak_head_t **bak_head)
{
    int32 read_size;
    int32 handle = OG_INVALID_HANDLE;

    if (cm_open_file(input_file, O_RDONLY | O_BINARY | O_SYNC, &handle) != OG_SUCCESS) {
        printf("[ogbackup] open file failed!");
        return OG_ERROR;
    }

    *bak_head = (bak_head_t *)(*read_buf);

    if (cm_read_file(handle, *read_buf, buf_size, &read_size) != OG_SUCCESS) {
        printf("[ogbackup] read file failed!");
        cm_close_file(handle);
        *bak_head = NULL;
        return OG_ERROR;
    }

    if ((uint32)read_size < sizeof(bak_head_t)) {
        printf("[ogbackup]read backupset is incomplete, expected %llu, but actually %llu.",
               (uint64)sizeof(bak_head_t), (uint64)read_size);
        cm_close_file(handle);
        *bak_head = NULL;
        return OG_ERROR;
    }

    cm_close_file(handle);
    return OG_SUCCESS;
}

status_t ogbak_do_query(ogbak_param_t* ogbak_param)
{
    if (check_common_params(ogbak_param) != OG_SUCCESS) {
        return OG_ERROR;
    }
    uint64_t len = strlen(ogbak_param->target_dir.str) + strlen(OGRAC_BACKUP_DIR) +
                   strlen(OGRAC_BACKUP_BACKUPSET) + 1;
    if (len > OGRAC_BACKUP_FILE_LENGTH) {
        printf("[ogbackup]The requested memory size is wrong in fill params for oGRAC query, please check!\n");
        return OG_ERROR;
    }
    char og_backup_dir[OGRAC_BACKUP_FILE_LENGTH] = {0};
    memset_s(og_backup_dir, OGRAC_BACKUP_FILE_LENGTH, 0, OGRAC_BACKUP_FILE_LENGTH);
    errno_t ret = snprintf_s((char *)og_backup_dir, len, len - 1, "%s%s%s", ogbak_param->target_dir.str,
                             OGRAC_BACKUP_DIR, OGRAC_BACKUP_BACKUPSET);
    if (ret == -1) {
        printf("[ogbackup]failed to concatenate strs for og_backup_dir!\n");
        return OG_ERROR;
    }
    if (cm_access_file((const char *)og_backup_dir, F_OK) != OG_SUCCESS) {
        printf("[ogbackup]the backupset file not exist!\n");
        return OG_ERROR;
    }
    char *read_buf = (char *)malloc(OG_BACKUP_BUFFER_SIZE);
    bak_head_t *bak_head = NULL;
    status_t status = ogbak_miner_parse_backup_info(og_backup_dir, &read_buf, OG_BACKUP_BUFFER_SIZE, &bak_head);
    if (status != OG_SUCCESS) {
        CM_FREE_PTR(read_buf);
        printf("[ogbackup]oGRAC query_incremental_mode failed!\n");
        return OG_ERROR;
    }
    if (bak_head->attr.level == 0) {
        printf("[ogbackup]the backupset is full backup!\n");
    } else {
        printf("[ogbackup]Incrementalmode：[%s].\n", bak_head->attr.backup_type ==
                BACKUP_MODE_INCREMENTAL ? "difference" : "cumulative");
    }
    CM_FREE_PTR(read_buf);
    printf("[ogbackup]oGRAC query_incremental_mode success.\n");
    return OG_SUCCESS;
}

ogbak_cmd_t *ogbak_generate_query_incremental_mode_cmd(void)
{
    ogbak_cmd_t* ogbak_cmd = (ogbak_cmd_t*)malloc(sizeof(ogbak_cmd_t));
    if (ogbak_cmd == NULL) {
        printf("[ogbackup]failed to malloc memory for ogbak_cmd!\n");
        return (ogbak_cmd_t *)NULL;
    }
    ogbak_cmd->parse_args = ogbak_parse_query_args;
    ogbak_cmd->do_exec = ogbak_do_query;
    return ogbak_cmd;
}
