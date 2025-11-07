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
 * ogbackup_backup.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_backup.c
 *
 * -------------------------------------------------------------------------
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include "ogbackup_module.h"
#include "ogbackup_info.h"
#include "ogbackup.h"
#include "ogbackup_common.h"
#include "unistd.h"
#include "cm_file.h"
#include "ogbackup_backup.h"

#define OGBAK_BACKUP_RETRY_MAX_NUM 2
#define OGBAK_BACKUP_CECHK_ONLINE_TIME 5

const struct option ogbak_backup_options[] = {
    {OGBAK_LONG_OPTION_BACKUP, no_argument, NULL, OGBAK_PARSE_OPTION_COMMON},
    {OGBAK_LONG_OPTION_USER, required_argument, NULL, OGBAK_SHORT_OPTION_USER},
    {OGBAK_LONG_OPTION_PASSWORD, required_argument, NULL, OGBAK_SHORT_OPTION_PASSWORD},
    {OGBAK_LONG_OPTION_HOST, required_argument, NULL, OGBAK_SHORT_OPTION_HOST},
    {OGBAK_LONG_OPTION_PORT, required_argument, NULL, OGBAK_SHORT_OPTION_PORT},
    {OGBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, OGBAK_SHORT_OPTION_TARGET_DIR},
    {OGBAK_LONG_OPTION_DEFAULTS_FILE, required_argument, NULL, OGBAK_SHORT_OPTION_DEFAULTS_FILE},
    {OGBAK_LONG_OPTION_SOCKET, required_argument, NULL, OGBAK_SHORT_OPTION_SOCKET},
    {OGBAK_LONG_OPTION_DATA_DIR, required_argument, NULL, OGBAK_SHORT_OPTION_DATA_DIR},
    {OGBAK_LONG_OPTION_INCREMENTAL, no_argument, NULL, OGBAK_SHORT_OPTION_INCREMENTAL},
    {OGBAK_LONG_OPTION_INCREMENTAL_CUMULATIVE, no_argument, NULL, OGBAK_SHORT_OPTION_INCREMENTAL_CUMULATIVE},
    {OGBAK_LONG_OPTION_DATABASESEXCLUDE, required_argument, NULL, OGBAK_SHORT_OPTION_DATABASES_EXCLUDE},
    {OGBAK_LONG_OPTION_PARALLEL, required_argument, NULL, OGBAK_SHORT_OPTION_PARALLEL},
    {OGBAK_LONG_OPTION_COMPRESS, required_argument, NULL, OGBAK_SHORT_OPTION_COMPRESS},
    {OGBAK_LONG_OPTION_BUFFER, required_argument, NULL, OGBAK_SHORT_OPTION_BUFFER},
    {OGBAK_LONG_OPTION_SKIP_BADBLOCK, no_argument, NULL, OGBAK_SHORT_OPTION_SKIP_BADBLOCK},
    {0, 0, 0, 0}
};

#define OGSQL_CONNEOG_CLOSED_32 "tcp connection is closed, reason: 32"

status_t convert_database_string_to_ograc(char *database, char *og_database)
{
    char* ptr = NULL;
    char mid_database[MAX_DATABASE_LENGTH] = {0};
    char *split = strtok_s(database, " ", &ptr);
    if (split == NULL) {
        return OG_ERROR;
    }
    while (split) {
        if (strlen(split) >= MAX_DATABASE_LENGTH) {
            return OG_ERROR;
        }
        MEMS_RETURN_IFERR(strcat_s(mid_database, MAX_DATABASE_LENGTH, split));
        MEMS_RETURN_IFERR(strcat_s(mid_database, MAX_DATABASE_LENGTH, OGSQL_EXCLUDE_SUFFIX));
        MEMS_RETURN_IFERR(strcat_s(mid_database, MAX_DATABASE_LENGTH, ","));
        split = strtok_s(NULL, " ", &ptr);
    }
    MEMS_RETURN_IFERR(memcpy_s(og_database, MAX_DATABASE_LENGTH, mid_database, strlen(mid_database) - 1));
    return OG_SUCCESS;
}

status_t generate_ograc_backup_dir(char *target_dir, char *og_backup_dir)
{
    int32 file_fd;
    errno_t ret;
    ret = snprintf_s(og_backup_dir, OGRAC_BACKUP_FILE_LENGTH, OGRAC_BACKUP_FILE_LENGTH - 1,
                     "%s%s", target_dir, OGRAC_BACKUP_DIR);
    PRTS_RETURN_IFERR(ret);
    if (cm_access_file(og_backup_dir, F_OK) != OG_SUCCESS) {
        if (cm_create_dir(og_backup_dir) != OG_SUCCESS) {
            printf("[ogbackup]Failed to create the directory for storing oGRAC bakcup files, ret is :%d\n", errno);
            return OG_ERROR;
        }
    }
    if (cm_open_file(og_backup_dir, O_RDONLY, &file_fd) != OG_SUCCESS) {
        printf("[ogbackup]Failed to open the oGRAC backup files directory. ret is :%d\n", errno);
        return OG_ERROR;
    }
    if (cm_chmod_file(S_IRWXU | S_IRWXG | S_IRWXO, file_fd) != OG_SUCCESS) {
        printf("[ogbackup]Failed to modify the permission on the oGRAC backup files directory. ret is :%d\n", errno);
        cm_close_file(file_fd);
        return OG_ERROR;
    }
    cm_close_file(file_fd);
    return OG_SUCCESS;
}

status_t get_statement_for_ograc(ogbak_param_t* ogbak_param, uint64_t len, char *statement,
    char *databases, char *og_backup_dir)
{
    errno_t ret;
    if (ogbak_param->is_incremental == OG_TRUE) {
        if (ogbak_param->is_incremental_cumulative == OG_TRUE) {
            ret = snprintf_s(statement, len, len - 1, "%s%s%s", OGSQL_INCREMENT_CUMULATIVE_BACKUP_STATEMENT_PREFIX,
                             og_backup_dir, OGSQL_STATEMENT_QUOTE);
        } else {
            ret = snprintf_s(statement, len, len - 1, "%s%s%s", OGSQL_INCREMENT_BACKUP_STATEMENT_PREFIX,
                             og_backup_dir, OGSQL_STATEMENT_QUOTE);
        }
    } else {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", OGSQL_FULL_BACKUP_STATEMENT_PREFIX,
                         og_backup_dir, OGSQL_STATEMENT_QUOTE);
    }
    FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    if (ogbak_param->compress_algo.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s%s", statement, OGSQL_COMPRESS_OPTION_PREFIX,
                         ogbak_param->compress_algo.str, OGSQL_COMPRESS_OPTION_SUFFIX);
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    if (ogbak_param->parallelism.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", statement,
                            OGSQL_PARALLELISM_OPTION, ogbak_param->parallelism.str);
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    if (ogbak_param->databases_exclude.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", statement, OGSQL_EXCLUDE_OPTION, databases);
        if (SECUREC_UNLIKELY(ret == -1)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return OG_ERROR;
        }
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    if (ogbak_param->buffer_size.str != NULL) {
        ret = snprintf_s(statement, len, len - 1, "%s%s%s", statement,
                         OGSQL_BUFFER_OPTION, ogbak_param->buffer_size.str);
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    if (ogbak_param->skip_badblock == OG_TRUE) {
        ret = snprintf_s(statement, len, len - 1, "%s%s", statement, OGSQL_SKIP_BADBLOCK);
        if (SECUREC_UNLIKELY(ret == -1)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return OG_ERROR;
        }
        FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    }
    ret = snprintf_s(statement, len, len - 1, "%s%s", statement, OGSQL_STATEMENT_END_CHARACTER);
    if (SECUREC_UNLIKELY(ret == -1)) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return OG_ERROR;
    }
    FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement);
    return OG_SUCCESS;
}


status_t fill_params_for_ograc_backup(ogbak_param_t* ogbak_param, char *og_params[])
{
    int param_index = 0;
    uint64_t len;
    char databases[MAX_DATABASE_LENGTH] = {0};
    if (fill_params_for_ogsql_login(og_params, &param_index, OGBAK_OGSQL_EXECV_MODE) != OG_SUCCESS) {
        printf("[ogbackup]failed to fill params for ogsql login!\n");
        return OG_ERROR;
    }
    char og_backup_dir[OGRAC_BACKUP_FILE_LENGTH] = {0};
    MEMS_RETURN_IFERR(memset_s(og_backup_dir, OGRAC_BACKUP_FILE_LENGTH, 0, OGRAC_BACKUP_FILE_LENGTH));
    if (generate_ograc_backup_dir(ogbak_param->target_dir.str, (char *)og_backup_dir) != OG_SUCCESS) {
        printf("[ogbackup]generate_ograc_backup_dir failed!\n");
        return OG_ERROR;
    }
    // must use heap space, because the parameter will be passed to the system call method.
    // we fork a child process to execute the system call method, the space on the stack pointed to
    // by the parent process may be released.
    len = strlen(OGSQL_INCREMENT_BACKUP_STATEMENT_PREFIX);
    len = (ogbak_param->is_incremental == OG_TRUE && ogbak_param->is_incremental_cumulative == OG_TRUE) ?
              strlen(OGSQL_INCREMENT_CUMULATIVE_BACKUP_STATEMENT_PREFIX) : len;
    len = len + strlen(og_backup_dir) + strlen(OGSQL_STATEMENT_QUOTE) + strlen(OGSQL_STATEMENT_END_CHARACTER) + 1;
    len += ogbak_param->parallelism.str != NULL ? strlen(OGSQL_PARALLELISM_OPTION) + ogbak_param->parallelism.len : 0;
    len += ogbak_param->compress_algo.str != NULL ? strlen(OGSQL_COMPRESS_OPTION_PREFIX) +
                                        ogbak_param->compress_algo.len + strlen(OGSQL_COMPRESS_OPTION_SUFFIX) : 0;
    len += ogbak_param->buffer_size.str != NULL ? strlen(OGSQL_BUFFER_OPTION) + ogbak_param->buffer_size.len : 0;
    len += ogbak_param->skip_badblock == OG_TRUE ? strlen(OGSQL_SKIP_BADBLOCK) : 0;
    if (ogbak_param->databases_exclude.str != NULL) {
        if (convert_database_string_to_ograc(ogbak_param->databases_exclude.str,
            (char *)databases) != OG_SUCCESS) {
            printf("[ogbackup]database convert to oGRAC failed!\n");
            return OG_ERROR;
        }
        len += strlen(OGSQL_EXCLUDE_OPTION) + strlen(databases);
    }
    char *statement = (char *)malloc(len);
    if (statement == NULL) {
        printf("[ogbackup]failed to apply storage for oGRAC backup!\n");
        OGBAK_RETURN_ERROR_IF_NULL(statement);
    }
    if (get_statement_for_ograc(ogbak_param, len, statement, databases, og_backup_dir) != OG_SUCCESS) {
        printf("[ogbackup]get statement for oGRAC failed!\n");
        return OG_ERROR;
    }
    og_params[param_index++] = statement;
    og_params[param_index++] = NULL;
    return OG_SUCCESS;
}

void ogbak_check_backup_output(char *output, bool32 *need_retry)
{
    if (strstr(output, OGSQL_CONNEOG_CLOSED_32) != NULL) {
        *need_retry = OG_TRUE;
    }
    return;
}
status_t ogbak_do_ogsql_backup(char *path, char *params[], bool32 *retry)
{
    errno_t status = 0;
    int32 pipe_stdout[2] = { 0 };
    if (pipe(pipe_stdout) != EOK) {
        printf("[ogbackup]create stdout pipe failed!\n");
        return OG_ERROR;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipe_stdout[PARENT_ID]);
        dup2(pipe_stdout[CHILD_ID], STD_OUT_ID);
        status = execv(path, params);
        perror("execve");
        if (status != EOK) {
            printf("[ogbackup]failed to execute shell command %d:%s\n", errno, strerror(errno));
            exit(OG_ERROR);
        }
    } else if (child_pid < 0) {
        printf("[ogbackup]failed to fork child process with result %d:%s\n", errno, strerror(errno));
        return OG_ERROR;
    }
    close(pipe_stdout[CHILD_ID]);
    char output[MAX_STATEMENT_LENGTH];
    bool32 need_retry = OG_FALSE;
    FILE *fp = fdopen(pipe_stdout[PARENT_ID], "r");
    while(fgets(output, MAX_STATEMENT_LENGTH, fp) != NULL) {
        // output ogsql backup result and check the error info
        printf("%s", output);
        ogbak_check_backup_output(output, &need_retry);
    }
    (void)fclose(fp);
    close(pipe_stdout[PARENT_ID]);
    int32 wait = waitpid(child_pid, &status, 0);
    if (wait == child_pid && WIFEXITED((unsigned int)status) && WEXITSTATUS((unsigned int)status) != 0) {
        printf("[ogbackup]child process exec backup failed, ret=%d, try to check oGRAC stat.\n", status);
        if (need_retry == OG_TRUE &&
            ogbak_check_ogsql_online(OGBAK_BACKUP_CECHK_ONLINE_TIME) == OG_SUCCESS) {
            *retry = OG_TRUE;
        }
        return OG_ERROR;
    }
    printf("[ogbackup]%s execute success and exit with: %d\n", "oGRAC backup", WEXITSTATUS((unsigned int)status));
    return OG_SUCCESS;
}

status_t ogbak_do_backup_ograc(ogbak_param_t* ogbak_param, bool32 *retry)
{
    char *og_params[OGBACKUP_MAX_PARAMETER_CNT] = {0};
    status_t status = fill_params_for_ograc_backup(ogbak_param, og_params);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]fill_params_for_ograc_backup failed!\n");
        return OG_ERROR;
    }
    char *ogsql_binary_path = NULL;
    if (get_ogsql_binary_path(&ogsql_binary_path) != OG_SUCCESS) {
        CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
        printf("[ogbackup]get_ogsql_binary_path failed!\n");
        return OG_ERROR;
    }
    status = ogbak_do_ogsql_backup(ogsql_binary_path, og_params, retry);
    // free space of heap
    CM_FREE_PTR(og_params[OGSQL_STATEMENT_INDEX]);
    CM_FREE_PTR(ogsql_binary_path);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]oGRAC data files backup failed!\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static inline void ogbak_hide_password(char* password)
{
    while (*password) {
        *password++ = 'x';
    }
}

status_t ogbak_do_backup(ogbak_param_t* ogbak_param)
{
    if (check_common_params(ogbak_param) != OG_SUCCESS) {
        return OG_ERROR;
    }

    uint32 retry_num = 0;
    while (retry_num < OGBAK_BACKUP_RETRY_MAX_NUM) {
        bool32 retry = OG_FALSE;
        if (ogbak_check_data_dir(ogbak_param->target_dir.str) != OG_SUCCESS) {
            printf("[ogbackup]check datadir is empty failed!\n");
            break;
        }

        if (ogbak_do_backup_ograc(ogbak_param, &retry) == OG_SUCCESS) {
            printf("[ogbackup]ograc data files backup success\n");
            free_input_params(ogbak_param);
            return OG_SUCCESS;
        }
        if (retry != OG_TRUE) {
            break;
        }
        printf("[ogbackup]call ogbak_do_backup_ograc failed, clear targer dir and retry again!\n");
        if (ogbak_clear_data_dir(ogbak_param->target_dir.str, ogbak_param->target_dir.str) != OG_SUCCESS) {
            printf("[ogbackup]clear targer dir %s failed for backup retry!\n", ogbak_param->target_dir.str);
            break;
        }
        retry_num++;
    };
    free_input_params(ogbak_param);
    printf("[ogbackup]ograc backup execute failed!\n");
    return OG_ERROR;
}

status_t ogbak_parse_backup_args(int32 argc, char** argv, ogbak_param_t* ogbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        OG_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, OGBAK_SHORT_OPTION_EXP, ogbak_backup_options, &opt_index);
        if (opt_s == OGBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case OGBAK_PARSE_OPTION_COMMON:
                break;
            case OGBAK_SHORT_OPTION_TARGET_DIR:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->target_dir));
                break;
            case OGBAK_SHORT_OPTION_USER:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->user));
                break;
            case OGBAK_SHORT_OPTION_PASSWORD:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->password));
                ogbak_hide_password(optarg);
                break;
            case OGBAK_SHORT_OPTION_HOST:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->host));
                break;
            case OGBAK_SHORT_OPTION_PORT:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->port));
                break;
            case OGBAK_SHORT_OPTION_DEFAULTS_FILE:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->defaults_file));
                break;
            case OGBAK_SHORT_OPTION_SOCKET:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->socket));
                break;
            case OGBAK_SHORT_OPTION_DATA_DIR:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->data_dir));
                break;
            case OGBAK_SHORT_OPTION_INCREMENTAL:
                ogbak_param->is_incremental = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_INCREMENTAL_CUMULATIVE:
                ogbak_param->is_incremental_cumulative = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_DATABASES_EXCLUDE:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->databases_exclude));
                break;
            case OGBAK_SHORT_OPTION_PARALLEL:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->parallelism));
                break;
            case OGBAK_SHORT_OPTION_COMPRESS:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->compress_algo));
                break;
            case OGBAK_SHORT_OPTION_BUFFER:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->buffer_size));
                break;
            case OGBAK_SHORT_OPTION_SKIP_BADBLOCK:
                ogbak_param->skip_badblock = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_UNRECOGNIZED:
            case OGBAK_SHORT_OPTION_NO_ARG:
                printf("[ogbackup]Parse option arguments of backup error!\n");
                return OG_ERROR;
            default:
                break;
        }
    }
    return OG_SUCCESS;
}

ogbak_cmd_t *ogbak_generate_backup_cmd(void)
{
    ogbak_cmd_t* ogbak_cmd = (ogbak_cmd_t*)malloc(sizeof(ogbak_cmd_t));
    if (ogbak_cmd == NULL) {
        printf("[ogbackup]failed to malloc memory for backup ogbak_cmd!\n");
        return (ogbak_cmd_t *)NULL;
    }
    printf("[ogbackup]process ogbak_generate_backup_cmd\n");
    ogbak_cmd->do_exec = ogbak_do_backup;
    ogbak_cmd->parse_args = ogbak_parse_backup_args;
    return ogbak_cmd;
};
