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
 * ogbackup_common.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_common.c
 *
 * -------------------------------------------------------------------------
 */
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include "ogbackup_module.h"
#include "cm_text.h"
#include "cm_date.h"
#include "cm_utils.h"
#include "cm_error.h"
#include "cm_config.h"
#include "ogbackup_common.h"
#include "cm_encrypt.h"

#define CANTAIN_BACKUP_TOOL_NAME "ogsql"
#define OGSQL_LOGIN_USER "SYS"
#define OGSQL_LOGIN_SYSDBA_STRING " / AS SYSDBA"
#define OGSQL_LOGIN_USER_FIRST "/"
#define OGSQL_LOGIN_CONN_FIRST "@"
#define OGSQL_LOGIN_CONN_SECOND ":"
#define OGSQL_SSL_LOGIN_AUTHENTICATION_OPTION "-q"
#define OGSQL_EXECUTE_SQL_STATEMENT_OPTION "-c"
#define OGSQL_CHECK_CONN_SHOW  "SHOW CHARSET"

#define OGSQL_INI_FILE_NAME "ogsql.ini"
#define OGRACD_INI_FILE_MAME "ogracd.ini"
#define OGSQL_INI_SYS_PASSWORD "SYS_PASSWORD"
#define OGSQL_DEC_SYS_PASSWORD "ENABLE_DBSTOR"
#define OGRACD_INI_LSNR_ADDR "LSNR_ADDR"
#define OGRACD_INI_LSNR_PORT "LSNR_PORT"

status_t ogbak_do_shell_background(text_t* command, int* child_pid, int exec_mode)
{
    char path[OG_FILE_NAME_BUFFER_SIZE] = {0};
    if (CM_IS_EMPTY(command)) {
        printf("[ogbackup]shell context is empty\n");
        return OG_ERROR;
    }
    int status;
    int param_index = 0;
    char* args[OG_MAX_CMD_ARGS + 1];
    pid_t child;
    const char* shell_name = getenv("SHELL");
    if (shell_name == NULL) {
        shell_name = DEFAULT_SHELL;
    }

    OG_RETURN_IFERR(realpath_file(shell_name, path, OG_FILE_NAME_BUFFER_SIZE));
    if (!cm_file_exist(path)) {
        printf("[ogbackup]the shell file path %s does not exist\n", path);
        return OG_ERROR;
    }
    args[(param_index)++] = path;
    args[(param_index)++] = "-c";
    args[(param_index)++] = command->str;
    args[(param_index)++] = NULL;

    child = fork();
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        int ret = execve(path, args, environ);
        if (ret == -1) {
            printf("[ogbackup]exec %s failed, reason %d\n", command->str, errno);
            exit(OG_ERROR);
        }
        return OG_SUCCESS;
    } else if (child < 0) {
        printf("[ogbackup]fork child process failed\n");
        return OG_ERROR;
    }

    // wait for process
    sleep(1);
    int wait = waitpid(child, &status, exec_mode);
    if (wait == child && WIFEXITED((unsigned int)status) && WEXITSTATUS((unsigned int)status) != 0) {
        printf("[ogbackup]child process exec failed\n");
        return OG_ERROR;
    }
    *child_pid = child;
    return OG_SUCCESS;
}

status_t ogbak_system_call(char *path, char *params[], char* operation)
{
    int result;
    pid_t pid = fork();
    if (pid < 0) {
        printf("[ogbackup]failed to fork child process with result %d:%s\n", errno, strerror(errno));
        return OG_ERROR;
    } else if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        result = execv(path, params);
        if (result == -1) {
            printf("[ogbackup]system call failed with result %d:%s\n", errno, strerror(errno));
            exit(OG_ERROR);
        }
    }
    
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED((unsigned int)status) && WEXITSTATUS((unsigned int)status) == 0) {
        printf("[ogbackup]%s execute success and exit with: %d\n", operation, WEXITSTATUS((unsigned int)status));
        return OG_SUCCESS;
    }

    printf("[ogbackup]%s execute failed!\n", operation);
    return OG_ERROR;
}

void free_system_call_params(char *params[], int start_index, int end_index)
{
    for (int i = start_index; i <= end_index; i++) {
        CM_FREE_PTR(params[i]);
    }
}

void free_input_params(ogbak_param_t* ogbak_param)
{
    CM_FREE_PTR(ogbak_param->host.str);
    CM_FREE_PTR(ogbak_param->user.str);
    CM_FREE_PTR(ogbak_param->password.str);
    CM_FREE_PTR(ogbak_param->port.str);
    CM_FREE_PTR(ogbak_param->target_dir.str);
    CM_FREE_PTR(ogbak_param->defaults_file.str);
    CM_FREE_PTR(ogbak_param->socket.str);
    CM_FREE_PTR(ogbak_param->execute.str);
    CM_FREE_PTR(ogbak_param->data_dir.str);
    CM_FREE_PTR(ogbak_param->parallelism.str);
    CM_FREE_PTR(ogbak_param->databases_exclude.str);
    CM_FREE_PTR(ogbak_param->pitr_time.str);
    CM_FREE_PTR(ogbak_param->pitr_scn.str);
    CM_FREE_PTR(ogbak_param->compress_algo.str);
    CM_FREE_PTR(ogbak_param->buffer_size.str);
}

status_t ogbak_parse_single_arg(char *optarg_local, text_t *ogbak_param_option)
{
    if (optarg_local == NULL) {
        return OG_ERROR;
    }
    errno_t ret;
    size_t optarg_size = strlen(optarg_local) + 1;
    if (optarg_size == 0) {
        printf("[ogbackup]The requested memory size is 0\n");
        return OG_ERROR;
    }
    // free in free_input_params() method
    char *param = (char*)malloc(optarg_size);
    if (param == NULL) {
        printf("[ogbackup]failed to malloc memory for param\n");
        return OG_ERROR;
    }

    ret = memset_s(param, optarg_size, 0, optarg_size);
    if (ret != EOK) {
        CM_FREE_PTR(param);
        printf("[ogbackup]failed to set memory for param\n");
        return OG_ERROR;
    }
    ret = strcpy_s(param, optarg_size, optarg_local);
    if (ret != EOK) {
        CM_FREE_PTR(param);
        printf("[ogbackup]failed to copy string for param\n");
        return OG_ERROR;
    }
    cm_str2text_safe(param, (uint32)strlen(param), ogbak_param_option);
    return OG_SUCCESS;
}

status_t check_pitr_params(ogbak_param_t* ogbak_param)
{
    uint64 pitr_scn;
    if (ogbak_param->is_pitr_cancel == OG_TRUE) {
        if (ogbak_param->pitr_time.len > 0 || ogbak_param->pitr_scn.len > 0) {
            printf("[ogbackup]PITR-UNTIL-CANCEL and PITR-TIME/PITR-SCN can not be specified at the same time.\n");
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
    }

    if (ogbak_param->pitr_time.str != NULL && ogbak_param->pitr_scn.str != NULL) {
        printf("[ogbackup]PITR-TIME and PITR-SCN can not be specified at the same time.\n");
        free_input_params(ogbak_param);
        return OG_ERROR;
    }

    if (ogbak_param->pitr_time.str != NULL && ogbak_param->pitr_time.len != 0) {
        date_t date;
        text_t date_fmt1 = { "YYYY-MM-DD HH24:MI:SS", 21 };
        if (cm_text2date(&(ogbak_param->pitr_time), &date_fmt1, &date) != OG_SUCCESS) {
            printf("PITR_TIME param value \'%s\' is invalid.\n", (&(ogbak_param->pitr_time))->str);
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
    }
    
    if (ogbak_param->pitr_scn.str != NULL && ogbak_param->pitr_scn.len != 0) {
        char c = ogbak_param->pitr_scn.str[0];
        if (c == '-') {
            printf("[ogbackup]pitr_scn should be a positive number!\n");
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
        if (cm_str2uint64(ogbak_param->pitr_scn.str, &pitr_scn) != OG_SUCCESS) {
            printf("[ogbackup]convert pitr_scn to uint64 failed!\n");
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t check_common_params(ogbak_param_t* ogbak_param)
{
    int32 parallelism_count;
    if (ogbak_param->target_dir.str == NULL || ogbak_param->target_dir.len == 0) {
        printf("[ogbackup]The --target-dir parameter cannot be NULL!\n");
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_param->target_dir.len > MAX_TARGET_DIR_LENGTH) {
        printf("[ogbackup]The --target-dir parameter length is too long!\n");
        free_input_params(ogbak_param);
        return OG_ERROR;
    }

    if (ogbak_param->parallelism.str != NULL && ogbak_param->parallelism.len != 0) {
        if (cm_str2int(ogbak_param->parallelism.str, &parallelism_count) != OG_SUCCESS) {
            printf("[ogbackup]convert parallelism to int32 failed!\n");
            free_input_params(ogbak_param);
            return OG_ERROR;
        }

        if (parallelism_count > MAX_PARALLELISM_COUNT || parallelism_count <= 0) {
            printf("[ogbackup]The --parallel parameter value should be in [1, 16].\n");
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
    }
    OG_RETURN_IFERR(check_pitr_params(ogbak_param));
    if (ogbak_param->repair_type.str != NULL && ogbak_param->repair_type.len != 0) {
        if (!cm_str_equal(ogbak_param->repair_type.str, "return_error") &&
            !cm_str_equal(ogbak_param->repair_type.str, "replace_checksum") &&
            !cm_str_equal(ogbak_param->repair_type.str, "discard_badblock")) {
            printf("[ogbackup]The --repair-type value is illegal.\n");
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t get_ogsql_config(const char *file_name, const char *conf_name, char *conf_value)
{
    char file_buf[OG_MAX_CONFIG_FILE_SIZE] = {0};
    uint32 text_size = sizeof(file_buf);
    if (cm_read_config_file(file_name, file_buf, &text_size, OG_FALSE, OG_FALSE) != OG_SUCCESS) {
        printf("[ogbackup]read config file failed!, the file_name is %s.\n", file_name);
        return OG_ERROR;
    }
    text_t text;
    text_t line;
    text_t name;
    text_t value;
    text.len = text_size;
    text.str = file_buf;
    int line_no = 0;
    
    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        if (line.len == 0) {
            printf("[ogbackup]please confirm ogsql.ini is vaild!\n");
            return OG_ERROR;
        }
        line_no++;
        cm_trim_text(&line);
        if (line.len >= OG_MAX_CONFIG_LINE_SIZE) {
            printf("[ogbackup]the line size is too long!\n");
            return OG_ERROR;
        }
        if (line.len == 0 || *line.str == '#') { /* commentted line */
            continue;
        }

        cm_split_text(&line, '=', '\0', &name, &value);
        cm_trim_text(&value);
        cm_text_upper(&name);  // Case insensitive
        cm_trim_text(&name);
        if (cm_text_str_equal_ins(&name, conf_name)) {
            errno_t ret = strncpy_s(conf_value, OG_PARAM_BUFFER_SIZE, value.str, value.len);
            return ret;
        }
    }
    return OG_ERROR;
}

status_t ogback_read_output_from_pipe_cmd(ogbak_child_info_t child_info, char *cmd_out)
{
    errno_t ret;
    close(child_info.to_child);
    uint32 read_count = 0;
    uint32 read_once = OGSQL_CMD_OUT_BUFFER_SIZE;
    char *cmd_buf = cmd_out;
    while (read_count < OGSQL_CMD_OUT_BUFFER_SIZE) {
        int32 read_size = read(child_info.from_child, cmd_buf, read_once);
        if (read_size == -1) {
            printf("[ogbackup]read ogsql output failed\n");
            close(child_info.from_child);
            return OG_ERROR;
        }

        if (read_size == 0) {
            break;
        }

        read_count = read_count + read_size;
        cmd_buf = cmd_buf + read_size;
        read_once = read_once - read_size;
    }
    close(child_info.from_child);
    int32 wait = waitpid(child_info.child_pid, &ret, 0);
    if (wait == child_info.child_pid && WIFEXITED((unsigned int)ret) && WEXITSTATUS((unsigned int)ret) != 0) {
        printf("[ogbackup]child process exec failed, ret=%d\n", ret);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t ogbak_decrypt_password_custom(SENSI_INFO char *cipherText, SENSI_INFO char *cmd_out_passwd)
{
    error_t ret = 0;
    char cmd_str[MAX_SHELL_CMD_LENGTH] = {0};
    text_t decrypt_cmd;
    ret = snprintf_s(cmd_str, MAX_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH - 1, "%s%s%s",
                     DECRYPT_CMD_ECHO, cipherText, DECRYPT_CMD_BASE64);
    if (ret == -1) {
        printf("[ogbackup]failed to snprintf for decrypt cmd\n");
        return OG_ERROR;
    }

    cm_str2text(cmd_str, &decrypt_cmd);
    if (ogbak_do_shell_get_output(&decrypt_cmd, cmd_out_passwd, ogback_read_output_from_pipe_cmd) != OG_SUCCESS) {
        printf("ogbackup]failed to decrypt password.\n");
        return OG_ERROR;
    }
    // remove '\n' from read pipe
    if (cmd_out_passwd[strlen(cmd_out_passwd) - 1] == '\n') {
        cmd_out_passwd[strlen(cmd_out_passwd) - 1] = '\0';
    }
    return OG_SUCCESS;
}

status_t get_ogsql_passwd(char *ogsql_ini_file_name, char *ogracd_ini_file_name, SENSI_INFO char *plainText,
                          uint32 plain_len)
{
    char cipherText[MAX_PASSWORD_LENGTH] = {0};
    char enable_dbstor[MAX_BOOL_STR_LENGTH] = {0};
    status_t status;
    status = get_ogsql_config(ogsql_ini_file_name, OGSQL_INI_SYS_PASSWORD, cipherText);
    if (status != OG_SUCCESS) {
        printf("[ctbackup]get ogsql config failed!\n");
        return status;
    }
    status = get_ogsql_config(ogracd_ini_file_name, OGSQL_DEC_SYS_PASSWORD, enable_dbstor);
    if (status != OG_SUCCESS) {
        printf("[ctbackup]get ogracd config failed!\n");
        return status;
    }
    bool32 is_dbstor = (strcmp(enable_dbstor, "TRUE") == 0) ? OG_TRUE : OG_FALSE;
    
    if (is_dbstor) {
        if (cm_base64_decode(cipherText, (uint32)strlen(cipherText), (uchar *)plainText, plain_len) == 0) {
            printf("[ctbackup]decrypt password failed in dbstor!\n");
            return OG_ERROR;
        }
    } else {
        status = ogbak_decrypt_password_custom(cipherText, plainText);
    }
    if (status != OG_SUCCESS) {
        printf("[ctbackup]decrypt password failed!\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t get_ogracd_ini_file_name(char *oGRACd_ini_file_path)
{
    const char *data_path = getenv("OGDB_DATA");
    if (data_path == NULL) {
        printf("[ogbackup]get data dir error!\n");
        return OG_ERROR;
    }
    int32 iret_snprintf;
    iret_snprintf = snprintf_s(oGRACd_ini_file_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/cfg/%s",
                               data_path, OGRACD_INI_FILE_MAME);
    PRTS_RETURN_IFERR(iret_snprintf);
    return OG_SUCCESS;
}

status_t get_ogsql_ini_file_name(char *ogsql_ini_file_name)
{
    const char *data_path = getenv("OGDB_DATA");
    if (data_path == NULL) {
        printf("[ogbackup]get data dir error!\n");
        return OG_ERROR;
    }
    int32 iret_snprintf;
    iret_snprintf = snprintf_s(ogsql_ini_file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/cfg/%s",
                               data_path, OGSQL_INI_FILE_NAME);
    PRTS_RETURN_IFERR(iret_snprintf);
    return OG_SUCCESS;
}

status_t get_real_addr(char *addr)
{
    char addr_tmp[OG_PARAM_BUFFER_SIZE] = {0};
    error_t ret;
    ret = strcpy_sp(addr_tmp, OG_PARAM_BUFFER_SIZE, addr);
    if (ret != EOK) {
        printf("[ogbackup]strcpy_sp for addr tmp failed!\n");
        return OG_ERROR;
    }
    uint32_t total_len = strlen(addr);
    uint32_t split_index = 0;
    for (uint32_t i = 0; i < total_len; i++) {
        if (addr_tmp[i] == ',') {
            split_index = i;
            break;
        }
    }
    // 只有一个ip
    if (split_index == 0) {
        return OG_SUCCESS;
    }
    // lsrn addr format: 127.0.0.1,x.x.x.x,y.y.y.y
    for (uint32_t i = split_index + 1; i < total_len; i++) {
        if (addr_tmp[i] == ',') {
            addr_tmp[i] = '\0';
            break;
        }
    }
    ret = strcpy_sp(addr, OG_PARAM_BUFFER_SIZE, addr_tmp + split_index + 1);
    if (ret != EOK) {
        printf("[ogbackup]strcpy_sp for addr failed!\n");
        return OG_ERROR;
    }
    addr[total_len - split_index] = '\0';
    return OG_SUCCESS;
}

status_t get_ogsql_lsrn_addr_and_port(const char *oGRACd_ini_file_name, char *addr, char *port)
{
    if (get_ogsql_config(oGRACd_ini_file_name, OGRACD_INI_LSNR_ADDR, addr) != OG_SUCCESS) {
        printf("[ogbackup]get ogsql lsrn addr failed!\n");
        return OG_ERROR;
    }
    // lsrn addr format: 127.0.0.1,x.x.x.x
    if (get_real_addr(addr) != OG_SUCCESS) {
        printf("[ogbackup]get ogsql lsrn real addr failed!\n");
        return OG_ERROR;
    }
    if (get_ogsql_config(oGRACd_ini_file_name, OGRACD_INI_LSNR_PORT, port) != OG_SUCCESS) {
        printf("[ogbackup]get ogsql lsrn port failed!\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t get_ogsql_login_for_passwd_addr_port(char **ogsql_login_info, ogbak_ogsql_exec_mode_t ogsql_exec_mode)
{
    char ogsql_ini_file_name[OG_MAX_FILE_PATH_LENGH] = {0};
    char ogracd_ini_file_name[OG_MAX_FILE_PATH_LENGH] = {0};
    if (get_ogsql_ini_file_name(ogsql_ini_file_name) != OG_SUCCESS ||
        get_ogracd_ini_file_name(ogracd_ini_file_name) != OG_SUCCESS) {
        return OG_ERROR;
    }
    char passwd[MAX_PASSWORD_LENGTH] = {0};
    char addr[OG_PARAM_BUFFER_SIZE] = {0};
    char port[OG_PARAM_BUFFER_SIZE] = {0};
    if (ogsql_exec_mode == OGBAK_OGSQL_EXECV_MODE &&
        get_ogsql_passwd(ogsql_ini_file_name, ogracd_ini_file_name, passwd, MAX_PASSWORD_LENGTH) != OG_SUCCESS) {
        printf("[ctbackup]get ogsql password failed!\n");
        return OG_ERROR;
    }
    if (get_ogsql_lsrn_addr_and_port(ogracd_ini_file_name, addr, port) != OG_SUCCESS) {
        return OG_ERROR;
    }
    uint64_t len = 0;
    if (ogsql_exec_mode == OGBAK_OGSQL_EXECV_MODE) {
        len = strlen(OGSQL_LOGIN_USER) + strlen(OGSQL_LOGIN_USER_FIRST) + strlen(passwd) +
              strlen(OGSQL_LOGIN_CONN_FIRST) +
              strlen(addr) + strlen(OGSQL_LOGIN_CONN_SECOND) + strlen(port) + 1;
    } else {
        len = strlen(OGSQL_LOGIN_USER) + strlen(OGSQL_LOGIN_CONN_FIRST) + strlen(addr) +
              strlen(OGSQL_LOGIN_CONN_SECOND) +
              strlen(port) + 1;
    }
    *ogsql_login_info = (char *)malloc(len);
    if (*ogsql_login_info == NULL) {
        printf("[ctbackup]failed to malloc for ogsql_login_info!\n");
        MEMS_RETURN_IFERR(memset_s(passwd, MAX_PASSWORD_LENGTH, 0, MAX_PASSWORD_LENGTH));
        return OG_ERROR;
    }
    errno_t ret;
    if (ogsql_exec_mode == OGBAK_OGSQL_EXECV_MODE) {
        ret = snprintf_s(*ogsql_login_info, len, len - 1, "%s%s%s%s%s%s%s", OGSQL_LOGIN_USER, OGSQL_LOGIN_USER_FIRST,
                         passwd, OGSQL_LOGIN_CONN_FIRST, addr, OGSQL_LOGIN_CONN_SECOND, port);
    } else {
        ret = snprintf_s(*ogsql_login_info, len, len - 1, "%s%s%s%s%s", OGSQL_LOGIN_USER, OGSQL_LOGIN_CONN_FIRST, addr,
                         OGSQL_LOGIN_CONN_SECOND, port);
    }

    if (ret == -1) {
        printf("[ctbackup]snprintf_s for ogsql_login_info failed!\n");
        CM_FREE_PTR(*ogsql_login_info);
        MEMS_RETURN_IFERR(memset_s(passwd, MAX_PASSWORD_LENGTH, 0, MAX_PASSWORD_LENGTH));
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(passwd, MAX_PASSWORD_LENGTH, 0, MAX_PASSWORD_LENGTH));
    return OG_SUCCESS;
}

status_t fill_params_for_ogsql_login(char *og_params[], int* param_index, ogbak_ogsql_exec_mode_t ogsql_exec_mode)
{
    char *ogsql_binary_path = NULL;
    // The first parameter should be the application name itself
    if (ogsql_exec_mode == OGBAK_OGSQL_EXECV_MODE) {
        og_params[(*param_index)++] = CANTAIN_BACKUP_TOOL_NAME;
    } else if (get_ogsql_binary_path(&ogsql_binary_path) != OG_SUCCESS) {
        printf("[ogbackup]get ogsql bin path failed!\n");
        return OG_ERROR;
    } else {
        og_params[(*param_index)++] = ogsql_binary_path;
    }
    og_params[(*param_index)++] = OGSQL_LOGIN_SYSDBA_STRING;
    og_params[(*param_index)++] = OGSQL_SSL_LOGIN_AUTHENTICATION_OPTION;
    og_params[(*param_index)++] = OGSQL_EXECUTE_SQL_STATEMENT_OPTION;
    return OG_SUCCESS;
}

status_t start_ogracd_server(void)
{
    int child_pid;
    text_t start_server_cmd;
    cm_str2text(START_OGRACD_SERVER_CMD, &start_server_cmd);
    status_t result = ogbak_do_shell_background(&start_server_cmd, &child_pid, 0);
    if (result != OG_SUCCESS) {
        printf("[ogbackup]start oGRACd server failed!\n");
        return OG_ERROR;
    }
    printf("[ogbackup]start oGRACd server success!\n");
    return OG_SUCCESS;
}

status_t check_ogracd_status(void)
{
    int child_pid;
    text_t check_ogracd_status_cmd;
    cm_str2text(CHECK_CANTAIND_STATUS_CMD, &check_ogracd_status_cmd);
    status_t result = ogbak_do_shell_background(&check_ogracd_status_cmd, &child_pid, 0);
    if (result != OG_SUCCESS) {
        printf("[ogbackup]oGRACd is running, cannot execute restore/recovery/force_archive!\n");
        return OG_ERROR;
    }
    printf("[ogbackup]check oGRACd status finished!\n");
    return OG_SUCCESS;
}

status_t stop_ogracd_server(void)
{
    int child_pid;
    text_t stop_ogracd_cmd;
    cm_str2text(STOP_OGRACD_SERVER_CMD, &stop_ogracd_cmd);
    status_t result = ogbak_do_shell_background(&stop_ogracd_cmd, &child_pid, 0);
    if (result != OG_SUCCESS) {
        printf("[ogbackup]stop oGRACd server failed!\n");
        return OG_ERROR;
    }
    printf("[ogbackup]stop oGRACd server finished!\n");
    return OG_SUCCESS;
}

status_t get_ogsql_binary_path(char** ogsql_binary_path)
{
    errno_t ret;
    uint64_t len;
    char* og_install_path = getenv("OGDB_HOME");
    if (og_install_path == NULL) {
        len = strlen(DEFAULT_OGSQL_PATH) + 1;
    } else {
        if (strlen(og_install_path) > OG_MAX_PATH_BUFFER_SIZE) {
            printf("[ogbackup]the og_install_path is too long!\n");
            return OG_ERROR;
        }
        len = strlen(og_install_path) + strlen(DEFAULT_OGSQL_PATH) + 1;
    }
    *ogsql_binary_path = (char *)malloc(len);
    if (*ogsql_binary_path == NULL) {
        printf("[ogbackup]failed to malloc for ogsql_binary_path!\n");
        return OG_ERROR;
    }
    ret = snprintf_s(*ogsql_binary_path, len, len - 1, "%s%s",
                     og_install_path == NULL ? "" : og_install_path, DEFAULT_OGSQL_PATH);
    if (ret == -1) {
        CM_FREE_PTR(*ogsql_binary_path);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t check_input_params(char* params)
{
    if (params[0] == '-' && params[1] == '-') {
        return OG_SUCCESS;
    }
    if (params[0] == '-' && (params[2] == '=' || strlen(params) == 2)) {
        return OG_SUCCESS;
    }
    printf("[ogbackup]param %s is illegal,please confirm!\n", params);
    return OG_ERROR;
}

status_t ogbak_check_data_dir(const char *path)
{
    struct dirent *dirp = NULL;
    DIR *dir = opendir(path);
    if (dir == NULL) {
        printf("[ogbackup]param datadir %s open failed, error code %d\n", path, errno);
        return OG_ERROR;
    }
    while ((dirp = readdir(dir)) != NULL) {
        if (strcmp(dirp->d_name, ".") && strcmp(dirp->d_name, "..")) {
            printf("[ogbackup]param datadir %s is not empty\n", path);
            (void)closedir(dir);
            return OG_ERROR;
        }
    }
    (void)closedir(dir);
    return OG_SUCCESS;
}

status_t ogbak_change_work_dir(const char *path)
{
    if (chdir(path) == -1) {
        printf("[ogbackup]change current work directory to %s failed, error code %d.\n", path, errno);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t ogbak_clear_data_dir(const char *sub_path, const char *src_path)
{
    if (sub_path == NULL || src_path == NULL) {
        return OG_ERROR;
    }
    struct dirent *dirp = NULL;
    char *cwdir = getcwd(NULL, 0);
    if (cwdir == NULL) {
        printf("[ogbackup]get current work directory failed, error code %d.\n", errno);
        return OG_ERROR;
    }
    DIR *dir = opendir(sub_path);
    if (dir == NULL) {
        printf("[ogbackup]param datadir %s open failed, error code %d\n", sub_path, errno);
        free(cwdir);
        return OG_ERROR;
    }
    if (ogbak_change_work_dir(sub_path) == -1) {
        free(cwdir);
        (void)closedir(dir);
        return OG_ERROR;
    }
    while ((dirp = readdir(dir)) != NULL) {
        if ((strcmp(dirp->d_name, ".") == 0) || (strcmp(dirp->d_name, "..") == 0)) {
            continue;
        }
        if (cm_dir_exist(dirp->d_name)) {
            if (ogbak_clear_data_dir(dirp->d_name, src_path) == OG_SUCCESS) {
                continue;
            }
            (void)closedir(dir);
            free(cwdir);
            return OG_ERROR;
        }
        if (remove(dirp->d_name) != 0) {
            printf("[ogbackup]remove file %s failed, error code %d.\n", dirp->d_name, errno);
            (void)closedir(dir);
            free(cwdir);
            return OG_ERROR;
        }
    }
    (void)closedir(dir);
    if (ogbak_change_work_dir(cwdir) == -1) {
        free(cwdir);
        return OG_ERROR;
    }
    free(cwdir);
    if (strcmp(sub_path, src_path) != 0 && remove(sub_path) != 0) {
        printf("[ogbackup]remove dir %s failed, error code %d.\n", sub_path, errno);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t ogbak_get_execve_args(text_t *command, char **args, char *path)
{
    uint32 param_index = 0;
    const char *shell_name = getenv("SHELL");
    if (shell_name == NULL) {
        shell_name = DEFAULT_SHELL;
    }
    OG_RETURN_IFERR(realpath_file(shell_name, path, OG_FILE_NAME_BUFFER_SIZE));
    if (!cm_file_exist(path)) {
        printf("[ogbackup]the shell file path %s does not exist\n", path);
        return OG_ERROR;
    }
    args[(param_index)++] = path;
    args[(param_index)++] = "-c";
    args[(param_index)++] = command->str;
    args[(param_index)++] = NULL;
    return OG_SUCCESS;
}

status_t ogbak_do_shell_get_output(text_t *command, char *cmd_out,
    status_t (*ogback_read_output_from_pipe_fun)(ogbak_child_info_t, char*))
{
    if (CM_IS_EMPTY(command)) {
        printf("[ogbackup]shell context is empty\n");
        return OG_ERROR;
    }
    errno_t status;
    ogbak_child_info_t child_info;
    char *args[OG_MAX_CMD_ARGS + 1];
    char path[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 pipe_stdin[2];
    int32 pipe_stdout[2];
    if (ogbak_get_execve_args(command, args, path) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (pipe(pipe_stdin) != EOK) {
        printf("[ogbackup]create stdin pipe failed!\n");
        return OG_ERROR;
    }
    if (pipe(pipe_stdout) != EOK) {
        printf("[ogbackup]create stdout pipe failed!\n");
        return OG_ERROR;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipe_stdin[CHILD_ID]);
        dup2(pipe_stdin[PARENT_ID], STD_IN_ID);
        close(pipe_stdout[PARENT_ID]);
        dup2(pipe_stdout[CHILD_ID], STD_OUT_ID);
        status = execve(path, args, environ);
        perror("execve");
        if (status != EOK) {
            printf("[ogbackup]failed to execute shell command %d:%s\n", errno, strerror(errno));
            exit(OG_ERROR);
        }
        return OG_SUCCESS;
    } else if (child_pid < 0) {
        printf("[ogbackup]failed to fork child process with result %d:%s\n", errno, strerror(errno));
        return OG_ERROR;
    }
    sleep(1);
    child_info.child_pid = child_pid;
    child_info.to_child = pipe_stdin[CHILD_ID];
    child_info.from_child = pipe_stdout[PARENT_ID];
    close(pipe_stdin[PARENT_ID]);
    close(pipe_stdout[CHILD_ID]);
    if (ogback_read_output_from_pipe_fun(child_info, cmd_out) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t fill_params_for_ogsql_cmd(char *og_params[], char *ogsql_cmd[])
{
    int param_index = 0;
    if (fill_params_for_ogsql_login(og_params, &param_index, OGBAK_OGSQL_SHELL_MODE) != OG_SUCCESS) {
        printf("[ogbackup]failed to fill params for ogsql login!\n");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < OG_MAX_CMD_ARGS && ogsql_cmd[i] != NULL; i++) {
        og_params[param_index++] = ogsql_cmd[i];
    }
    og_params[param_index++] = NULL;
    return OG_SUCCESS;
}

status_t ogbak_check_dir_access(const char *path)
{
    if (cm_access_file(path, F_OK) != OG_SUCCESS) {
        printf("[ogbackup] the directory %s can not access!\n", path);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t ogbak_check_ogsql_online(uint32 retry_time)
{
    status_t status;
    char *og_params[OGBACKUP_MAX_PARAMETER_CNT] = { 0 };
    int32_t param_index = 0;
    status = fill_params_for_ogsql_login(og_params, &param_index, OGBAK_OGSQL_EXECV_MODE);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]check_ogsql_online failed!\n");
        return OG_ERROR;
    }
    og_params[param_index++] = OGSQL_CHECK_CONN_SHOW;
    // The last parameter must be NULL
    og_params[param_index++] = NULL;
    char *ogsql_binary_path = NULL;
    if (get_ogsql_binary_path(&ogsql_binary_path) != OG_SUCCESS) {
        printf("[ogbackup]check_ogsql_online failed!\n");
        return OG_ERROR;
    }
    struct timeval start_work_time;
    gettimeofday(&start_work_time, NULL);
    struct timeval current_time;
    uint32_t interval_time = 0;
    status = OG_ERROR;
    while (interval_time <= retry_time) {
        if (ogbak_system_call(ogsql_binary_path, og_params, "check_ogsql_online") == OG_SUCCESS) {
            status = OG_SUCCESS;
            break;
        }
        cm_sleep(OGSQL_CHECK_CONN_SLEEP_TIME_MS);
        gettimeofday(&current_time, NULL);
        interval_time = current_time.tv_sec - start_work_time.tv_sec;
    }
    // free space of heap
    CM_FREE_PTR(ogsql_binary_path);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]check_ogsql_online failed! try to connect ogsql for %u secs.\n", interval_time);
        return OG_ERROR;
    }
    printf("[ogbackup]check_ogsql_online success\n");
    return OG_SUCCESS;
}

status_t check_ogsql_online(void)
{
    int child_pid;
    text_t try_conn_ogsql_cmd;
    cm_str2text(TRY_CONN_OGSQL_CMD, &try_conn_ogsql_cmd);
    status_t result = ogbak_do_shell_background(&try_conn_ogsql_cmd, &child_pid, 0);
    if (result != OG_SUCCESS) {
        printf("[ogbackup]try conn ogsql failed!\n");
        return OG_ERROR;
    }
    printf("[ogbackup]ogsql now is ready to be connected!\n");
    return OG_SUCCESS;
}
