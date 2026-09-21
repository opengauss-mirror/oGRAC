/*
 * This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * init_exec.c
 *
 *
 * IDENTIFICATION
 * src/driver/ogodbc/init_exec.c
 */
#include "init_exec.h"
#include "cm_charset.h"
#include "cm_date.h"
#include "cm_file.h"
#include "cm_spinlock.h"
#include "cm_timer.h"
#include "cm_utils.h"

roundrobin_counter_map counter_map[MAX_HOST_SIZE];
int host_counter = 0;
int max_connect_num = 1 << 30;
connection_list_map connection_list[MAX_HOST_SIZE];
uint32 connection_counter = 0;
static spinlock_t g_load_balance_lock = 0;
static uint32 g_lb_env_refcount = 0;
static uint32 g_lb_inflight = 0;
static bool32 g_lb_pending_free = OG_FALSE;
static void *dl_open;
static SQLGetPrivateProfileStringFunc sqlGetPrivateProfileString;

void load_odbc_config()
{
    void *dl_inst = NULL;
    const char *func = "SQLGetPrivateProfileString";
    const char *odbcinst = "libodbcinst.so";
    void **profile = (void **)(&sqlGetPrivateProfileString);

    if (dl_open != NULL) {
        return;
    }
    dl_inst = dlopen(odbcinst, RTLD_LAZY);
    if (dl_inst == NULL) {
        return;
    }
    *profile = dlsym(dl_inst, func);
    dl_open = dl_inst;
}

static void write_odbc_log(connection_class *conn, const char *log_buf)
{
    char log_path[OG_MAX_FILE_PATH_LENGH];
    FILE *fp = NULL;
    int ret;

    if (conn == NULL || log_buf == NULL || conn->connInfo.logdir[0] == '\0') {
        return;
    }

    if (!cm_dir_exist(conn->connInfo.logdir)) {
        if (cm_create_dir_ex(conn->connInfo.logdir) != OG_SUCCESS) {
            return;
        }
    }

    ret = snprintf_s(log_path, sizeof(log_path), sizeof(log_path) - 1, "%s/%s",
                     conn->connInfo.logdir, ODBC_LOG_FILE);
    if (ret == -1) {
        return;
    }

    fp = fopen(log_path, "a+");
    if (fp == NULL) {
        return;
    }

    (void)fwrite(log_buf, 1, strlen(log_buf), fp);
    (void)fflush(fp);
    (void)fclose(fp);
}

void write_odbc_error_log(connection_class *conn)
{
    char time_str[OG_MAX_TIME_STRLEN];
    char log_buf[OG_MESSAGE_BUFFER_SIZE];
    int ret;

    if (conn == NULL || conn->error_msg == NULL) {
        return;
    }

    if (cm_timestamp2str(cm_now(), "YYYY-MM-DD HH24:MI:SS.FF3", time_str, sizeof(time_str)) != OG_SUCCESS) {
        time_str[0] = '\0';
    }

    ret = snprintf_s(log_buf, sizeof(log_buf), sizeof(log_buf) - 1,
                     "[%s] [ERROR] %s\n", time_str, conn->error_msg);
    if (ret == -1) {
        return;
    }

    write_odbc_log(conn, log_buf);
}

void write_odbc_info_log(connection_class *conn, const char *msg)
{
    char time_str[OG_MAX_TIME_STRLEN];
    char log_buf[OG_MESSAGE_BUFFER_SIZE];
    int ret;

    if (conn == NULL || msg == NULL) {
        return;
    }

    if (cm_timestamp2str(cm_now(), "YYYY-MM-DD HH24:MI:SS.FF3", time_str, sizeof(time_str)) != OG_SUCCESS) {
        time_str[0] = '\0';
    }

    ret = snprintf_s(log_buf, sizeof(log_buf), sizeof(log_buf) - 1,
                     "[%s] [INFO] %s\n", time_str, msg);
    if (ret == -1) {
        return;
    }

    write_odbc_log(conn, log_buf);
}

void set_conn_error(connection_class *conn, char *msg)
{
    if (conn == NULL) {
        return;
    }
    conn->err_sign = 1;
    conn->error_msg = msg;
    write_odbc_error_log(conn);
}

/* Format ogconn_connect failure with host and log via set_conn_error.
 * buf must remain valid while conn->error_msg still points to it. */
static void set_ogconn_connect_error(connection_class *conn, char *buf, size_t buf_len, const char *host)
{
    int error_code = 0;
    const char *error_msg = NULL;
    int ret;

    if (conn == NULL || buf == NULL || buf_len == 0 || host == NULL || host[0] == '\0') {
        return;
    }

    ogconn_get_error(conn->ogconn, &error_code, &error_msg);
    if (error_msg == NULL || error_msg[0] == '\0') {
        error_msg = "unknown error";
    }

    ret = snprintf_s(buf, buf_len, buf_len - 1,
                     "Failed to connect to %s, msg: %s.", host, error_msg);
    if (ret == -1) {
        set_conn_error(conn, "Failed to connect.");
        return;
    }
    set_conn_error(conn, buf);
}

static SQLRETURN verify_conn_info(connection_class *conn, ConnInfo *ci)
{
    if (ci->username[0] == '\0' || ci->password[0] == '\0') {
        set_conn_error(conn, "Username or Password is invalid.");
        return SQL_ERROR;
    }
    if (ci->server[0] == '\0') {
        set_conn_error(conn, "Servername is invalid.");
        return SQL_ERROR;
    }
    if (ci->port[0] == '\0') {
        set_conn_error(conn, "Port is invalid.");
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

static status_t set_ssl_param(connection_class *conn, ConnInfo *info)
{
    status_t status;

    status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_SSL_CA, info->ssl_ca, (uint32)strlen(info->ssl_ca));
    if (status != OGCONN_SUCCESS) {
        get_err(conn);
        return OG_ERROR;
    }

    status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_SSL_KEY, info->ssl_key, (uint32)strlen(info->ssl_key));
    if (status != OGCONN_SUCCESS) {
        get_err(conn);
        return OG_ERROR;
    }

    status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_SSL_MODE, &info->ssl_mode, sizeof(ogconn_ssl_mode_t));
    if (status != OGCONN_SUCCESS) {
        get_err(conn);
        return OG_ERROR;
    }

    status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_SSL_CERT, info->ssl_cert, (uint32)strlen(info->ssl_cert));
    if (status != OGCONN_SUCCESS) {
        get_err(conn);
        return OG_ERROR;
    }

    status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_SSL_CRL, info->ssl_crl, (uint32)strlen(info->ssl_crl));
    if (status != OGCONN_SUCCESS) {
        get_err(conn);
        return OG_ERROR;
    }

    status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_SSL_CIPHER,
                                  info->ssl_encryption, (uint32)strlen(info->ssl_encryption));
    if (status != OGCONN_SUCCESS) {
        get_err(conn);
        return OG_ERROR;
    }

    status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_UDS_SERVER_PATH,
                                  info->uds_path, (uint32)strlen(info->uds_path));
    if (status != OGCONN_SUCCESS) {
        get_err(conn);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/* clt_disconnect frees server_path; restore it before the next failover attempt. */
static status_t restore_uds_path(connection_class *conn, ConnInfo *info)
{
    status_t status;

    if (info->uds_path[0] == '\0') {
        return OG_SUCCESS;
    }

    status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_UDS_SERVER_PATH,
                                  info->uds_path, (uint32)strlen(info->uds_path));
    if (status != OGCONN_SUCCESS) {
        get_err(conn);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t init_ssl_info(connection_class *conn, ConnInfo *info)
{
    status_t status;
    char ssl_encryption[SSL_ENCRYPTION_KEY_LEN];
    char str_buf[KEYPWD_BUF_LEN];
    int32 file = 0;
    int32 read_size = 0;
    uint32 ssl_encryption_len = sizeof(ssl_encryption);
    uint32 str_buf_len = sizeof(str_buf);
    uchar read_buf[AES_READ_LEN];

    status = set_ssl_param(conn, info);
    if (status != OG_SUCCESS) {
        return status;
    }
    
    if (info->sslpassword != NULL && info->sslpassword[0] != 0 && info->ssl_key != NULL && info->ssl_key[0] != 0) {
        bool32 is_file_exist = cm_file_exist(info->ssl_factory);
        status = cm_open_file_ex(info->ssl_factory, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &file);
        if (status != OG_SUCCESS || !is_file_exist) {
            if (conn->error_msg == NULL) {
                set_conn_error(conn, "failed to open ssl file");
            } else {
                write_odbc_error_log(conn);
            }
            return OG_ERROR;
        }

        if (cm_read_file(file, read_buf, AES_READ_LEN, &read_size) != OG_SUCCESS) {
            if (conn->error_msg == NULL) {
                set_conn_error(conn, "failed to read ssl file");
            } else {
                write_odbc_error_log(conn);
            }
            cm_close_file(file);
            return OG_ERROR;
        }
        cm_close_file(file);

        status = cm_base64_encode((unsigned char *)read_buf, AES_READ_LEN, ssl_encryption, &ssl_encryption_len);
        if (status != OG_SUCCESS) {
            if (conn->error_msg == NULL) {
                set_conn_error(conn, "failed to encode ssl encryption key");
            } else {
                write_odbc_error_log(conn);
            }
            return OG_ERROR;
        }

        status = cm_decrypt_passwd(OG_TRUE, info->sslpassword, (unsigned int)strlen(info->sslpassword),
                                   str_buf, &str_buf_len, info->ssl_key_native, ssl_encryption);
        if (status != OG_SUCCESS) {
            if (conn->error_msg == NULL) {
                set_conn_error(conn, "failed to decrypt ssl password");
            } else {
                write_odbc_error_log(conn);
            }
            return OG_ERROR;
        }

        status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_SSL_KEYPWD, str_buf, str_buf_len);
        if (status != OGCONN_SUCCESS) {
            get_err(conn);
            return OG_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(str_buf, KEYPWD_BUF_LEN, 0, KEYPWD_BUF_LEN));
        return OG_SUCCESS;
    }

    status = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_SSL_KEYPWD, "", 0);
    if (status != OGCONN_SUCCESS) {
        get_err(conn);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void free_load_balance_info_locked(void)
{
    for (uint32 i = 0; i < MAX_HOST_SIZE; i++) {
        CM_FREE_PTR(counter_map[i].multi_host);
    }

    for (uint32 i = 0; i < MAX_HOST_SIZE; i++) {
        CM_FREE_PTR(connection_list[i].host);
    }
    host_counter = 0;
    connection_counter = 0;
}

void free_load_balance_info(void)
{
    cm_spin_lock(&g_load_balance_lock, NULL);
    free_load_balance_info_locked();
    g_lb_pending_free = OG_FALSE;
    cm_spin_unlock(&g_load_balance_lock);
}

void retain_load_balance_env(void)
{
    cm_spin_lock(&g_load_balance_lock, NULL);
    g_lb_env_refcount++;
    /* A new environment keeps process-global tables alive. */
    g_lb_pending_free = OG_FALSE;
    cm_spin_unlock(&g_load_balance_lock);
}

void release_load_balance_env(void)
{
    cm_spin_lock(&g_load_balance_lock, NULL);
    if (g_lb_env_refcount > 0) {
        g_lb_env_refcount--;
    }
    if (g_lb_env_refcount == 0) {
        if (g_lb_inflight == 0) {
            free_load_balance_info_locked();
            g_lb_pending_free = OG_FALSE;
        } else {
            /* Defer free until in-flight SQLConnect finishes. */
            g_lb_pending_free = OG_TRUE;
        }
    }
    cm_spin_unlock(&g_load_balance_lock);
}

/* Mark create_connection as using global LB tables; pairs with end_load_balance_use. */
static void begin_load_balance_use(void)
{
    cm_spin_lock(&g_load_balance_lock, NULL);
    g_lb_inflight++;
    cm_spin_unlock(&g_load_balance_lock);
}

static void end_load_balance_use(void)
{
    cm_spin_lock(&g_load_balance_lock, NULL);
    if (g_lb_inflight > 0) {
        g_lb_inflight--;
    }
    if (g_lb_inflight == 0 && g_lb_pending_free && g_lb_env_refcount == 0) {
        free_load_balance_info_locked();
        g_lb_pending_free = OG_FALSE;
    }
    cm_spin_unlock(&g_load_balance_lock);
}

static int compare_strings(const void *url1, const void *url2)
{
    return strcmp(*(const char **)url1, *(const char **)url2);
}

static status_t roundrobin_balance(connection_class *conn, char *url_identifier[],
                                   char *load_balance_url[], int valid_count)
{
    errno_t err;
    uint32 total_url_len = 0;
    uint32 total_url_index = 0;
    bool32 is_new_url = 0;
    uint32 value = 0;
    uint32 host_index = 0;
    char *sort_url[MAX_HOST_SIZE] = {0};
    char *total_url = NULL;

    for (int i = 0; i < valid_count; i++) {
        sort_url[i] = (char *)malloc(strlen(url_identifier[i]) + 1);
        if (!sort_url[i]) {
            set_conn_error(conn, "Couldn't allocate memory for roundrobin url.");
            for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
                CM_FREE_PTR(sort_url[j]);
            }
            return OG_ERROR;
        }

        err = memcpy_s(sort_url[i], strlen(url_identifier[i]) + 1, url_identifier[i], strlen(url_identifier[i]) + 1);
        if (err != 0) {
            set_conn_error(conn, "Secure C lib has throw an error.");
            for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
                CM_FREE_PTR(sort_url[j]);
            }
            return OG_ERROR;
        }
        total_url_len = total_url_len + strlen(url_identifier[i]) + 1;
    }

    qsort(sort_url, valid_count, sizeof(char *), compare_strings);

    if (total_url_len == 0 || total_url_len > MAX_URL_LEN) {
        set_conn_error(conn, "Roundrobin host set key is too long.");
        for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
            CM_FREE_PTR(sort_url[j]);
        }
        return OG_ERROR;
    }

    total_url = (char *)malloc(total_url_len);
    if (!total_url) {
        set_conn_error(conn, "Couldn't allocate memory for roundrobin host total url.");
        for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
            CM_FREE_PTR(sort_url[j]);
        }
        return OG_ERROR;
    }

    for (uint32 i = 0; i < valid_count; i++) {
        uint32 url_len = (uint32)strlen(sort_url[i]);
        uint32 remain = total_url_len - total_url_index;
        if (url_len >= remain) {
            set_conn_error(conn, "Roundrobin host is too long.");
            CM_FREE_PTR(total_url);
            for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
                CM_FREE_PTR(sort_url[j]);
            }
            return OG_ERROR;
        }

        err = memcpy_s(total_url + total_url_index, remain, sort_url[i], url_len);
        if (err != 0) {
            set_conn_error(conn, "Secure C lib has throw an error.");
            CM_FREE_PTR(total_url);
            for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
                CM_FREE_PTR(sort_url[j]);
            }
            return OG_ERROR;
        }
        total_url_index = total_url_index + url_len;
        if (i == valid_count - 1) {
            total_url[total_url_index] = '\0';
        } else {
            if (total_url_index + 1 >= total_url_len) {
                set_conn_error(conn, "Roundrobin host is too long.");
                CM_FREE_PTR(total_url);
                for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
                    CM_FREE_PTR(sort_url[j]);
                }
                return OG_ERROR;
            }
            total_url[total_url_index] = ',';
            total_url_index = total_url_index + 1;
        }
    }

    for (uint32 i = 0; i < MAX_HOST_SIZE; i++) {
        CM_FREE_PTR(sort_url[i]);
    }

    cm_spin_lock(&g_load_balance_lock, NULL);
    if (host_counter >= MAX_HOST_SIZE) {
        cm_spin_unlock(&g_load_balance_lock);
        CM_FREE_PTR(total_url);
        return OG_ERROR;
    }

    for (uint32 i = 0; i < host_counter; i++) {
        if (strcmp(counter_map[i].multi_host, total_url) == 0) {
            value = counter_map[i].count;
            host_index = i;
            is_new_url = 1;
            break;
        }
    }

    value = (value + 1) % max_connect_num;
    if (is_new_url == 0) {
        counter_map[host_counter].count = value;
        counter_map[host_counter].multi_host = (char *)malloc(strlen(total_url) + 1);
        if (!counter_map[host_counter].multi_host) {
            cm_spin_unlock(&g_load_balance_lock);
            CM_FREE_PTR(total_url);
            set_conn_error(conn, "Couldn't allocate memory for host map.");
            return OG_ERROR;
        }

        err = memcpy_s(counter_map[host_counter].multi_host, strlen(total_url) + 1, total_url, strlen(total_url) + 1);
        if (err != 0) {
            CM_FREE_PTR(counter_map[host_counter].multi_host);
            cm_spin_unlock(&g_load_balance_lock);
            CM_FREE_PTR(total_url);
            set_conn_error(conn, "Secure C lib has throw an error.");
            return OG_ERROR;
        }
        host_counter = host_counter + 1;
    } else {
        counter_map[host_index].count = value;
    }
    cm_spin_unlock(&g_load_balance_lock);
    CM_FREE_PTR(total_url);

    int index = value % valid_count;
    for (uint32 i = 0; i < valid_count; i++) {
        uint32 primitive_index = (index + i) % valid_count;
        load_balance_url[i] = (char *)malloc(strlen(url_identifier[primitive_index]) + 1);
        if (!load_balance_url[i]) {
            set_conn_error(conn, "Couldn't allocate memory for balance url.");
            return OG_ERROR;
        }

        err = memcpy_s(load_balance_url[i], strlen(url_identifier[primitive_index]) + 1,
                       url_identifier[primitive_index], strlen(url_identifier[primitive_index]) + 1);
        if (err != 0) {
            set_conn_error(conn, "Secure C lib has throw an error.");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t shuffle_balance(connection_class *conn, char *url_identifier[],
                                char *load_balance_url[], int valid_count)
{
    errno_t err;
    uint32 rand_number = 0;
    char *temp = NULL;

    for (uint32 i = valid_count - 1; i > 0; i--) {
        /* cm_random uses OS/OpenSSL entropy; no process-global srand needed. */
        rand_number = cm_random(i + 1);
        temp = url_identifier[rand_number];
        url_identifier[rand_number] = url_identifier[i];
        url_identifier[i] = temp;
    }

    for (uint32 i = 0; i < valid_count; i++) {
        load_balance_url[i] = (char *)malloc(strlen(url_identifier[i]) + 1);
        if (!load_balance_url[i]) {
            set_conn_error(conn, "Couldn't allocate memory for balance url.");
            return OG_ERROR;
        }

        err = memcpy_s(load_balance_url[i], strlen(url_identifier[i]) + 1,
                       url_identifier[i], strlen(url_identifier[i]) + 1);
        if (err != 0) {
            set_conn_error(conn, "Secure C lib has throw an error.");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t leastconn_balance(connection_class *conn, char *url_identifier[],
                                  char *load_balance_url[], int valid_count)
{
    errno_t err;
    bool32 is_existed = 0;
    uint32 index_1 = 0;
    uint32 index_2 = 0;
    uint32 connection_number_1 = 0;
    uint32 connection_number_2 = 0;
    char *temp = NULL;

    cm_spin_lock(&g_load_balance_lock, NULL);
    for (uint32 i = 0; i < valid_count; i++) {
        is_existed = 0;
        for (uint32 j = 0; j < connection_counter; j++) {
            if (strcmp(connection_list[j].host, url_identifier[i]) == 0) {
                is_existed = 1;
                break;
            }
        }
        if (is_existed == 0) {
            if (connection_counter >= MAX_HOST_SIZE) {
                cm_spin_unlock(&g_load_balance_lock);
                set_conn_error(conn, "Leastconn host map is full.");
                return OG_ERROR;
            }
            connection_list[connection_counter].connection_count = 0;
            connection_list[connection_counter].cached_connection = 0;
            connection_list[connection_counter].host = (char *)malloc(strlen(url_identifier[i]) + 1);
            if (!connection_list[connection_counter].host) {
                cm_spin_unlock(&g_load_balance_lock);
                set_conn_error(conn, "Couldn't allocate memory for host map.");
                return OG_ERROR;
            }

            err = memcpy_s(connection_list[connection_counter].host, strlen(url_identifier[i]) + 1,
                           url_identifier[i], strlen(url_identifier[i]) + 1);
            if (err != 0) {
                CM_FREE_PTR(connection_list[connection_counter].host);
                cm_spin_unlock(&g_load_balance_lock);
                set_conn_error(conn, "Secure C lib has throw an error.");
                return OG_ERROR;
            }
            connection_counter = connection_counter + 1;
        }
    }

    for (uint32 i = 0; i < valid_count - 1; i++) {
        for (uint32 j = 0; j < valid_count - 1 - i; j++) {
            index_1 = 0;
            index_2 = 0;
            for (uint32 k = 0; k < connection_counter; k++) {
                if (strcmp(connection_list[k].host, url_identifier[j]) == 0) {
                    index_1 = k;
                }
                if (strcmp(connection_list[k].host, url_identifier[j + 1]) == 0) {
                    index_2 = k;
                }
            }
            connection_number_1 = connection_list[index_1].connection_count
                                  + connection_list[index_1].cached_connection;
            connection_number_2 = connection_list[index_2].connection_count
                                  + connection_list[index_2].cached_connection;
            if (connection_number_1 > connection_number_2) {
                temp = url_identifier[j];
                url_identifier[j] = url_identifier[j + 1];
                url_identifier[j + 1] = temp;
            }
        }
    }
    cm_spin_unlock(&g_load_balance_lock);

    for (uint32 i = 0; i < valid_count; i++) {
        load_balance_url[i] = (char *)malloc(strlen(url_identifier[i]) + 1);
        if (!load_balance_url[i]) {
            set_conn_error(conn, "Couldn't allocate memory for balance url.");
            return OG_ERROR;
        }
        err = memcpy_s(load_balance_url[i], strlen(url_identifier[i]) + 1,
                       url_identifier[i], strlen(url_identifier[i]) + 1);
        if (err != 0) {
            set_conn_error(conn, "Secure C lib has throw an error.");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t priority_balance(connection_class *conn, ConnInfo *info, char *url_identifier[],
                                 char *load_balance_url[], int valid_count)
{
    char *end_number;
    errno_t err;
    status_t status;
    uint32 priority_number_len = strlen(info->auto_balance) - strlen(PRIORITY);
    char priority_suffix[MAX_SUFFIX_LEN];
    char *no_priority_host[MAX_HOST_SIZE] = {0};
    char *no_priority_roundrobin_host[MAX_HOST_SIZE] = {0};

    if (priority_number_len <= 0) {
        return roundrobin_balance(conn, url_identifier, load_balance_url, valid_count);
    }

    if (priority_number_len >= MAX_SUFFIX_LEN) {
        set_conn_error(conn, "Priority number conversion failed.");
        return OG_ERROR;
    }

    err = memcpy_s(priority_suffix, sizeof(priority_suffix), info->auto_balance + strlen(PRIORITY),
                   priority_number_len);
    if (err != 0) {
        set_conn_error(conn, "Secure C lib has throw an error.");
        return OG_ERROR;
    }
    priority_suffix[priority_number_len] = '\0';

    long priority_number_val = strtol(priority_suffix, &end_number, 10);
    /* Require a full numeric suffix: reject empty, trailing garbage (priority2abc), and negatives. */
    if (end_number == priority_suffix || *end_number != '\0' || priority_number_val < 0) {
        set_conn_error(conn, "Priority number conversion failed.");
        return OG_ERROR;
    }
    uint32 priority_number = (uint32)priority_number_val;

    if (priority_number > (uint32)valid_count) {
        set_conn_error(conn, "Priority number exceeds the total number of hosts.");
        return OG_ERROR;
    }

    if (priority_number > 0) {
        status = roundrobin_balance(conn, url_identifier, load_balance_url, priority_number);
        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }
        uint32 no_priority_size = valid_count - priority_number;
        /* All hosts are in the priority group; nothing left for the backup roundrobin. */
        if (no_priority_size == 0) {
            return OG_SUCCESS;
        }

        for (uint32 i = 0; i < no_priority_size; i++) {
            uint32 url_len = strlen(url_identifier[i + priority_number]) + 1;
            no_priority_host[i] = (char *)malloc(url_len);
            if (!no_priority_host[i]) {
                set_conn_error(conn, "Couldn't allocate memory for priority host.");
                for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
                    CM_FREE_PTR(no_priority_host[j]);
                }
                return OG_ERROR;
            }

            err = memcpy_s(no_priority_host[i], url_len, url_identifier[i + priority_number], url_len);
            if (err != 0) {
                set_conn_error(conn, "Secure C lib has throw an error.");
                for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
                    CM_FREE_PTR(no_priority_host[j]);
                }
                return OG_ERROR;
            }
        }

        status = roundrobin_balance(conn, no_priority_host, no_priority_roundrobin_host, no_priority_size);
        if (status != OG_SUCCESS) {
            for (uint32 i = 0; i < MAX_HOST_SIZE; i++) {
                CM_FREE_PTR(no_priority_host[i]);
                CM_FREE_PTR(no_priority_roundrobin_host[i]);
            }
            return OG_ERROR;
        }

        for (uint32 i = 0; i < no_priority_size; i++) {
            uint32 host_len = strlen(no_priority_roundrobin_host[i]) + 1;
            load_balance_url[i + priority_number] = (char *)malloc(host_len);
            if (!load_balance_url[i + priority_number]) {
                set_conn_error(conn, "Couldn't allocate memory for balance url.");
                for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
                    CM_FREE_PTR(no_priority_host[j]);
                    CM_FREE_PTR(no_priority_roundrobin_host[j]);
                }
                return OG_ERROR;
            }

            err = memcpy_s(load_balance_url[i + priority_number], host_len, no_priority_roundrobin_host[i], host_len);
            if (err != 0) {
                set_conn_error(conn, "Secure C lib has throw an error.");
                for (uint32 j = 0; j < MAX_HOST_SIZE; j++) {
                    CM_FREE_PTR(no_priority_host[j]);
                    CM_FREE_PTR(no_priority_roundrobin_host[j]);
                }
                return OG_ERROR;
            }
        }
    } else {
        status = roundrobin_balance(conn, url_identifier, load_balance_url, valid_count);
        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    for (uint32 i = 0; i < MAX_HOST_SIZE; i++) {
        CM_FREE_PTR(no_priority_host[i]);
        CM_FREE_PTR(no_priority_roundrobin_host[i]);
    }

    return OG_SUCCESS;
}

static status_t set_balance_url(connection_class *conn, char *url_identifier[],
                                char *load_balance_url[], int valid_count)
{
    errno_t err;

    for (uint32 i = 0; i < valid_count; i++) {
        uint32 url_len = strlen(url_identifier[i]) + 1;
        load_balance_url[i] = (char *)malloc(url_len);
        if (!load_balance_url[i]) {
            set_conn_error(conn, "Couldn't allocate memory for load balance url.");
            return OG_ERROR;
        }
        err = memcpy_s(load_balance_url[i], url_len, url_identifier[i], url_len);
        if (err != 0) {
            set_conn_error(conn, "Secure C lib has throw an error.");
            return OG_ERROR;
        }
    }
        
    return OG_SUCCESS;
}

static void log_load_balance_result(connection_class *conn, ConnInfo *info,
                                    char *load_balance_url[], int valid_count)
{
    char log_buf[MAX_VALUE_BUFF_LEN];
    char url_list[MAX_VALUE_BUFF_LEN];
    const char *mode = "default";
    uint32 offset = 0;
    int ret;

    if (conn == NULL || info == NULL || valid_count <= 0) {
        return;
    }

    if (info->auto_balance[0] != '\0') {
        mode = info->auto_balance;
    }

    url_list[0] = '\0';
    for (int i = 0; i < valid_count; i++) {
        if (load_balance_url[i] == NULL) {
            continue;
        }
        if (offset > 0) {
            ret = snprintf_s(url_list + offset, sizeof(url_list) - offset,
                             sizeof(url_list) - offset - 1, ", ");
            if (ret == -1) {
                break;
            }
            offset += (uint32)ret;
        }
        ret = snprintf_s(url_list + offset, sizeof(url_list) - offset,
                         sizeof(url_list) - offset - 1, "%s", load_balance_url[i]);
        if (ret == -1) {
            break;
        }
        offset += (uint32)ret;
    }

    ret = snprintf_s(log_buf, sizeof(log_buf), sizeof(log_buf) - 1,
                     "Autobalance mode: %s, load balance result: %s", mode, url_list);
    if (ret != -1) {
        write_odbc_info_log(conn, log_buf);
    }
}

static status_t multi_host_choose(connection_class *conn, ConnInfo *info, char *url_identifier[],
                                  char *load_balance_url[], int valid_count)
{
    status_t status;

    if (valid_count <= 1 || info->auto_balance[0] == '\0') {
        status = set_balance_url(conn, url_identifier, load_balance_url, valid_count);
    } else if (strcmp(info->auto_balance, ROUNDROBIN) == 0) {
        status = roundrobin_balance(conn, url_identifier, load_balance_url, valid_count);
    } else if (strcmp(info->auto_balance, SHUFFLE) == 0) {
        status = shuffle_balance(conn, url_identifier, load_balance_url, valid_count);
    } else if (strcmp(info->auto_balance, LEASTCONN) == 0) {
        status = leastconn_balance(conn, url_identifier, load_balance_url, valid_count);
    } else if (strncmp(info->auto_balance, PRIORITY, strlen(PRIORITY)) == 0) {
        status = priority_balance(conn, info, url_identifier, load_balance_url, valid_count);
    } else {
        status = set_balance_url(conn, url_identifier, load_balance_url, valid_count);
    }

    if (status == OG_SUCCESS) {
        log_load_balance_result(conn, info, load_balance_url, valid_count);
    }
    return status;
}

static int parse_host_or_port(const char *str, char *address[])
{
    int count = 0;
    const char *p = str;
    const char *field_start = NULL;
    size_t field_len = 0;

    if (str == NULL) {
        return 0;
    }

    while (*p != '\0') {
        field_start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        field_len = (size_t)(p - field_start);

        /* Reject empty fields from ",,", leading/trailing commas, and whitespace-only tokens. */
        {
            size_t begin = 0;
            size_t end = field_len;
            while (begin < end && (field_start[begin] == ' ' || field_start[begin] == '\t')) {
                begin++;
            }
            while (end > begin && (field_start[end - 1] == ' ' || field_start[end - 1] == '\t')) {
                end--;
            }
            if (begin >= end) {
                for (int i = 0; i < count; i++) {
                    CM_FREE_PTR(address[i]);
                }
                for (int i = 0; i < MAX_HOST_SIZE; i++) {
                    address[i] = NULL;
                }
                return PARSE_HOST_PORT_ERR_EMPTY;
            }
            field_start += begin;
            field_len = end - begin;
        }

        if (count >= MAX_HOST_SIZE) {
            for (int i = 0; i < count; i++) {
                CM_FREE_PTR(address[i]);
            }
            for (int i = 0; i < MAX_HOST_SIZE; i++) {
                address[i] = NULL;
            }
            return PARSE_HOST_PORT_ERR_TOO_MANY;
        }

        /* Reject oversized fields before malloc(field_len + 1). */
        if (field_len >= MAX_ADDRESS_LEN || field_len + 1 < field_len) {
            for (int i = 0; i < count; i++) {
                CM_FREE_PTR(address[i]);
            }
            for (int i = 0; i < MAX_HOST_SIZE; i++) {
                address[i] = NULL;
            }
            return PARSE_HOST_PORT_ERR_TOO_LONG;
        }

        address[count] = (char *)malloc(field_len + 1);
        if (!address[count]) {
            for (int i = 0; i < count; i++) {
                CM_FREE_PTR(address[i]);
            }
            for (int i = 0; i < MAX_HOST_SIZE; i++) {
                address[i] = NULL;
            }
            return PARSE_HOST_PORT_ERR_NOMEM;
        }
        if (memcpy_s(address[count], field_len + 1, field_start, field_len) != 0) {
            CM_FREE_PTR(address[count]);
            for (int i = 0; i < count; i++) {
                CM_FREE_PTR(address[i]);
            }
            for (int i = 0; i < MAX_HOST_SIZE; i++) {
                address[i] = NULL;
            }
            return PARSE_HOST_PORT_ERR_NOMEM;
        }
        address[count][field_len] = '\0';
        count++;

        if (*p == ',') {
            p++;
            /* Trailing comma means an empty field after the last delimiter. */
            if (*p == '\0') {
                for (int i = 0; i < count; i++) {
                    CM_FREE_PTR(address[i]);
                }
                for (int i = 0; i < MAX_HOST_SIZE; i++) {
                    address[i] = NULL;
                }
                return PARSE_HOST_PORT_ERR_EMPTY;
            }
        }
    }

    for (int i = count; i < MAX_HOST_SIZE; i++) {
        address[i] = NULL;
    }
    return count;
}

static status_t get_url_info(connection_class *conn, char *url_identifier[], int valid_count,
                             const parsed_address_lists_t *addrs)
{
    uint32 connHostlen = 0;
    uint32 serverLen = 0;
    uint32 portLen = 0;
    errno_t err;

    if (addrs == NULL) {
        set_conn_error(conn, "Failed to parse host or port list.");
        return OG_ERROR;
    }

    for (int i = 0; i < valid_count; i++) {
        /* 1 host / N ports or N hosts / 1 port: reuse the single entry by index, no pointer aliasing. */
        char *host = addrs->hosts[addrs->host_number == 1 ? 0 : i];
        char *port = addrs->ports[addrs->port_number == 1 ? 0 : i];

        serverLen = strlen(host);
        portLen = strlen(port);
        connHostlen = serverLen + portLen + 1 + 1;
        if (connHostlen > MAX_ADDRESS_LEN) {
            set_conn_error(conn, "Host and port combination exceeds the maximum address length.");
            return OG_ERROR;
        }
        char address[MAX_ADDRESS_LEN];
        err = memcpy_s(address, sizeof(address), host, serverLen);
        if (err != 0) {
            set_conn_error(conn, "Secure C lib has throw an error.");
            return OG_ERROR;
        }
        address[serverLen] = ':';
        err = memcpy_s(address + serverLen + 1, sizeof(address) - serverLen - 1, port, portLen);
        if (err != 0) {
            set_conn_error(conn, "Secure C lib has throw an error.");
            return OG_ERROR;
        }

        address[connHostlen - 1] = '\0';
        url_identifier[i] = strdup(address);
        if (url_identifier[i] == NULL) {
            set_conn_error(conn, "Couldn't allocate memory for url identifier.");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

/* Caller must hold g_load_balance_lock. Returns entry index, or -1 on failure. */
static int find_or_add_leastconn_host(connection_class *conn, const char *balance_url)
{
    errno_t err;

    for (uint32 k = 0; k < connection_counter; k++) {
        if (strcmp(connection_list[k].host, balance_url) == 0) {
            return (int)k;
        }
    }

    if (connection_counter >= MAX_HOST_SIZE) {
        set_conn_error(conn, "Leastconn host map is full.");
        return -1;
    }

    connection_list[connection_counter].connection_count = 0;
    connection_list[connection_counter].cached_connection = 0;
    connection_list[connection_counter].host = (char *)malloc(strlen(balance_url) + 1);
    if (!connection_list[connection_counter].host) {
        set_conn_error(conn, "Couldn't allocate memory for host map.");
        return -1;
    }

    err = memcpy_s(connection_list[connection_counter].host, strlen(balance_url) + 1,
                   balance_url, strlen(balance_url) + 1);
    if (err != 0) {
        CM_FREE_PTR(connection_list[connection_counter].host);
        set_conn_error(conn, "Secure C lib has throw an error.");
        return -1;
    }

    connection_counter = connection_counter + 1;
    return (int)(connection_counter - 1);
}

static status_t load_least_connect(connection_class *conn, ConnInfo *info, char *balance_url)
{
    status_t status;
    int connection_index = -1;

    /* Occupy a slot before connect so concurrent leastconn sorts see in-flight work.
     * Insert the host if missing so counter updates never silently no-op. */
    cm_spin_lock(&g_load_balance_lock, NULL);
    connection_index = find_or_add_leastconn_host(conn, balance_url);
    if (connection_index < 0) {
        cm_spin_unlock(&g_load_balance_lock);
        return OG_ERROR;
    }
    connection_list[connection_index].cached_connection =
        connection_list[connection_index].cached_connection + 1;
    cm_spin_unlock(&g_load_balance_lock);

    status = ogconn_connect(conn->ogconn, balance_url, info->username, info->password);

    cm_spin_lock(&g_load_balance_lock, NULL);
    connection_index = -1;
    for (uint32 k = 0; k < connection_counter; k++) {
        if (strcmp(connection_list[k].host, balance_url) == 0) {
            connection_index = (int)k;
            break;
        }
    }

    if (connection_index >= 0) {
        if (connection_list[connection_index].cached_connection > 0) {
            connection_list[connection_index].cached_connection =
                connection_list[connection_index].cached_connection - 1;
        }
        if (status == OG_SUCCESS) {
            connection_list[connection_index].connection_count =
                connection_list[connection_index].connection_count + 1;
        }
    } else if (status == OG_SUCCESS) {
        /* Table was cleared between occupy and connect; re-add so the live
         * connection is still counted for leastconn. */
        connection_index = find_or_add_leastconn_host(conn, balance_url);
        if (connection_index >= 0) {
            connection_list[connection_index].connection_count = 1;
        }
    }
    cm_spin_unlock(&g_load_balance_lock);

    return status;
}

void release_least_connect(connection_class *conn)
{
    if (conn == NULL || conn->flag != 0 || conn->connected_host[0] == '\0') {
        return;
    }

    if (strcmp(conn->connInfo.auto_balance, LEASTCONN) != 0) {
        conn->connected_host[0] = '\0';
        return;
    }

    cm_spin_lock(&g_load_balance_lock, NULL);
    for (uint32 k = 0; k < connection_counter; k++) {
        if (strcmp(connection_list[k].host, conn->connected_host) != 0) {
            continue;
        }
        if (connection_list[k].connection_count > 0) {
            connection_list[k].connection_count--;
        }
        break;
    }
    cm_spin_unlock(&g_load_balance_lock);
    conn->connected_host[0] = '\0';
}

static void free_parsed_address_lists(parsed_address_lists_t *addrs)
{
    if (addrs == NULL) {
        return;
    }
    for (int i = 0; i < MAX_HOST_SIZE; i++) {
        CM_FREE_PTR(addrs->hosts[i]);
        CM_FREE_PTR(addrs->ports[i]);
    }
}

static void free_create_connection_temps(char *url_identifier[], char *load_balance_url[],
                                        parsed_address_lists_t *addrs)
{
    for (uint32 i = 0; i < MAX_HOST_SIZE; i++) {
        CM_FREE_PTR(url_identifier[i]);
        CM_FREE_PTR(load_balance_url[i]);
    }
    free_parsed_address_lists(addrs);
}

static status_t create_connection(connection_class *conn, ConnInfo *info)
{
    status_t status = OG_ERROR;
    char *url_identifier[MAX_HOST_SIZE] = {0};
    char *load_balance_url[MAX_HOST_SIZE] = {0};
    parsed_address_lists_t addrs = {0};
    char fail_msg[OG_MESSAGE_BUFFER_SIZE];
    bool32 stop_failover = OG_FALSE;

    addrs.host_number = parse_host_or_port(info->server, addrs.hosts);
    addrs.port_number = parse_host_or_port(info->port, addrs.ports);
    if (addrs.host_number == PARSE_HOST_PORT_ERR_TOO_MANY ||
        addrs.port_number == PARSE_HOST_PORT_ERR_TOO_MANY) {
        free_parsed_address_lists(&addrs);
        set_conn_error(conn, "Host or port list exceeds maximum of 100.");
        return OG_ERROR;
    }

    if (addrs.host_number == PARSE_HOST_PORT_ERR_EMPTY ||
        addrs.port_number == PARSE_HOST_PORT_ERR_EMPTY) {
        free_parsed_address_lists(&addrs);
        set_conn_error(conn, "Host or port list contains an empty entry.");
        return OG_ERROR;
    }

    if (addrs.host_number == PARSE_HOST_PORT_ERR_TOO_LONG ||
        addrs.port_number == PARSE_HOST_PORT_ERR_TOO_LONG) {
        free_parsed_address_lists(&addrs);
        set_conn_error(conn, "Host or port entry exceeds the maximum address length.");
        return OG_ERROR;
    }

    if (addrs.host_number < 0 || addrs.port_number < 0) {
        free_parsed_address_lists(&addrs);
        set_conn_error(conn, "Couldn't allocate memory while parsing host or port list.");
        return OG_ERROR;
    }

    if (addrs.host_number == 0 || addrs.port_number == 0) {
        free_parsed_address_lists(&addrs);
        set_conn_error(conn, "Failed to parse host or port list.");
        return OG_ERROR;
    }

    if (addrs.host_number != addrs.port_number && addrs.host_number != 1 && addrs.port_number != 1) {
        free_parsed_address_lists(&addrs);
        set_conn_error(conn, "host and port list counts are incompatible. "
                             "Use N hosts with N ports, 1 host with N ports, or N hosts with 1 port.");
        return OG_ERROR;
    }

    int valid_count = addrs.host_number > addrs.port_number ? addrs.host_number : addrs.port_number;

    begin_load_balance_use();

    if (get_url_info(conn, url_identifier, valid_count, &addrs) == OG_SUCCESS) {
        status = multi_host_choose(conn, info, url_identifier, load_balance_url, valid_count);
        if (status != OG_SUCCESS) {
            if (conn->error_msg == NULL) {
                set_conn_error(conn, "Failed to choose host for load balance.");
            }
        } else {
            for (int i = 0; i < valid_count; i++) {
                if (strcmp(info->auto_balance, LEASTCONN) == 0) {
                    status = load_least_connect(conn, info, load_balance_url[i]);
                } else {
                    status = ogconn_connect(conn->ogconn, load_balance_url[i], info->username, info->password);
                }

                if (status == OG_SUCCESS) {
                    conn->flag = 0;
                    /* Clear residual error from earlier failed hosts in this attempt. */
                    conn->err_sign = 0;
                    conn->error_msg = NULL;
                    /* Keep the connection even if connected_host copy fails.
                     * Do not decrease leastconn connection_count here; disconnect
                     * simply cannot match the host when connected_host is empty. */
                    if (memcpy_s(conn->connected_host, sizeof(conn->connected_host),
                                 load_balance_url[i], strlen(load_balance_url[i]) + 1) != 0) {
                        conn->connected_host[0] = '\0';
                    }
                    if (snprintf_s(fail_msg, sizeof(fail_msg), sizeof(fail_msg) - 1,
                                   "Successfully connected to %s.", load_balance_url[i]) != -1) {
                        write_odbc_info_log(conn, fail_msg);
                    }
                    free_create_connection_temps(url_identifier, load_balance_url, &addrs);
                    end_load_balance_use();
                    return OG_SUCCESS;
                }

                /* Log failed node and underlying error before trying the next host. */
                set_ogconn_connect_error(conn, fail_msg, sizeof(fail_msg), load_balance_url[i]);

                /* Reset residual pipe/options state before trying the next host.
                 * ogconn_disconnect does not clear error_code/message, so get_err
                 * after the loop still reports the last connect failure.
                 * It does free UDS server_path — restore from ConnInfo for the next try. */
                ogconn_disconnect(conn->ogconn);
                if (restore_uds_path(conn, info) != OG_SUCCESS) {
                    stop_failover = OG_TRUE;
                    break;
                }
            }

            if (!stop_failover) {
                get_err(conn);
            }
        }
    }

    free_create_connection_temps(url_identifier, load_balance_url, &addrs);
    end_load_balance_use();
    return OG_ERROR;
}

SQLRETURN og_db_connect(connection_class *conn, ConnInfo *info)
{
    uint32 asc_len = AES256_SIZE / 2;
    char asc_key[AES256_SIZE / 2 + 4];
    char *ssl_encryption = info->ssl_encryption;
    char *ssl_factory = info->ssl_factory;
    uint32 ssl_factory_len = (uint32)strlen(ssl_factory);
    uint32 key_file_len = SSL_ENCRYPTION_KEY_LEN;
    char *ssl_key_native = info->ssl_key_native;
    uint32 ssl_encryption_len = OG_MAX_CIPHER_LEN;

    if (verify_conn_info(conn, info) != SQL_SUCCESS) {
        return SQL_ERROR;
    }

    if (info->charset[0] != '\0') {
        int ret = ogconn_set_conn_attr(conn->ogconn, OGCONN_ATTR_CHARSET_TYPE,
                                       info->charset, strlen(info->charset));
        if (ret != 0) {
            set_conn_error(conn, "set charset type failed.");
            return SQL_ERROR;
        }
    }

    if (init_ssl_info(conn, info) != OG_SUCCESS) {
        return SQL_ERROR;
    }

    if (create_connection(conn, info) != OG_SUCCESS) {
        return SQL_ERROR;
    }

    if (ssl_factory_len != MAX_SSL_KEY_LEN) {
        MEMS_RETURN_IFERR(memset_s(ssl_factory, SSL_MAX_PARAM_LEN, 0, SSL_MAX_PARAM_LEN));
        MEMS_RETURN_IFERR(memset_s(ssl_key_native, SSL_MAX_KEY_LEN, 0, SSL_MAX_KEY_LEN));
        OG_RETURN_IFERR(cm_rand((unsigned char *)asc_key, asc_len));
        OG_RETURN_IFERR(cm_base64_encode((unsigned char *)asc_key, asc_len, ssl_factory, &key_file_len));
        OG_RETURN_IFERR(cm_generate_work_key(ssl_factory, ssl_key_native, SSL_MAX_KEY_LEN));
    }

    int encrypt_rs = ogconn_encrypt_password(info->password, (uint32)strlen(info->password), ssl_key_native,
                                ssl_factory, ssl_encryption, &ssl_encryption_len);
    if (encrypt_rs != 0) {
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

void get_err(HDBC conn)
{
    connection_class *pConn = (connection_class *)conn;
    ogconn_get_error(pConn->ogconn, &pConn->error_code, (const char **)&pConn->error_msg);
    pConn->err_sign = (pConn->error_msg) ? 1 : 0;
    if (pConn->error_code == 0) {
        pConn->error_msg = NULL;
    } else if (pConn->error_msg != NULL) {
        write_odbc_error_log(pConn);
    }
}

static char *mode_set[] = {"DISABLED", "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_FULL"};

SQLRETURN init_odbc_dsn(connection_class *conn, ConnInfo *info)
{
    char *INIT_DSN = info->dsn;
    uint32 index = 0;
    char ssl_mode[MAX_MODE_LEN];
    int mode_total = sizeof(mode_set) / sizeof(mode_set[0]);

    ssl_mode[0] = '\0';
    if (sqlGetPrivateProfileString == NULL) {
        set_conn_error(conn, "failed to load symbol from dynamic library file");
        return SQL_ERROR;
    }

    info->ssl_mode = OGCONN_SSL_PREFERRED;
    sqlGetPrivateProfileString(INIT_DSN, SERVERNAME, "", info->server, sizeof(info->server), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, DATABASE, "", info->database, sizeof(info->database), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, USERNAME, "", info->username, sizeof(info->username), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, PASSWORD, "", info->password, sizeof(info->password), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, PORT, "", info->port, sizeof(info->port), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, AUTO_BALANCE, "", info->auto_balance, sizeof(info->auto_balance), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, LOGDIR, "", info->logdir, sizeof(info->logdir), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, CHARSET, "", info->charset, sizeof(info->charset), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, SSL_CA, "", info->ssl_ca, sizeof(info->ssl_ca), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, SSL_CERT, "", info->ssl_cert, sizeof(info->ssl_cert), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, SSL_KEY, "", info->ssl_key, sizeof(info->ssl_key), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, SSL_PASSWORD, "", info->sslpassword, sizeof(info->sslpassword), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, SSL_CRL, "", info->ssl_crl, sizeof(info->ssl_crl), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, SSL_ENCRYPTION, "", info->ssl_encryption,
                               sizeof(info->ssl_encryption), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, SSL_KEY_NATIVE, "", info->ssl_key_native,
                               sizeof(info->ssl_key_native), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, SSL_FACTORY, "", info->ssl_factory, sizeof(info->ssl_factory), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, UDS_PATH, "", info->uds_path, sizeof(info->uds_path), ODBC_INI);
    sqlGetPrivateProfileString(INIT_DSN, SSL_MODE, "", ssl_mode, sizeof(ssl_mode), ODBC_INI);

    while (index < mode_total) {
        if ((uint32)strlen(ssl_mode) != (uint32)strlen(mode_set[index])) {
            index++;
            continue;
        }

        bool32 matched = 0;
        size_t p = 0;
        while (p < (uint32)strlen(ssl_mode)) {
            if (UPPER(ssl_mode[p]) != UPPER(mode_set[index][p])) {
                matched = 1;
                break;
            }
            p++;
        }
        if (matched) {
            index++;
            continue;
        }

        info->ssl_mode = (ogconn_ssl_mode_t)index;
        break;
    }
    return SQL_SUCCESS;
}

static status_t bind_data_to_pos(statement *stmt, sql_input_data *input_data)
{
    input_data->param_stream = (char *)malloc(MAX_VALUE_BUFF_LEN);
    if (input_data->param_stream == NULL) {
        return SQL_ERROR;
    }
    if (memset_s(input_data->param_stream, MAX_VALUE_BUFF_LEN, 0, MAX_VALUE_BUFF_LEN) != 0) {
        set_conn_error(stmt->conn, "secure C lib has throw an error.");
        return SQL_ERROR;
    }

    return ogconn_bind_by_pos2(stmt->ctconn_stmt, input_data->index, input_data->og_type, input_data->param_stream,
                               input_data->param_len, input_data->param_size, input_data->param_type);
}

static SQLRETURN bind_string_param(statement *stmt, sql_input_data *input_data)
{
    status_t status;
    uint16 *ind = NULL;

    if (input_data->size == NULL || *input_data->size != SQL_DATA_AT_EXEC) {
        if (input_data->size != NULL) {
            ind = input_data->param_size;
        }
        status = ogconn_bind_by_pos2(stmt->ctconn_stmt, input_data->index, input_data->og_type,
                input_data->param_value, input_data->param_len, ind, input_data->param_type);
    } else {
        status = bind_data_to_pos(stmt, input_data);
    }

    if (status != OG_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}
 
static SQLRETURN bind_sql_param(statement *stmt, sql_input_data *input_data)
{
    ogconn_type_t og_type = input_data->og_type;
    uint16 *ind = NULL;
    status_t status;

    if (og_type == OGCONN_TYPE_NUMBER2 || og_type == OGCONN_TYPE_NUMBER
        || og_type == OGCONN_TYPE_DECIMAL) {
        if (input_data->sql_type == SQL_C_CHAR) {
            return bind_string_param(stmt, input_data);
        } else {
            input_data->is_convert = SQL_TRUE;
            status = ogconn_bind_by_pos2(stmt->ctconn_stmt, input_data->index, input_data->og_type,
                input_data->input_param, OG_BUFF_SIZE, input_data->param_size, input_data->param_type);
        }
    } else if (og_type == OGCONN_TYPE_DATE || og_type == OGCONN_TYPE_TIMESTAMP
               || og_type == OGCONN_TYPE_TIMESTAMP_TZ || og_type == OGCONN_TYPE_TIMESTAMP_LTZ) {
        if (input_data->size != NULL) {
            ind = input_data->param_size;
        }
        if (input_data->sql_type == SQL_C_CHAR) {
            status = ogconn_bind_by_pos2(stmt->ctconn_stmt, input_data->index, OGCONN_TYPE_STRING,
                input_data->param_value, input_data->param_len, ind, input_data->param_type);
        } else {
            input_data->is_convert = SQL_TRUE;
            status = ogconn_bind_by_pos2(stmt->ctconn_stmt, input_data->index, OGCONN_TYPE_TIMESTAMP,
                input_data->input_param, OG_BUFF_SIZE, input_data->param_size, input_data->param_type);
        }
    } else {
        return bind_string_param(stmt, input_data);
    }

    if (status != OG_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

SQLRETURN bind_param_by_c_type(statement *stmt, sql_input_data *input_data)
{
    SQLRETURN ret;

    ret = bind_sql_param(stmt, input_data);
    if (ret == SQL_ERROR) {
        return SQL_ERROR;
    }

    if (ret == SQL_SUCCESS) {
        if (input_data->size == NULL) {
            input_data->param_offset = input_data->param_offset + input_data->param_len;
        } else if (*(input_data->size) == SQL_NTS) {
            input_data->param_offset = strlen(input_data->param_value);
        } else if (*(input_data->size) == SQL_DATA_AT_EXEC) {
            input_data->param_offset = 0;
        } else {
            input_data->param_offset = *input_data->size;
        }
    }
    if (input_data->sql_type == SQL_C_CHAR
        || input_data->sql_type == SQL_WVARCHAR
        || input_data->sql_type == SQL_WLONGVARCHAR) {
        ogconn_sql_set_param_c_type(stmt->ctconn_stmt, input_data->index, OG_TRUE);
    }
    return ret;
}

void clean_up_bind_param(sql_input_data *input_data)
{
    if (input_data != NULL) {
        if (input_data->input_param) {
            free(input_data->input_param);
            input_data->input_param = NULL;
        }
        if (input_data->param_size) {
            free(input_data->param_size);
            input_data->param_size = NULL;
        }
        if (input_data->param_stream) {
            free(input_data->param_stream);
            input_data->param_stream = NULL;
        }
    }
}

void clean_up_param(bilist_node_t *node, bilist_t *params, sql_input_data *input_data)
{
    cm_bilist_del(node, params);
    clean_up_bind_param(input_data);
    if (input_data != NULL) {
        free(input_data);
        input_data = NULL;
    }
}

void del_stmt_param(bilist_t *params, bool8 is_init)
{
    bilist_node_t *item_param = params->head;
    bilist_node_t *next_param = NULL;
    sql_input_data *input_data = NULL;

    while (item_param != NULL) {
        input_data = (sql_input_data *)((char *)item_param - OFFSET_OF(sql_input_data, data_list));
        next_param = item_param->next;
        if (is_init) {
            if (input_data->param_flag == NOT_EXEC_PARAM || input_data->param_flag == EXEC_PARAM) {
                clean_up_param(item_param, params, input_data);
            }
        } else {
            if (input_data->param_flag == INIT_PARAM ||
                input_data->param_flag == EXEC_PARAM ||
                input_data->param_flag == FREE_PARAM) {
                clean_up_param(item_param, params, input_data);
            }
        }
        item_param = next_param;
    }
}

SQLRETURN malloc_bind_param(sql_input_data *input_data)
{
    uint64 bind_len_size = sizeof(uint16) * input_data->param_count;
    uint64 value_size = sizeof(paramData) * input_data->param_count;
    errno_t err;

    if (input_data->param_count == 0) {
        return SQL_INVALID_HANDLE;
    }

    char *value_len_buff = (char *)malloc(bind_len_size);
    if (value_len_buff == NULL) {
        return SQL_INVALID_HANDLE;
    }

    err = memset_s(value_len_buff, bind_len_size, 0, bind_len_size);
    if (err != 0) {
        free(value_len_buff);
        value_len_buff = NULL;
        return SQL_INVALID_HANDLE;
    }
    input_data->param_size = (uint16 *)value_len_buff;
    if (!input_data->is_convert) {
        return SQL_SUCCESS;
    }

    char *value_buff = (char *)malloc(value_size);
    if (value_buff == NULL) {
        return SQL_INVALID_HANDLE;
    }
    err = memset_s(value_buff, value_size, 0, value_size);
    if (err != 0) {
        free(value_buff);
        value_buff = NULL;
        return SQL_INVALID_HANDLE;
    }
    input_data->input_param = (paramData *)value_buff;
    return SQL_SUCCESS;
}

sql_input_data *generate_bind_param_instance(bilist_node_t *item_param, uint32 pos)
{
    sql_input_data *input_data = NULL;

    while (item_param != NULL) {
        input_data = (sql_input_data *)((char *)item_param - OFFSET_OF(sql_input_data, data_list));
        if (input_data->index != pos) {
            item_param = item_param->next;
            continue;
        }
        return input_data;
    }
    return NULL;
}

db_type_map type_map[] = {
    {SQL_FLOAT, OGCONN_TYPE_REAL},
    {SQL_DOUBLE, OGCONN_TYPE_REAL},
    {SQL_NUMERIC, OGCONN_TYPE_NUMBER2},
    {SQL_DECIMAL, OGCONN_TYPE_NUMBER2},
    {SQL_CHAR, OGCONN_TYPE_CHAR},
    {SQL_WCHAR, OGCONN_TYPE_CHAR},
    {SQL_VARCHAR, OGCONN_TYPE_VARCHAR},
    {SQL_WVARCHAR, OGCONN_TYPE_VARCHAR},
    {SQL_INTEGER, OGCONN_TYPE_INTEGER},
    {SQL_BIGINT, OGCONN_TYPE_BIGINT},
    {SQL_DATE, OGCONN_TYPE_DATE},
    {SQL_TIME, OGCONN_TYPE_DATE},
    {SQL_TYPE_TIMESTAMP, OGCONN_TYPE_TIMESTAMP},
    {SQL_TIMESTAMP, OGCONN_TYPE_TIMESTAMP},
    {SQL_TYPE_DATE, OGCONN_TYPE_DATE},
    {SQL_TYPE_TIME, OGCONN_TYPE_DATE},
    {SQL_BINARY, OGCONN_TYPE_BINARY},
    {SQL_VARBINARY, OGCONN_TYPE_VARBINARY},
    {SQL_LONGVARCHAR, OGCONN_TYPE_CLOB},
    {SQL_WLONGVARCHAR, OGCONN_TYPE_CLOB},
    {SQL_LONGVARBINARY, OGCONN_TYPE_BLOB}
};

const int TYPE_MAP_SIZE = sizeof(type_map) / sizeof(type_map[0]);

ogconn_type_t sql_type_map_to_db_type(SQLSMALLINT sql_type)
{
    for (int i = 0; i < TYPE_MAP_SIZE; i++) {
        if (type_map[i].sql_Type == sql_type) {
            return type_map[i].db_Type;
        }
    }
    return OGCONN_TYPE_UNKNOWN;
}

c_type_map sql_type_map[] = {
    {OGCONN_TYPE_INTEGER, SQL_C_SLONG},
    {OGCONN_TYPE_BOOLEAN, SQL_C_SLONG},
    {OGCONN_TYPE_BIGINT, SQL_C_ULONG},
    {OGCONN_TYPE_REAL, SQL_C_DOUBLE},
    {OGCONN_TYPE_NUMBER, SQL_C_NUMERIC},
    {OGCONN_TYPE_NUMBER2, SQL_C_NUMERIC},
    {OGCONN_TYPE_DECIMAL, SQL_C_NUMERIC},
    {OGCONN_TYPE_DATE, SQL_C_TYPE_TIMESTAMP},
    {OGCONN_TYPE_TIMESTAMP, SQL_C_TYPE_TIMESTAMP},
    {OGCONN_TYPE_TIMESTAMP_TZ_FAKE, SQL_C_TYPE_TIMESTAMP},
    {OGCONN_TYPE_TIMESTAMP_TZ, SQL_C_TYPE_TIMESTAMP},
    {OGCONN_TYPE_TIMESTAMP_LTZ, SQL_C_TYPE_TIMESTAMP},
    {OGCONN_TYPE_CHAR, SQL_C_CHAR},
    {OGCONN_TYPE_VARCHAR, SQL_C_CHAR},
    {OGCONN_TYPE_STRING, SQL_C_CHAR},
    {OGCONN_TYPE_CLOB, SQL_C_CHAR},
    {OGCONN_TYPE_BINARY, SQL_C_CHAR},
    {OGCONN_TYPE_VARBINARY, SQL_C_CHAR},
    {OGCONN_TYPE_BLOB, SQL_C_CHAR}
};

const int C_TYPE_MAP_SIZE = sizeof(sql_type_map) / sizeof(sql_type_map[0]);

SQLSMALLINT db_type_map_to_c_type(uint16 type)
{
    for (int i = 0; i < C_TYPE_MAP_SIZE; i++) {
        if (sql_type_map[i].db_Type == type) {
            return sql_type_map[i].sql_Type;
        }
    }
    return SQL_C_DEFAULT;
}

sql_input_data *build_bind_param(bilist_t *param_list, uint32 pos)
{
    sql_input_data *input_data = NULL;

    input_data = generate_bind_param_instance(param_list->head, pos);
    if (input_data != NULL) {
        return input_data;
    }
    
    input_data = (sql_input_data*)malloc(sizeof(sql_input_data));
    if (input_data != NULL) {
        input_data->index = pos;
        input_data->input_param = NULL;
        input_data->param_size = NULL;
        input_data->param_stream = NULL;
        cm_bilist_add_tail(&input_data->data_list, param_list);
    }
    return input_data;
}

type_size_map size_map[] = {
    {SQL_C_SBIGINT, sizeof(SQLBIGINT)},
    {SQL_C_UBIGINT, sizeof(SQLBIGINT)},
    {SQL_C_STINYINT, sizeof(SQLCHAR)},
    {SQL_C_UTINYINT, sizeof(SQLCHAR)},
    {SQL_C_SSHORT, sizeof(SQLSMALLINT)},
    {SQL_C_USHORT, sizeof(SQLSMALLINT)},
    {SQL_C_SHORT, sizeof(SQLSMALLINT)},
    {SQL_C_FLOAT, sizeof(SQLREAL)},
    {SQL_C_DOUBLE, sizeof(SQLDOUBLE)},
    {SQL_C_NUMERIC, sizeof(SQL_NUMERIC_STRUCT)},
    {SQL_C_SLONG, sizeof(SQLINTEGER)},
    {SQL_C_ULONG, sizeof(SQLINTEGER)},
    {SQL_C_LONG, sizeof(SQLINTEGER)},
    {SQL_C_TYPE_DATE, sizeof(SQL_DATE_STRUCT)},
    {SQL_C_TYPE_TIME, sizeof(SQL_TIME_STRUCT)},
    {SQL_C_TYPE_TIMESTAMP, sizeof(SQL_TIMESTAMP_STRUCT)},
    {SQL_C_BIT, sizeof(SQLCHAR)}
};

const int TYPE_SIZE_MAP_SIZE = sizeof(size_map) / sizeof(size_map[0]);

SQLULEN cal_len_of_sql_type(SQLSMALLINT sql_c_type)
{
    for (int i = 0; i < TYPE_SIZE_MAP_SIZE; i++) {
        if (size_map[i].sql_Type == sql_c_type) {
            return size_map[i].size;
        }
    }
    return 0;
}

SQLULEN cal_column_len(SQLSMALLINT ValueType,
                       SQLULEN ColumnSize,
                       SQLLEN BufferLength,
                       const SQLPOINTER ValuePtr,
                       SQLLEN *StrLen_or_IndPtr)
{
    SQLULEN size = cal_len_of_sql_type(ValueType);
    if (size > 0) {
        return size;
    }
    if (StrLen_or_IndPtr && *StrLen_or_IndPtr == SQL_NTS) {
        return (SQLULEN)strlen((const char *)ValuePtr);
    }
    return BufferLength > ColumnSize ? BufferLength : ColumnSize;
}

void close_odbc_config()
{
    og_timer_t *timer = NULL;

    if (dl_open != NULL) {
        timer = g_timer();
        cm_close_thread(&timer->thread);
        dlclose(dl_open);
        dl_open = NULL;
    }
}