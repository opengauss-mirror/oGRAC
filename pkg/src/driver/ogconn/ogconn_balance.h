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
 * ogconn_balance.h
 *
 *
 * IDENTIFICATION
 * src/driver/ogconn/ogconn_balance.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CTCONN_BALANCE_H__
#define __CTCONN_BALANCE_H__

#include "cm_spinlock.h"
#include "cm_text.h"
#include "ogconn_common.h"
#include "cm_encrypt.h"
#include "cm_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODE_LIST_EXTEND_SIZE 8
#define HEART_BEAT_CHECK_INTERVEL 3000
#define HEART_BEAT_TRY_TIMES 3
#define HEART_BEAT_TRY_INTERVEL 100
#define HEART_BEAT_CONNECT_TIMEOUT 30
#define HEART_BEAT_SOCKET_TIMEOUT 10
#define OG_MAX_SSL_KEYPWD (OG_MAX_CIPHER_LEN + 4)
#define OG_MAX_FACTOR_KEY_LEN (OG_MAX_FACTOR_KEY_STR_LEN + 4)
#define OG_MAX_LOCAL_KEY_LEN (OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4)

typedef enum en_node_status {
    NODE_STATUS_UNKNOWN = 0,
    NODE_STATUS_ONLINE,
    NODE_STATUS_OFFLINE,
    NODE_STATUS_DELETED,
    NODE_STATUS_QUERYTIMEOUT,
    NODE_STATUS_UNSTABLE,
    NODE_STATUS_ROUTE_CONFLICT,
} node_status_t;

/* check_node */
typedef struct st_check_entry {
    text_t ip_port;
    ogconn_conn_t conn;
    bool32 conn_valid;
} check_entry_t;

/* node information */
typedef struct st_node_info {
    spinlock_t lock;
    text_t node_url;
    volatile uint32 ref_count;
    double weight;
    node_status_t status;
    check_entry_t *check_entry; // for heart beat, never parallel
} node_info_t;

/* connection information */
typedef struct st_cluster_info {
    spinlock_t lock;
    char user[OG_NAME_BUFFER_SIZE];
    char cipher[OG_PARAM_BUFFER_SIZE];
    char local_key[OG_MAX_LOCAL_KEY_LEN];
    char factor_key[OG_FILE_NAME_BUFFER_SIZE];
    uint32 cipher_len;
    ogconn_ssl_mode_t ssl_mode;
    char ssl_ca[OG_FILE_NAME_BUFFER_SIZE + 1];
    char ssl_cert[OG_FILE_NAME_BUFFER_SIZE + 1];
    char ssl_key[OG_FILE_NAME_BUFFER_SIZE + 1];
    char ssl_crl[OG_FILE_NAME_BUFFER_SIZE + 1];
    char ssl_cipher[OG_PARAM_BUFFER_SIZE + 1];
    char ssl_keypwd[OG_PASSWORD_BUFFER_SIZE + 1];
    uint32 keypwd_len;
} cluster_info_t;

/* clusterUrl */
typedef struct st_cluster {
    spinlock_t lock;
    text_t cluster_url;
    list_t node_list;
    cluster_info_t cluster_info;
} cluster_t;

/* cluster_manager */
typedef struct st_cluster_manager {
    // cluster global infos
    spinlock_t lock;
    volatile bool32 inited;
    volatile uint32 cluster_count; // real cluster count
    list_t clusters;
    list_t check_pool;
    thread_t heart_thread;
    volatile bool32 thread_process;
} cluster_manager_t;

status_t clt_cluster_connect(clt_conn_t *conn, text_t *cls_url, const char *user, const char *password,
                             const char *ssl_keypwd, const char *tenant);
void decrease_cluster_count(clt_conn_t *conn);
#endif