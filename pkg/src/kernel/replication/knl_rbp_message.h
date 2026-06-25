/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * Cantian is licensed under Mulan PSL v2.
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
 * knl_rbp_message.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/knl_rbp_message.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __KNL_RBP_MESSAGE_H__
#define __KNL_RBP_MESSAGE_H__

#include "knl_interface.h"
#include "knl_log.h"

#define RBP_BATCH_PAGE_NUM  100
#define RBP_PAGE_SIZE       8192
#define RBP_MSG_LEN         64
#define RBP_BUFFER_COUNT    8

/* The message protocol format between Kernel and RBP */
typedef struct st_rbp_msg_hdr {
    uint32 msg_type;
    uint32 msg_length; /* length of the message header plus message content */
    uint32 queue_id;
    int32 msg_fd;
} rbp_msg_hdr_t;

typedef struct st_rbp_msg_ack {
    rbp_msg_hdr_t header;
    uint32 ack_type;
    uint32 ack_data;
} rbp_msg_ack_t;

#define RBP_SET_MSG_HEADER(msgptr, type, length, fd)   \
    do { \
        ((rbp_msg_hdr_t*) (msgptr))->msg_type = (type);     \
        ((rbp_msg_hdr_t*) (msgptr))->msg_length = (length); \
        ((rbp_msg_hdr_t*) (msgptr))->msg_fd = (int32)(fd);         \
    } while (0)

#define RBP_MSG_TYPE(msgptr) \
    (((const rbp_msg_hdr_t*)(msgptr))->msg_type)

/* Kernel request message to RBP */
#define RBP_REQ_PAGE_READ           20000   /* Kernel read page from RBP */
#define RBP_REQ_PAGE_WRITE          20100   /* Kernel write page to RBP */
#define RBP_REQ_BATCH_PAGE_READ     21000   /* background worker read batch page from RBP */
#define RBP_REQ_READ_META_CHUNK     22000   /* read page_id/page_lsn metadata snapshot from RBP */
#define RBP_REQ_BATCH_PAGE_READ_SELECTED 23000 /* batch read selected page ids from RBP */
#define RBP_REQ_READ_CKPT           31000   /* get rbp recover point */
#define RBP_REQ_NOTIFY_MSG          41000
#define RBP_REQ_SHAKE_HAND          51000
#define RBP_REQ_CLOSE_CONN          61000

/* read rbp result status values */
#define RBP_READ_RESULT_OK          0
#define RBP_READ_RESULT_NOPAGE      1
#define RBP_READ_RESULT_ERROR       2

/* writer_inst_id / writer_global_seq identify multi-writer page versions for peer RBPS. */
typedef struct st_rbp_page_item {
    page_id_t page_id;
    uint32 session_id;
    uint32 writer_inst_id;
    uint64 writer_global_seq;
    log_point_t rbp_trunc_point;
    log_point_t rbp_lrp_point;
    char block[RBP_PAGE_SIZE];  /* page content */
} rbp_page_item_t;

/* Kernel read page from RBP */
typedef struct st_rbp_read_req {
    rbp_msg_hdr_t header;
    page_id_t page_id;
    uint16 buf_pool_id;
    uint16 reserved[3];
} rbp_read_req_t;

/* background worker read page from RBP */
typedef struct st_rbp_batch_read_req {
    rbp_msg_hdr_t header;
    log_point_t rbp_skip_point;  // we only pull rbp pages which lrp_point >= rbp_skip_point
} rbp_batch_read_req_t;

#define RBP_META_CHUNK_NUM 1024

typedef struct st_rbp_meta_item {
    page_id_t page_id;
    uint64 page_lsn;
    uint32 page_pcn;
    uint32 source_node;
    uint32 queue_id;
    uint32 reserved;
} rbp_meta_item_t;

typedef struct st_rbp_read_meta_req {
    rbp_msg_hdr_t header;
    uint64 epoch;
    uint64 cursor;
    uint32 max_count;
    uint32 reserved;
} rbp_read_meta_req_t;

typedef struct st_rbp_read_meta_resp {
    rbp_msg_hdr_t header;
    uint32 result;         /* RBP_READ_RESULT_XXX */
    uint32 count;
    uint64 epoch;
    uint64 cursor;
    uint64 next_cursor;
    uint64 total_count;
    bool32 done;
    uint32 reserved;
    rbp_meta_item_t items[RBP_META_CHUNK_NUM];
} rbp_read_meta_resp_t;

typedef struct st_rbp_selected_page_req {
    page_id_t page_id;
    uint64 selected_lsn;
} rbp_selected_page_req_t;

typedef struct st_rbp_batch_selected_read_req {
    rbp_msg_hdr_t header;
    uint32 count;
    uint32 reserved;
    rbp_selected_page_req_t pages[RBP_BATCH_PAGE_NUM];
} rbp_batch_selected_read_req_t;

/* Kernel write page to RBP */
typedef struct st_rbp_write_req {
    rbp_msg_hdr_t header;
    uint32 page_num;
    log_point_t batch_begin_point;
    log_point_t batch_trunc_point;
    log_point_t batch_lrp_point;
    rbp_page_item_t pages[RBP_BATCH_PAGE_NUM];
    uint32 page_num_tail;   // for validate page_num, page_num_tail must equel page_num
} rbp_write_req_t;

typedef struct st_rbp_read_ckpt_req {
    rbp_msg_hdr_t header;
    bool32 check_end_point;
    log_point_t aly_end_point;  /* the redo analysis end point */
} rbp_read_ckpt_req_t;


typedef struct st_rbp_read_resp {
    rbp_msg_hdr_t header;
    uint32 result;         /* RBP_READ_RESULT_XXX */
    uint32 unused;
    page_id_t pageid;
    log_point_t rbp_trunc_point;
    char block[RBP_PAGE_SIZE];  /* used for RBP to send page */
} rbp_read_resp_t;

typedef struct st_rbp_batch_read_resp {
    rbp_msg_hdr_t header;
    uint32 result;         /* RBP_READ_RESULT_XXX */
    uint32 count;
    char msg[RBP_MSG_LEN];
    rbp_page_item_t pages[RBP_BATCH_PAGE_NUM];
} rbp_batch_read_resp_t;

typedef struct st_rbp_read_ckpt_resp {
    rbp_msg_hdr_t header;
    bool32 rbp_unsafe;
    log_point_t begin_point;
    log_point_t rcy_point;
    log_point_t lrp_point;
    uint64 max_lsn;
    char unsafe_reason[RBP_MSG_LEN];
} rbp_read_ckpt_resp_t;

typedef enum en_rbp_notify_msg {
    MSG_RBP_INVALID = 0,
    MSG_RBP_READ_BEGIN,
    MSG_RBP_READ_END,
    MSG_RBP_HEART_BEAT,
} rbp_notify_msg_e;

typedef enum en_rbp_notify_ack {
    ACK_RBP_INVALID = 0,
    ACK_RBP_READ_BEGIN,
} rbp_notify_ack_e;

typedef struct st_rbp_db_status {
    char local_host[CM_MAX_IP_LEN];
    repl_role_t db_role;
    db_status_t db_open;
} rbp_db_status_t;

typedef struct st_rbp_notify_req {
    rbp_msg_hdr_t header;
    rbp_notify_msg_e msg;
    rbp_db_status_t db_stat;
} rbp_notify_req_t;

typedef struct st_rbp_shake_hand_req {
    rbp_msg_hdr_t header;
    uint32 queue_id;
    bool32 is_temp;
    bool32 is_standby;
    uint32 unused;
} rbp_shake_hand_req_t;

typedef struct st_rbp_shake_hand_resp {
    rbp_msg_hdr_t header;
    uint32 queue_id;
    bool32 is_temp;
} rbp_shake_hand_resp_t;

#endif
