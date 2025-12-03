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
* ogconn_inner.h
*
*
* IDENTIFICATION
* src/driver/ogconn/ogconn_inner.h
*
* -------------------------------------------------------------------------
*/
#ifndef __CTCONN_INNER_H__
#define __CTCONN_INNER_H__

#include "ogconn.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
    1. this struct is used with API:ogconn_desc_inner_column_by_id
    2. it used for inner C client tool to get column describe information
    3. 3rd user want to get column describe should use API:ogconn_get_desc_attr to ensure compatibility
*/
typedef struct st_ctconn_inner_column_desc {
    char *name;
    unsigned short size;
    unsigned char precision;
    char scale;
    unsigned short type;
    unsigned char nullable;
    unsigned char is_character;
    unsigned char is_array;
    unsigned char is_jsonb;
    unsigned char auto_increment;
} ogconn_inner_column_desc_t;

int ogconn_connect_inner(ogconn_conn_t pconn, const char *url, const char *user, const char *password, unsigned int
    version);
int ogconn_get_locator_info(ogconn_stmt_t stmt, void *locator, unsigned int *outline, unsigned int *really_sz,
    unsigned int *loc_sz);

int ogconn_read_ori_row(ogconn_stmt_t pstmt, void **ori_row, unsigned int *size);
int ogconn_get_lob_size_by_id(ogconn_stmt_t stmt, unsigned int id, unsigned int *size);
unsigned int ogconn_get_call_version(ogconn_conn_t conn);
unsigned int ogconn_get_shd_node_type(ogconn_conn_t conn);
const char *ogconn_get_version(void);
int ogconn_desc_inner_column_by_id(ogconn_stmt_t pstmt, uint32 id, ogconn_inner_column_desc_t *desc);
int ogconn_column_as_array(ogconn_stmt_t pstmt, uint32 id, char *str, uint32 buf_size);

#ifdef WIN32
void ogconn_set_gts_scn(ogconn_stmt_t *pstmt, unsigned __int64 gts_scn);
void ogconn_get_charset(ogconn_stmt_t stmt, unsigned __int16 *charset_id);
int ogconn_set_charset(ogconn_stmt_t stmt, unsigned __int16 charset_id);
#else
void ogconn_set_gts_scn(ogconn_stmt_t *pstmt, unsigned long long gts_scn);
void ogconn_get_charset(ogconn_stmt_t stmt, unsigned short *charset_id);
int ogconn_set_charset(ogconn_stmt_t pstmt, uint16 charset_id);
#endif

int ogconn_bind_value_len_by_pos(ogconn_stmt_t pstmt, uint32 pos, const void *data, uint16 *ind, bool32 is_trans,
                              bool32 ind_not_null);
int ogconn_sql_set_param_c_type(ogconn_stmt_t pstmt, uint32 pos, bool32 ctype);
int ogconn_get_autotrace_result(ogconn_stmt_t stmt);

#ifdef __cplusplus
}
#endif

#endif
