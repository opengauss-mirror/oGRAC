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
 * convert.h
 *
 *
 * IDENTIFICATION
 * src/driver/ogodbc/convert.h
 */
#ifndef CONVERT_H
#define CONVERT_H

#include "init_exec.h"

SQLRETURN build_fetch_param(statement *stmt, uint32 total_param);
SQLRETURN ograc_sql_bind_param(statement *stmt,
                               SQLUSMALLINT param_num,
                               SQLSMALLINT input_type,
                               SQLSMALLINT value_type,
                               SQLSMALLINT param_type,
                               SQLULEN column_len,
                               SQLSMALLINT dec_number,
                               SQLPOINTER value_ptr,
                               SQLLEN buf_size,
                               SQLLEN *str_size);
SQLRETURN ograc_fetch_data(statement *stmt);
SQLRETURN ograc_get_data(statement *stmt,
                         SQLUSMALLINT col_num,
                         SQLSMALLINT ctype,
                         SQLPOINTER data,
                         SQLLEN buf_size,
                         SQLLEN *strlen);
SQLRETURN ograc_put_data(statement *stmt, SQLPOINTER data, SQLLEN size);
#endif