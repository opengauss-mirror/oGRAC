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
 * execute.h
 *
 *
 * IDENTIFICATION
 * src/driver/ogodbc/execute.h
 */
#ifndef EXECUTE_H
#define EXECUTE_H

#include "statement.h"

void clean_env_handle(SQLHENV henv);
void clean_conn_handle(SQLHDBC hdbc);
status_t set_conn_attr(connection_class *conn, SQLPOINTER Value, SQLINTEGER StringLength, int32 attr);
SQLRETURN ograc_prepare(statement *stmt, const SQLCHAR *text);
SQLRETURN ograc_execute(statement *stmt);
#endif