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
 * statement.h
 *
 *
 * IDENTIFICATION
 * src/driver/ogodbc/statement.h
 */
#ifndef STATEMENT_H
#define STATEMENT_H

#include "connection.h"

#define STMT_ERROR 1
#define LIST_STEP 32
#define LIST_RANGE 32768

SQLRETURN ograc_AllocStmt(SQLHDBC hdbc, SQLHSTMT *phstmt);
void ograc_free_stmt(statement *stmt);
SQLRETURN ograc_set_stmt_attr(statement *StatementHandle, SQLINTEGER Attribute,
                        SQLPOINTER Value, SQLINTEGER StringLength);
#endif