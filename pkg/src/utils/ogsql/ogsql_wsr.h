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
 * ogsql_wsr.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogsql/ogsql_wsr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OGSQL_WSR_H__
#define __OGSQL_WSR_H__

#include "ogsql.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EWSR_SQL_HTML_ID = 900,
    EWSR_LONGSQL_HTML_ID = 1000,
} WSR_HTML_ID;

status_t ogsql_wsr(text_t *cmd_text);

#ifdef __cplusplus
}
#endif

#endif