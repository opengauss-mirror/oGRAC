/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef __OGSQL_LOAD_H__
#define __OGSQL_LOAD_H__

#include "ogsql.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup OGSQL_CMD
* @brief The API of `ogsql` command interface
* @{ */
void ogsql_show_loader_opts(void);
status_t ogsql_load(text_t *cmd_text);

/** @} */  // end group OGSQL_CMD

#ifdef __cplusplus
}
#endif

#endif  // end __OGSQL_LOAD_H__