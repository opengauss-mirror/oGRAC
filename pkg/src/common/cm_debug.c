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
#include "cm_debug.h"

static void (*g_hook_pre_exit)(void) = NULL;

void cm_set_hook_pre_exit(void (*hook_pre_exit)(void))
{
    g_hook_pre_exit = hook_pre_exit;
}

void cm_pre_exit(void)
{
    if (g_hook_pre_exit != NULL) {
        g_hook_pre_exit();
    }
}

bool8 cm_is_debug_env(void)
{
#ifdef DB_DEBUG_VERSION
    return OG_TRUE;
#else
    return OG_FALSE;
#endif
}
