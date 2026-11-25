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
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "securec.h"
#include "cms_log_module.h"
#include "cbb_test_log.h"

void write_log_to_file(const char *file, int line, const char *format, ...)
{
    char msg[OG_MAX_LOG_CONTENT_LENGTH] = { 0 };
    va_list args;
    int32 ret;

    if (!LOG_OPER_ON || format == NULL) {
        return;
    }

    va_start(args, format);
    ret = vsnprintf_s(msg, sizeof(msg), sizeof(msg) - 1, format, args);
    va_end(args);
    if (ret < 0) {
        return;
    }

    cm_write_normal_log(LOG_OPER, LEVEL_INFO, (char *)file, (uint32)line, (int)MODULE_ID, OG_TRUE, "%s", msg);
}