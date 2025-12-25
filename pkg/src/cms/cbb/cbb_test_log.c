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
 * cms_test_log.c
 *
 *
 * IDENTIFICATION
 * src/cms/cbb/cbb_test_log.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include "cm_timer.h"
#include "cms_param.h"
#include "cbb_test_log.h"

#define LOG_FILE "/opt/ograc/log/cms/run/cbb_lock.log"
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void write_log_to_file(const char *file, int line, const char *format, ...) {
    if (!LOG_OPER_ON) {
        return;
    }
    pthread_mutex_lock(&log_mutex);

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file != NULL) {
        char time_str[OG_MAX_TIME_STRLEN] = { 0 };
        (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", time_str, OG_MAX_TIME_STRLEN);

        fprintf(log_file, "[%s] (%s:%d) ", time_str, file, line);

        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);

        fprintf(log_file, "\n");
        fclose(log_file);
    } else {
        fprintf(stderr, "Error opening log file: %s\n", LOG_FILE);
    }

    pthread_mutex_unlock(&log_mutex);
}