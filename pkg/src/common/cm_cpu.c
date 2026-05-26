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
 * cm_cpu.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_cpu.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_error.h"
#include "cm_cpu.h"

static char g_cpu_info_str[CPU_INFO_STR_SIZE];
static int g_cpu_info[CPU_SEG_MAX_NUM][SMALL_RECORD_SIZE];
static int g_cpu_group_num = 0;
static cpu_set_t g_masks[CPU_SEG_MAX_NUM];

int get_cpu_group_num(void)
{
    return g_cpu_group_num;
}

cpu_set_t* get_cpu_masks(void)
{
    return g_masks;
}

int* get_cpu_info(void)
{
    return (int*)g_cpu_info;
}

char *get_g_cpu_info(void)
{
    return g_cpu_info_str;
}

static int init_cpu_mask(char *cpu_info_str, int *cpu_group_num, int cpu_info[CPU_SEG_MAX_NUM][SMALL_RECORD_SIZE])
{
    errno_t errcode;
    if (cpu_info_str[0] == '0' && strlen(cpu_info_str) == 1) {
        return OG_SUCCESS;
    }
    char *p = NULL;
    char *str = strtok_r(cpu_info_str, " ", &p);
    char cpu_group_str[CPU_SEG_MAX_NUM][SMALL_RECORD_SIZE];
    while (str != NULL) {
        errcode = strcpy_s(cpu_group_str[(*cpu_group_num)++], SMALL_RECORD_SIZE, str);
        MEMS_RETURN_IFERR(errcode);
        str = strtok_r(NULL, " ", &p);
    }
    for (int i = 0; i < *cpu_group_num; i++) {
        char *cpu_p = NULL;
        char cpu_group_str_cp[SMALL_RECORD_SIZE];
        errcode = strcpy_s(cpu_group_str_cp, SMALL_RECORD_SIZE, cpu_group_str[i]);
        MEMS_RETURN_IFERR(errcode);
        char *cpu_str = strtok_r(cpu_group_str_cp, ",", &cpu_p);
        int count = 0;
        while (cpu_str != NULL) {
            int s = 0, e = 0;
            int num = sscanf_s(cpu_str, "%d-%d", &s, &e);
            if (num == 1) {
                e = s;
            } else if (num != 2) {
                OG_LOG_RUN_ERR(
            "cpu configuration error, num = %d, s = %d, e = %d, should be like \"0-3\" or \"0\", but \"%s\"", 
                    num, s, e, cpu_str);
                return OG_ERROR;
            }
            for (int j = s; j <= e; j++) {
                cpu_info[i][count++] = j;
            }
            cpu_str = strtok_r(NULL, ",", &cpu_p);
        }
        cpu_info[i][count] = -1;
    }
    return OG_SUCCESS;
}

static void set_cpu_mask(void)
{
    for (int i = 0; i < g_cpu_group_num; i++) {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        for (int j = 0; j < SMALL_RECORD_SIZE; j++) {
            if (g_cpu_info[i][j] >= 0) {
                CPU_SET(g_cpu_info[i][j], &mask);
            } else {
                break;
            }
        }
        g_masks[i] = mask;
    }
}

status_t init_cpu_info(void)
{
    if (init_cpu_mask(g_cpu_info_str, &g_cpu_group_num, g_cpu_info) != 0 || g_cpu_group_num == 0) {
        OG_LOG_RUN_ERR("g_cpu_group_num init error, g_cpu_group_num is %d", g_cpu_group_num);
        return OG_ERROR;
    }
    set_cpu_mask();
    return OG_SUCCESS;
}
