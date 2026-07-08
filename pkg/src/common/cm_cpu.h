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
 * cm_cpu.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_cpu.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_CPU_H__
#define __CM_CPU_H__

#include "cm_defs.h"

#ifdef WIN32
#else
#include <sched.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CPU_INFO_STR_SIZE 10240
#define CPU_SEG_MAX_NUM 64
#define SMALL_RECORD_SIZE 128

int get_cpu_group_num(void);
cpu_set_t* get_cpu_masks(void);
int* get_cpu_info(void);
char *get_g_cpu_info(void);
status_t init_cpu_info(void);

#ifdef __cplusplus
}
#endif

#endif
