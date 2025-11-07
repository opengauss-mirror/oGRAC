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
 * ogbackup.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_OGBACKUP_H
#define OGRACDB_OGBACKUP_H

#include "ogbackup_info.h"
#include "cm_text.h"
#include "cm_defs.h"
#include "cm_signal.h"
#include "cm_coredump.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PRODUCT_NAME "OGRAC"
#define OGBACKUP_NAME "ogbackup"
#define COMMENT_SPACE 25

void ogbackup_show_help(void);

EXTER_ATTACK status_t ogbak_process_args(int32 argc, char** argv);

#ifdef __cplusplus
}
#endif

#endif // end OGRACDB_OGBACKUP_H