/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
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
 * cms_disk_usage.h
 *
 * IDENTIFICATION
 * src/cms/cms/cms_disk_usage.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_DISK_USAGE_H
#define CMS_DISK_USAGE_H

#include "cm_thread.h"
#include "cms_msg_def.h"

#ifdef __cplusplus
extern "C" {
#endif

void cms_disk_usage_check_entry(thread_t *thread);
void CmsDiskUsageGetSnapshot(CmsDiskUsageSnapshotT *snapshot);
void CmsDiskUsageGetReadonlyConfig(CmsDiskReadonlyConfigInfoT *config);
status_t cms_disk_usage_update_config(const char *key, const char *value, char *err_info, uint32 err_len);
status_t cms_disk_usage_update_readonly_config(const char *key, const char *value, char *err_info, uint32 err_len);
status_t cms_disk_usage_recover_readwrite_now(char *err_info, uint32 err_len);

#ifdef __cplusplus
}
#endif

#endif
