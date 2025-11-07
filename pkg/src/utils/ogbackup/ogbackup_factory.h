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
 * ogbackup_factory.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_factory.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef OGRACDB_OGBACKUP_FACTORY_H
#define OGRACDB_OGBACKUP_FACTORY_H

#include "ogbackup_info.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef ogbak_cmd_t* (* ogbak_cmd_generate_interface)(void);

ogbak_cmd_t* ogbak_factory_generate_cmd(ogbak_topic_t ogbak_topic);

#ifdef __cplusplus
}
#endif

#endif // OGRACDB_OGBACKUP_FACTORY_H
