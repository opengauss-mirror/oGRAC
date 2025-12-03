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
 * ogbackup_factory.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_factory.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogbackup_module.h"
#include "ogbackup_factory.h"
#include "ogbackup_backup.h"
#include "ogbackup_prepare.h"
#include "ogbackup_archivelog.h"
#include "ogbackup_query.h"
#include "ogbackup_purge_logs.h"

const char* g_ogbak_cmd_name[] = {
    [OGBAK_INVALID] = "invalid",
    [OGBAK_VERSION] = "version",
    [OGBAK_HELP] = "help",
    [OGBAK_BACKUP] = "backup",
    [OGBAK_PREPARE] = "prepare",
    [OGBAK_ARCHIVE_LOG] = "archivelog",
    [OGBAK_QUERY_INCREMENTAL_MODE] = "query_incremental_mode",
    [OGBAK_PURGE_LOGS] = "purge_logs"
};

ogbak_cmd_generate_interface g_ogbak_cmd_generate_set[] = {
    [OGBAK_BACKUP] = (ogbak_cmd_generate_interface) ogbak_generate_backup_cmd,
    [OGBAK_PREPARE] = (ogbak_cmd_generate_interface) ogbak_generate_prepare_cmd,
    [OGBAK_ARCHIVE_LOG] = (ogbak_cmd_generate_interface) ogbak_generate_archivelog_cmd,
    [OGBAK_QUERY_INCREMENTAL_MODE] = (ogbak_cmd_generate_interface) ogbak_generate_query_incremental_mode_cmd,
    [OGBAK_PURGE_LOGS] = (ogbak_cmd_generate_interface) ogbak_generate_purge_logs_cmd
};

ogbak_cmd_t* ogbak_factory_generate_cmd(ogbak_topic_t ogbak_topic)
{
    ogbak_cmd_generate_interface cmd_generate = g_ogbak_cmd_generate_set[ogbak_topic];
    ogbak_cmd_t* cmd = cmd_generate();
    if (cmd == NULL) {
        printf("[ogbackup]failed to generate cmd!\n");
        return (ogbak_cmd_t*)NULL;
    }
    cmd->ogbak_topic = ogbak_topic;
    cmd->cmd_name = g_ogbak_cmd_name[ogbak_topic];
    return cmd;
}
