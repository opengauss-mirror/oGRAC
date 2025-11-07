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
 * ogbackup.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogbackup_module.h"
#include "ogbackup.h"
#include "ogbackup_factory.h"
#include "ogbackup_common.h"

#ifdef WIN32
const char *oGRACd_get_dbversion()
{
    return "NONE";
}
#else

extern const char* oGRACd_get_dbversion(void);

#endif

static void ogbackup_show_version(void)
{
    printf("%s\n", oGRACd_get_dbversion());
}

static void ogbackup_show_usage(void)
{
    printf("Usage: [ogbackup --backup | ogbackup --prepare | ogbackup --archivelog\n");
    printf("     | ogbackup --query-incremental-mode | ogbackup --purge-logs\n");    
    printf("                                                                | ogbackup --help]  [OPTIONS]\n");
    printf("Options:\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");
    printf("--target-dir=#           This option specifies the destination directory for the backup.\n");
    printf("%*s%s", COMMENT_SPACE, "", "This option specifies the source directory for "
                                            "prepare or query-incremental-mode.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --prepare | --query-incremental-mode.\n");
    printf("--socket=#               This option specifies the socket to use when connecting to "
                                        "the local database server.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --copy-back\n");
    printf("--incremental            This option tells ogbackup to create an incremental backup.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");
    printf("--cumulative             This option specifies the incremental backup type to cumulative. "
                                        "Note: the type can be switched only after a new full backup.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup --incremental\n");
    printf("--databases-exclude=#    Excluding databases based on name.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");
    printf("--parallel=#             This option specifies the number of threads to use "
                                        "for backup, prepare or copy-back.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --prepare | --copy-back\n");

    printf("--compress=lz4           This option tells ogbackup to compress output data, "
                                    "only can choose lz4 compression algorithm.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");

    printf("--decompress             This option tells ogbackup to decompress backup data, "
                                    "lz4 is chosen by default.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --prepare\n");
    printf("--force-ddl              This option tells ogbackup to ignore the SQL error when reconciel.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --reconciel\n");
    printf("--skip-badblock          This option tells ogbackup to ignore badblock in datafiles when backup.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");
    printf("--repair-type            This option tells ogbackup to choose repair-type for badblock in datafiles.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --restore.\n");
}

void ogbackup_show_help(void)
{
    ogbackup_show_version();
    ogbackup_show_usage();
}

static inline ogbak_topic_t ogbak_parse_topic(char** argv, int32 argc)
{
    if (cm_str_equal(argv[1], "-v") || cm_str_equal(argv[1], "--version")) {
        return OGBAK_VERSION;
    }
    if (cm_str_equal(argv[1], "-h") || cm_str_equal(argv[1], "--help")) {
        return OGBAK_HELP;
    }

    if (cm_str_equal(argv[1], OGBAK_ARG_BACKUP)) {
        return OGBAK_BACKUP;
    }

    if (cm_str_equal(argv[1], OGBAK_ARG_PREPARE)) {
        return OGBAK_PREPARE;
    }

    if (cm_str_equal(argv[1], OGBAK_ARG_ARCHIVELOG)) {
        return OGBAK_ARCHIVE_LOG;
    }

    if (cm_str_equal(argv[1], OGBAK_ARG_QUERY_INCREMENTAL_MODE)) {
        return OGBAK_QUERY_INCREMENTAL_MODE;
    }

    if (cm_str_equal(argv[1], OGBAK_ARG_PURGE_LOGS)) {
        return OGBAK_PURGE_LOGS;
    }
    return OGBAK_INVALID;
}

EXTER_ATTACK status_t ogbak_process_args(int32 argc, char** argv)
{
    if (argc > OGBACKUP_MAX_PARAMETER_CNT) {
        printf("The current number of ogbackup parameters exceeds %u\n", OGBACKUP_MAX_PARAMETER_CNT);
        return OG_ERROR;
    }
    ogbak_topic_t topic = ogbak_parse_topic(argv, argc);
    if (topic == OGBAK_INVALID) {
        return OG_ERROR;
    }
    if (topic == OGBAK_HELP) {
        ogbackup_show_help();
        return OG_SUCCESS;
    }
    if (topic == OGBAK_VERSION) {
        ogbackup_show_version();
        return OG_SUCCESS;
    }
    ogbak_cmd_t* ogbak_cmd = ogbak_factory_generate_cmd(topic);
    if (ogbak_cmd == NULL) {
        printf("[ogbackup]failed to generate ogbak_cmd!\n");
        return OG_ERROR;
    }
    ogbak_param_t empty_ogbak_param = {0};
    ogbak_cmd->ogbak_param = &empty_ogbak_param;
    if (ogbak_cmd->parse_args(argc, argv, ogbak_cmd->ogbak_param) != OG_SUCCESS) {
        printf("cmd %s parse args error!\n", ogbak_cmd->cmd_name);
        free_input_params(ogbak_cmd->ogbak_param);
        free(ogbak_cmd);
        return OG_ERROR;
    }
    if (ogbak_cmd->do_exec(ogbak_cmd->ogbak_param) != OG_SUCCESS) {
        printf("cmd %s execute error!\n", ogbak_cmd->cmd_name);
        free(ogbak_cmd);
        return OG_ERROR;
    }
    free(ogbak_cmd);
    return OG_SUCCESS;
}
