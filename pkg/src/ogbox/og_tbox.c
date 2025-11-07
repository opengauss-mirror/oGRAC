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
 * og_tbox.c
 *
 *
 * IDENTIFICATION
 * src/ogbox/og_tbox.c
 *
 * -------------------------------------------------------------------------
 */
#include "og_tbox_module.h"
#include "cm_date.h"
#include "og_miner.h"
#include "og_repair.h"
#include "og_func.h"
#include "cm_kmc.h"
#include "og_tbox.h"
#include "og_tbox_audit.h"
#ifdef WIN32
#define cm_strdup _strdup
#else
#define cm_strdup strdup
#endif

#ifdef WIN32
const char *oGRACd_get_dbversion()
{
    return "NONE";
}
#endif

static void usage(void)
{
    printf("ogbox contains cminer, crepair and cfunc tools for oGRAC.\n"
           "\n"
           "Usage:\n"
           "  ogbox -T [cminer | crepair | cfunc] [OPTIONS]\n"
           "\nRequired options:\n"
           "  -T TOOLNAME  the cminer tool, crepair tool or cfunc tool to use\n");

    printf("\nCommon options:\n"
           "  --help, -h       show this help, then exit\n"
           "  --version, -V    output version information, then exit\n"
           "\nExamples:\n"
           "  ogbox --help\n"
           "  ogbox -T cminer  --help\n"
           "  ogbox -T crepair --help\n"
           "  ogbox -T cfunc   --help\n"
           "  ogbox -T cminer  -l XXX\n"
           "  ogbox -T crepair -f XXX -s XXX -t XXX\n"
           "  ogbox -T cfunc   -f int2pageid XXX\n");
}

static status_t tbox_option_t_check(int argc, char *argv[], char **tool_name)
{
    int32 c = miner_getopt(argc, argv, "T:");
    while (c != -1) {
        if (c == 'T') {
            if (*tool_name != NULL) {
                printf("must secify cminer or crepair or cfunc to use\n");
                CM_FREE_PTR(*tool_name);
                return OG_ERROR;
            }
            *tool_name = (char *)cm_strdup(g_gm_optarg);
            break;
        } else {
            printf("try use \"--help\" for more information.\n");
            CM_FREE_PTR(*tool_name);
            return OG_ERROR;
        }
    }

    if (*tool_name == NULL) {
        printf("try use \"--help\" for more information.\n");
        return OG_ERROR;
    }
    
    return OG_SUCCESS;
}

static status_t tbox_call_miner(int argc, char *argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    date_t c_start;
    date_t c_end;
    c_start = cm_now();
    if (miner_execute(argc, argv) != OG_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("Ctbox miner error, OG-%05d, %s\n", err_code, err_msg);
        return OG_ERROR;
    }
    c_end = cm_now();
    printf("Ctbox miner use time %f s\n", (double)(c_end - c_start) / MS_PER_SEC);
    return OG_SUCCESS;
}

static status_t tbox_call_repair(int argc, char *argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    status_t status = repair_execute(argc, argv);
    if (status != OG_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("Ctbox repair error, OG-%05d, %s\n", err_code, err_msg);
    }
    tbox_write_audit_log(argc, argv, err_code);
    return status;
}

static status_t tbox_call_func(int argc, char *argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    if (func_execute(argc, argv) != OG_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("Ctbox func error, OG-%05d, %s\n", err_code, err_msg);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t tbox_exe_tool_by_tname(int argc, char *argv[], char *tool_name)
{
    if (strcmp(tool_name, "cminer") == 0) {
        return tbox_call_miner(argc, argv);
    } else if (strcmp(tool_name, "crepair") == 0) {
        return tbox_call_repair(argc, argv);
    } else if (strcmp(tool_name, "cfunc") == 0) {
        return tbox_call_func(argc, argv);
    } else {
        printf("invalid tool name : \"%s\"\n", tool_name);
        return OG_ERROR;
    }
}


EXTER_ATTACK int main(int argc, char *argv[])
{
    char *tool_name = NULL;

    if (argc > 1) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "-h") == 0) {
            usage();
            return OG_SUCCESS;
        }

        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
            tbox_print_version();
            return OG_SUCCESS;
        }

        if (strcmp(argv[1], "-T") != 0) {
            printf("invalid argument : \"%s\"", argv[1]);
            printf("the first option must be -T.\n");
            return OG_SUCCESS;
        }
    }

    status_t ret = tbox_option_t_check(argc, argv, &tool_name);
    if (ret == OG_SUCCESS) {
        cm_str_lower(tool_name);
        ret = tbox_exe_tool_by_tname(argc, argv, tool_name);
    }

    CM_FREE_PTR(tool_name);
    return ret;
}
