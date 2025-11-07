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
 * ogbackup_main.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_main.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogbackup.h"
#include "ogbackup_info.h"

int32 main(int32 argc, char *argv[])
{
    SET_UNHANDLED_EXECEPTION_FILTER(OGBACKUP_NAME);

    OG_RETURN_IFERR(cm_regist_signal(SIGQUIT, SIG_IGN));

    if (argc > 1) {
        if (ogbak_process_args(argc, argv) != OG_SUCCESS) {
            ogbackup_show_help();
            exit(EXIT_FAILURE);
        }
    }
    exit(EXIT_SUCCESS);
}
