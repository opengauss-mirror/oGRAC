/* -------------------------------------------------------------------------
 * This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
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
 */
#include <stdio.h>
#include "explain/expl_common.h"

int main(void)
{
    expl_helper_t helper = { 0 };
    helper.display_option = OG_GET_MASK(EXPL_COL_TYPE_ID) | OG_GET_MASK(EXPL_COL_TYPE_TABLE);
    helper.fmt_sizes[EXPL_COL_TYPE_ID] = 2;
    helper.fmt_sizes[EXPL_COL_TYPE_OPERATION] = 24;
    helper.fmt_sizes[EXPL_COL_TYPE_TABLE] = 4;

    uint32 width = expl_get_explain_width(&helper);
    if (width != sizeof("| Id | Name |") - 1 || helper.width != width) {
        (void)fprintf(stderr, "unexpected EXPLAIN header width: %u (saved %u)\n", width, helper.width);
        return 1;
    }
    return 0;
}
