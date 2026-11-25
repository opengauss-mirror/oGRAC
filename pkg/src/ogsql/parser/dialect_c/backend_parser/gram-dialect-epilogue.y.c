/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

void c_parser_init(base_yy_extra_type *yyext)
{
    parser_init(yyext);
}

static void c_base_yyerror(YYLTYPE * yylloc, core_yyscan_t yyscanner, const char *msg)
{
    base_yyerror(yylloc, yyscanner, msg);
}


#include "scan-backend.inc"
#undef SCANINC
