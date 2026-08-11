/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * openGauss is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * ---------------------------------------------------------------------------------------
 *
 * bison_gram_common.h
 *
 * IDENTIFICATION
 *        pkg/src/ogsql/parser/bison_gram_common.h
 *
 * ---------------------------------------------------------------------------------------
 */
#ifndef BISON_GRAM_COMMON_H
#define BISON_GRAM_COMMON_H

#include "cm_error.h"

/* Shared generated-parser glue. */
#define YYLLOC_DEFAULT(Current, Rhs, N) \
    do { \
        if (N) \
            (Current) = (Rhs)[1]; \
        else \
            (Current) = (Rhs)[0]; \
    } while (0)

#define YYMALLOC(size) core_yyalloc(size, yyscanner)
#define YYFREE(ptr) core_yyfree(ptr, yyscanner)

#ifdef YYLEX_PARAM
#define YYLEX yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX yylex(&yylval, &yylloc, yyscanner)
#endif

/* Evaluate ret once and preserve the error raised by the callee. */
#define BISON_ABORT_IFERR(ret)                            \
    do {                                                  \
        status_t _status_ = (ret);                        \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) {  \
            cm_set_error_pos(__FILE__, __LINE__);         \
            YYABORT;                                      \
        }                                                 \
    } while (0)

#endif
