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
#include <stddef.h>
#include <stddef.h>

#include "cm_types.h"
#include "keywords.h"

/* ScanKeywordList lookup.data.for.SQL.keywords. */
#include "kwlist_d.h"
#include "dialect_a/backend_parser/kwlist_a_d.h"
#include "dialect_b/backend_parser/kwlist_b_d.h"
#include "dialect_c/backend_parser/kwlist_c_d.h"

#define OG_KEYWORD(kwname,value,category) category,

const uint8 ScanKeywordCategories[SCANKEYWORDS_NUM_KEYWORDS] = {
    #include "kwlist.h"
};

#undef OG_KEYWORD

