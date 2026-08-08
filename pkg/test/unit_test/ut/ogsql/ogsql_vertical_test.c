/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co., Ltd. All rights reserved.
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
 * ogsql_vertical_test.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include <string.h>
#include "ogsql_vertical.h"

#define OGSQL_TEST_CHECK(expr) do {                                             \
    if (!(expr)) {                                                              \
        (void)fprintf(stderr, "check failed: %s (%s:%d)\n", #expr, __FILE__, __LINE__); \
        return 1;                                                               \
    }                                                                           \
} while (0)

static text_t MakeText(char *buf)
{
    text_t text;

    text.str = buf;
    text.len = (uint32)strlen(buf);
    return text;
}

static int TestMarkerRecognition(void)
{
    char normal_buf[] = "select 1";
    char marker_buf[] = "select 1;\\v";
    char marker_semicolon_buf[] = "select 1;\\v;";
    char marker_space_buf[] = "select 1; \\V ;";
    char marker_only_buf[] = "\\v;";
    char prefixed_buf[] = "select 1;foo\\v";
    text_t normal = MakeText(normal_buf);
    text_t marker = MakeText(marker_buf);
    text_t marker_semicolon = MakeText(marker_semicolon_buf);
    text_t marker_space = MakeText(marker_space_buf);
    text_t marker_only = MakeText(marker_only_buf);
    text_t prefixed = MakeText(prefixed_buf);

    OGSQL_TEST_CHECK(ogsql_vertical_is_terminated(&normal) == OG_FALSE);
    OGSQL_TEST_CHECK(ogsql_vertical_is_terminated(&marker) == OG_TRUE);
    OGSQL_TEST_CHECK(ogsql_vertical_is_terminated(&marker_semicolon) == OG_TRUE);
    OGSQL_TEST_CHECK(ogsql_vertical_is_terminated(&marker_space) == OG_TRUE);
    OGSQL_TEST_CHECK(ogsql_vertical_is_marker_only(&marker) == OG_FALSE);
    OGSQL_TEST_CHECK(ogsql_vertical_is_marker_only(&marker_semicolon) == OG_FALSE);
    OGSQL_TEST_CHECK(ogsql_vertical_is_marker_only(&marker_only) == OG_TRUE);
    OGSQL_TEST_CHECK(ogsql_vertical_is_marker_only(&prefixed) == OG_FALSE);
    return 0;
}

static int TestMarkerStripping(void)
{
    char marker_buf[] = "select 1;\\v";
    char marker_semicolon_buf[] = "select 1;\\v;";
    char marker_space_buf[] = "select 1; \\V ;";
    text_t marker = MakeText(marker_buf);
    text_t marker_semicolon = MakeText(marker_semicolon_buf);
    text_t marker_space = MakeText(marker_space_buf);

    OGSQL_TEST_CHECK(ogsql_vertical_strip_marker(&marker) == OG_TRUE);
    OGSQL_TEST_CHECK(marker.len == strlen("select 1"));
    OGSQL_TEST_CHECK(strncmp(marker.str, "select 1", marker.len) == 0);

    OGSQL_TEST_CHECK(ogsql_vertical_strip_marker(&marker_semicolon) == OG_TRUE);
    OGSQL_TEST_CHECK(marker_semicolon.len == strlen("select 1"));
    OGSQL_TEST_CHECK(strncmp(marker_semicolon.str, "select 1", marker_semicolon.len) == 0);

    OGSQL_TEST_CHECK(ogsql_vertical_strip_marker(&marker_space) == OG_TRUE);
    OGSQL_TEST_CHECK(marker_space.len == strlen("select 1"));
    OGSQL_TEST_CHECK(strncmp(marker_space.str, "select 1", marker_space.len) == 0);
    return 0;
}

static int TestLineAndPaddingCalculation(void)
{
    OGSQL_TEST_CHECK(ogsql_vertical_text_lines("single") == 1);
    OGSQL_TEST_CHECK(ogsql_vertical_text_lines("line1\nline2") == 2);
    OGSQL_TEST_CHECK(ogsql_vertical_text_lines("line1\nline2\n") == 3);
    OGSQL_TEST_CHECK(ogsql_vertical_label_padding(2, 10) == 9);
    OGSQL_TEST_CHECK(ogsql_vertical_label_padding(10, 10) == 1);
    OGSQL_TEST_CHECK(ogsql_vertical_label_padding(12, 10) == 1);
    OGSQL_TEST_CHECK(ogsql_vertical_value_indent(5) == 8);
    OGSQL_TEST_CHECK(ogsql_vertical_value_indent(10) == 13);
    return 0;
}

static int TestPageCalculation(void)
{
    OGSQL_TEST_CHECK(ogsql_vertical_need_newpage(4, 20, 100) == OG_FALSE);
    OGSQL_TEST_CHECK(ogsql_vertical_need_newpage(84, 20, 100) == OG_TRUE);
    OGSQL_TEST_CHECK(ogsql_vertical_need_newpage(84, 20, 105) == OG_FALSE);
    OGSQL_TEST_CHECK(ogsql_vertical_need_newpage(1000, 20, 0) == OG_FALSE);
    return 0;
}

int main(void)
{
    if (TestMarkerRecognition() != 0 || TestMarkerStripping() != 0 ||
        TestLineAndPaddingCalculation() != 0 || TestPageCalculation() != 0) {
        return 1;
    }
    (void)printf("ogsql_vertical_test passed\n");
    return 0;
}
