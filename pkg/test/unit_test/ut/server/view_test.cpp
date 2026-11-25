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

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>

extern "C" {
#include "cm_io_record.h"
#include "knl_interface.h"
}

#ifdef __cplusplus
extern "C" {
#endif
status_t vw_syncpoint_stat_open(knl_handle_t se, knl_cursor_t *cursor);
status_t vw_syncpoint_stat_fetch(knl_handle_t session, knl_cursor_t *cursor);
#ifdef __cplusplus
}
#endif


class view_test : public testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

TEST(view_test, test1)
{
    knl_handle_t se = 0;
    knl_cursor_t cursor;
    status_t ret = vw_syncpoint_stat_open(se, &cursor);
    EXPECT_EQ(ret, OG_SUCCESS);
}