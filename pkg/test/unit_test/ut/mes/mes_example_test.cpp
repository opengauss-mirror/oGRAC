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

#define __LINUX_USER__
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <stdint.h>
extern "C"
{
#include  "cm_defs.h"
#include "mes_func.h"
#include "cm_error.h"
}

using namespace std;

extern mes_instance_t g_mes;

class MesTest : public testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

TEST_F(MesTest, mes_connection_test)
{
    bool32 ret = OG_ERROR;
    uint32 inst_id = 0;
    char *ip = NULL;
    uint16 port = 0;
    ret = mes_connection_ready(inst_id);
    EXPECT_EQ(OG_SUCCESS, ret);   
}