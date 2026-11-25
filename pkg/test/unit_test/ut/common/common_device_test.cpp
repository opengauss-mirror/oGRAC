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

extern "C"
{
#include "cm_device.h"
#include "cm_file.h"
#include "cm_dbs_ulog.h"
#include "cm_dbs_pgpool.h"
#include "cm_dbs_map.h"
#include "cm_io_record.h"
}

using namespace std;

class CMDeviceTest : public testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
        GlobalMockObject::reset();
        record_io_stat_init();
    }
};

TEST_F(CMDeviceTest, CreateDeviceTest)
{
    MOCKER(cm_dbs_pg_create).stubs().will(returnValue(OG_SUCCESS));
    status_t ret = cm_create_device("TEST", DEV_TYPE_PGPOOL, 0, NULL);
    GlobalMockObject::reset();
    record_io_stat_print();
}