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
#include "cms_work.h"
#include "cms_disk_lock.h"
#include "cm_malloc.h"
#include "cm_file.h"

using namespace std;

extern "C" {
extern status_t cms_disk_lock_init_file(cms_disk_lock_t* lock, 
                    const char* dev, uint64 offset, int64 inst_id, bool32 is_write);
}
class CmsDiskLockTest : public testing::Test {
protected:
    void InitGlobalCmsParam()
    {
    }
    void UninitGlobalCmsParam()
    {
    }
    void SetUp() override
    {
        InitGlobalCmsParam();
    }
    void TearDown() override
    {
        UninitGlobalCmsParam();
        GlobalMockObject::reset();
    }  
};

TEST_F(CmsDiskLockTest, lock_init_fail)
{
    cms_disk_lock_t lock = {0};
    int64 node_id = 0;
    lock.flock = malloc(sizeof(cms_flock_t));
    int ret = cms_disk_lock_init_file(&lock, "./fake", 0, node_id, false);
    EXPECT_EQ(ret, OG_SUCCESS);
}