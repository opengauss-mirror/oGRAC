#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include "ogbackup.h"
#include "ogbackup_backup.h"
#include "ogbackup_common.h"
#include "ogbackup_info.h"
#include "ogbackup_prepare.h"
#include "ogbackup_archivelog.h"
#include "ogbackup_factory.h"

using namespace std;

class TestCtbackup : public testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
        GlobalMockObject::reset();
    }
};
