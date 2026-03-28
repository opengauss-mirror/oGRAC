#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <cstring>
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

TEST_F(TestCtbackup, GetStatementForOgracBuildsFullBackupSqlWithOptions)
{
    ogbak_param_t ogbak_param = {0};
    char parallel[] = "4";
    char compress[] = "lz4";
    char buffer[] = "64M";
    char databases[] = "TEST_DB";
    char dir[] = "/home/backup/oGRAC/";
    char statement[256] = {0};

    ogbak_param.parallelism.str = parallel;
    ogbak_param.parallelism.len = (uint32)strlen(parallel);
    ogbak_param.compress_algo.str = compress;
    ogbak_param.compress_algo.len = (uint32)strlen(compress);
    ogbak_param.buffer_size.str = buffer;
    ogbak_param.buffer_size.len = (uint32)strlen(buffer);
    ogbak_param.databases_exclude.str = databases;
    ogbak_param.databases_exclude.len = (uint32)strlen(databases);
    ogbak_param.skip_badblock = OG_TRUE;

    ASSERT_EQ(get_statement_for_ograc(&ogbak_param, sizeof(statement), statement, databases, dir), OG_SUCCESS);
    ASSERT_STREQ(statement, "BACKUP DATABASE INCREMENTAL LEVEL 0 FORMAT '/home/backup/oGRAC/' as lz4 compressed "
                            "backupset  PARALLELISM 4 EXCLUDE FOR TABLESPACE TEST_DB BUFFER SIZE 64M SKIP "
                            "BADBLOCK;");
}
