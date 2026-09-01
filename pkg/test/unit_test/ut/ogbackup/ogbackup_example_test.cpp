#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __cplusplus
#ifndef _Atomic
#define _Atomic
#endif
#ifndef _Bool
#define _Bool bool
#endif
#endif
#include "ogbackup.h"
#include "ogbackup_backup.h"
#include "ogbackup_common.h"
#include "ogbackup_info.h"
#include "ogbackup_prepare.h"
#include "ogbackup_archivelog.h"
#include "ogbackup_factory.h"
#include "ogbackup_restore.h"
#include "ogbackup_scheme_d.h"
#include "bak_ctrl_restore.h"
#include "bak_offline_decoder.h"
#include "bak_page_restore.h"
#include "cm_device.h"
#include "bak_common.h"
#include "knl_page.h"
#include "knl_db_ctrl.h"
#include "knl_db_ctrl_persistent.h"
#include "dtc_database.h"
#include "cm_checksum.h"
#include "cm_encrypt.h"
#include "knl_compress.h"
#include "openssl/evp.h"
#include <pwd.h>
#include <ctime>
#include <cstdlib>

using namespace std;

class TestCtbackup : public testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
        ogbak_restore_clear_scheme_d_unit_test_hooks();
        (void)unsetenv("OGRAC_SCHEME_D_ALLOW_DISPOSABLE_WAIVER");
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

static void RemoveTree(const std::string &path)
{
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        (void)remove(path.c_str());
        return;
    }
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        std::string child = path + "/" + entry->d_name;
        struct stat st;
        if (lstat(child.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            RemoveTree(child);
        } else {
            (void)remove(child.c_str());
        }
    }
    (void)closedir(dir);
    (void)rmdir(path.c_str());
}

static std::string MakeTempDir(const char *prefix)
{
    char tmpl[128];
    (void)snprintf(tmpl, sizeof(tmpl), "/tmp/%sXXXXXX", prefix);
    char *dir = mkdtemp(tmpl);
    EXPECT_NE(dir, nullptr);
    return std::string(dir == nullptr ? "/tmp/ogbackup_bad_tmp" : dir);
}

static void MakeDir(const std::string &path)
{
    ASSERT_EQ(mkdir(path.c_str(), 0700), 0);
}

static void WriteTextFile(const std::string &path, const std::string &content)
{
    FILE *fp = fopen(path.c_str(), "w");
    ASSERT_NE(fp, nullptr);
    ASSERT_EQ(fwrite(content.data(), 1, content.size(), fp), content.size());
    ASSERT_EQ(fclose(fp), 0);
}

static void WriteBinaryFile(const std::string &path, const void *data, size_t size)
{
    FILE *fp = fopen(path.c_str(), "wb");
    ASSERT_NE(fp, nullptr);
    ASSERT_EQ(fwrite(data, 1, size, fp), size);
    ASSERT_EQ(fclose(fp), 0);
}

static void CalcBackupsetHeadChecksum(bak_head_t *head, uint32 size)
{
    uint16 headChecksum;
    uint16 fileChecksum;
    head->attr.head_checksum = OG_INVALID_CHECKSUM;
    head->attr.file_checksum = OG_INVALID_CHECKSUM;
    headChecksum = REDUCE_CKS2UINT16(cm_get_checksum(head, sizeof(bak_head_t)));
    fileChecksum = REDUCE_CKS2UINT16(cm_get_checksum(head, size));
    head->attr.head_checksum = headChecksum;
    head->attr.file_checksum = fileChecksum;
}

static std::string MakeDataPage(uint16 fileId, uint32 pageNo, char fill)
{
    std::string page(SIZE_K(8), fill);
    errno_t ret = memset_s(&page[0], sizeof(page_head_t), 0, sizeof(page_head_t));
    EXPECT_EQ(ret, EOK);
    (void)memcpy(&page[0], &pageNo, sizeof(pageNo));
    (void)memcpy(&page[sizeof(pageNo)], &fileId, sizeof(fileId));
    page[6] = 4;
    page[7] = 2;
    page_calc_checksum((page_head_t *)&page[0], SIZE_K(8));
    return page;
}

static std::string MakeControlPiece(uint32 pageCount, bool withDssPath = false)
{
    std::string piece((size_t)pageCount * OG_DFLT_CTRL_BLOCK_SIZE, '\0');
    ctrl_page_t *pages = reinterpret_cast<ctrl_page_t *>(&piece[0]);
    for (uint32 i = 0; i < pageCount; i++) {
        pages[i].head.type = PAGE_TYPE_CTRL;
        pages[i].head.size_units = 4;
        pages[i].head.pcn = i;
        pages[i].tail.pcn = i;
        page_calc_checksum((page_head_t *)&pages[i], OG_DFLT_CTRL_BLOCK_SIZE);
    }
    if (withDssPath) {
        const char dssPath[] = "+vg1/sys.dat";
        errno_t ret = memcpy_s(pages[0].buf, sizeof(pages[0].buf), dssPath, sizeof(dssPath));
        EXPECT_EQ(ret, EOK);
        page_calc_checksum((page_head_t *)&pages[0], OG_DFLT_CTRL_BLOCK_SIZE);
    }
    return piece;
}

static void WriteRealBackupset(const std::string &dir, const char *tag, uint32 level, const char *baseTag,
    uint64 completionTime, const std::vector<bak_file_t> &files, compress_algo_e compress = COMPRESS_NONE,
    encrypt_algorithm_t encryptAlg = ENCRYPT_NONE, const std::vector<bak_dependence_t> &depends = {},
    const char *controlFiles = nullptr)
{
    bak_head_t head;
    errno_t ret = memset_s(&head, sizeof(head), 0, sizeof(head));
    ASSERT_EQ(ret, EOK);
    head.version.major_ver = BAK_VERSION_MAJOR;
    head.version.min_ver = BAK_VERSION_MIN;
    head.version.magic = BAK_VERSION_MAGIC;
    ASSERT_EQ(strcpy_s(head.attr.tag, OG_NAME_BUFFER_SIZE, tag), EOK);
    ASSERT_EQ(strcpy_s(head.attr.base_tag, OG_NAME_BUFFER_SIZE, baseTag), EOK);
    head.attr.backup_type = BACKUP_MODE_INCREMENTAL;
    head.attr.level = level;
    head.attr.compress = compress;
    head.encrypt_info.encrypt_alg = encryptAlg;
    head.file_count = (uint32)files.size();
    head.depend_num = (uint32)depends.size();
    head.db_id = 10;
    ASSERT_EQ(strcpy_s(head.db_name, OG_DB_NAME_LEN, "TESTDB"), EOK);
    ASSERT_EQ(strcpy_s(head.db_version, OG_DB_NAME_LEN, "1.0.0"), EOK);
    if (controlFiles != nullptr) {
        ASSERT_EQ(strcpy_s(head.control_files, OG_MAX_CONFIG_LINE_SIZE, controlFiles), EOK);
    }
    head.completion_time = completionTime;
    head.ctrlinfo.rcy_point.lsn = completionTime;
    head.ctrlinfo.lrp_point.lsn = completionTime + 10;

    std::string content(sizeof(bak_head_t) + sizeof(bak_file_t) * files.size() +
        sizeof(bak_dependence_t) * depends.size(), '\0');
    (void)memcpy(&content[0], &head, sizeof(head));
    if (!files.empty()) {
        (void)memcpy(&content[sizeof(bak_head_t)], files.data(), sizeof(bak_file_t) * files.size());
    }
    if (!depends.empty()) {
        (void)memcpy(&content[sizeof(bak_head_t) + sizeof(bak_file_t) * files.size()], depends.data(),
            sizeof(bak_dependence_t) * depends.size());
    }
    bak_head_t *diskHead = reinterpret_cast<bak_head_t *>(&content[0]);
    CalcBackupsetHeadChecksum(diskHead, (uint32)content.size());
    WriteBinaryFile(dir + "/backupset", content.data(), content.size());
}

static std::string CompressPayload(compress_algo_e algo, const std::string &payload)
{
    knl_compress_t ctx;
    errno_t ret = memset_s(&ctx, sizeof(ctx), 0, sizeof(ctx));
    EXPECT_EQ(ret, EOK);
    if (knl_compress_alloc(algo, &ctx, OG_TRUE) != OG_SUCCESS) {
        ADD_FAILURE() << "compress alloc failed";
        return "";
    }
    ctx.compress_level = ZSTD_DEFAULT_COMPRESS_LEVEL;
    if (knl_compress_init(algo, &ctx, OG_TRUE) != OG_SUCCESS) {
        ADD_FAILURE() << "compress init failed";
        knl_compress_free(algo, &ctx, OG_TRUE);
        return "";
    }
    std::string out;
    std::string chunk(SIZE_M(1), '\0');
    if (algo == COMPRESS_LZ4) {
        LZ4F_preferences_t ref = LZ4F_INIT_PREFERENCES;
        ref.compressionLevel = ctx.compress_level;
        size_t beginSize = LZ4F_compressBegin(ctx.lz4f_cstream, &chunk[0], (uint32)chunk.size(), &ref);
        if (LZ4F_isError(beginSize)) {
            ADD_FAILURE() << "lz4 frame begin failed";
            knl_compress_free(algo, &ctx, OG_TRUE);
            return "";
        }
        out.append(chunk.data(), beginSize);
    }
    knl_compress_set_input(algo, &ctx, const_cast<char *>(payload.data()), (uint32)payload.size());
    do {
        if (knl_compress(algo, &ctx, OG_FALSE, &chunk[0], (uint32)chunk.size()) != OG_SUCCESS) {
            ADD_FAILURE() << "compress update failed";
            knl_compress_free(algo, &ctx, OG_TRUE);
            return "";
        }
        out.append(chunk.data(), ctx.write_len);
    } while (ctx.finished != OG_TRUE);
    knl_compress_set_input(algo, &ctx, NULL, 0);
    do {
        if (knl_compress(algo, &ctx, OG_TRUE, &chunk[0], (uint32)chunk.size()) != OG_SUCCESS) {
            ADD_FAILURE() << "compress final failed";
            knl_compress_free(algo, &ctx, OG_TRUE);
            return "";
        }
        out.append(chunk.data(), ctx.write_len);
    } while (ctx.finished != OG_TRUE);
    knl_compress_free(algo, &ctx, OG_TRUE);
    return out;
}

static void FillEncryptedCatalogFields(const char *password, bak_head_t *head, char *key)
{
    ASSERT_EQ(cm_rand((uchar *)head->encrypt_info.salt, OG_KDF2SALTSIZE), OG_SUCCESS);
    uint32 cipherLen = OG_PASSWORD_BUFFER_SIZE;
    ASSERT_EQ(cm_generate_scram_sha256(const_cast<char *>(password), (uint32)strlen(password),
        OG_KDF2DEFITERATION, (uchar *)head->sys_pwd, &cipherLen), OG_SUCCESS);
    ASSERT_EQ(cm_encrypt_KDF2((uchar *)password, (uint32)strlen(password), (uchar *)head->encrypt_info.salt,
        OG_KDF2SALTSIZE, OG_KDF2DEFITERATION, (uchar *)key, OG_AES256KEYSIZE), OG_SUCCESS);
}

static std::string EncryptPayload(const std::string &plain, const char *key, bak_file_t *file)
{
    if (cm_rand(file->gcm_iv, BAK_DEFAULT_GCM_IV_LENGTH) != OG_SUCCESS) {
        ADD_FAILURE() << "iv generation failed";
        return "";
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        ADD_FAILURE() << "cipher context allocation failed";
        return "";
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (const unsigned char *)key,
        (const unsigned char *)file->gcm_iv) == 0) {
        ADD_FAILURE() << "encrypt init failed";
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    std::string cipher(plain.size(), '\0');
    int32 outLen = 0;
    if (EVP_EncryptUpdate(ctx, (unsigned char *)&cipher[0], &outLen, (const unsigned char *)plain.data(),
        (int32)plain.size()) == 0 || outLen != (int32)plain.size()) {
        ADD_FAILURE() << "encrypt update failed";
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)&cipher[0], &outLen) == 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, EVP_GCM_TLS_TAG_LEN, file->gcm_tag) == 0) {
        ADD_FAILURE() << "encrypt final failed";
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    EVP_CIPHER_CTX_free(ctx);
    return cipher;
}

typedef struct st_decode_capture {
    std::string data;
} decode_capture_t;

static status_t CapturePlaintextCb(const char *buf, uint32 size, uint64 logicalOffset, void *ctx)
{
    decode_capture_t *capture = (decode_capture_t *)ctx;
    if (logicalOffset != capture->data.size()) {
        return OG_ERROR;
    }
    capture->data.append(buf, size);
    return OG_SUCCESS;
}

static bak_offline_decode_opts_t MakeDecodeOpts(compress_algo_e compress, encrypt_algorithm_t encryptAlg,
    const bak_head_t &head, const bak_file_t &file, const char *password, uint64 physicalSize)
{
    bak_offline_decode_opts_t opts;
    errno_t ret = memset_s(&opts, sizeof(opts), 0, sizeof(opts));
    EXPECT_EQ(ret, EOK);
    opts.compress = compress;
    opts.encrypt_alg = encryptAlg;
    opts.encrypt_info = head.encrypt_info;
    ret = memcpy_s(opts.sys_pwd, sizeof(opts.sys_pwd), head.sys_pwd, sizeof(opts.sys_pwd));
    EXPECT_EQ(ret, EOK);
    opts.password = password;
    opts.file = &file;
    opts.physical_size = physicalSize;
    return opts;
}

static bak_dependence_t MakeDependence(const char *fileDest)
{
    bak_dependence_t dep;
    errno_t ret = memset_s(&dep, sizeof(dep), 0, sizeof(dep));
    EXPECT_EQ(ret, EOK);
    dep.device = DEVICE_DISK;
    if (fileDest != nullptr) {
        EXPECT_EQ(strcpy_s(dep.file_dest, OG_FILE_NAME_BUFFER_SIZE, fileDest), EOK);
    }
    return dep;
}

static bak_file_t MakeBakFile(bak_file_type_t type, uint32 id, uint32 secId, const char *spcName, uint64 size)
{
    bak_file_t file;
    errno_t ret = memset_s(&file, sizeof(file), 0, sizeof(file));
    EXPECT_EQ(ret, EOK);
    file.type = type;
    file.id = id;
    file.sec_id = secId;
    file.size = size;
    file.inst_id = 0;
    file.rst_id = 1;
    if (spcName != nullptr) {
        EXPECT_EQ(strcpy_s(file.spc_name, OG_NAME_BUFFER_SIZE, spcName), EOK);
    }
    return file;
}

static bool Exists(const std::string &path)
{
    return access(path.c_str(), F_OK) == 0;
}

static std::string ReadFileSlice(const std::string &path, size_t offset, size_t size)
{
    std::string data(size, '\0');
    FILE *fp = fopen(path.c_str(), "rb");
    EXPECT_NE(fp, nullptr);
    if (fp == nullptr) {
        return data;
    }
    EXPECT_EQ(fseek(fp, (long)offset, SEEK_SET), 0);
    size_t readSize = fread(&data[0], 1, size, fp);
    EXPECT_EQ(readSize, size);
    EXPECT_EQ(fclose(fp), 0);
    return data;
}

static std::string ReadWholeFile(const std::string &path)
{
    FILE *fp = fopen(path.c_str(), "rb");
    EXPECT_NE(fp, nullptr);
    if (fp == nullptr) {
        return "";
    }
    EXPECT_EQ(fseek(fp, 0, SEEK_END), 0);
    long size = ftell(fp);
    EXPECT_GE(size, 0);
    EXPECT_EQ(fseek(fp, 0, SEEK_SET), 0);
    std::string data((size_t)size, '\0');
    if (size > 0) {
        EXPECT_EQ(fread(&data[0], 1, (size_t)size, fp), (size_t)size);
    }
    EXPECT_EQ(fclose(fp), 0);
    return data;
}

static std::string FileEntry(const std::string &backupId, const std::string &src, const std::string &target,
    const std::string &absoluteSrc)
{
    uint64 size = 0;
    uint32 checksum = ogbak_offline_calc_file_checksum(absoluteSrc.c_str(), &size);
    char line[1024];
    (void)snprintf(line, sizeof(line),
        "file backup_id=%s type=data src=%s target=%s size=%llu checksum=%u\n",
        backupId.c_str(), src.c_str(), target.c_str(), size, checksum);
    return std::string(line);
}

static void SetTextParam(const char *value, text_t *text)
{
    ASSERT_EQ(ogbak_parse_single_arg(const_cast<char *>(value), text), OG_SUCCESS);
}

static uint32 OfflineCtrlLogSegment(bool clustered)
{
    return clustered ? (OG_MAX_INSTANCES + CTRL_LOG_SEGMENT) : (1 + CTRL_LOG_SEGMENT);
}

static uint32 OfflineCtrlSpaceSegment(bool clustered)
{
    uint32 offset = OfflineCtrlLogSegment(clustered);
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 pagesPerInst = (OG_MAX_LOG_FILES - 1) / count + 1;
    offset += pagesPerInst * (clustered ? OG_MAX_INSTANCES : 1);
    return offset;
}

static uint32 OfflineCtrlDatafileSegment(bool clustered)
{
    uint32 offset = OfflineCtrlSpaceSegment(clustered);
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(space_ctrl_t);
    offset += (OG_MAX_SPACES - 1) / count + 1;
    return offset;
}

static uint32 OfflineCtrlArchSegment(bool clustered)
{
    uint32 offset = OfflineCtrlDatafileSegment(clustered);
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(datafile_ctrl_t);
    offset += (OG_MAX_DATA_FILES - 1) / count + 1;
    return offset;
}

static arch_ctrl_t *OfflineCtrlGetArchItem(ctrl_page_t *pages, uint32 id, uint32 offset, uint32 nodeId)
{
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(arch_ctrl_t);
    uint32 pagesPerInst = (OG_MAX_ARCH_NUM - 1) / count + 1;
    uint32 pageId = offset + pagesPerInst * nodeId + id / count;
    uint32 slot = id % count;
    return reinterpret_cast<arch_ctrl_t *>(pages[pageId].buf + slot * sizeof(arch_ctrl_t));
}

static std::string MakeControlPieceWithLocalPaths(bool clustered = false)
{
    uint32 pageCount = clustered ? CTRL_MAX_PAGES_CLUSTERED : CTRL_MAX_PAGES_NONCLUSTERED;
    std::string piece = MakeControlPiece(pageCount);
    ctrl_page_t *pages = reinterpret_cast<ctrl_page_t *>(&piece[0]);
    core_ctrl_t *core = reinterpret_cast<core_ctrl_t *>(pages[CORE_CTRL_PAGE_ID].buf);
    core->clustered = clustered ? OG_TRUE : OG_FALSE;
    const uint32 archLocator = 3;
    const uint32 archAsn = 7;
    dtc_node_ctrl_t *node = reinterpret_cast<dtc_node_ctrl_t *>(pages[CTRL_LOG_SEGMENT].buf);
    node->rcy_point.asn = 4;
    node->rcy_point.block_id = 6262;
    node->rcy_point.rst_id = 0;
    node->rcy_point.lfn = 6262;
    node->rcy_point.lsn = 3206144;
    node->lrp_point.asn = 4;
    node->lrp_point.block_id = 6262;
    node->lrp_point.rst_id = 0;
    node->lrp_point.lfn = 6262;
    node->lrp_point.lsn = 3206144;
    node->log_hwm = 3;
    node->log_first = 1;
    node->log_last = 1;
    node->archived_start = archLocator;
    node->archived_end = archLocator + 1;

    datafile_ctrl_t *df = reinterpret_cast<datafile_ctrl_t *>(
        db_get_ctrl_item(pages, 1, sizeof(datafile_ctrl_t), OfflineCtrlDatafileSegment(clustered)));
    df->id = 1;
    df->used = OG_TRUE;
    df->type = DEV_TYPE_FILE;
    EXPECT_EQ(strcpy_s(df->name, sizeof(df->name), "/home/ograc/data/sys.dat"), EOK);

    log_file_ctrl_t *log = reinterpret_cast<log_file_ctrl_t *>(
        db_get_log_ctrl_item(pages, 1, sizeof(log_file_ctrl_t), OfflineCtrlLogSegment(clustered), 0));
    log->type = DEV_TYPE_FILE;
    log->file_id = 1;
    log->size = SIZE_M(16);
    log->block_size = 512;
    log->status = LOG_FILE_CURRENT;
    EXPECT_EQ(strcpy_s(log->name, sizeof(log->name), "/home/ograc/data/redo01.log"), EOK);

    arch_ctrl_t *arch = OfflineCtrlGetArchItem(pages, archLocator, OfflineCtrlArchSegment(clustered), 0);
    arch->recid = 1;
    arch->asn = archAsn;
    arch->rst_id = 1;
    EXPECT_EQ(strcpy_s(arch->name, sizeof(arch->name), "/home/ograc/data/archive/7.arc"), EOK);

    for (uint32 i = 0; i < pageCount; i++) {
        if (pages[i].tail.checksum != OG_INVALID_CHECKSUM) {
            page_calc_checksum(reinterpret_cast<page_head_t *>(&pages[i]), OG_DFLT_CTRL_BLOCK_SIZE);
        }
    }
    return piece;
}

static std::string MakeControlPieceWithLocalTargets(const std::string &dataPath,
    const std::string &redoPath, const std::string &archivePath, uint64 datafileSize, uint64 redoSize)
{
    std::string piece = MakeControlPieceWithLocalPaths();
    ctrl_page_t *pages = reinterpret_cast<ctrl_page_t *>(&piece[0]);
    datafile_ctrl_t *df = reinterpret_cast<datafile_ctrl_t *>(
        db_get_ctrl_item(pages, 1, sizeof(datafile_ctrl_t), OfflineCtrlDatafileSegment(false)));
    df->size = datafileSize;
    df->flag = 0x01;
    EXPECT_EQ(strcpy_s(df->name, sizeof(df->name), dataPath.c_str()), EOK);

    space_ctrl_t *space = reinterpret_cast<space_ctrl_t *>(
        db_get_ctrl_item(pages, 1, sizeof(space_ctrl_t), OfflineCtrlSpaceSegment(false)));
    space->id = 1;
    space->used = OG_TRUE;
    space->flag = 0x0001;
    space->file_hwm = 1;
    space->files[0] = 1;

    log_file_ctrl_t *log = reinterpret_cast<log_file_ctrl_t *>(
        db_get_log_ctrl_item(pages, 1, sizeof(log_file_ctrl_t), OfflineCtrlLogSegment(false), 0));
    log->size = redoSize;
    EXPECT_EQ(strcpy_s(log->name, sizeof(log->name), redoPath.c_str()), EOK);

    arch_ctrl_t *arch = OfflineCtrlGetArchItem(pages, 3, OfflineCtrlArchSegment(false), 0);
    EXPECT_EQ(strcpy_s(arch->name, sizeof(arch->name), archivePath.c_str()), EOK);

    for (uint32 i = 0; i < CTRL_MAX_PAGES_NONCLUSTERED; i++) {
        if (pages[i].tail.checksum != OG_INVALID_CHECKSUM) {
            page_calc_checksum(reinterpret_cast<page_head_t *>(&pages[i]), OG_DFLT_CTRL_BLOCK_SIZE);
        }
    }
    return piece;
}

static std::string MakeControlPieceWithDssPathsAndSizes(uint64 datafileSize, uint64 redoSize)
{
    std::string piece = MakeControlPieceWithLocalPaths();
    ctrl_page_t *pages = reinterpret_cast<ctrl_page_t *>(&piece[0]);
    datafile_ctrl_t *df = reinterpret_cast<datafile_ctrl_t *>(
        db_get_ctrl_item(pages, 1, sizeof(datafile_ctrl_t), OfflineCtrlDatafileSegment(false)));
    df->type = DEV_TYPE_RAW;
    df->size = datafileSize;
    df->flag = 0x01;
    EXPECT_EQ(strcpy_s(df->name, sizeof(df->name), "+vg1/sys.dat"), EOK);

    space_ctrl_t *space = reinterpret_cast<space_ctrl_t *>(
        db_get_ctrl_item(pages, 1, sizeof(space_ctrl_t), OfflineCtrlSpaceSegment(false)));
    space->id = 1;
    space->used = OG_TRUE;
    space->flag = 0x0001;
    space->file_hwm = 1;
    space->files[0] = 1;

    log_file_ctrl_t *log = reinterpret_cast<log_file_ctrl_t *>(
        db_get_log_ctrl_item(pages, 1, sizeof(log_file_ctrl_t), OfflineCtrlLogSegment(false), 0));
    log->type = DEV_TYPE_RAW;
    log->size = redoSize;
    EXPECT_EQ(strcpy_s(log->name, sizeof(log->name), "+vg2/redo01.dat"), EOK);

    for (uint32 i = 0; i < CTRL_MAX_PAGES_NONCLUSTERED; i++) {
        if (pages[i].tail.checksum != OG_INVALID_CHECKSUM) {
            page_calc_checksum(reinterpret_cast<page_head_t *>(&pages[i]), OG_DFLT_CTRL_BLOCK_SIZE);
        }
    }
    return piece;
}

TEST_F(TestCtbackup, OfflineControlRestoreDecodesRawControlFiles)
{
    std::string root = MakeTempDir("ogbak_ctrl_decode_");
    std::string target = root + "/target";
    MakeDir(target);
    std::string ctrlPiece = MakeControlPiece(CTRL_MAX_PAGES_NONCLUSTERED);
    WriteBinaryFile(root + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    bak_offline_ctrl_restore_opts_t opts = {0};
    bak_offline_ctrl_restore_result_t result;
    opts.target_dir = target.c_str();
    opts.expected_payload_size = ctrlPiece.size();
    opts.reject_dss_to_local = OG_TRUE;

    ASSERT_EQ(bak_offline_restore_ctrlfile((root + "/ctrl_0_0.bak").c_str(), &opts, &result), OG_SUCCESS);
    EXPECT_EQ(result.raw_ctrl_file_count, (uint32)BAK_OFFLINE_CTRL_FILE_COUNT);
    EXPECT_EQ(result.raw_ctrl_file_size, (uint64)CTRL_MAX_PAGES_NONCLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE);
    EXPECT_EQ(result.ctrl_page_count, (uint32)CTRL_MAX_PAGES_NONCLUSTERED);
    EXPECT_EQ(result.checksum_checked, OG_TRUE);
    EXPECT_FALSE(Exists(target + "/ctrl_0_0.bak"));
    EXPECT_TRUE(Exists(target + "/data/ctrl1"));
    EXPECT_TRUE(Exists(target + "/data/ctrl2"));
    EXPECT_TRUE(Exists(target + "/data/ctrl3"));
    EXPECT_EQ(ReadFileSlice(target + "/data/ctrl1", 0, 16), ctrlPiece.substr(0, 16));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlRestoreRejectsMalformedShortPiece)
{
    std::string root = MakeTempDir("ogbak_ctrl_short_");
    std::string target = root + "/target";
    MakeDir(target);
    std::string shortPiece(OG_DFLT_CTRL_BLOCK_SIZE, '\0');
    WriteBinaryFile(root + "/ctrl_0_0.bak", shortPiece.data(), shortPiece.size());

    bak_offline_ctrl_restore_opts_t opts = {0};
    bak_offline_ctrl_restore_result_t result;
    opts.target_dir = target.c_str();
    opts.expected_payload_size = shortPiece.size();
    opts.reject_dss_to_local = OG_TRUE;

    EXPECT_EQ(bak_offline_restore_ctrlfile((root + "/ctrl_0_0.bak").c_str(), &opts, &result), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/data/ctrl1"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlRestoreRejectsChecksumMismatch)
{
    std::string root = MakeTempDir("ogbak_ctrl_cks_");
    std::string target = root + "/target";
    MakeDir(target);
    std::string ctrlPiece = MakeControlPiece(CTRL_MAX_PAGES_NONCLUSTERED);
    ctrlPiece[128] = 'X';
    WriteBinaryFile(root + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    bak_offline_ctrl_restore_opts_t opts = {0};
    bak_offline_ctrl_restore_result_t result;
    opts.target_dir = target.c_str();
    opts.expected_payload_size = ctrlPiece.size();
    opts.reject_dss_to_local = OG_TRUE;

    EXPECT_EQ(bak_offline_restore_ctrlfile((root + "/ctrl_0_0.bak").c_str(), &opts, &result), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/data/ctrl1"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlRestoreRejectsDssPathForLocalTarget)
{
    std::string root = MakeTempDir("ogbak_ctrl_dss_");
    std::string target = root + "/target";
    MakeDir(target);
    std::string ctrlPiece = MakeControlPiece(CTRL_MAX_PAGES_NONCLUSTERED, true);
    WriteBinaryFile(root + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    bak_offline_ctrl_restore_opts_t opts = {0};
    bak_offline_ctrl_restore_result_t result;
    opts.target_dir = target.c_str();
    opts.expected_payload_size = ctrlPiece.size();
    opts.reject_dss_to_local = OG_TRUE;

    EXPECT_EQ(bak_offline_restore_ctrlfile((root + "/ctrl_0_0.bak").c_str(), &opts, &result), OG_ERROR);
    EXPECT_EQ(result.contains_dss_paths, OG_TRUE);
    EXPECT_FALSE(Exists(target + "/data/ctrl1"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlRewriteLocalPaths)
{
    std::string root = MakeTempDir("ogbak_ctrl_rewrite_");
    std::string target = root + "/target";
    MakeDir(target);
    MakeDir(target + "/data");
    MakeDir(target + "/redo");
    MakeDir(target + "/arch");
    std::string ctrlPiece = MakeControlPieceWithLocalPaths();
    WriteBinaryFile(root + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    bak_offline_ctrl_path_map_item_t items[3];
    ASSERT_EQ(memset_s(items, sizeof(items), 0, sizeof(items)), EOK);
    items[0].type = BAK_OFFLINE_CTRL_PATH_DATAFILE;
    items[0].file_id = 1;
    ASSERT_EQ(strcpy_s(items[0].target_path, sizeof(items[0].target_path),
        (target + "/data/data_SYSTEM_1.dbf").c_str()), EOK);
    items[1].type = BAK_OFFLINE_CTRL_PATH_LOGFILE;
    items[1].file_id = 1;
    items[1].node_id = 0;
    ASSERT_EQ(strcpy_s(items[1].target_path, sizeof(items[1].target_path),
        (target + "/redo/log_0_1.bak").c_str()), EOK);
    items[2].type = BAK_OFFLINE_CTRL_PATH_ARCHIVE;
    items[2].file_id = 7;
    items[2].node_id = 0;
    items[2].rst_id = 1;
    ASSERT_EQ(strcpy_s(items[2].target_path, sizeof(items[2].target_path),
        (target + "/arch/arch_0_1_7.bak").c_str()), EOK);

    bak_offline_ctrl_path_map_t map;
    ASSERT_EQ(memset_s(&map, sizeof(map), 0, sizeof(map)), EOK);
    map.items = items;
    map.item_capacity = 3;
    map.item_count = 3;

    bak_offline_ctrl_restore_opts_t opts = {0};
    bak_offline_ctrl_restore_result_t result;
    opts.target_dir = target.c_str();
    opts.expected_payload_size = ctrlPiece.size();
    opts.reject_dss_to_local = OG_TRUE;
    opts.rewrite_paths = OG_TRUE;
    opts.path_map = &map;

    ASSERT_EQ(bak_offline_restore_ctrlfile((root + "/ctrl_0_0.bak").c_str(), &opts, &result), OG_SUCCESS);
    EXPECT_EQ(result.control_rewrite_done, OG_TRUE);
    EXPECT_EQ(result.rewritten_datafiles, 1U);
    EXPECT_EQ(result.rewritten_logfiles, 1U);
    EXPECT_EQ(result.rewritten_archives, 1U);
    std::string raw = ReadFileSlice(target + "/data/ctrl1", 0, ctrlPiece.size());
    EXPECT_EQ(raw.find("/home/ograc/data/sys.dat"), std::string::npos);
    EXPECT_NE(raw.find(target + "/data/data_SYSTEM_1.dbf"), std::string::npos);
    EXPECT_NE(raw.find(target + "/redo/log_0_1.bak"), std::string::npos);
    EXPECT_NE(raw.find(target + "/arch/arch_0_1_7.bak"), std::string::npos);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlBuildPathMapUsesRecoveryPointForCurrentLogAsn)
{
    std::string root = MakeTempDir("ogbak_ctrl_log_asn_");
    std::string target = root + "/target";
    MakeDir(target);
    MakeDir(target + "/data");
    MakeDir(target + "/redo");
    std::string ctrlPiece = MakeControlPieceWithLocalPaths();

    bak_offline_ctrl_path_map_item_t items[8];
    ASSERT_EQ(memset_s(items, sizeof(items), 0, sizeof(items)), EOK);
    bak_offline_ctrl_path_map_t map;
    ASSERT_EQ(memset_s(&map, sizeof(map), 0, sizeof(map)), EOK);
    map.items = items;
    map.item_capacity = 8;

    ASSERT_EQ(bak_offline_ctrl_build_path_map(&ctrlPiece[0], ctrlPiece.size(), target.c_str(), &map), OG_SUCCESS);

    bak_offline_ctrl_path_map_item_t *logItem = nullptr;
    for (uint32 i = 0; i < map.item_count; i++) {
        if (map.items[i].type == BAK_OFFLINE_CTRL_PATH_LOGFILE && map.items[i].file_id == 1) {
            logItem = &map.items[i];
            break;
        }
    }
    ASSERT_NE(logItem, nullptr);
    EXPECT_EQ(logItem->rcy_asn, 4U);
    EXPECT_EQ(logItem->rcy_block_id, 6262U);
    EXPECT_EQ(logItem->log_first, 1U);
    EXPECT_EQ(logItem->log_last, 1U);
    EXPECT_EQ(logItem->generated_log_head_asn, 5U);
    ASSERT_STREQ(logItem->log_asn_reason, "current-from-rcy-point");
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlBuildPathMapFailsWhenRecoveryPointIsMissing)
{
    std::string root = MakeTempDir("ogbak_ctrl_log_asn_bad_");
    std::string target = root + "/target";
    MakeDir(target);
    MakeDir(target + "/data");
    MakeDir(target + "/redo");
    std::string ctrlPiece = MakeControlPieceWithLocalPaths();
    ctrl_page_t *pages = reinterpret_cast<ctrl_page_t *>(&ctrlPiece[0]);
    dtc_node_ctrl_t *node = reinterpret_cast<dtc_node_ctrl_t *>(pages[CTRL_LOG_SEGMENT].buf);
    node->rcy_point.asn = 0;
    page_calc_checksum(reinterpret_cast<page_head_t *>(&pages[CTRL_LOG_SEGMENT]), OG_DFLT_CTRL_BLOCK_SIZE);

    bak_offline_ctrl_path_map_item_t items[8];
    ASSERT_EQ(memset_s(items, sizeof(items), 0, sizeof(items)), EOK);
    bak_offline_ctrl_path_map_t map;
    ASSERT_EQ(memset_s(&map, sizeof(map), 0, sizeof(map)), EOK);
    map.items = items;
    map.item_capacity = 8;

    EXPECT_EQ(bak_offline_ctrl_build_path_map(&ctrlPiece[0], ctrlPiece.size(), target.c_str(), &map), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlRewriteArchiveMatchesLocatorWithWildcardRst)
{
    std::string root = MakeTempDir("ogbak_ctrl_arch_locator_");
    std::string target = root + "/target";
    MakeDir(target);
    MakeDir(target + "/arch");
    std::string ctrlPiece = MakeControlPieceWithLocalPaths();
    WriteBinaryFile(root + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    bak_offline_ctrl_path_map_item_t items[8];
    ASSERT_EQ(memset_s(items, sizeof(items), 0, sizeof(items)), EOK);
    items[0].type = BAK_OFFLINE_CTRL_PATH_ARCHIVE;
    items[0].file_id = 7;  // archive ASN, not the control ring locator
    items[0].node_id = 0;
    items[0].rst_id = 0;   // real local backup catalogs can expose unknown rst_id here
    ASSERT_EQ(strcpy_s(items[0].target_path, sizeof(items[0].target_path),
        (target + "/arch/arch_0_0_7.bak").c_str()), EOK);

    bak_offline_ctrl_path_map_t map;
    ASSERT_EQ(memset_s(&map, sizeof(map), 0, sizeof(map)), EOK);
    map.items = items;
    map.item_capacity = 8;
    map.item_count = 1;

    bak_offline_ctrl_restore_opts_t opts = {0};
    bak_offline_ctrl_restore_result_t result;
    opts.target_dir = target.c_str();
    opts.expected_payload_size = ctrlPiece.size();
    opts.reject_dss_to_local = OG_TRUE;
    opts.rewrite_paths = OG_TRUE;
    opts.path_map = &map;

    ASSERT_EQ(bak_offline_restore_ctrlfile((root + "/ctrl_0_0.bak").c_str(), &opts, &result), OG_SUCCESS);
    EXPECT_EQ(result.rewritten_archives, 1U);
    std::string raw = ReadFileSlice(target + "/data/ctrl1", 0, ctrlPiece.size());
    EXPECT_EQ(raw.find("/home/ograc/data/archive/7.arc"), std::string::npos);
    EXPECT_NE(raw.find(target + "/arch/arch_0_0_7.bak"), std::string::npos);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlRewriteArchiveReportsUnsupportedWhenNotInControlRing)
{
    std::string root = MakeTempDir("ogbak_ctrl_arch_unsupported_");
    std::string target = root + "/target";
    MakeDir(target);
    MakeDir(target + "/arch");
    std::string ctrlPiece = MakeControlPiece(CTRL_MAX_PAGES_NONCLUSTERED);
    WriteBinaryFile(root + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    bak_offline_ctrl_path_map_item_t item;
    ASSERT_EQ(memset_s(&item, sizeof(item), 0, sizeof(item)), EOK);
    item.type = BAK_OFFLINE_CTRL_PATH_ARCHIVE;
    item.file_id = 7;
    item.node_id = 0;
    item.rst_id = 1;
    ASSERT_EQ(strcpy_s(item.target_path, sizeof(item.target_path),
        (target + "/arch/arch_0_1_7.bak").c_str()), EOK);

    bak_offline_ctrl_path_map_t map;
    ASSERT_EQ(memset_s(&map, sizeof(map), 0, sizeof(map)), EOK);
    map.items = &item;
    map.item_capacity = 1;
    map.item_count = 1;

    bak_offline_ctrl_restore_opts_t opts = {0};
    bak_offline_ctrl_restore_result_t result;
    opts.target_dir = target.c_str();
    opts.expected_payload_size = ctrlPiece.size();
    opts.reject_dss_to_local = OG_TRUE;
    opts.rewrite_paths = OG_TRUE;
    opts.path_map = &map;

    EXPECT_EQ(bak_offline_restore_ctrlfile((root + "/ctrl_0_0.bak").c_str(), &opts, &result), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/data/ctrl1"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlRewriteClusteredControl)
{
    std::string root = MakeTempDir("ogbak_ctrl_rewrite_cluster_");
    std::string target = root + "/target";
    MakeDir(target);
    MakeDir(target + "/data");
    std::string ctrlPiece = MakeControlPieceWithLocalPaths(true);
    WriteBinaryFile(root + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    bak_offline_ctrl_path_map_item_t items[8];
    ASSERT_EQ(memset_s(items, sizeof(items), 0, sizeof(items)), EOK);
    items[0].type = BAK_OFFLINE_CTRL_PATH_DATAFILE;
    items[0].file_id = 1;
    ASSERT_EQ(strcpy_s(items[0].target_path, sizeof(items[0].target_path),
        (target + "/data/data_SYSTEM_1.dbf").c_str()), EOK);

    bak_offline_ctrl_path_map_t map;
    ASSERT_EQ(memset_s(&map, sizeof(map), 0, sizeof(map)), EOK);
    map.items = items;
    map.item_capacity = 8;
    map.item_count = 1;

    bak_offline_ctrl_restore_opts_t opts = {0};
    bak_offline_ctrl_restore_result_t result;
    opts.target_dir = target.c_str();
    opts.expected_payload_size = ctrlPiece.size();
    opts.reject_dss_to_local = OG_TRUE;
    opts.rewrite_paths = OG_TRUE;
    opts.path_map = &map;

    ASSERT_EQ(bak_offline_restore_ctrlfile((root + "/ctrl_0_0.bak").c_str(), &opts, &result), OG_SUCCESS);
    EXPECT_EQ(result.raw_ctrl_file_size, (uint64)CTRL_MAX_PAGES_CLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE);
    EXPECT_EQ(result.rewritten_datafiles, 1U);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineControlRewriteRejectsEscapingPath)
{
    std::string root = MakeTempDir("ogbak_ctrl_rewrite_escape_");
    std::string target = root + "/target";
    MakeDir(target);
    std::string ctrlPiece = MakeControlPieceWithLocalPaths();
    WriteBinaryFile(root + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    bak_offline_ctrl_path_map_item_t item;
    ASSERT_EQ(memset_s(&item, sizeof(item), 0, sizeof(item)), EOK);
    item.type = BAK_OFFLINE_CTRL_PATH_DATAFILE;
    item.file_id = 1;
    ASSERT_EQ(strcpy_s(item.target_path, sizeof(item.target_path), "/tmp/escape.dbf"), EOK);

    bak_offline_ctrl_path_map_t map;
    ASSERT_EQ(memset_s(&map, sizeof(map), 0, sizeof(map)), EOK);
    map.items = &item;
    map.item_capacity = 1;
    map.item_count = 1;

    bak_offline_ctrl_restore_opts_t opts = {0};
    bak_offline_ctrl_restore_result_t result;
    opts.target_dir = target.c_str();
    opts.expected_payload_size = ctrlPiece.size();
    opts.reject_dss_to_local = OG_TRUE;
    opts.rewrite_paths = OG_TRUE;
    opts.path_map = &map;

    EXPECT_EQ(bak_offline_restore_ctrlfile((root + "/ctrl_0_0.bak").c_str(), &opts, &result), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/data/ctrl1"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, ParseOfflineRestoreArgs)
{
    ogbak_param_t param = {0};
    char arg0[] = "ogbackup";
    char arg1[] = "--offline-restore";
    char arg2[] = "--backup-dir=/tmp/repo";
    char arg3[] = "--target-dir=/tmp/target";
    char arg4[] = "--backup-id=inc1";
    char arg5[] = "--force";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5};

    ASSERT_EQ(ogbak_parse_restore_args(6, argv, &param), OG_SUCCESS);
    EXPECT_EQ(param.is_offline, OG_TRUE);
    EXPECT_EQ(param.is_force, OG_TRUE);
    ASSERT_STREQ(param.backup_dir.str, "/tmp/repo");
    ASSERT_STREQ(param.target_dir.str, "/tmp/target");
    ASSERT_STREQ(param.backup_id.str, "inc1");
    EXPECT_EQ(param.storage.str, nullptr);
    EXPECT_EQ(param.path_map.str, nullptr);
    free_input_params(&param);
}

TEST_F(TestCtbackup, ParseOfflineRestoreArgsRejectsRemovedInspectOption)
{
    ogbak_param_t param = {0};
    char arg0[] = "ogbackup";
    char arg1[] = "--offline-restore";
    char arg2[] = "--backup-dir=/tmp/repo";
    char arg3[] = "--target-dir=/tmp/target";
    char arg4[] = "--inspect";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4};

    EXPECT_EQ(ogbak_parse_restore_args(5, argv, &param), OG_ERROR);
    free_input_params(&param);
}

TEST_F(TestCtbackup, PrepareDoesNotExposeOfflineRestoreAction)
{
    ogbak_param_t param = {0};
    char arg0[] = "ogbackup";
    char arg1[] = "--prepare";
    char arg2[] = "--offline-restore";
    char arg3[] = "--backup-dir=/tmp/repo";
    char arg4[] = "--target-dir=/tmp/target";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4};

    EXPECT_EQ(ogbak_parse_prepare_args(5, argv, &param), OG_ERROR);
    free_input_params(&param);
}

TEST_F(TestCtbackup, OfflineRestoreDryRunBuildsPlanWithoutWritingTarget)
{
    std::string root = MakeTempDir("ogbak_restore_dry_");
    std::string repo = root + "/repo";
    std::string srcDir = repo + "/full";
    std::string target = root + "/target";
    MakeDir(repo);
    MakeDir(srcDir);
    WriteTextFile(srcDir + "/system.dbf", "full-data");
    WriteTextFile(repo + "/offline_restore.manifest",
        "global version=1 archive_required=true\n"
        "backup id=full1 type=full version_major=2 version_minor=1 version_magic=0 db_id=10 cluster_id=20 "
        "db_version=1.0.0 start_lsn=1 end_lsn=10 checkpoint_lsn=8 completion_time=100\n" +
        FileEntry("full1", "full/system.dbf", "data/system.dbf", srcDir + "/system.dbf") +
        "arch backup_id=full1 node=0 rst_id=1 start_asn=1 end_asn=2 start_lsn=1 end_lsn=10\n");

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;
    param.is_dry_run = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    EXPECT_FALSE(Exists(target));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreAutoDetectsDssAndRequiresForceBeforeWrite)
{
    std::string root = MakeTempDir("ogbak_restore_dss_force_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    WriteTextFile(repo + "/data.bak", "dss-data");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "data.bak", "+vg1/datafile1", repo + "/data.bak"));

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(target));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreCopiesFullBackupFiles)
{
    std::string root = MakeTempDir("ogbak_restore_full_");
    std::string repo = root + "/repo";
    std::string srcDir = repo + "/full";
    std::string target = root + "/target";
    MakeDir(repo);
    MakeDir(srcDir);
    WriteTextFile(srcDir + "/ctrl.bak", "control");
    WriteTextFile(srcDir + "/system.dbf", "full-data");
    WriteTextFile(repo + "/offline_restore.manifest",
        "global version=1\n"
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full/ctrl.bak", "ctrl/ctrl.bak", srcDir + "/ctrl.bak") +
        FileEntry("full1", "full/system.dbf", "data/system.dbf", srcDir + "/system.dbf"));

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    EXPECT_TRUE(Exists(target + "/ctrl/ctrl.bak"));
    EXPECT_TRUE(Exists(target + "/data/system.dbf"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreReadsRealFullBackupsetWithoutManifest)
{
    std::string root = MakeTempDir("ogbak_restore_real_full_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string ctrlPiece = MakeControlPieceWithLocalPaths();
    WriteBinaryFile(repo + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());
    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", "", 0);
    std::string page = MakeDataPage(1, 3, 'F');
    std::string emptyPage(SIZE_K(8), '\0');
    std::string afterEmptyPage = MakeDataPage(1, 5, 'G');
    std::string payload = page + emptyPage + afterEmptyPage;
    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", payload.data(), payload.size());
    WriteTextFile(repo + "/arch_0_7_0.bak", "arch-real");

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr, ctrlPiece.size()));
    files.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", payload.size()));
    files.push_back(MakeBakFile(BACKUP_ARCH_FILE, 7, 0, nullptr, strlen("arch-real")));
    WriteRealBackupset(repo, "full_real", 0, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    EXPECT_TRUE(Exists(target + "/data/ctrl1"));
    EXPECT_TRUE(Exists(target + "/data/ctrl2"));
    EXPECT_TRUE(Exists(target + "/data/ctrl3"));
    EXPECT_FALSE(Exists(target + "/ctrl/ctrl_0_0.bak"));
    EXPECT_TRUE(Exists(target + "/data/data_SYSTEM_1.dbf"));
    EXPECT_TRUE(Exists(target + "/arch/arch_0_1_7.bak"));
    EXPECT_EQ(ReadFileSlice(target + "/data/data_SYSTEM_1.dbf", SIZE_K(8) * 3 + 128, 1), std::string("F"));
    EXPECT_EQ(ReadFileSlice(target + "/data/data_SYSTEM_1.dbf", SIZE_K(8) * 5 + 128, 1), std::string("G"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestorePathMapAutoRewritesControlPaths)
{
    std::string root = MakeTempDir("ogbak_restore_pathmap_auto_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string ctrlPiece = MakeControlPieceWithLocalPaths();
    WriteBinaryFile(repo + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());
    std::string page = MakeDataPage(1, 3, 'F');
    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", page.data(), page.size());
    WriteTextFile(repo + "/log_0_1_0.bak", "redo-real");
    WriteTextFile(repo + "/arch_0_7_0.bak", "arch-real");

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr, ctrlPiece.size()));
    files.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", page.size()));
    files.push_back(MakeBakFile(BACKUP_LOG_FILE, 1, 0, nullptr, strlen("redo-real")));
    files.push_back(MakeBakFile(BACKUP_ARCH_FILE, 7, 0, nullptr, strlen("arch-real")));
    WriteRealBackupset(repo, "full_real_pathmap", 0, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("auto", &param.path_map);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    EXPECT_TRUE(Exists(target + "/.ogbackup_offline_restore_file_phase_complete"));
    std::string marker = ReadWholeFile(target + "/.ogbackup_offline_restore_file_phase_complete");
    EXPECT_NE(marker.find("path_mapping=auto"), std::string::npos);
    EXPECT_NE(marker.find("control_rewrite=done"), std::string::npos);
    std::string raw = ReadFileSlice(target + "/data/ctrl1", 0, ctrlPiece.size());
    EXPECT_EQ(raw.find("/home/ograc/data/sys.dat"), std::string::npos);
    EXPECT_NE(raw.find(target + "/data/data_SYSTEM_1.dbf"), std::string::npos);
    EXPECT_TRUE(Exists(target + "/data/data_SYSTEM_1.dbf"));
    EXPECT_TRUE(Exists(target + "/redo/log_0_1.bak"));
    EXPECT_TRUE(Exists(target + "/arch/arch_0_1_7.bak"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestorePathMapAutoFailureStopsBeforeMarkers)
{
    std::string root = MakeTempDir("ogbak_restore_pathmap_fail_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string ctrlPiece = MakeControlPiece(CTRL_MAX_PAGES_NONCLUSTERED);
    WriteBinaryFile(repo + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());
    const char emptyPayload = '\0';
    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", &emptyPayload, 0);

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr, ctrlPiece.size()));
    files.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", 0));
    WriteRealBackupset(repo, "full_bad_pathmap", 0, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("auto", &param.path_map);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_file_phase_complete"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_in_progress"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_failed"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsDssControlPieceForLocalTarget)
{
    std::string root = MakeTempDir("ogbak_restore_dss_ctrl_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string ctrlPiece = MakeControlPiece(CTRL_MAX_PAGES_NONCLUSTERED, true);
    WriteBinaryFile(repo + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr, ctrlPiece.size()));
    WriteRealBackupset(repo, "full_dss_ctrl", 0, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_file_phase_complete"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_in_progress"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_failed"));
    EXPECT_FALSE(Exists(target + "/data/ctrl1"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreControlSizeMismatchStopsBeforeMarkers)
{
    std::string root = MakeTempDir("ogbak_restore_ctrl_size_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string shortPiece(OG_DFLT_CTRL_BLOCK_SIZE, '\0');
    WriteBinaryFile(repo + "/ctrl_0_0.bak", shortPiece.data(), shortPiece.size());

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr,
        (uint64)CTRL_MAX_PAGES_NONCLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE));
    WriteRealBackupset(repo, "full_bad_ctrl_size", 0, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_file_phase_complete"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_in_progress"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_failed"));
    EXPECT_FALSE(Exists(target + "/data/ctrl1"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreControlChecksumMismatchStopsBeforeMarkers)
{
    std::string root = MakeTempDir("ogbak_restore_ctrl_cks_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string ctrlPiece = MakeControlPiece(CTRL_MAX_PAGES_NONCLUSTERED);
    ctrlPiece[128] = 'X';
    WriteBinaryFile(repo + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr, ctrlPiece.size()));
    WriteRealBackupset(repo, "full_bad_ctrl_cks", 0, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_file_phase_complete"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_in_progress"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_failed"));
    EXPECT_FALSE(Exists(target + "/data/ctrl1"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreDryRunRejectsDssControlPieceForLocalTarget)
{
    std::string root = MakeTempDir("ogbak_restore_dss_ctrl_dry_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string ctrlPiece = MakeControlPiece(CTRL_MAX_PAGES_NONCLUSTERED, true);
    WriteBinaryFile(repo + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr, ctrlPiece.size()));
    WriteRealBackupset(repo, "full_dss_ctrl_dry", 0, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;
    param.is_dry_run = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(target));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreAppliesRealIncrementalBackupsetPages)
{
    std::string root = MakeTempDir("ogbak_restore_real_inc_");
    std::string repo = root + "/repo";
    std::string full = repo + "/full";
    std::string inc = repo + "/inc";
    std::string target = root + "/target";
    MakeDir(repo);
    MakeDir(full);
    MakeDir(inc);

    std::string fullPage = MakeDataPage(1, 2, 'A');
    std::string incPage = MakeDataPage(1, 2, 'B');
    WriteBinaryFile(full + "/data_SYSTEM_1_0.bak", fullPage.data(), fullPage.size());
    WriteBinaryFile(inc + "/data_SYSTEM_1_0.bak", incPage.data(), incPage.size());

    std::vector<bak_file_t> fullFiles;
    fullFiles.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", fullPage.size()));
    WriteRealBackupset(full, "full_real", 0, "", 100, fullFiles);
    std::vector<bak_file_t> incFiles;
    incFiles.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", incPage.size()));
    std::vector<bak_dependence_t> depends;
    depends.push_back(MakeDependence("full/backupset"));
    WriteRealBackupset(inc, "inc_real", 1, "full_real", 200, incFiles, COMPRESS_NONE, ENCRYPT_NONE, depends);

    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full_real type=full backupset=full/backupset completion_time=100\n"
        "backup id=inc_real type=incremental parent=full_real backupset=inc/backupset completion_time=200\n");

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("inc_real", &param.backup_id);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    EXPECT_EQ(ReadFileSlice(target + "/data/data_SYSTEM_1.dbf", SIZE_K(8) * 2 + 128, 1), std::string("B"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreSkipsZeroSizeIncrementalDatafilePiece)
{
    std::string root = MakeTempDir("ogbak_restore_inc_zero_");
    std::string repo = root + "/repo";
    std::string full = repo + "/full";
    std::string inc = repo + "/inc";
    std::string target = root + "/target";
    MakeDir(repo);
    MakeDir(full);
    MakeDir(inc);

    std::string fullPage = MakeDataPage(1, 2, 'A');
    WriteBinaryFile(full + "/data_SYSTEM_1_0.bak", fullPage.data(), fullPage.size());
    WriteBinaryFile(inc + "/data_SYSTEM_1_0.bak", "", 0);

    std::vector<bak_file_t> fullFiles;
    fullFiles.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", fullPage.size()));
    WriteRealBackupset(full, "full_real", 0, "", 100, fullFiles);

    std::vector<bak_file_t> incFiles;
    incFiles.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", 0));
    std::vector<bak_dependence_t> depends;
    depends.push_back(MakeDependence("full/backupset"));
    WriteRealBackupset(inc, "inc_zero", 1, "full_real", 200, incFiles, COMPRESS_NONE, ENCRYPT_NONE, depends);

    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full_real type=full backupset=full/backupset completion_time=100\n"
        "backup id=inc_zero type=incremental parent=full_real backupset=inc/backupset completion_time=200\n");

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("inc_zero", &param.backup_id);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    EXPECT_EQ(ReadFileSlice(target + "/data/data_SYSTEM_1.dbf", SIZE_K(8) * 2 + 128, 1), std::string("A"));
    EXPECT_TRUE(Exists(target + "/.ogbackup_offline_restore_file_phase_complete"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsZeroCatalogSizeWithNonEmptyPayload)
{
    std::string root = MakeTempDir("ogbak_restore_inc_zero_bad_");
    std::string repo = root + "/repo";
    MakeDir(repo);

    std::string page = MakeDataPage(1, 2, 'B');
    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", page.data(), page.size());

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", 0));
    WriteRealBackupset(repo, "inc_zero_bad", 1, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam((root + "/target").c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsNonZeroCatalogSizeWithEmptyPayload)
{
    std::string root = MakeTempDir("ogbak_restore_inc_zero_bad2_");
    std::string repo = root + "/repo";
    MakeDir(repo);

    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", "", 0);

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", SIZE_K(8)));
    WriteRealBackupset(repo, "inc_zero_bad2", 1, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam((root + "/target").c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreDoesNotSkipEmptyPagesForIncrementalBackupset)
{
    std::string root = MakeTempDir("ogbak_restore_inc_empty_");
    std::string repo = root + "/repo";
    std::string full = repo + "/full";
    std::string inc = repo + "/inc";
    std::string target = root + "/target";
    MakeDir(repo);
    MakeDir(full);
    MakeDir(inc);

    std::string fullPage = MakeDataPage(1, 2, 'A');
    std::string emptyPage(SIZE_K(8), '\0');
    WriteBinaryFile(full + "/data_SYSTEM_1_0.bak", fullPage.data(), fullPage.size());
    WriteBinaryFile(inc + "/data_SYSTEM_1_0.bak", emptyPage.data(), emptyPage.size());

    std::vector<bak_file_t> fullFiles;
    fullFiles.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", fullPage.size()));
    WriteRealBackupset(full, "full_real", 0, "", 100, fullFiles);

    std::vector<bak_file_t> incFiles;
    incFiles.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", emptyPage.size()));
    std::vector<bak_dependence_t> depends;
    depends.push_back(MakeDependence("full/backupset"));
    WriteRealBackupset(inc, "inc_empty", 1, "full_real", 200, incFiles, COMPRESS_NONE, ENCRYPT_NONE, depends);

    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full_real type=full backupset=full/backupset completion_time=100\n"
        "backup id=inc_empty type=incremental parent=full_real backupset=inc/backupset completion_time=200\n");

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("inc_empty", &param.backup_id);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_TRUE(Exists(target + "/.ogbackup_offline_restore_failed"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsDbstorPayloadNaming)
{
    std::string root = MakeTempDir("ogbak_restore_dbstor_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    WriteTextFile(repo + "/arch_0_9_64_c8.bak", "arch-dbstor");

    bak_file_t arch = MakeBakFile(BACKUP_ARCH_FILE, 9, 0, nullptr, strlen("arch-dbstor"));
    arch.start_lsn = 100;
    arch.end_lsn = 200;
    std::vector<bak_file_t> files;
    files.push_back(arch);
    WriteRealBackupset(repo, "full_dbstor", 0, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreSelectsFullIncrementalChain)
{
    std::string root = MakeTempDir("ogbak_restore_inc_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    WriteTextFile(repo + "/full.dbf", "full");
    WriteTextFile(repo + "/inc.dbf", "inc");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n"
        "backup id=inc1 type=incremental parent=full1 db_id=10 cluster_id=20 db_version=1.0.0 completion_time=200\n" +
        FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf") +
        FileEntry("inc1", "inc.dbf", "data/system.dbf", repo + "/inc.dbf"));

    ogbak_offline_manifest_t manifest;
    ogbak_offline_plan_t plan;
    ogbak_param_t param = {0};
    char backupId[] = "inc1";
    param.backup_id.str = backupId;
    param.backup_id.len = (uint32)strlen(backupId);

    ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
    ASSERT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_SUCCESS);
    ASSERT_EQ(plan.chain_count, 2U);
    EXPECT_STREQ(plan.chain[0]->id, "full1");
    EXPECT_STREQ(plan.chain[1]->id, "inc1");
    ogbak_offline_free_plan(&plan);
    ogbak_offline_free_manifest(&manifest);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreSelectsFullCumulativeChain)
{
    std::string root = MakeTempDir("ogbak_restore_cum_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    WriteTextFile(repo + "/full.dbf", "full");
    WriteTextFile(repo + "/cum.dbf", "cum");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n"
        "backup id=cum1 type=cumulative parent=full1 db_id=10 cluster_id=20 db_version=1.0.0 completion_time=300\n" +
        FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf") +
        FileEntry("cum1", "cum.dbf", "data/system.dbf", repo + "/cum.dbf"));

    ogbak_offline_manifest_t manifest;
    ogbak_offline_plan_t plan;
    ogbak_param_t param = {0};
    char backupId[] = "cum1";
    param.backup_id.str = backupId;
    param.backup_id.len = (uint32)strlen(backupId);

    ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
    ASSERT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_SUCCESS);
    ASSERT_EQ(plan.chain_count, 2U);
    EXPECT_STREQ(plan.chain[0]->id, "full1");
    EXPECT_STREQ(plan.chain[1]->id, "cum1");
    ogbak_offline_free_plan(&plan);
    ogbak_offline_free_manifest(&manifest);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreOrdersCompleteParallelBackupPiecesForSerialExecution)
{
    std::string root = MakeTempDir("ogbak_restore_sections_ok_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    WriteTextFile(repo + "/s0.bak", "0");
    WriteTextFile(repo + "/s1.bak", "1");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full completion_time=100\n"
        "file backup_id=full1 type=data src=s1.bak target=data/system.dbf size=1 file_id=1 "
        "sec_id=1 sec_start=8192 sec_end=16384 parallel=true\n"
        "file backup_id=full1 type=data src=s0.bak target=data/system.dbf size=1 file_id=1 "
        "sec_id=0 sec_start=0 sec_end=8192 parallel=true\n");
    ogbak_offline_manifest_t manifest;
    ogbak_offline_plan_t plan;
    ogbak_param_t param = {0};
    ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
    ASSERT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_SUCCESS);
    ASSERT_TRUE(plan.parallel_pieces);
    EXPECT_EQ(plan.files[0]->sec_id, 0U);
    EXPECT_EQ(plan.files[1]->sec_id, 1U);
    ogbak_offline_free_plan(&plan);
    ogbak_offline_free_manifest(&manifest);
    RemoveTree(root);
}

TEST_F(TestCtbackup, ParseOfflineRestoreInPlaceAndPasswordFile)
{
    ogbak_param_t param = {0};
    char arg0[] = "ogbackup";
    char arg1[] = "--offline-restore";
    char arg2[] = "--backup-dir=/tmp/repo";
    char arg3[] = "--in-place";
    char arg4[] = "--force";
    char arg5[] = "--password-file=/secure/ogbackup.password";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5};

    ASSERT_EQ(ogbak_parse_restore_args(6, argv, &param), OG_SUCCESS);
    EXPECT_EQ(param.is_in_place, OG_TRUE);
    EXPECT_EQ(param.is_force, OG_TRUE);
    EXPECT_EQ(param.target_dir.str, nullptr);
    ASSERT_STREQ(param.password_file.str, "/secure/ogbackup.password");
    free_input_params(&param);
}

TEST_F(TestCtbackup, OfflineRestoreLocalInPlaceRepreparesTargetsAndCommitsControlLast)
{
    std::string root = MakeTempDir("ogbak_restore_local_inplace_");
    std::string repo = root + "/repo";
    std::string original = root + "/original";
    std::string dataDir = original + "/data";
    std::string redoDir = original + "/redo";
    std::string archDir = original + "/archive";
    MakeDir(repo);
    MakeDir(original);
    MakeDir(dataDir);
    MakeDir(redoDir);
    MakeDir(archDir);

    std::string dataPath = dataDir + "/sys.dat";
    std::string redoPath = redoDir + "/redo01.log";
    std::string archivePath = archDir + "/7.arc";
    std::string ctrl1 = original + "/ctrl1";
    std::string ctrl2 = original + "/ctrl2";
    std::string ctrl3 = original + "/ctrl3";
    uint64 datafileSize = SIZE_K(64);
    uint64 redoSize = SIZE_M(1);
    std::string ctrlPiece = MakeControlPieceWithLocalTargets(dataPath, redoPath, archivePath,
        datafileSize, redoSize);
    std::string page = MakeDataPage(1, 3, 'I');
    WriteBinaryFile(repo + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());
    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", page.data(), page.size());
    WriteTextFile(dataPath, "wrong-size-data");
    WriteTextFile(redoPath, "wrong-size-redo");

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr, ctrlPiece.size()));
    files.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", page.size()));
    std::string controlFiles = ctrl1 + "," + ctrl2 + "," + ctrl3;
    WriteRealBackupset(repo, "full_local_inplace", 0, "", 100, files, COMPRESS_NONE,
        ENCRYPT_NONE, {}, controlFiles.c_str());

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    param.is_offline = OG_TRUE;
    param.is_in_place = OG_TRUE;
    param.is_force = OG_TRUE;

    ASSERT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    struct stat dataStat;
    struct stat redoStat;
    ASSERT_EQ(stat(dataPath.c_str(), &dataStat), 0);
    ASSERT_EQ(stat(redoPath.c_str(), &redoStat), 0);
    EXPECT_EQ((uint64)dataStat.st_size, datafileSize);
    EXPECT_EQ((uint64)redoStat.st_size, redoSize);
    EXPECT_EQ(ReadFileSlice(dataPath, SIZE_K(8) * 3 + 128, 1), std::string("I"));
    EXPECT_TRUE(Exists(ctrl1));
    EXPECT_TRUE(Exists(ctrl2));
    EXPECT_TRUE(Exists(ctrl3));
    EXPECT_TRUE(Exists(repo + "/.ogbackup_offline_restore_file_phase_complete"));
    EXPECT_FALSE(Exists(repo + "/.ogbackup_offline_restore_in_progress"));
    EXPECT_FALSE(Exists(repo + "/.ogbackup_offline_restore_failed"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsMissingAndOverlappingParallelPieces)
{
    const char *badRanges[] = {
        "sec_id=2 sec_start=16384 sec_end=24576",
        "sec_id=1 sec_start=4096 sec_end=12288",
    };
    for (uint32 i = 0; i < 2; i++) {
        std::string root = MakeTempDir("ogbak_restore_sections_bad_");
        std::string repo = root + "/repo";
        MakeDir(repo);
        WriteTextFile(repo + "/s0.bak", "0");
        WriteTextFile(repo + "/s1.bak", "1");
        WriteTextFile(repo + "/offline_restore.manifest",
            std::string("backup id=full1 type=full completion_time=100\n") +
            "file backup_id=full1 type=data src=s0.bak target=data/system.dbf size=1 file_id=1 "
            "sec_id=0 sec_start=0 sec_end=8192 parallel=true\n" +
            "file backup_id=full1 type=data src=s1.bak target=data/system.dbf size=1 file_id=1 " +
            badRanges[i] + " parallel=true\n");
        ogbak_offline_manifest_t manifest;
        ogbak_offline_plan_t plan;
        ogbak_param_t param = {0};
        ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
        EXPECT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_ERROR);
        ogbak_offline_free_manifest(&manifest);
        RemoveTree(root);
    }
}

TEST_F(TestCtbackup, OfflineRestoreRejectsDuplicateTagsAndCumulativeOnDifferentialBranch)
{
    std::string root = MakeTempDir("ogbak_restore_chain_branch_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    WriteTextFile(repo + "/f.bak", "f");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full completion_time=100\n"
        "backup id=diff1 type=incremental parent=full1 completion_time=200\n"
        "backup id=cum1 type=cumulative parent=diff1 completion_time=300\n"
        "file backup_id=full1 type=data src=f.bak target=data/system.dbf size=1\n"
        "file backup_id=diff1 type=data src=f.bak target=data/system.dbf size=1\n"
        "file backup_id=cum1 type=data src=f.bak target=data/system.dbf size=1\n");
    ogbak_offline_manifest_t manifest;
    ogbak_offline_plan_t plan;
    ogbak_param_t param = {0};
    char selected[] = "cum1";
    param.backup_id.str = selected;
    param.backup_id.len = (uint32)strlen(selected);
    ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
    EXPECT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_ERROR);
    ogbak_offline_free_manifest(&manifest);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreFailsWhenParentBackupMissing)
{
    std::string root = MakeTempDir("ogbak_restore_missing_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    WriteTextFile(repo + "/inc.dbf", "inc");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=inc1 type=incremental parent=full_missing db_id=10 cluster_id=20 db_version=1.0.0 "
        "completion_time=200\n" +
        FileEntry("inc1", "inc.dbf", "data/system.dbf", repo + "/inc.dbf"));

    ogbak_offline_manifest_t manifest;
    ogbak_offline_plan_t plan;
    ogbak_param_t param = {0};
    char backupId[] = "inc1";
    param.backup_id.str = backupId;
    param.backup_id.len = (uint32)strlen(backupId);

    ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
    EXPECT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_ERROR);
    ogbak_offline_free_manifest(&manifest);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreFailsOnChecksumMismatch)
{
    std::string root = MakeTempDir("ogbak_restore_cks_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    WriteTextFile(repo + "/full.dbf", "full");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n"
        "file backup_id=full1 type=data src=full.dbf target=data/system.dbf size=4 checksum=1\n");

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreFailsOnVersionMismatch)
{
    std::string root = MakeTempDir("ogbak_restore_ver_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    WriteTextFile(repo + "/full.dbf", "full");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full version_major=1 version_minor=0 version_magic=0 db_id=10 cluster_id=20 "
        "db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf"));

    ogbak_offline_manifest_t manifest;
    ogbak_offline_plan_t plan;
    ogbak_param_t param = {0};
    ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
    EXPECT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_ERROR);
    ogbak_offline_free_manifest(&manifest);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreFailsOnDatabaseIdentityMismatch)
{
    std::string root = MakeTempDir("ogbak_restore_dbid_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    WriteTextFile(repo + "/full.dbf", "full");
    WriteTextFile(repo + "/inc.dbf", "inc");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n"
        "backup id=inc1 type=incremental parent=full1 db_id=11 cluster_id=20 db_version=1.0.0 completion_time=200\n" +
        FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf") +
        FileEntry("inc1", "inc.dbf", "data/system.dbf", repo + "/inc.dbf"));

    ogbak_offline_manifest_t manifest;
    ogbak_offline_plan_t plan;
    ogbak_param_t param = {0};
    char backupId[] = "inc1";
    param.backup_id.str = backupId;
    param.backup_id.len = (uint32)strlen(backupId);

    ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
    EXPECT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_ERROR);
    ogbak_offline_free_manifest(&manifest);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreFailsOnArchiveGapWhenArchiveRequired)
{
    std::string root = MakeTempDir("ogbak_restore_archgap_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    WriteTextFile(repo + "/full.dbf", "full");
    WriteTextFile(repo + "/offline_restore.manifest",
        "global version=1 archive_required=true\n"
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf") +
        "arch backup_id=full1 node=0 rst_id=1 start_asn=1 end_asn=2 start_lsn=1 end_lsn=20\n"
        "arch backup_id=full1 node=0 rst_id=1 start_asn=4 end_asn=5 start_lsn=40 end_lsn=50\n");

    ogbak_offline_manifest_t manifest;
    ogbak_offline_plan_t plan;
    ogbak_param_t param = {0};
    ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
    EXPECT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_ERROR);
    ogbak_offline_free_manifest(&manifest);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsNonEmptyTargetUnlessForced)
{
    std::string root = MakeTempDir("ogbak_restore_force_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    MakeDir(target);
    WriteTextFile(repo + "/full.dbf", "full");
    WriteTextFile(target + "/existing", "old");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf"));

    ogbak_param_t rejectParam = {0};
    SetTextParam(repo.c_str(), &rejectParam.backup_dir);
    SetTextParam(target.c_str(), &rejectParam.target_dir);
    rejectParam.is_offline = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&rejectParam), OG_ERROR);

    ogbak_param_t forceParam = {0};
    SetTextParam(repo.c_str(), &forceParam.backup_dir);
    SetTextParam(target.c_str(), &forceParam.target_dir);
    forceParam.is_offline = OG_TRUE;
    forceParam.is_force = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&forceParam), OG_SUCCESS);
    EXPECT_TRUE(Exists(target + "/data/system.dbf"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreCopiesLargeFilesWithStreamingCopy)
{
    std::string root = MakeTempDir("ogbak_restore_largecopy_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);

    std::string large(SIZE_M(3), 'L');
    large[SIZE_M(2) + 17] = 'X';
    WriteBinaryFile(repo + "/large.ctrl", large.data(), large.size());
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "large.ctrl", "ctrl/ctrl_0_0.bak", repo + "/large.ctrl"));

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;
    ASSERT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    EXPECT_EQ(ReadFileSlice(target + "/ctrl/ctrl_0_0.bak", SIZE_M(2) + 17, 1), "X");
    EXPECT_TRUE(Exists(target + "/.ogbackup_offline_restore_file_phase_complete"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreFailsOnDataPageChecksumMismatch)
{
    std::string root = MakeTempDir("ogbak_restore_pagecks_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string page = MakeDataPage(1, 1, 'C');
    page[128] = 'X';
    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", page.data(), page.size());

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", page.size()));
    WriteRealBackupset(repo, "full_bad_page", 0, "", 100, files);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_TRUE(Exists(target + "/.ogbackup_offline_restore_failed"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineDecoderEmitsPlainCompressedEncryptedAndCombinedPayloads)
{
    std::string root = MakeTempDir("ogbak_decoder_payload_");
    std::string plain = MakeDataPage(1, 1, 'A') + MakeDataPage(1, 2, 'B');
    bak_head_t head;
    bak_file_t file = MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", plain.size());
    errno_t ret = memset_s(&head, sizeof(head), 0, sizeof(head));
    ASSERT_EQ(ret, EOK);
    const char password[] = "UnitTestPassword#1";
    char key[OG_AES256KEYSIZE] = {0};
    head.encrypt_info.encrypt_alg = AES_256_GCM;
    FillEncryptedCatalogFields(password, &head, key);

    struct DecodeCase {
        const char *name;
        compress_algo_e compress;
        encrypt_algorithm_t encryptAlg;
    } cases[] = {
        {"plain", COMPRESS_NONE, ENCRYPT_NONE},
        {"compressed", COMPRESS_LZ4, ENCRYPT_NONE},
        {"encrypted", COMPRESS_NONE, AES_256_GCM},
        {"compressed_encrypted", COMPRESS_LZ4, AES_256_GCM},
    };

    for (const DecodeCase &item : cases) {
        std::string physical = item.compress == COMPRESS_NONE ? plain : CompressPayload(item.compress, plain);
        bak_file_t localFile = file;
        if (item.encryptAlg != ENCRYPT_NONE) {
            physical = EncryptPayload(physical, key, &localFile);
        }
        std::string path = root + "/" + item.name + ".bak";
        WriteBinaryFile(path, physical.data(), physical.size());
        decode_capture_t capture;
        bak_offline_decode_opts_t opts = MakeDecodeOpts(item.compress, item.encryptAlg, head, localFile,
            item.encryptAlg == ENCRYPT_NONE ? nullptr : password, physical.size());
        EXPECT_EQ(bak_offline_decode_backup_file(path.c_str(), &opts, CapturePlaintextCb, &capture), OG_SUCCESS)
            << item.name;
        EXPECT_EQ(capture.data, plain) << item.name;
    }
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineDecoderRejectsMissingAndWrongPasswordAndDamagedPayload)
{
    std::string root = MakeTempDir("ogbak_decoder_bad_crypto_");
    std::string plain = MakeDataPage(1, 1, 'E');
    bak_head_t head;
    bak_file_t file = MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", plain.size());
    errno_t ret = memset_s(&head, sizeof(head), 0, sizeof(head));
    ASSERT_EQ(ret, EOK);
    const char password[] = "UnitTestPassword#2";
    char key[OG_AES256KEYSIZE] = {0};
    head.encrypt_info.encrypt_alg = AES_256_GCM;
    FillEncryptedCatalogFields(password, &head, key);
    std::string cipher = EncryptPayload(plain, key, &file);
    std::string path = root + "/enc.bak";
    WriteBinaryFile(path, cipher.data(), cipher.size());

    decode_capture_t capture;
    bak_offline_decode_opts_t missing = MakeDecodeOpts(COMPRESS_NONE, AES_256_GCM, head, file, nullptr,
        cipher.size());
    EXPECT_EQ(bak_offline_decode_backup_file(path.c_str(), &missing, CapturePlaintextCb, &capture), OG_ERROR);

    bak_offline_decode_opts_t wrong = MakeDecodeOpts(COMPRESS_NONE, AES_256_GCM, head, file, "wrong-password",
        cipher.size());
    EXPECT_EQ(bak_offline_decode_backup_file(path.c_str(), &wrong, CapturePlaintextCb, &capture), OG_ERROR);

    cipher[0] ^= 0x1;
    WriteBinaryFile(path, cipher.data(), cipher.size());
    bak_offline_decode_opts_t damaged = MakeDecodeOpts(COMPRESS_NONE, AES_256_GCM, head, file, password,
        cipher.size());
    EXPECT_EQ(bak_offline_decode_backup_file(path.c_str(), &damaged, CapturePlaintextCb, &capture), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreDoesNotWriteBeforeEncryptedPayloadAuthentication)
{
    std::string root = MakeTempDir("ogbak_restore_gcm_target_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);

    const char password[] = "UnitTestRestorePassword#1";
    std::string plain = MakeDataPage(1, 1, 'G');
    bak_head_t head;
    ASSERT_EQ(memset_s(&head, sizeof(head), 0, sizeof(head)), EOK);
    head.version.major_ver = BAK_VERSION_MAJOR;
    head.version.min_ver = BAK_VERSION_MIN;
    head.version.magic = BAK_VERSION_MAGIC;
    ASSERT_EQ(strcpy_s(head.attr.tag, OG_NAME_BUFFER_SIZE, "full_gcm"), EOK);
    head.attr.backup_type = BACKUP_MODE_INCREMENTAL;
    head.attr.level = 0;
    head.encrypt_info.encrypt_alg = AES_256_GCM;
    head.file_count = 1;
    head.db_id = 10;
    ASSERT_EQ(strcpy_s(head.db_name, OG_DB_NAME_LEN, "TESTDB"), EOK);
    ASSERT_EQ(strcpy_s(head.db_version, OG_DB_NAME_LEN, "1.0.0"), EOK);
    head.completion_time = 100;
    head.ctrlinfo.rcy_point.lsn = 100;
    head.ctrlinfo.lrp_point.lsn = 110;

    char key[OG_AES256KEYSIZE] = {0};
    FillEncryptedCatalogFields(password, &head, key);
    bak_file_t file = MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", plain.size());
    std::string cipher = EncryptPayload(plain, key, &file);
    file.size = cipher.size();
    std::string catalog(sizeof(bak_head_t) + sizeof(bak_file_t), '\0');
    (void)memcpy(&catalog[0], &head, sizeof(head));
    (void)memcpy(&catalog[sizeof(bak_head_t)], &file, sizeof(file));
    CalcBackupsetHeadChecksum(reinterpret_cast<bak_head_t *>(&catalog[0]), (uint32)catalog.size());
    WriteBinaryFile(repo + "/backupset", catalog.data(), catalog.size());

    /* Corrupt the final ciphertext byte so GCM emits plaintext before tag failure. */
    cipher[cipher.size() - 1] ^= 0x1;
    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", cipher.data(), cipher.size());

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam(password, &param.password);
    param.is_offline = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/data/data_SYSTEM_1.dbf"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRefusesExistingFailedMarker)
{
    std::string root = MakeTempDir("ogbak_restore_failed_marker_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    MakeDir(target);
    WriteTextFile(repo + "/full.dbf", "full");
    WriteTextFile(target + "/.ogbackup_offline_restore_failed", "previous failure\n");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf"));

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;
    param.is_force = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(target + "/data/system.dbf"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsCompressedAndEncryptedBackupsets)
{
    std::string root = MakeTempDir("ogbak_restore_comp_enc_");
    std::string compressedRepo = root + "/compressed";
    std::string encryptedRepo = root + "/encrypted";
    std::string target = root + "/target";
    MakeDir(compressedRepo);
    MakeDir(encryptedRepo);

    std::vector<bak_file_t> files;
    WriteRealBackupset(compressedRepo, "full_compressed", 0, "", 100, files, COMPRESS_LZ4);
    WriteRealBackupset(encryptedRepo, "full_encrypted", 0, "", 100, files, COMPRESS_NONE, AES_256_GCM);

    ogbak_param_t compressedParam = {0};
    SetTextParam(compressedRepo.c_str(), &compressedParam.backup_dir);
    SetTextParam(target.c_str(), &compressedParam.target_dir);
    compressedParam.is_offline = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&compressedParam), OG_ERROR);

    ogbak_param_t encryptedParam = {0};
    SetTextParam(encryptedRepo.c_str(), &encryptedParam.backup_dir);
    SetTextParam(target.c_str(), &encryptedParam.target_dir);
    encryptedParam.is_offline = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&encryptedParam), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsCompressedPageAndMixedPageSize)
{
    std::string root = MakeTempDir("ogbak_restore_pagefmt_");
    std::string compressedRepo = root + "/compressed_page";
    std::string mixedRepo = root + "/mixed_page";
    std::string target = root + "/target";
    MakeDir(compressedRepo);
    MakeDir(mixedRepo);

    std::string compressedPage = MakeDataPage(1, 1, 'P');
    ((page_head_t *)&compressedPage[0])->compressed = 1;
    page_calc_checksum((page_head_t *)&compressedPage[0], SIZE_K(8));
    WriteBinaryFile(compressedRepo + "/data_SYSTEM_1_0.bak", compressedPage.data(), compressedPage.size());

    std::string firstPage = MakeDataPage(1, 1, 'M');
    std::string secondPage = MakeDataPage(1, 2, 'N');
    ((page_head_t *)&secondPage[0])->size_units = 4;
    std::string mixedPayload = firstPage + secondPage;
    WriteBinaryFile(mixedRepo + "/data_SYSTEM_1_0.bak", mixedPayload.data(), mixedPayload.size());

    std::vector<bak_file_t> compressedFiles;
    compressedFiles.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", compressedPage.size()));
    WriteRealBackupset(compressedRepo, "full_compressed_page", 0, "", 100, compressedFiles);

    std::vector<bak_file_t> mixedFiles;
    mixedFiles.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", mixedPayload.size()));
    WriteRealBackupset(mixedRepo, "full_mixed_page", 0, "", 100, mixedFiles);

    ogbak_param_t compressedParam = {0};
    SetTextParam(compressedRepo.c_str(), &compressedParam.backup_dir);
    SetTextParam(target.c_str(), &compressedParam.target_dir);
    compressedParam.is_offline = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&compressedParam), OG_ERROR);

    ogbak_param_t mixedParam = {0};
    SetTextParam(mixedRepo.c_str(), &mixedParam.backup_dir);
    SetTextParam((target + "_mixed").c_str(), &mixedParam.target_dir);
    mixedParam.is_offline = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&mixedParam), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsUnsafeTargetPaths)
{
    std::string root = MakeTempDir("ogbak_restore_path_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    WriteTextFile(repo + "/full.dbf", "full");

    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "/tmp/escape.dbf", repo + "/full.dbf"));
    ogbak_param_t absParam = {0};
    SetTextParam(repo.c_str(), &absParam.backup_dir);
    SetTextParam(target.c_str(), &absParam.target_dir);
    absParam.is_offline = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&absParam), OG_ERROR);

    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "data/../escape.dbf", repo + "/full.dbf"));
    ogbak_param_t dotdotParam = {0};
    SetTextParam(repo.c_str(), &dotdotParam.backup_dir);
    SetTextParam(target.c_str(), &dotdotParam.target_dir);
    dotdotParam.is_offline = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&dotdotParam), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsSymlinkPaths)
{
    std::string root = MakeTempDir("ogbak_restore_symlink_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    std::string outside = root + "/outside";
    MakeDir(repo);
    MakeDir(target);
    MakeDir(outside);
    WriteTextFile(repo + "/full.dbf", "full");
    ASSERT_EQ(symlink(outside.c_str(), (target + "/linkdir").c_str()), 0);
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "linkdir/system.dbf", repo + "/full.dbf"));

    ogbak_param_t targetSymlinkParam = {0};
    SetTextParam(repo.c_str(), &targetSymlinkParam.backup_dir);
    SetTextParam(target.c_str(), &targetSymlinkParam.target_dir);
    targetSymlinkParam.is_offline = OG_TRUE;
    targetSymlinkParam.is_force = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&targetSymlinkParam), OG_ERROR);

    RemoveTree(target);
    MakeDir(target);
    (void)remove((repo + "/full.dbf").c_str());
    WriteTextFile(outside + "/real.dbf", "full");
    ASSERT_EQ(symlink((outside + "/real.dbf").c_str(), (repo + "/full.dbf").c_str()), 0);
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "safe/system.dbf", outside + "/real.dbf"));

    ogbak_param_t srcSymlinkParam = {0};
    SetTextParam(repo.c_str(), &srcSymlinkParam.backup_dir);
    SetTextParam(target.c_str(), &srcSymlinkParam.target_dir);
    srcSymlinkParam.is_offline = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&srcSymlinkParam), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsLiveTargetEvenWithForce)
{
    std::string root = MakeTempDir("ogbak_restore_live_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    MakeDir(target);
    MakeDir(target + "/ctrl");
    WriteTextFile(repo + "/full.dbf", "full");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf"));

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    param.is_offline = OG_TRUE;
    param.is_force = OG_TRUE;
    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, OfflineRestoreRejectsUnsupportedManifestFormats)
{
    std::string root = MakeTempDir("ogbak_restore_unsupported_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    WriteTextFile(repo + "/full.dbf", "full");
    const char *unsupportedAttrs[] = {
        "compressed=true",
        "sparse=true",
        "storage_type=dbstor",
        "parallel_stream=true",
    };

    for (uint32 i = 0; i < (uint32)(sizeof(unsupportedAttrs) / sizeof(unsupportedAttrs[0])); i++) {
        WriteTextFile(repo + "/offline_restore.manifest",
            "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
            FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf").substr(0,
                FileEntry("full1", "full.dbf", "data/system.dbf", repo + "/full.dbf").size() - 1) +
            " " + unsupportedAttrs[i] + "\n");

        ogbak_offline_manifest_t manifest;
        ogbak_offline_plan_t plan;
        ogbak_param_t param = {0};
        ASSERT_EQ(ogbak_offline_load_manifest(repo.c_str(), &manifest), OG_SUCCESS);
        EXPECT_EQ(ogbak_offline_build_plan(&manifest, &param, &plan), OG_ERROR);
        ogbak_offline_free_manifest(&manifest);
    }
    RemoveTree(root);
}

static std::string CurrentUserName()
{
    struct passwd *pw = getpwuid(geteuid());
    return std::string(pw == nullptr ? "root" : pw->pw_name);
}

static std::string SchemeDBackupsetChecksum(const std::string &backupDir)
{
    char hash[OGBAK_SCHEME_D_HASH_HEX_LEN + 1] = {0};
    char err[1024] = {0};
    if (ogbak_scheme_d_sha256_file(backupDir.c_str(), hash, sizeof(hash), err, sizeof(err)) != OG_SUCCESS) {
        ADD_FAILURE() << err;
        return "";
    }
    return std::string(hash);
}

static std::string SchemeDEvidenceJson(const std::string &backupDir, bool includeAllNodes)
{
    uint64 now = (uint64)time(nullptr);
    std::string checksum = SchemeDBackupsetChecksum(backupDir);
    std::string nodes = includeAllNodes ?
        "\"nodes\":[{\"name\":\"node0\",\"db\":\"stopped\",\"cms\":\"stopped\",\"ogracd\":\"stopped\","
        "\"dssserver\":\"stopped\"},{\"name\":\"node1\",\"db\":\"stopped\",\"cms\":\"stopped\","
        "\"ogracd\":\"stopped\",\"dssserver\":\"stopped\"}]" :
        "\"nodes\":[{\"name\":\"node0\",\"db\":\"unknown\",\"cms\":\"stopped\",\"ogracd\":\"stopped\","
        "\"dssserver\":\"stopped\"}]";
    char buf[4096];
    (void)snprintf(buf, sizeof(buf),
        "{"
        "\"schema_version\":1,"
        "\"cluster_id\":\"cluster-a\","
        "\"generated_at\":%llu,"
        "\"expires_at\":%llu,"
        "\"operator\":\"tester\","
        "\"restore_user\":\"%s\","
        "\"expected_dss_home\":\"/tmp/dsshome\","
        "\"expected_dssserver_exe\":\"/tmp/dss/bin/dssserver\","
        "\"backupset_path\":\"%s\","
        "\"backupset_checksum\":\"%s\","
        "\"snapshot_id\":\"snap-001\","
        "\"snapshot_created_at\":%llu,"
        "\"snapshot_devices\":[\"wwid-1\"],"
        "\"vg_names\":[\"+vg1\",\"vg2\"],"
        "%s,"
        "\"old_vg_rollback_reference\":\"rollback-001\""
        "}",
        (unsigned long long)now, (unsigned long long)(now + 3600), CurrentUserName().c_str(),
        backupDir.c_str(), checksum.c_str(), (unsigned long long)(now - 10), nodes.c_str());
    return std::string(buf);
}

static std::string SchemeDDisposableEvidenceJson(const std::string &backupDir, const std::string &environmentClass,
    bool dataLossAccepted, bool productionUseForbidden, const std::string &authorizedBy,
    const std::string &authorizedAtField, const std::string &waiverReason, const std::string &wwids,
    bool includeAllNodes, bool includeRealSnapshot)
{
    uint64 now = (uint64)time(nullptr);
    std::string checksum = SchemeDBackupsetChecksum(backupDir);
    std::string nodes = includeAllNodes ?
        "\"nodes\":[{\"name\":\"node0\",\"db\":\"stopped\",\"cms\":\"stopped\",\"ogracd\":\"stopped\","
        "\"dssserver\":\"stopped\"},{\"name\":\"node1\",\"db\":\"stopped\",\"cms\":\"stopped\","
        "\"ogracd\":\"stopped\",\"dssserver\":\"stopped\"}]" :
        "\"nodes\":[{\"name\":\"node0\",\"db\":\"unknown\",\"cms\":\"stopped\",\"ogracd\":\"stopped\","
        "\"dssserver\":\"stopped\"}]";
    std::string snapshotFields = includeRealSnapshot ?
        "\"snapshot_id\":\"snap-should-not-coexist\",\"snapshot_created_at\":" + std::to_string(now - 10) + "," :
        "\"snapshot_id\":\"WAIVED\",";
    std::string authorizedAt = authorizedAtField.empty() ? "" : "\"authorized_at\":" + authorizedAtField + ",";
    char buf[8192];
    (void)snprintf(buf, sizeof(buf),
        "{"
        "\"schema_version\":1,"
        "\"cluster_id\":\"cluster-a\","
        "\"generated_at\":%llu,"
        "\"expires_at\":%llu,"
        "\"operator\":\"tester\","
        "\"restore_user\":\"%s\","
        "\"expected_dss_home\":\"/tmp/dsshome\","
        "\"expected_dssserver_exe\":\"/tmp/dss/bin/dssserver\","
        "\"backupset_path\":\"%s\","
        "\"backupset_checksum\":\"%s\","
        "\"environment_class\":\"%s\","
        "\"snapshot_mode\":\"waived\","
        "\"rollback_mode\":\"reinitialize_dss_vg\","
        "\"data_loss_accepted\":%s,"
        "\"production_use_forbidden\":%s,"
        "\"waiver_reason\":\"%s\","
        "\"authorized_by\":\"%s\","
        "%s"
        "%s"
        "\"target_wwids\":%s,"
        "\"vg_names\":[\"+vg1\",\"vg2\",\"vg3\"],"
        "%s,"
        "\"reset_procedure\":\"restricted header cleanup plus dsscmd cv\""
        "}",
        (unsigned long long)now, (unsigned long long)(now + 3600), CurrentUserName().c_str(),
        backupDir.c_str(), checksum.c_str(), environmentClass.c_str(), dataLossAccepted ? "true" : "false",
        productionUseForbidden ? "true" : "false", waiverReason.c_str(), authorizedBy.c_str(),
        authorizedAt.c_str(), snapshotFields.c_str(), wwids.c_str(), nodes.c_str());
    return std::string(buf);
}

static std::string SchemeDValidDisposableEvidenceJson(const std::string &backupDir)
{
    return SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true, "developer",
        std::to_string((uint64)time(nullptr) - 5), "declared development DSS LUNs are disposable",
        "[\"wwid-alpha\",\"wwid-beta\",\"wwid-gamma\"]", true, false);
}

static uint32 g_schemeDProviderChecks = 0;
static uint32 g_schemeDInitChecks = 0;
static uint32 g_schemeDPreflightChecks = 0;
static uint32 g_schemeDStatChecks = 0;
static uint32 g_schemeDExecuteCalls = 0;

static void ResetSchemeDHookCounters()
{
    g_schemeDProviderChecks = 0;
    g_schemeDInitChecks = 0;
    g_schemeDPreflightChecks = 0;
    g_schemeDStatChecks = 0;
    g_schemeDExecuteCalls = 0;
}

static status_t SchemeDProviderSuccessHook(const ogbak_scheme_d_evidence_t *evidence,
    ogbak_scheme_d_provider_t *provider, char *errBuf, uint32 errSize)
{
    (void)errBuf;
    (void)errSize;
    g_schemeDProviderChecks++;
    EXPECT_STREQ(evidence->expected_dss_home, "/tmp/dsshome");
    if (strcpy_s(provider->pid, sizeof(provider->pid), "12345") != EOK ||
        strcpy_s(provider->owner, sizeof(provider->owner), CurrentUserName().c_str()) != EOK ||
        strcpy_s(provider->exe, sizeof(provider->exe), "/tmp/dss/bin/dssserver") != EOK ||
        strcpy_s(provider->cmdline, sizeof(provider->cmdline),
        "/tmp/dss/bin/dssserver -D /tmp/dsshome -M") != EOK ||
        strcpy_s(provider->dss_home, sizeof(provider->dss_home), "/tmp/dsshome") != EOK ||
        strcpy_s(provider->socket_path, sizeof(provider->socket_path), "/tmp/dsshome/.dss_unix_d_socket") != EOK) {
        return OG_ERROR;
    }
    provider->allowed = OG_TRUE;
    return OG_SUCCESS;
}

static status_t SchemeDProviderRejectHook(const ogbak_scheme_d_evidence_t *evidence,
    ogbak_scheme_d_provider_t *provider, char *errBuf, uint32 errSize)
{
    (void)evidence;
    (void)provider;
    g_schemeDProviderChecks++;
    (void)snprintf(errBuf, errSize, "mock provider rejected");
    return OG_ERROR;
}

static status_t SchemeDInitSuccessHook()
{
    g_schemeDInitChecks++;
    return OG_SUCCESS;
}

static status_t SchemeDPreflightSuccessHook(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    char *failureReason, uint32 failureReasonSize)
{
    (void)param;
    (void)failureReason;
    (void)failureReasonSize;
    g_schemeDPreflightChecks++;
    EXPECT_EQ(plan->file_count, 1U);
    return OG_SUCCESS;
}

static status_t SchemeDStatSuccessHook(device_type_t type, const char *path, uint64 *size, uint64 *writtenSize)
{
    g_schemeDStatChecks++;
    EXPECT_EQ(type, DEV_TYPE_RAW);
    EXPECT_STREQ(path, "+vg1/datafile1");
    *size = SIZE_K(8);
    *writtenSize = 2048;
    return OG_SUCCESS;
}

static status_t SchemeDExecuteHookShouldNotRun(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    char *failureReason, uint32 failureReasonSize)
{
    (void)param;
    (void)plan;
    g_schemeDExecuteCalls++;
    (void)snprintf(failureReason, failureReasonSize, "execute hook should not run in preflight-only");
    return OG_ERROR;
}

TEST_F(TestCtbackup, OfflineRestoreRejectsRemovedDssOptionsAndHidesPassword)
{
    const char *removedOptions[] = {
        "--storage=dss",
        "--dss-map=+vg1:+vg2",
        "--allow-inplace-dss-restore",
        "--dss-scheme-d",
        "--dss-scheme-d-evidence=/tmp/evidence.json",
        "--dss-write-plan-out=/tmp/plan.json",
    };
    for (const char *removed : removedOptions) {
        ogbak_param_t parsed = {0};
        char arg0[] = "ogbackup";
        char arg1[] = "--offline-restore";
        char arg2[] = "--backup-dir=/tmp/repo";
        char arg3[] = "--target-dir=/tmp/target";
        std::vector<char> option(removed, removed + strlen(removed) + 1);
        char *argv[] = {arg0, arg1, arg2, arg3, option.data()};
        EXPECT_EQ(ogbak_parse_restore_args(5, argv, &parsed), OG_ERROR) << removed;
        free_input_params(&parsed);
    }

    ogbak_param_t passwordParsed = {0};
    char p0[] = "ogbackup";
    char p1[] = "--offline-restore";
    char p2[] = "--backup-dir=/tmp/repo";
    char p3[] = "--target-dir=/tmp/target";
    char p4[] = "--password=SecretForParserOnly";
    char *pargv[] = {p0, p1, p2, p3, p4};
    ASSERT_EQ(ogbak_parse_restore_args(5, pargv, &passwordParsed), OG_SUCCESS);
    ASSERT_STREQ(passwordParsed.password.str, "SecretForParserOnly");
    EXPECT_EQ(std::string(p4).find("SecretForParserOnly"), std::string::npos);
    free_input_params(&passwordParsed);
}

TEST_F(TestCtbackup, SchemeDPreflightOnlyPublishesPlanAndSkipsPayloadWrites)
{
    std::string root = MakeTempDir("ogbak_scheme_d_preflight_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string page = MakeDataPage(0, 0, 'F');
    WriteBinaryFile(repo + "/full.dbf", page.data(), page.size());
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "+vg1/datafile1", repo + "/full.dbf"));
    std::string evidencePath = root + "/evidence.json";
    std::string planPath = root + "/plan.json";
    WriteTextFile(evidencePath, SchemeDEvidenceJson(repo, true));
    ASSERT_EQ(chmod(evidencePath.c_str(), 0600), 0);

    ResetSchemeDHookCounters();
    ogbak_restore_set_scheme_d_unit_test_hooks(SchemeDProviderSuccessHook, SchemeDStatSuccessHook,
        SchemeDInitSuccessHook, SchemeDPreflightSuccessHook, SchemeDExecuteHookShouldNotRun);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("dss", &param.storage);
    SetTextParam(evidencePath.c_str(), &param.dss_scheme_d_evidence);
    SetTextParam(planPath.c_str(), &param.dss_write_plan_out);
    param.is_offline = OG_TRUE;
    param.is_force = OG_TRUE;
    param.allow_inplace_dss_restore = OG_TRUE;
    param.dss_scheme_d = OG_TRUE;
    param.dss_scheme_d_preflight_only = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    EXPECT_TRUE(Exists(planPath));
    std::string plan = ReadWholeFile(planPath);
    EXPECT_NE(plan.find("\"target\":\"+vg1/datafile1\""), std::string::npos);
    EXPECT_NE(plan.find("\"entry_count\": 1"), std::string::npos);
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_in_progress"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_failed"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_file_phase_complete"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_scheme_d_first_write"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_scheme_d_unsafe"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_scheme_d_complete"));
    EXPECT_EQ(g_schemeDProviderChecks, 1U);
    EXPECT_EQ(g_schemeDInitChecks, 1U);
    EXPECT_EQ(g_schemeDPreflightChecks, 1U);
    EXPECT_EQ(g_schemeDStatChecks, 1U);
    EXPECT_EQ(g_schemeDExecuteCalls, 0U);
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDPreflightOnlyRejectsProviderBeforeWritePlan)
{
    std::string root = MakeTempDir("ogbak_scheme_d_preflight_bad_provider_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string page = MakeDataPage(0, 0, 'F');
    WriteBinaryFile(repo + "/full.dbf", page.data(), page.size());
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "+vg1/datafile1", repo + "/full.dbf"));
    std::string evidencePath = root + "/evidence.json";
    std::string planPath = root + "/plan.json";
    WriteTextFile(evidencePath, SchemeDEvidenceJson(repo, true));
    ASSERT_EQ(chmod(evidencePath.c_str(), 0600), 0);

    ResetSchemeDHookCounters();
    ogbak_restore_set_scheme_d_unit_test_hooks(SchemeDProviderRejectHook, SchemeDStatSuccessHook,
        SchemeDInitSuccessHook, SchemeDPreflightSuccessHook, SchemeDExecuteHookShouldNotRun);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("dss", &param.storage);
    SetTextParam(evidencePath.c_str(), &param.dss_scheme_d_evidence);
    SetTextParam(planPath.c_str(), &param.dss_write_plan_out);
    param.is_offline = OG_TRUE;
    param.is_force = OG_TRUE;
    param.allow_inplace_dss_restore = OG_TRUE;
    param.dss_scheme_d = OG_TRUE;
    param.dss_scheme_d_preflight_only = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(planPath));
    EXPECT_EQ(g_schemeDProviderChecks, 1U);
    EXPECT_EQ(g_schemeDInitChecks, 0U);
    EXPECT_EQ(g_schemeDPreflightChecks, 0U);
    EXPECT_EQ(g_schemeDStatChecks, 0U);
    EXPECT_EQ(g_schemeDExecuteCalls, 0U);
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDDisposableWaiverValidatesExplicitEvidenceFields)
{
    std::string root = MakeTempDir("ogbak_scheme_d_waiver_ev_");
    std::string backupDir = root + "/backup";
    MakeDir(backupDir);
    std::string waived = root + "/waived.json";
    WriteTextFile(waived, SchemeDValidDisposableEvidenceJson(backupDir));
    ASSERT_EQ(chmod(waived.c_str(), 0600), 0);

    ogbak_scheme_d_evidence_t evidence;
    char err[1024] = {0};
    EXPECT_EQ(ogbak_scheme_d_validate_evidence(waived.c_str(), backupDir.c_str(), OG_FALSE, &evidence, err,
        sizeof(err)), OG_ERROR);
    EXPECT_EQ(ogbak_scheme_d_validate_evidence(waived.c_str(), backupDir.c_str(), OG_TRUE, &evidence, err,
        sizeof(err)), OG_ERROR);
    ASSERT_EQ(setenv("OGRAC_SCHEME_D_ALLOW_DISPOSABLE_WAIVER", "development-only", 1), 0);
    EXPECT_EQ(ogbak_scheme_d_validate_evidence(waived.c_str(), backupDir.c_str(), OG_TRUE, &evidence, err,
        sizeof(err)), OG_SUCCESS);
    EXPECT_EQ(evidence.disposable_waiver, OG_TRUE);
    EXPECT_STREQ(evidence.snapshot_id, "WAIVED");
    EXPECT_EQ(evidence.target_wwid_count, 3U);
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDDisposableWaiverAcceptsLongStringValuesBeforeLaterKeys)
{
    std::string root = MakeTempDir("ogbak_scheme_d_waiver_long_");
    std::string backupDir = root + "/backup";
    MakeDir(backupDir);
    std::string longReason(220, 'x');
    longReason += " node1 maintenance provider is open and aligned with current PR owner";
    std::string waived = root + "/waived.json";
    WriteTextFile(waived, SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true,
        "developer", std::to_string((uint64)time(nullptr) - 5), longReason,
        "[\"wwid-alpha\",\"wwid-beta\",\"wwid-gamma\"]", true, false));
    ASSERT_EQ(chmod(waived.c_str(), 0600), 0);
    ASSERT_EQ(setenv("OGRAC_SCHEME_D_ALLOW_DISPOSABLE_WAIVER", "development-only", 1), 0);

    ogbak_scheme_d_evidence_t evidence;
    char err[1024] = {0};
    EXPECT_EQ(ogbak_scheme_d_validate_evidence(waived.c_str(), backupDir.c_str(), OG_TRUE, &evidence, err,
        sizeof(err)), OG_SUCCESS) << err;
    EXPECT_STREQ(evidence.authorized_by, "developer");
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDDisposableWaiverRejectsUnsafeManifestVariants)
{
    std::string root = MakeTempDir("ogbak_scheme_d_waiver_bad_");
    std::string backupDir = root + "/backup";
    MakeDir(backupDir);
    ASSERT_EQ(setenv("OGRAC_SCHEME_D_ALLOW_DISPOSABLE_WAIVER", "development-only", 1), 0);

    struct Variant {
        const char *name;
        std::string json;
    };
    const char *validWwids = "[\"wwid-alpha\",\"wwid-beta\",\"wwid-gamma\"]";
    std::vector<Variant> variants = {
        {"bad_env", SchemeDDisposableEvidenceJson(backupDir, "production", true, true, "developer",
            std::to_string((uint64)time(nullptr) - 5), "reason", validWwids, true, false)},
        {"no_data_loss", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", false, true,
            "developer", std::to_string((uint64)time(nullptr) - 5), "reason", validWwids, true, false)},
        {"prod_allowed", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, false,
            "developer", std::to_string((uint64)time(nullptr) - 5), "reason", validWwids, true, false)},
        {"missing_auth_by", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true,
            "", std::to_string((uint64)time(nullptr) - 5), "reason", validWwids, true, false)},
        {"missing_auth_at", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true,
            "developer", "", "reason", validWwids, true, false)},
        {"missing_reason", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true,
            "developer", std::to_string((uint64)time(nullptr) - 5), "", validWwids, true, false)},
        {"wwid_empty", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true,
            "developer", std::to_string((uint64)time(nullptr) - 5), "reason", "[]", true, false)},
        {"wwid_duplicate", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true,
            "developer", std::to_string((uint64)time(nullptr) - 5), "reason",
            "[\"wwid-alpha\",\"wwid-alpha\",\"wwid-gamma\"]", true, false)},
        {"wwid_unsafe", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true,
            "developer", std::to_string((uint64)time(nullptr) - 5), "reason", "[\"wwid alpha\"]", true, false)},
        {"real_snapshot", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true,
            "developer", std::to_string((uint64)time(nullptr) - 5), "reason", validWwids, true, true)},
        {"bad_node", SchemeDDisposableEvidenceJson(backupDir, "disposable_development_only", true, true,
            "developer", std::to_string((uint64)time(nullptr) - 5), "reason", validWwids, false, false)},
    };

    for (const auto &variant : variants) {
        std::string path = root + "/" + variant.name + ".json";
        WriteTextFile(path, variant.json);
        ASSERT_EQ(chmod(path.c_str(), 0600), 0);
        ogbak_scheme_d_evidence_t evidence;
        char err[1024] = {0};
        EXPECT_EQ(ogbak_scheme_d_validate_evidence(path.c_str(), backupDir.c_str(), OG_TRUE, &evidence, err,
            sizeof(err)), OG_ERROR) << variant.name;
    }
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDDisposableWaiverPreflightOnlyKeepsNoPayloadBoundary)
{
    std::string root = MakeTempDir("ogbak_scheme_d_waiver_preflight_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    std::string page = MakeDataPage(0, 0, 'F');
    WriteBinaryFile(repo + "/full.dbf", page.data(), page.size());
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "+vg1/datafile1", repo + "/full.dbf"));
    std::string evidencePath = root + "/evidence.json";
    std::string planPath = root + "/plan.json";
    WriteTextFile(evidencePath, SchemeDValidDisposableEvidenceJson(repo));
    ASSERT_EQ(chmod(evidencePath.c_str(), 0600), 0);
    ASSERT_EQ(setenv("OGRAC_SCHEME_D_ALLOW_DISPOSABLE_WAIVER", "development-only", 1), 0);

    ResetSchemeDHookCounters();
    ogbak_restore_set_scheme_d_unit_test_hooks(SchemeDProviderSuccessHook, SchemeDStatSuccessHook,
        SchemeDInitSuccessHook, SchemeDPreflightSuccessHook, SchemeDExecuteHookShouldNotRun);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("dss", &param.storage);
    SetTextParam(evidencePath.c_str(), &param.dss_scheme_d_evidence);
    SetTextParam(planPath.c_str(), &param.dss_write_plan_out);
    param.is_offline = OG_TRUE;
    param.is_force = OG_TRUE;
    param.allow_inplace_dss_restore = OG_TRUE;
    param.dss_scheme_d = OG_TRUE;
    param.dss_scheme_d_preflight_only = OG_TRUE;
    param.dss_scheme_d_disposable_waiver = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    EXPECT_TRUE(Exists(planPath));
    std::string plan = ReadWholeFile(planPath);
    EXPECT_NE(plan.find("\"snapshot_id\": \"WAIVED\""), std::string::npos);
    EXPECT_FALSE(Exists(target + "/.ogbackup_offline_restore_in_progress"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_scheme_d_first_write"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_scheme_d_unsafe"));
    EXPECT_FALSE(Exists(target + "/.ogbackup_scheme_d_complete"));
    EXPECT_EQ(g_schemeDProviderChecks, 1U);
    EXPECT_EQ(g_schemeDInitChecks, 1U);
    EXPECT_EQ(g_schemeDPreflightChecks, 1U);
    EXPECT_EQ(g_schemeDStatChecks, 1U);
    EXPECT_EQ(g_schemeDExecuteCalls, 0U);
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDDisposableWaiverDoesNotBypassProviderGuard)
{
    std::string root = MakeTempDir("ogbak_scheme_d_waiver_provider_");
    std::string repo = root + "/repo";
    std::string target = root + "/target";
    MakeDir(repo);
    WriteTextFile(repo + "/full.dbf", "full-data");
    WriteTextFile(repo + "/offline_restore.manifest",
        "backup id=full1 type=full db_id=10 cluster_id=20 db_version=1.0.0 completion_time=100\n" +
        FileEntry("full1", "full.dbf", "+vg1/datafile1", repo + "/full.dbf"));
    std::string evidencePath = root + "/evidence.json";
    std::string planPath = root + "/plan.json";
    WriteTextFile(evidencePath, SchemeDValidDisposableEvidenceJson(repo));
    ASSERT_EQ(chmod(evidencePath.c_str(), 0600), 0);
    ASSERT_EQ(setenv("OGRAC_SCHEME_D_ALLOW_DISPOSABLE_WAIVER", "development-only", 1), 0);

    ResetSchemeDHookCounters();
    ogbak_restore_set_scheme_d_unit_test_hooks(SchemeDProviderRejectHook, SchemeDStatSuccessHook,
        SchemeDInitSuccessHook, SchemeDPreflightSuccessHook, SchemeDExecuteHookShouldNotRun);

    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("dss", &param.storage);
    SetTextParam(evidencePath.c_str(), &param.dss_scheme_d_evidence);
    SetTextParam(planPath.c_str(), &param.dss_write_plan_out);
    param.is_offline = OG_TRUE;
    param.is_force = OG_TRUE;
    param.allow_inplace_dss_restore = OG_TRUE;
    param.dss_scheme_d = OG_TRUE;
    param.dss_scheme_d_preflight_only = OG_TRUE;
    param.dss_scheme_d_disposable_waiver = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    EXPECT_FALSE(Exists(planPath));
    EXPECT_EQ(g_schemeDProviderChecks, 1U);
    EXPECT_EQ(g_schemeDInitChecks, 0U);
    EXPECT_EQ(g_schemeDPreflightChecks, 0U);
    EXPECT_EQ(g_schemeDStatChecks, 0U);
    EXPECT_EQ(g_schemeDExecuteCalls, 0U);
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDValidatesEvidenceAndRejectsBadNodeState)
{
    std::string root = MakeTempDir("ogbak_scheme_d_ev_");
    std::string backupDir = root + "/backup";
    MakeDir(backupDir);
    WriteTextFile(backupDir + "/payload.bin", "original-payload");
    std::string good = root + "/good.json";
    std::string bad = root + "/bad.json";
    WriteTextFile(good, SchemeDEvidenceJson(backupDir, true));
    WriteTextFile(bad, SchemeDEvidenceJson(backupDir, false));
    ASSERT_EQ(chmod(good.c_str(), 0600), 0);
    ASSERT_EQ(chmod(bad.c_str(), 0600), 0);

    ogbak_scheme_d_evidence_t evidence;
    char err[1024] = {0};
    EXPECT_EQ(ogbak_scheme_d_validate_evidence(good.c_str(), backupDir.c_str(), OG_FALSE, &evidence, err,
        sizeof(err)),
        OG_SUCCESS);
    EXPECT_STREQ(evidence.snapshot_id, "snap-001");
    EXPECT_EQ(evidence.vg_count, 2U);
    WriteTextFile(backupDir + "/payload.bin", "tampered-payload");
    memset(err, 0, sizeof(err));
    EXPECT_EQ(ogbak_scheme_d_validate_evidence(good.c_str(), backupDir.c_str(), OG_FALSE, &evidence, err,
        sizeof(err)), OG_ERROR);
    EXPECT_NE(std::string(err).find("checksum mismatch"), std::string::npos);
    EXPECT_EQ(ogbak_scheme_d_validate_evidence(bad.c_str(), backupDir.c_str(), OG_FALSE, &evidence, err,
        sizeof(err)),
        OG_ERROR);
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDParsesDssserverMaintenanceCmdlineNarrowly)
{
    char parsed[OG_MAX_FILE_PATH_LENGH] = {0};
    EXPECT_EQ(ogbak_scheme_d_parse_dssserver_cmdline(
        "/tmp/dss/bin/dssserver -D /tmp/dsshome -M", "/tmp/dsshome", parsed, sizeof(parsed)), OG_SUCCESS);
    EXPECT_STREQ(parsed, "/tmp/dsshome");
    EXPECT_EQ(ogbak_scheme_d_parse_dssserver_cmdline(
        "/tmp/dss/bin/dssserver -D /tmp/dsshome -M --readonly-volume", "/tmp/dsshome", parsed,
        sizeof(parsed)), OG_ERROR);
    EXPECT_EQ(ogbak_scheme_d_parse_dssserver_cmdline(
        "/tmp/dss/bin/dssserver -D /tmp/other -M", "/tmp/dsshome", parsed, sizeof(parsed)), OG_ERROR);
}

TEST_F(TestCtbackup, SchemeDWritePlanAndMarkerStateMachine)
{
    std::string root = MakeTempDir("ogbak_scheme_d_plan_");
    std::string backupDir = root + "/backup";
    std::string targetDir = root + "/target";
    MakeDir(backupDir);
    MakeDir(targetDir);
    std::string evidencePath = root + "/evidence.json";
    WriteTextFile(evidencePath, SchemeDEvidenceJson(backupDir, true));
    ASSERT_EQ(chmod(evidencePath.c_str(), 0600), 0);

    ogbak_scheme_d_evidence_t evidence;
    ogbak_scheme_d_provider_t provider = {0};
    ogbak_scheme_d_plan_t *plan = (ogbak_scheme_d_plan_t *)malloc(sizeof(ogbak_scheme_d_plan_t));
    ASSERT_NE(plan, nullptr);
    ASSERT_EQ(memset_s(plan, sizeof(*plan), 0, sizeof(*plan)), EOK);
    char err[1024] = {0};
    ASSERT_EQ(ogbak_scheme_d_validate_evidence(evidencePath.c_str(), backupDir.c_str(), OG_FALSE, &evidence, err,
        sizeof(err)), OG_SUCCESS);
    ASSERT_EQ(strcpy_s(provider.pid, sizeof(provider.pid), "123"), EOK);
    std::string planPath = root + "/plan.json";
    ASSERT_EQ(ogbak_scheme_d_begin_plan(planPath.c_str(), &evidence, &provider, plan, err, sizeof(err)),
        OG_SUCCESS);
    ASSERT_EQ(ogbak_scheme_d_append_plan_entry(plan, "+vg1/datafile1", "datafile", 0, 8192, 16384, 8192,
        nullptr, err, sizeof(err)), OG_SUCCESS);
    ASSERT_EQ(ogbak_scheme_d_finish_plan(plan, err, sizeof(err)), OG_SUCCESS);
    EXPECT_EQ(strlen(plan->hash), (size_t)OGBAK_SCHEME_D_HASH_HEX_LEN);
    EXPECT_EQ(ogbak_scheme_d_mark_first_write(targetDir.c_str(), &evidence, plan, err, sizeof(err)),
        OG_SUCCESS);
    EXPECT_EQ(ogbak_scheme_d_check_unsafe_marker(targetDir.c_str(), err, sizeof(err)), OG_ERROR);
    EXPECT_EQ(ogbak_scheme_d_mark_complete(targetDir.c_str(), &evidence, plan, err, sizeof(err)),
        OG_SUCCESS);
    EXPECT_EQ(ogbak_scheme_d_check_unsafe_marker(targetDir.c_str(), err, sizeof(err)), OG_SUCCESS);
    free(plan);
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDWritePlanFinishHashesLargePlansWithoutEvidenceJsonLimit)
{
    std::string root = MakeTempDir("ogbak_scheme_d_large_plan_");
    std::string backupDir = root + "/backup";
    MakeDir(backupDir);
    std::string evidencePath = root + "/evidence.json";
    WriteTextFile(evidencePath, SchemeDEvidenceJson(backupDir, true));
    ASSERT_EQ(chmod(evidencePath.c_str(), 0600), 0);

    ogbak_scheme_d_evidence_t evidence;
    ogbak_scheme_d_provider_t provider = {0};
    ogbak_scheme_d_plan_t *plan = (ogbak_scheme_d_plan_t *)malloc(sizeof(ogbak_scheme_d_plan_t));
    ASSERT_NE(plan, nullptr);
    ASSERT_EQ(memset_s(plan, sizeof(*plan), 0, sizeof(*plan)), EOK);
    char err[1024] = {0};
    ASSERT_EQ(ogbak_scheme_d_validate_evidence(evidencePath.c_str(), backupDir.c_str(), OG_FALSE, &evidence, err,
        sizeof(err)), OG_SUCCESS);
    ASSERT_EQ(strcpy_s(provider.pid, sizeof(provider.pid), "123"), EOK);
    std::string planPath = root + "/large_plan.json";
    ASSERT_EQ(ogbak_scheme_d_begin_plan(planPath.c_str(), &evidence, &provider, plan, err, sizeof(err)),
        OG_SUCCESS);
    for (uint32 i = 0; i < 9000; i++) {
        std::string target = "+vg1/datafile" + std::to_string(i);
        ASSERT_EQ(ogbak_scheme_d_append_plan_entry(plan, target.c_str(), "datafile", 0, 8192, 16384, 8192,
            nullptr, err, sizeof(err)), OG_SUCCESS);
    }
    ASSERT_EQ(ogbak_scheme_d_finish_plan(plan, err, sizeof(err)), OG_SUCCESS) << err;
    EXPECT_GT(ReadWholeFile(planPath).size(), (size_t)SIZE_M(1));
    EXPECT_EQ(strlen(plan->hash), (size_t)OGBAK_SCHEME_D_HASH_HEX_LEN);
    free(plan);
    RemoveTree(root);
}

static status_t RejectingPageWriteGuard(const char *targetPath, uint32 fileId, uint32 pageNo, uint64 offset,
    uint32 length, void *ctx)
{
    uint32 *calls = reinterpret_cast<uint32 *>(ctx);
    (*calls)++;
    EXPECT_NE(std::string(targetPath).find("/target.dbf"), std::string::npos);
    EXPECT_EQ(fileId, 1U);
    EXPECT_EQ(pageNo, 7U);
    EXPECT_EQ(offset, (uint64)7 * SIZE_K(8));
    EXPECT_EQ(length, (uint32)SIZE_K(8));
    return OG_ERROR;
}

TEST_F(TestCtbackup, SchemeDPageRangeUsesRealPageOffsetAndGuardRunsBeforeWrite)
{
    uint64 offset = 0;
    uint64 length = 0;
    ASSERT_EQ(bak_offline_calc_page_write_range(7, SIZE_K(8), &offset, &length), OG_SUCCESS);
    EXPECT_EQ(offset, (uint64)7 * SIZE_K(8));
    EXPECT_EQ(length, (uint64)SIZE_K(8));

    std::string root = MakeTempDir("ogbak_scheme_d_guard_");
    std::string src = root + "/data_SYSTEM_1_0.bak";
    std::string dst = root + "/target.dbf";
    std::string page = MakeDataPage(1, 7, 'R');
    WriteBinaryFile(src, page.data(), page.size());

    bak_offline_page_apply_opts_t opts = {0};
    opts.expected_file_id = 1;
    opts.expected_payload_size = page.size();
    opts.verify_page_checksum = OG_TRUE;
    opts.target_device_type = DEV_TYPE_FILE;
    uint32 calls = 0;
    opts.write_guard = RejectingPageWriteGuard;
    opts.write_guard_ctx = &calls;
    EXPECT_EQ(bak_offline_apply_data_pages(src.c_str(), dst.c_str(), &opts), OG_ERROR);
    EXPECT_EQ(calls, 1U);
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDProviderGetstatusReadinessRequiresMaintenanceOpen)
{
    EXPECT_EQ(ogbak_scheme_d_provider_getstatus_ready(
        "Server status of instance 0 is open and READONLY.\nMaster id is 0 .\nDSS_MAINTAIN is TRUE.\n"),
        OG_TRUE);
    EXPECT_EQ(ogbak_scheme_d_provider_getstatus_ready(
        "Server status of instance 0 is prepare and NORMAL.\nMaster id is 0 .\nDSS_MAINTAIN is TRUE.\n"),
        OG_FALSE);
    EXPECT_EQ(ogbak_scheme_d_provider_getstatus_ready(
        "Server status of instance 0 is unknown and NORMAL.\nMaster id is 0 .\nDSS_MAINTAIN is TRUE.\n"),
        OG_FALSE);
    EXPECT_EQ(ogbak_scheme_d_provider_getstatus_ready(
        "Server status of instance 0 is open and READWRITE.\nMaster id is 0 .\nDSS_MAINTAIN is FALSE.\n"),
        OG_FALSE);
}

TEST_F(TestCtbackup, SchemeDTargetManifestOnlyExportsControlAndPayloadSizesNoProvider)
{
    std::string root = MakeTempDir("ogbak_scheme_d_manifest_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    std::string ctrlPiece = MakeControlPieceWithDssPathsAndSizes(SIZE_M(1), SIZE_M(16));
    std::string highPage = MakeDataPage(1, 127, 'H');
    WriteBinaryFile(repo + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());
    WriteBinaryFile(repo + "/data_SYSTEM_1_0.bak", highPage.data(), highPage.size());

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr, ctrlPiece.size()));
    files.push_back(MakeBakFile(BACKUP_DATA_FILE, 1, 0, "SYSTEM", highPage.size()));
    WriteRealBackupset(repo, "full_scheme_d_manifest", 0, "", 100, files, COMPRESS_NONE, ENCRYPT_NONE, {},
        "(+vg1/ctrl1,+vg1/ctrl2,+vg1/ctrl3)");

    std::string manifestOut = root + "/target_manifest.json";
    std::string target = root + "/target";
    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("dss", &param.storage);
    SetTextParam(manifestOut.c_str(), &param.dss_target_manifest_out);
    param.is_offline = OG_TRUE;
    param.is_force = OG_TRUE;
    param.dss_scheme_d = OG_TRUE;
    param.dss_scheme_d_target_manifest_only = OG_TRUE;

    ASSERT_EQ(ogbak_do_offline_restore(&param), OG_SUCCESS);
    std::string manifest = ReadWholeFile(manifestOut);
    EXPECT_NE(manifest.find("\"mode\": \"target_manifest_only\""), std::string::npos);
    EXPECT_NE(manifest.find("\"path\":\"+vg1/ctrl1\""), std::string::npos);
    EXPECT_NE(manifest.find("\"path\":\"+vg1/ctrl3\""), std::string::npos);
    EXPECT_EQ(manifest.find("+vg1/ctrl3)"), std::string::npos);
    EXPECT_NE(manifest.find("\"path\":\"+vg1/sys.dat\""), std::string::npos);
    EXPECT_NE(manifest.find("\"control_size\":1048576"), std::string::npos);
    EXPECT_NE(manifest.find("\"payload_max_end\":1048576"), std::string::npos);
    EXPECT_NE(manifest.find("\"path\":\"+vg2/redo01.dat\""), std::string::npos);
    EXPECT_NE(manifest.find("\"unknown_target_count\": 0"), std::string::npos);
    EXPECT_FALSE(Exists(root + "/.ogbackup_scheme_d_first_write"));
    EXPECT_FALSE(Exists(root + "/.ogbackup_offline_restore_in_progress"));
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDTargetManifestOnlyBlocksMissingControlSize)
{
    std::string root = MakeTempDir("ogbak_scheme_d_manifest_block_");
    std::string repo = root + "/repo";
    MakeDir(repo);
    std::string ctrlPiece = MakeControlPiece(CTRL_MAX_PAGES_NONCLUSTERED);
    std::string page = MakeDataPage(9, 3, 'B');
    WriteBinaryFile(repo + "/ctrl_0_0.bak", ctrlPiece.data(), ctrlPiece.size());
    WriteBinaryFile(repo + "/data_SYSTEM_9_0.bak", page.data(), page.size());

    std::vector<bak_file_t> files;
    files.push_back(MakeBakFile(BACKUP_CTRL_FILE, 0, 0, nullptr, ctrlPiece.size()));
    files.push_back(MakeBakFile(BACKUP_DATA_FILE, 9, 0, "SYSTEM", page.size()));
    WriteRealBackupset(repo, "full_scheme_d_manifest_block", 0, "", 100, files, COMPRESS_NONE, ENCRYPT_NONE, {},
        "+vg1/ctrl1,+vg1/ctrl2,+vg1/ctrl3");

    std::string manifestOut = root + "/target_manifest.json";
    std::string target = root + "/target";
    ogbak_param_t param = {0};
    SetTextParam(repo.c_str(), &param.backup_dir);
    SetTextParam(target.c_str(), &param.target_dir);
    SetTextParam("dss", &param.storage);
    SetTextParam(manifestOut.c_str(), &param.dss_target_manifest_out);
    param.is_offline = OG_TRUE;
    param.is_force = OG_TRUE;
    param.dss_scheme_d = OG_TRUE;
    param.dss_scheme_d_target_manifest_only = OG_TRUE;

    EXPECT_EQ(ogbak_do_offline_restore(&param), OG_ERROR);
    std::string manifest = ReadWholeFile(manifestOut);
    EXPECT_NE(manifest.find("\"status\": \"BLOCKED\""), std::string::npos);
    EXPECT_NE(manifest.find("no matching required control metadata entry"), std::string::npos);
    RemoveTree(root);
}

TEST_F(TestCtbackup, SchemeDWritePlanRecordsRealHighPageRange)
{
    std::string root = MakeTempDir("ogbak_scheme_d_real_range_");
    std::string backupDir = root + "/backup";
    MakeDir(backupDir);
    std::string evidencePath = root + "/evidence.json";
    WriteTextFile(evidencePath, SchemeDEvidenceJson(backupDir, true));
    ASSERT_EQ(chmod(evidencePath.c_str(), 0600), 0);

    ogbak_scheme_d_evidence_t evidence;
    ogbak_scheme_d_provider_t provider = {0};
    ogbak_scheme_d_plan_t *plan = (ogbak_scheme_d_plan_t *)malloc(sizeof(ogbak_scheme_d_plan_t));
    ASSERT_NE(plan, nullptr);
    ASSERT_EQ(memset_s(plan, sizeof(*plan), 0, sizeof(*plan)), EOK);
    char err[1024] = {0};
    ASSERT_EQ(ogbak_scheme_d_validate_evidence(evidencePath.c_str(), backupDir.c_str(), OG_FALSE, &evidence, err,
        sizeof(err)), OG_SUCCESS);
    ASSERT_EQ(strcpy_s(provider.pid, sizeof(provider.pid), "123"), EOK);
    std::string planPath = root + "/plan.json";
    ASSERT_EQ(ogbak_scheme_d_begin_plan(planPath.c_str(), &evidence, &provider, plan, err, sizeof(err)),
        OG_SUCCESS);
    ASSERT_EQ(ogbak_scheme_d_append_plan_range(plan, "+vg1/sys.dat", "datafile", 1, (uint64)127 * SIZE_K(8),
        SIZE_K(8), SIZE_M(1), 0, SIZE_M(1), 0, "data_SYSTEM_1_0.bak", err, sizeof(err)), OG_SUCCESS);
    ASSERT_EQ(ogbak_scheme_d_finish_plan(plan, err, sizeof(err)), OG_SUCCESS);
    std::string text = ReadWholeFile(planPath);
    EXPECT_NE(text.find("\"offset\":1040384"), std::string::npos);
    EXPECT_NE(text.find("\"end\":1048576"), std::string::npos);
    EXPECT_EQ(ogbak_scheme_d_assert_plan_range(plan, "+vg1/sys.dat", 1, (uint64)127 * SIZE_K(8),
        SIZE_K(8), err, sizeof(err)), OG_SUCCESS);
    EXPECT_EQ(ogbak_scheme_d_assert_plan_range(plan, "+vg1/sys.dat", 1, (uint64)128 * SIZE_K(8),
        SIZE_K(8), err, sizeof(err)), OG_ERROR);
    free(plan);
    RemoveTree(root);
}
