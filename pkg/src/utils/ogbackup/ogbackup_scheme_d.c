/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * ogbackup_scheme_d.c
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_scheme_d.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogbackup_scheme_d.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "cm_encrypt.h"
#include "cm_file.h"

#define OGBAK_SCHEME_D_MAX_JSON_SIZE SIZE_M(1)
#define OGBAK_SCHEME_D_MARKER_FIRST_WRITE ".ogbackup_scheme_d_first_write"
#define OGBAK_SCHEME_D_MARKER_UNSAFE ".ogbackup_scheme_d_unsafe"
#define OGBAK_SCHEME_D_MARKER_COMPLETE ".ogbackup_scheme_d_complete"
#define OGBAK_SCHEME_D_DISPOSABLE_GATE_ENV "OGRAC_SCHEME_D_ALLOW_DISPOSABLE_WAIVER"
#define OGBAK_SCHEME_D_DISPOSABLE_GATE_VALUE "development-only"
#define OGBAK_SCHEME_D_PROVIDER_PROBE_TIMEOUT_SEC 5

static void ogbak_scheme_d_set_error(char *err_buf, uint32 err_size, const char *fmt, ...)
{
    if (err_buf == NULL || err_size == 0) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    int32 ret = vsnprintf_s(err_buf, err_size, err_size - 1, fmt, args);
    va_end(args);
    if (ret == -1) {
        (void)strcpy_s(err_buf, err_size, "scheme D validation failed");
    }
}

static const char *ogbak_scheme_d_skip_ws(const char *pos)
{
    while (pos != NULL && (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n')) {
        pos++;
    }
    return pos;
}

static const char *ogbak_scheme_d_parse_string(const char *pos, char *out, uint32 out_size)
{
    if (pos == NULL || *pos != '"' || out == NULL || out_size == 0) {
        return NULL;
    }
    pos++;
    uint32 used = 0;
    while (*pos != '\0' && *pos != '"') {
        if (*pos == '\\') {
            pos++;
            if (*pos == '\0') {
                return NULL;
            }
        }
        if (used + 1 >= out_size) {
            return NULL;
        }
        out[used++] = *pos++;
    }
    if (*pos != '"') {
        return NULL;
    }
    out[used] = '\0';
    return pos + 1;
}

static const char *ogbak_scheme_d_find_key(const char *json, const char *key)
{
    const char *pos = json;
    char item[OG_MAX_CONFIG_LINE_SIZE] = {0};
    while (pos != NULL && *pos != '\0') {
        if (*pos != '"') {
            pos++;
            continue;
        }
        const char *end = ogbak_scheme_d_parse_string(pos, item, sizeof(item));
        if (end == NULL) {
            return NULL;
        }
        end = ogbak_scheme_d_skip_ws(end);
        if (*end == ':' && strcmp(item, key) == 0) {
            return ogbak_scheme_d_skip_ws(end + 1);
        }
        pos = end;
    }
    return NULL;
}

static status_t ogbak_scheme_d_json_string(const char *json, const char *key, char *out, uint32 out_size,
    char *err_buf, uint32 err_size)
{
    const char *pos = ogbak_scheme_d_find_key(json, key);
    if (pos == NULL || ogbak_scheme_d_parse_string(pos, out, out_size) == NULL) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence missing string field %s", key);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_json_uint64(const char *json, const char *key, uint64 *value,
    char *err_buf, uint32 err_size)
{
    const char *pos = ogbak_scheme_d_find_key(json, key);
    if (pos == NULL || *pos < '0' || *pos > '9') {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence missing numeric field %s", key);
        return OG_ERROR;
    }
    uint64 result = 0;
    while (*pos >= '0' && *pos <= '9') {
        result = result * 10 + (uint64)(*pos - '0');
        pos++;
    }
    *value = result;
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_json_string_optional(const char *json, const char *key, char *out, uint32 out_size,
    char *err_buf, uint32 err_size)
{
    const char *pos = ogbak_scheme_d_find_key(json, key);
    if (pos == NULL) {
        if (out != NULL && out_size > 0) {
            out[0] = '\0';
        }
        return OG_SUCCESS;
    }
    if (ogbak_scheme_d_parse_string(pos, out, out_size) == NULL) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence has invalid string field %s", key);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_json_uint64_optional(const char *json, const char *key, uint64 *value,
    char *err_buf, uint32 err_size)
{
    const char *pos = ogbak_scheme_d_find_key(json, key);
    if (pos == NULL) {
        if (value != NULL) {
            *value = 0;
        }
        return OG_SUCCESS;
    }
    if (*pos < '0' || *pos > '9') {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence has invalid numeric field %s", key);
        return OG_ERROR;
    }
    uint64 result = 0;
    while (*pos >= '0' && *pos <= '9') {
        result = result * 10 + (uint64)(*pos - '0');
        pos++;
    }
    *value = result;
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_json_bool(const char *json, const char *key, bool32 *value,
    char *err_buf, uint32 err_size)
{
    const char *pos = ogbak_scheme_d_find_key(json, key);
    if (pos == NULL) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence missing bool field %s", key);
        return OG_ERROR;
    }
    if (strncmp(pos, "true", strlen("true")) == 0 &&
        (pos[strlen("true")] == '\0' || pos[strlen("true")] == ',' || pos[strlen("true")] == '}' ||
        pos[strlen("true")] == ']' || pos[strlen("true")] == ' ' || pos[strlen("true")] == '\t' ||
        pos[strlen("true")] == '\r' || pos[strlen("true")] == '\n')) {
        *value = OG_TRUE;
        return OG_SUCCESS;
    }
    if (strncmp(pos, "false", strlen("false")) == 0 &&
        (pos[strlen("false")] == '\0' || pos[strlen("false")] == ',' || pos[strlen("false")] == '}' ||
        pos[strlen("false")] == ']' || pos[strlen("false")] == ' ' || pos[strlen("false")] == '\t' ||
        pos[strlen("false")] == '\r' || pos[strlen("false")] == '\n')) {
        *value = OG_FALSE;
        return OG_SUCCESS;
    }
    ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence has invalid bool field %s", key);
    return OG_ERROR;
}

static bool32 ogbak_scheme_d_status_stopped(const char *status)
{
    return (strcmp(status, "stopped") == 0 || strcmp(status, "absent") == 0 || strcmp(status, "none") == 0) ?
        OG_TRUE : OG_FALSE;
}

static const char *ogbak_scheme_d_skip_json_value(const char *pos)
{
    pos = ogbak_scheme_d_skip_ws(pos);
    if (pos == NULL || *pos == '\0') {
        return NULL;
    }
    if (*pos == '"') {
        char tmp[OG_MAX_CONFIG_LINE_SIZE] = {0};
        return ogbak_scheme_d_parse_string(pos, tmp, sizeof(tmp));
    }
    if (*pos == '{' || *pos == '[') {
        char open_ch = *pos;
        char close_ch = open_ch == '{' ? '}' : ']';
        uint32 depth = 0;
        bool32 in_string = OG_FALSE;
        while (*pos != '\0') {
            if (*pos == '"' && (pos == NULL || *(pos - 1) != '\\')) {
                in_string = !in_string;
            } else if (!in_string && *pos == open_ch) {
                depth++;
            } else if (!in_string && *pos == close_ch) {
                if (--depth == 0) {
                    return pos + 1;
                }
            }
            pos++;
        }
        return NULL;
    }
    while (*pos != '\0' && *pos != ',' && *pos != '}' && *pos != ']') {
        pos++;
    }
    return pos;
}

static status_t ogbak_scheme_d_parse_vgs(const char *json, ogbak_scheme_d_evidence_t *evidence,
    char *err_buf, uint32 err_size)
{
    const char *pos = ogbak_scheme_d_find_key(json, "vg_names");
    if (pos == NULL || *pos != '[') {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence missing vg_names array");
        return OG_ERROR;
    }
    pos++;
    evidence->vg_count = 0;
    for (;;) {
        pos = ogbak_scheme_d_skip_ws(pos);
        if (*pos == ']') {
            break;
        }
        if (evidence->vg_count >= OGBAK_SCHEME_D_MAX_VGS ||
            ogbak_scheme_d_parse_string(pos, evidence->vg_names[evidence->vg_count],
            OG_NAME_BUFFER_SIZE) == NULL) {
            ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence has invalid vg_names entry");
            return OG_ERROR;
        }
        pos = ogbak_scheme_d_parse_string(pos, evidence->vg_names[evidence->vg_count], OG_NAME_BUFFER_SIZE);
        evidence->vg_count++;
        pos = ogbak_scheme_d_skip_ws(pos);
        if (*pos == ',') {
            pos++;
            continue;
        }
        if (*pos == ']') {
            break;
        }
        return OG_ERROR;
    }
    if (evidence->vg_count == 0) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence vg_names must not be empty");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_parse_nodes(const char *json, ogbak_scheme_d_evidence_t *evidence,
    char *err_buf, uint32 err_size)
{
    const char *pos = ogbak_scheme_d_find_key(json, "nodes");
    if (pos == NULL || *pos != '[') {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence missing nodes array");
        return OG_ERROR;
    }
    pos++;
    evidence->node_count = 0;
    while (*(pos = ogbak_scheme_d_skip_ws(pos)) != ']') {
        if (*pos != '{') {
            ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence nodes entry must be object");
            return OG_ERROR;
        }
        const char *obj_end = ogbak_scheme_d_skip_json_value(pos);
        if (obj_end == NULL || *(obj_end - 1) != '}') {
            ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence node object is malformed");
            return OG_ERROR;
        }
        char obj[OG_MAX_CONFIG_LINE_SIZE] = {0};
        uint32 len = (uint32)(obj_end - pos);
        if (len >= sizeof(obj)) {
            ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence node object is too large");
            return OG_ERROR;
        }
        (void)memcpy_s(obj, sizeof(obj), pos, len);
        char node_name[OG_NAME_BUFFER_SIZE] = {0};
        char db[OG_NAME_BUFFER_SIZE] = {0};
        char cms[OG_NAME_BUFFER_SIZE] = {0};
        char ogracd[OG_NAME_BUFFER_SIZE] = {0};
        char dssserver[OG_NAME_BUFFER_SIZE] = {0};
        if (ogbak_scheme_d_json_string(obj, "name", node_name, sizeof(node_name), err_buf, err_size) != OG_SUCCESS ||
            ogbak_scheme_d_json_string(obj, "db", db, sizeof(db), err_buf, err_size) != OG_SUCCESS ||
            ogbak_scheme_d_json_string(obj, "cms", cms, sizeof(cms), err_buf, err_size) != OG_SUCCESS ||
            ogbak_scheme_d_json_string(obj, "ogracd", ogracd, sizeof(ogracd), err_buf, err_size) != OG_SUCCESS ||
            ogbak_scheme_d_json_string(obj, "dssserver", dssserver, sizeof(dssserver), err_buf,
            err_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (ogbak_scheme_d_status_stopped(db) != OG_TRUE || ogbak_scheme_d_status_stopped(cms) != OG_TRUE ||
            ogbak_scheme_d_status_stopped(ogracd) != OG_TRUE ||
            ogbak_scheme_d_status_stopped(dssserver) != OG_TRUE) {
            ogbak_scheme_d_set_error(err_buf, err_size,
                "scheme D evidence node %s has non-stopped status db=%s cms=%s ogracd=%s dssserver=%s",
                node_name, db, cms, ogracd, dssserver);
            return OG_ERROR;
        }
        evidence->node_count++;
        pos = ogbak_scheme_d_skip_ws(obj_end);
        if (*pos == ',') {
            pos++;
        }
    }
    if (evidence->node_count == 0) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence nodes must not be empty");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_parse_target_wwids(const char *json, ogbak_scheme_d_evidence_t *evidence,
    char *err_buf, uint32 err_size)
{
    const char *pos = ogbak_scheme_d_find_key(json, "target_wwids");
    if (pos == NULL || *pos != '[') {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D disposable waiver missing target_wwids array");
        return OG_ERROR;
    }
    pos++;
    evidence->target_wwid_count = 0;
    for (;;) {
        pos = ogbak_scheme_d_skip_ws(pos);
        if (*pos == ']') {
            break;
        }
        if (evidence->target_wwid_count >= OGBAK_SCHEME_D_MAX_WWIDS ||
            ogbak_scheme_d_parse_string(pos, evidence->target_wwids[evidence->target_wwid_count],
            OG_NAME_BUFFER_SIZE) == NULL) {
            ogbak_scheme_d_set_error(err_buf, err_size, "scheme D disposable waiver has invalid target_wwids entry");
            return OG_ERROR;
        }
        for (uint32 i = 0; i < evidence->target_wwid_count; i++) {
            if (strcmp(evidence->target_wwids[i], evidence->target_wwids[evidence->target_wwid_count]) == 0) {
                ogbak_scheme_d_set_error(err_buf, err_size,
                    "scheme D disposable waiver target_wwids contains duplicate %s",
                    evidence->target_wwids[evidence->target_wwid_count]);
                return OG_ERROR;
            }
        }
        pos = ogbak_scheme_d_parse_string(pos, evidence->target_wwids[evidence->target_wwid_count],
            OG_NAME_BUFFER_SIZE);
        evidence->target_wwid_count++;
        pos = ogbak_scheme_d_skip_ws(pos);
        if (*pos == ',') {
            pos++;
            continue;
        }
        if (*pos == ']') {
            break;
        }
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 ogbak_scheme_d_wwid_char_allowed(char c)
{
    return (bool32)(isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.' || c == ':');
}

static status_t ogbak_scheme_d_validate_disposable_wwids(const ogbak_scheme_d_evidence_t *evidence,
    char *err_buf, uint32 err_size)
{
    if (evidence->target_wwid_count == 0) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D disposable waiver target_wwids must explicitly list authorized disposable targets");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < evidence->target_wwid_count; i++) {
        const char *wwid = evidence->target_wwids[i];
        if (wwid[0] == '\0') {
            ogbak_scheme_d_set_error(err_buf, err_size,
                "scheme D disposable waiver target_wwids contains empty entry");
            return OG_ERROR;
        }
        for (const char *p = wwid; *p != '\0'; p++) {
            if (ogbak_scheme_d_wwid_char_allowed(*p) != OG_TRUE) {
                ogbak_scheme_d_set_error(err_buf, err_size,
                    "scheme D disposable waiver target_wwids contains unsafe entry %s", wwid);
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

static void ogbak_scheme_d_hex(const uchar *bytes, uint32 len, char *hex, uint32 hex_size)
{
    static const char digits[] = "0123456789abcdef";
    if (hex_size < len * 2 + 1) {
        return;
    }
    for (uint32 i = 0; i < len; i++) {
        hex[i * 2] = digits[(bytes[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = digits[bytes[i] & 0x0F];
    }
    hex[len * 2] = '\0';
}

static status_t ogbak_scheme_d_sha256_buffer(const char *buf, uint32 len, char *hex, uint32 hex_size)
{
    uchar sha[32] = {0};
    uint32 sha_len = sizeof(sha);
    if (cm_generate_sha256((uchar *)buf, len, sha, &sha_len) != OG_SUCCESS || sha_len != sizeof(sha)) {
        return OG_ERROR;
    }
    ogbak_scheme_d_hex(sha, sha_len, hex, hex_size);
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_sha256_file_content(const char *path, char *hex, uint32 hex_size,
    char *err_buf, uint32 err_size)
{
    if (path == NULL || hex == NULL || hex_size < OGBAK_SCHEME_D_HASH_HEX_LEN + 1) {
        return OG_ERROR;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        if (ctx != NULL) {
            EVP_MD_CTX_free(ctx);
        }
        ogbak_scheme_d_set_error(err_buf, err_size, "calculate scheme D file sha256 failed: %s", path);
        return OG_ERROR;
    }

    int fd = open(path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        EVP_MD_CTX_free(ctx);
        ogbak_scheme_d_set_error(err_buf, err_size, "open scheme D file for sha256 failed: %s errno=%d",
            path, errno);
        return OG_ERROR;
    }
    char buf[SIZE_K(64)];
    status_t status = OG_SUCCESS;
    for (;;) {
        ssize_t read_size = read(fd, buf, sizeof(buf));
        if (read_size < 0) {
            status = OG_ERROR;
            break;
        }
        if (read_size == 0) {
            break;
        }
        if (EVP_DigestUpdate(ctx, buf, (size_t)read_size) != 1) {
            status = OG_ERROR;
            break;
        }
    }
    (void)close(fd);

    uchar sha[32] = {0};
    uint32 sha_len = sizeof(sha);
    if (status == OG_SUCCESS && EVP_DigestFinal_ex(ctx, sha, &sha_len) != 1) {
        status = OG_ERROR;
    }
    EVP_MD_CTX_free(ctx);
    if (status != OG_SUCCESS || sha_len != sizeof(sha)) {
        ogbak_scheme_d_set_error(err_buf, err_size, "calculate scheme D file sha256 failed: %s", path);
        return OG_ERROR;
    }
    ogbak_scheme_d_hex(sha, sha_len, hex, hex_size);
    return OG_SUCCESS;
}

static bool32 ogbak_scheme_d_is_sha256_hex(const char *value)
{
    if (value == NULL || strlen(value) != OGBAK_SCHEME_D_HASH_HEX_LEN) {
        return OG_FALSE;
    }
    for (const char *pos = value; *pos != '\0'; pos++) {
        if (!isxdigit((unsigned char)*pos)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static status_t ogbak_scheme_d_read_text_file(const char *path, char **buf, uint32 *size,
    char *err_buf, uint32 err_size)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        st.st_size > OGBAK_SCHEME_D_MAX_JSON_SIZE) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence file is invalid: %s", path);
        return OG_ERROR;
    }
    int fd = open(path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        ogbak_scheme_d_set_error(err_buf, err_size, "open scheme D file %s failed, errno=%d", path, errno);
        return OG_ERROR;
    }
    char *text = (char *)malloc((size_t)st.st_size + 1);
    if (text == NULL) {
        (void)close(fd);
        return OG_ERROR;
    }
    ssize_t read_size = read(fd, text, (size_t)st.st_size);
    (void)close(fd);
    if (read_size != st.st_size) {
        CM_FREE_PTR(text);
        ogbak_scheme_d_set_error(err_buf, err_size, "read scheme D file %s failed", path);
        return OG_ERROR;
    }
    text[read_size] = '\0';
    *buf = text;
    *size = (uint32)read_size;
    return OG_SUCCESS;
}

static int ogbak_scheme_d_name_cmp(const void *left, const void *right)
{
    const char *const *left_name = (const char *const *)left;
    const char *const *right_name = (const char *const *)right;
    return strcmp(*left_name, *right_name);
}

static bool32 ogbak_scheme_d_is_runtime_marker(const char *name)
{
    static const char *const markers[] = {
        ".ogbackup_offline_restore_in_progress",
        ".ogbackup_offline_restore_failed",
        ".ogbackup_offline_restore_file_phase_complete",
        ".ogbackup_scheme_d_first_write",
        ".ogbackup_scheme_d_unsafe",
        ".ogbackup_scheme_d_complete",
    };
    for (uint32 i = 0; i < (uint32)(sizeof(markers) / sizeof(markers[0])); i++) {
        if (strcmp(name, markers[i]) == 0) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t ogbak_scheme_d_sha256_update_text(EVP_MD_CTX *ctx, const char *text)
{
    if (text == NULL) {
        text = "";
    }
    return EVP_DigestUpdate(ctx, text, strlen(text) + 1) == 1 ? OG_SUCCESS : OG_ERROR;
}

static status_t ogbak_scheme_d_sha256_update_uint64(EVP_MD_CTX *ctx, uint64 value)
{
    return EVP_DigestUpdate(ctx, &value, sizeof(value)) == 1 ? OG_SUCCESS : OG_ERROR;
}

static void ogbak_scheme_d_free_names(char **names, uint32 count)
{
    if (names == NULL) {
        return;
    }
    for (uint32 i = 0; i < count; i++) {
        CM_FREE_PTR(names[i]);
    }
    CM_FREE_PTR(names);
}

static status_t ogbak_scheme_d_join_path(const char *base, const char *name, char *path, uint32 path_size)
{
    if (base == NULL || name == NULL || path == NULL) {
        return OG_ERROR;
    }
    int32 ret = snprintf_s(path, path_size, path_size - 1, "%s/%s", base, name);
    return ret == -1 ? OG_ERROR : OG_SUCCESS;
}

static status_t ogbak_scheme_d_join_rel(const char *base, const char *name, char *path, uint32 path_size)
{
    if (name == NULL || path == NULL) {
        return OG_ERROR;
    }
    int32 ret;
    if (base == NULL || base[0] == '\0') {
        ret = snprintf_s(path, path_size, path_size - 1, "%s", name);
    } else {
        ret = snprintf_s(path, path_size, path_size - 1, "%s/%s", base, name);
    }
    return ret == -1 ? OG_ERROR : OG_SUCCESS;
}

static status_t ogbak_scheme_d_sha256_regular(EVP_MD_CTX *ctx, const char *path, const char *rel,
    const struct stat *st, char *err_buf, uint32 err_size)
{
    if (ogbak_scheme_d_sha256_update_text(ctx, "file") != OG_SUCCESS ||
        ogbak_scheme_d_sha256_update_text(ctx, rel) != OG_SUCCESS ||
        ogbak_scheme_d_sha256_update_uint64(ctx, (uint64)st->st_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    int fd = open(path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        ogbak_scheme_d_set_error(err_buf, err_size, "open scheme D sha256 file %s failed, errno=%d", path, errno);
        return OG_ERROR;
    }
    char buf[SIZE_K(64)];
    status_t status = OG_SUCCESS;
    for (;;) {
        ssize_t read_size = read(fd, buf, sizeof(buf));
        if (read_size == 0) {
            break;
        }
        if (read_size < 0 || EVP_DigestUpdate(ctx, buf, (size_t)read_size) != 1) {
            status = OG_ERROR;
            break;
        }
    }
    (void)close(fd);
    return status;
}

static status_t ogbak_scheme_d_sha256_symlink(EVP_MD_CTX *ctx, const char *path, const char *rel)
{
    char target[OG_MAX_FILE_PATH_LENGH] = {0};
    ssize_t len = readlink(path, target, sizeof(target) - 1);
    if (len < 0) {
        return OG_ERROR;
    }
    target[len] = '\0';
    return ogbak_scheme_d_sha256_update_text(ctx, "symlink") == OG_SUCCESS &&
        ogbak_scheme_d_sha256_update_text(ctx, rel) == OG_SUCCESS &&
        ogbak_scheme_d_sha256_update_text(ctx, target) == OG_SUCCESS ? OG_SUCCESS : OG_ERROR;
}

static status_t ogbak_scheme_d_sha256_dir(EVP_MD_CTX *ctx, const char *path, const char *rel,
    char *err_buf, uint32 err_size);

static status_t ogbak_scheme_d_sha256_path(EVP_MD_CTX *ctx, const char *path, const char *rel,
    char *err_buf, uint32 err_size)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        ogbak_scheme_d_set_error(err_buf, err_size, "stat scheme D sha256 path %s failed, errno=%d", path, errno);
        return OG_ERROR;
    }
    if (S_ISREG(st.st_mode)) {
        return ogbak_scheme_d_sha256_regular(ctx, path, rel, &st, err_buf, err_size);
    }
    if (S_ISDIR(st.st_mode)) {
        return ogbak_scheme_d_sha256_dir(ctx, path, rel, err_buf, err_size);
    }
    if (S_ISLNK(st.st_mode)) {
        return ogbak_scheme_d_sha256_symlink(ctx, path, rel);
    }
    ogbak_scheme_d_set_error(err_buf, err_size, "unsupported scheme D sha256 path type: %s", path);
    return OG_ERROR;
}

static status_t ogbak_scheme_d_collect_dir_names(const char *path, char ***names_out, uint32 *count_out,
    char *err_buf, uint32 err_size)
{
    DIR *dir = opendir(path);
    if (dir == NULL) {
        ogbak_scheme_d_set_error(err_buf, err_size, "open scheme D sha256 dir %s failed, errno=%d", path, errno);
        return OG_ERROR;
    }
    char **names = NULL;
    uint32 count = 0;
    status_t status = OG_SUCCESS;
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (ogbak_scheme_d_is_runtime_marker(entry->d_name) == OG_TRUE) {
            continue;
        }
        char **new_names = (char **)realloc(names, sizeof(char *) * (count + 1));
        if (new_names == NULL) {
            status = OG_ERROR;
            break;
        }
        names = new_names;
        names[count] = (char *)malloc(strlen(entry->d_name) + 1);
        if (names[count] == NULL || strcpy_s(names[count], strlen(entry->d_name) + 1, entry->d_name) != EOK) {
            status = OG_ERROR;
            break;
        }
        count++;
    }
    (void)closedir(dir);
    if (status != OG_SUCCESS) {
        ogbak_scheme_d_free_names(names, count);
        return OG_ERROR;
    }
    qsort(names, count, sizeof(char *), ogbak_scheme_d_name_cmp);
    *names_out = names;
    *count_out = count;
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_sha256_dir(EVP_MD_CTX *ctx, const char *path, const char *rel,
    char *err_buf, uint32 err_size)
{
    if (ogbak_scheme_d_sha256_update_text(ctx, "dir") != OG_SUCCESS ||
        ogbak_scheme_d_sha256_update_text(ctx, rel) != OG_SUCCESS) {
        return OG_ERROR;
    }

    char **names = NULL;
    uint32 count = 0;
    if (ogbak_scheme_d_collect_dir_names(path, &names, &count, err_buf, err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    status_t status = OG_SUCCESS;
    for (uint32 i = 0; i < count; i++) {
        char child_path[OG_MAX_FILE_PATH_LENGH] = {0};
        char child_rel[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_scheme_d_join_path(path, names[i], child_path, sizeof(child_path)) != OG_SUCCESS ||
            ogbak_scheme_d_join_rel(rel, names[i], child_rel, sizeof(child_rel)) != OG_SUCCESS ||
            ogbak_scheme_d_sha256_path(ctx, child_path, child_rel, err_buf, err_size) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }
    }
    ogbak_scheme_d_free_names(names, count);
    return status;
}

static status_t ogbak_scheme_d_check_file_owner_mode(const char *path, const char *restore_user,
    char *err_buf, uint32 err_size)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        ogbak_scheme_d_set_error(err_buf, err_size, "stat scheme D evidence %s failed", path);
        return OG_ERROR;
    }
    if (st.st_uid != 0) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D evidence owner must be root; path=%s uid=%u restore_user=%s",
            path, (uint32)st.st_uid, restore_user == NULL ? "" : restore_user);
        return OG_ERROR;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence must not be group/world writable: %s", path);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_sha256_file(const char *path, char *hex, uint32 hex_size, char *err_buf, uint32 err_size)
{
    if (path == NULL || hex == NULL || hex_size < OGBAK_SCHEME_D_HASH_HEX_LEN + 1) {
        return OG_ERROR;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        if (ctx != NULL) {
            EVP_MD_CTX_free(ctx);
        }
        ogbak_scheme_d_set_error(err_buf, err_size, "calculate scheme D sha256 failed: %s", path);
        return OG_ERROR;
    }

    status_t status = ogbak_scheme_d_sha256_path(ctx, path, "", err_buf, err_size);
    uchar sha[32] = {0};
    uint32 sha_len = sizeof(sha);
    if (status == OG_SUCCESS && EVP_DigestFinal_ex(ctx, sha, &sha_len) != 1) {
        status = OG_ERROR;
    }
    EVP_MD_CTX_free(ctx);
    if (status != OG_SUCCESS || sha_len != sizeof(sha)) {
        ogbak_scheme_d_set_error(err_buf, err_size, "calculate scheme D sha256 failed: %s", path);
        return OG_ERROR;
    }
    ogbak_scheme_d_hex(sha, sha_len, hex, hex_size);
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_verify_backupset_checksum(const char *backup_dir, const char *expected_checksum,
    char *err_buf, uint32 err_size)
{
    if (backup_dir == NULL || expected_checksum == NULL ||
        ogbak_scheme_d_is_sha256_hex(expected_checksum) != OG_TRUE) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D backupset_checksum must be a 64-character hexadecimal SHA-256 digest");
        return OG_ERROR;
    }

    char actual_checksum[OGBAK_SCHEME_D_HASH_HEX_LEN + 1] = {0};
    if (ogbak_scheme_d_sha256_file(backup_dir, actual_checksum, sizeof(actual_checksum), err_buf, err_size) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }
    if (strcasecmp(actual_checksum, expected_checksum) != 0) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D backupset checksum mismatch: backup_dir=%s expected=%s actual=%s",
            backup_dir, expected_checksum, actual_checksum);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_realpath_equal(const char *left, const char *right)
{
    char left_real[OG_MAX_FILE_PATH_LENGH] = {0};
    char right_real[OG_MAX_FILE_PATH_LENGH] = {0};
    if (realpath(left, left_real) == NULL || realpath(right, right_real) == NULL) {
        return strcmp(left, right) == 0 ? OG_SUCCESS : OG_ERROR;
    }
    return strcmp(left_real, right_real) == 0 ? OG_SUCCESS : OG_ERROR;
}

static status_t ogbak_scheme_d_validate_snapshot_evidence(const char *json, ogbak_scheme_d_evidence_t *evidence,
    bool32 disposable_waiver_requested, char *err_buf, uint32 err_size)
{
    if (disposable_waiver_requested == OG_TRUE) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D disposable waiver requested but evidence is not snapshot_mode=waived");
        return OG_ERROR;
    }
    if (strcmp(evidence->snapshot_mode, "waived") == 0) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D evidence snapshot_mode=waived requires explicit disposable-waiver authorization");
        return OG_ERROR;
    }
    if (ogbak_scheme_d_json_string(json, "snapshot_id", evidence->snapshot_id,
        sizeof(evidence->snapshot_id), err_buf, err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (evidence->snapshot_id[0] == '\0') {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence snapshot_id must not be empty");
        return OG_ERROR;
    }
    if (ogbak_scheme_d_json_uint64(json, "snapshot_created_at", &evidence->snapshot_created_at,
        err_buf, err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (evidence->snapshot_created_at == 0) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D evidence snapshot_created_at must not be zero");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_validate_disposable_waiver(const char *json, ogbak_scheme_d_evidence_t *evidence,
    char *err_buf, uint32 err_size)
{
    const char *gate = getenv(OGBAK_SCHEME_D_DISPOSABLE_GATE_ENV);
    if (gate == NULL || strcmp(gate, OGBAK_SCHEME_D_DISPOSABLE_GATE_VALUE) != 0) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D disposable waiver requires %s=%s",
            OGBAK_SCHEME_D_DISPOSABLE_GATE_ENV, OGBAK_SCHEME_D_DISPOSABLE_GATE_VALUE);
        return OG_ERROR;
    }
    if (ogbak_scheme_d_json_string(json, "environment_class", evidence->environment_class,
        sizeof(evidence->environment_class), err_buf, err_size) != OG_SUCCESS ||
        ogbak_scheme_d_json_string(json, "snapshot_mode", evidence->snapshot_mode,
        sizeof(evidence->snapshot_mode), err_buf, err_size) != OG_SUCCESS ||
        ogbak_scheme_d_json_string(json, "rollback_mode", evidence->rollback_mode,
        sizeof(evidence->rollback_mode), err_buf, err_size) != OG_SUCCESS ||
        ogbak_scheme_d_json_string(json, "waiver_reason", evidence->waiver_reason,
        sizeof(evidence->waiver_reason), err_buf, err_size) != OG_SUCCESS ||
        ogbak_scheme_d_json_string(json, "authorized_by", evidence->authorized_by,
        sizeof(evidence->authorized_by), err_buf, err_size) != OG_SUCCESS ||
        ogbak_scheme_d_json_string(json, "reset_procedure", evidence->reset_procedure,
        sizeof(evidence->reset_procedure), err_buf, err_size) != OG_SUCCESS ||
        ogbak_scheme_d_json_uint64(json, "authorized_at", &evidence->authorized_at, err_buf,
        err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    bool32 data_loss_accepted = OG_FALSE;
    bool32 production_use_forbidden = OG_FALSE;
    if (ogbak_scheme_d_json_bool(json, "data_loss_accepted", &data_loss_accepted, err_buf,
        err_size) != OG_SUCCESS ||
        ogbak_scheme_d_json_bool(json, "production_use_forbidden", &production_use_forbidden, err_buf,
        err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (strcmp(evidence->environment_class, "disposable_development_only") != 0 ||
        strcmp(evidence->snapshot_mode, "waived") != 0 ||
        strcmp(evidence->rollback_mode, "reinitialize_dss_vg") != 0 ||
        data_loss_accepted != OG_TRUE || production_use_forbidden != OG_TRUE ||
        evidence->waiver_reason[0] == '\0' || evidence->authorized_by[0] == '\0' ||
        evidence->reset_procedure[0] == '\0') {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D disposable waiver evidence fields are invalid or incomplete");
        return OG_ERROR;
    }
    time_t now = time(NULL);
    if (evidence->authorized_at == 0 || evidence->authorized_at > (uint64)now + 300 ||
        evidence->authorized_at > evidence->expires_at) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D disposable waiver authorized_at invalid authorized_at=%llu expires_at=%llu now=%lld",
            evidence->authorized_at, evidence->expires_at, (long long)now);
        return OG_ERROR;
    }
    if (ogbak_scheme_d_json_string_optional(json, "snapshot_id", evidence->snapshot_id,
        sizeof(evidence->snapshot_id), err_buf, err_size) != OG_SUCCESS ||
        ogbak_scheme_d_json_uint64_optional(json, "snapshot_created_at", &evidence->snapshot_created_at,
        err_buf, err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if ((evidence->snapshot_id[0] != '\0' && strcmp(evidence->snapshot_id, "WAIVED") != 0) ||
        evidence->snapshot_created_at != 0) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D disposable waiver is mutually exclusive with real snapshot evidence");
        return OG_ERROR;
    }
    if (evidence->snapshot_id[0] == '\0' && strcpy_s(evidence->snapshot_id,
        sizeof(evidence->snapshot_id), "WAIVED") != EOK) {
        return OG_ERROR;
    }
    if (ogbak_scheme_d_parse_target_wwids(json, evidence, err_buf, err_size) != OG_SUCCESS ||
        ogbak_scheme_d_validate_disposable_wwids(evidence, err_buf, err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    evidence->disposable_waiver = OG_TRUE;
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_validate_evidence(const char *path, const char *backup_dir,
    bool32 disposable_waiver_requested,
    ogbak_scheme_d_evidence_t *evidence, char *err_buf, uint32 err_size)
{
    if (path == NULL || backup_dir == NULL || evidence == NULL) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(evidence, sizeof(*evidence), 0, sizeof(*evidence));
    if (ret != EOK) {
        return OG_ERROR;
    }
    if (strcpy_s(evidence->path, sizeof(evidence->path), path) != EOK) {
        return OG_ERROR;
    }
    char *json = NULL;
    uint32 json_size = 0;
    if (ogbak_scheme_d_read_text_file(path, &json, &json_size, err_buf, err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    uint64 schema_version = 0;
    status_t status = ogbak_scheme_d_json_uint64(json, "schema_version", &schema_version, err_buf, err_size);
    if (status == OG_SUCCESS && schema_version != OGBAK_SCHEME_D_EVIDENCE_SCHEMA_VERSION) {
        ogbak_scheme_d_set_error(err_buf, err_size, "unsupported scheme D evidence schema_version=%llu",
            schema_version);
        status = OG_ERROR;
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_json_string(json, "restore_user", evidence->restore_user,
            sizeof(evidence->restore_user), err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_check_file_owner_mode(path, evidence->restore_user, err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_json_string(json, "cluster_id", evidence->cluster_id,
            sizeof(evidence->cluster_id), err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_json_string(json, "operator", evidence->operator_name,
            sizeof(evidence->operator_name), err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_json_string(json, "expected_dss_home", evidence->expected_dss_home,
            sizeof(evidence->expected_dss_home), err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_json_string(json, "expected_dssserver_exe", evidence->expected_dssserver_exe,
            sizeof(evidence->expected_dssserver_exe), err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_json_string(json, "backupset_path", evidence->backupset_path,
            sizeof(evidence->backupset_path), err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_json_string(json, "backupset_checksum", evidence->backupset_checksum,
            sizeof(evidence->backupset_checksum), err_buf, err_size);
    }
    if (status == OG_SUCCESS && ogbak_scheme_d_is_sha256_hex(evidence->backupset_checksum) != OG_TRUE) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D evidence backupset_checksum must be a 64-character hexadecimal SHA-256 digest");
        status = OG_ERROR;
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_json_string_optional(json, "snapshot_mode", evidence->snapshot_mode,
            sizeof(evidence->snapshot_mode), err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        (void)ogbak_scheme_d_json_string(json, "old_vg_rollback_reference", evidence->rollback_reference,
            sizeof(evidence->rollback_reference), NULL, 0);
        status = ogbak_scheme_d_json_uint64(json, "generated_at", &evidence->generated_at, err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_json_uint64(json, "expires_at", &evidence->expires_at, err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = (disposable_waiver_requested == OG_TRUE) ?
            ogbak_scheme_d_validate_disposable_waiver(json, evidence, err_buf, err_size) :
            ogbak_scheme_d_validate_snapshot_evidence(json, evidence, disposable_waiver_requested, err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        time_t now = time(NULL);
        if (evidence->generated_at == 0 || evidence->expires_at <= (uint64)now) {
            ogbak_scheme_d_set_error(err_buf, err_size,
                "scheme D evidence time window invalid generated_at=%llu expires_at=%llu now=%lld",
                evidence->generated_at, evidence->expires_at, (long long)now);
            status = OG_ERROR;
        }
    }
    if (status == OG_SUCCESS && ogbak_scheme_d_realpath_equal(backup_dir, evidence->backupset_path) != OG_SUCCESS) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D evidence backupset_path does not match --backup-dir: evidence=%s backup_dir=%s",
            evidence->backupset_path, backup_dir);
        status = OG_ERROR;
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_verify_backupset_checksum(backup_dir, evidence->backupset_checksum, err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_parse_vgs(json, evidence, err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_parse_nodes(json, evidence, err_buf, err_size);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_sha256_buffer(json, json_size, evidence->hash, sizeof(evidence->hash));
    }
    CM_FREE_PTR(json);
    return status;
}

status_t ogbak_scheme_d_validate_current_user(const ogbak_scheme_d_evidence_t *evidence,
    char *err_buf, uint32 err_size)
{
    if (evidence == NULL) {
        return OG_ERROR;
    }
    struct passwd *pw = getpwnam(evidence->restore_user);
    if (pw == NULL) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D restore_user does not exist: %s",
            evidence->restore_user);
        return OG_ERROR;
    }
    if (geteuid() != pw->pw_uid) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D requires current euid to match restore_user; euid=%u restore_user=%s uid=%u",
            (uint32)geteuid(), evidence->restore_user, (uint32)pw->pw_uid);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_parse_dssserver_cmdline(const char *cmdline, const char *expected_dss_home,
    char *parsed_dss_home, uint32 home_size)
{
    if (cmdline == NULL || expected_dss_home == NULL || parsed_dss_home == NULL || home_size == 0) {
        return OG_ERROR;
    }
    char copy[OG_MAX_CONFIG_LINE_SIZE] = {0};
    if (strlen(cmdline) >= sizeof(copy) || strcpy_s(copy, sizeof(copy), cmdline) != EOK) {
        return OG_ERROR;
    }
    bool32 has_m = OG_FALSE;
    bool32 has_d = OG_FALSE;
    bool32 forbidden = OG_FALSE;
    char *save = NULL;
    char *token = strtok_r(copy, " \t\r\n", &save);
    while (token != NULL) {
        if (strcmp(token, "-M") == 0) {
            has_m = OG_TRUE;
        } else if (strcmp(token, "-D") == 0) {
            token = strtok_r(NULL, " \t\r\n", &save);
            if (token == NULL || strcpy_s(parsed_dss_home, home_size, token) != EOK) {
                return OG_ERROR;
            }
            has_d = OG_TRUE;
        } else if (strcmp(token, "--readonly-volume") == 0 ||
            strcmp(token, "--inplace-restore-writer") == 0) {
            forbidden = OG_TRUE;
        }
        token = strtok_r(NULL, " \t\r\n", &save);
    }
    if (forbidden == OG_TRUE || has_m != OG_TRUE || has_d != OG_TRUE ||
        strcmp(parsed_dss_home, expected_dss_home) != 0) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 ogbak_scheme_d_read_proc_text(const char *pid, const char *name, char *buf, uint32 buf_size,
    bool32 nul_to_space)
{
    char path[OG_MAX_FILE_PATH_LENGH] = {0};
    if (snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%s/%s", pid, name) == -1) {
        return OG_FALSE;
    }
    int fd = open(path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        return OG_FALSE;
    }
    ssize_t size = read(fd, buf, buf_size - 1);
    (void)close(fd);
    if (size <= 0) {
        return OG_FALSE;
    }
    buf[size] = '\0';
    for (ssize_t i = 0; i < size; i++) {
        if (buf[i] == '\n' || buf[i] == '\r' || (nul_to_space == OG_TRUE && buf[i] == '\0')) {
            buf[i] = ' ';
        }
    }
    return OG_TRUE;
}

static status_t ogbak_scheme_d_check_socket(const ogbak_scheme_d_evidence_t *evidence,
    ogbak_scheme_d_provider_t *provider, char *err_buf, uint32 err_size)
{
    if (snprintf_s(provider->socket_path, sizeof(provider->socket_path), sizeof(provider->socket_path) - 1,
        "%s/.dss_unix_d_socket", evidence->expected_dss_home) == -1) {
        return OG_ERROR;
    }
    struct stat st;
    if (stat(provider->socket_path, &st) != 0) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D DSS socket not found: %s",
            provider->socket_path);
        return OG_ERROR;
    }
    struct passwd *pw = getpwnam(evidence->restore_user);
    if (pw == NULL || st.st_uid != pw->pw_uid || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D DSS socket owner/mode invalid: path=%s uid=%u mode=%o restore_user=%s",
            provider->socket_path, (uint32)st.st_uid, (uint32)(st.st_mode & 0777), evidence->restore_user);
        return OG_ERROR;
    }
    char parent[OG_MAX_FILE_PATH_LENGH] = {0};
    if (strcpy_s(parent, sizeof(parent), provider->socket_path) != EOK) {
        return OG_ERROR;
    }
    char *slash = strrchr(parent, '/');
    if (slash != NULL) {
        *slash = '\0';
        if (stat(parent, &st) != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            ogbak_scheme_d_set_error(err_buf, err_size,
                "scheme D DSS socket parent mode invalid: path=%s mode=%o", parent,
                (uint32)(st.st_mode & 0777));
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static bool32 ogbak_scheme_d_contains_status_token(const char *output, const char *token)
{
    const char *prefix = "Server status of instance ";
    const char *pos = output == NULL ? NULL : strstr(output, prefix);
    if (pos == NULL) {
        return OG_FALSE;
    }
    pos = strstr(pos, " is ");
    if (pos == NULL) {
        return OG_FALSE;
    }
    pos += strlen(" is ");
    size_t token_len = strlen(token);
    return strncmp(pos, token, token_len) == 0 &&
        (pos[token_len] == ' ' || pos[token_len] == '\t' || pos[token_len] == '\r' || pos[token_len] == '\n') ?
        OG_TRUE : OG_FALSE;
}

bool32 ogbak_scheme_d_provider_getstatus_ready(const char *output)
{
    if (output == NULL || strstr(output, "DSS_MAINTAIN is TRUE") == NULL) {
        return OG_FALSE;
    }
    return ogbak_scheme_d_contains_status_token(output, "open");
}

static void ogbak_scheme_d_reap_probe(pid_t pid)
{
    int status = 0;
    if (waitpid(pid, &status, WNOHANG) == pid) {
        return;
    }
    (void)kill(pid, SIGTERM);
    for (uint32 i = 0; i < 10; i++) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            return;
        }
        (void)usleep(100000);
    }
    (void)kill(pid, SIGKILL);
    (void)waitpid(pid, &status, 0);
}

static status_t ogbak_scheme_d_run_dsscmd_getstatus(const char *dsscmd, const char *dss_home,
    char *output, uint32 output_size, int *wait_status, bool32 *timed_out)
{
    if (output == NULL || output_size == 0 || wait_status == NULL || timed_out == NULL) {
        return OG_ERROR;
    }
    output[0] = '\0';
    *wait_status = 0;
    *timed_out = OG_FALSE;
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return OG_ERROR;
    }
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }
    pid_t pid = fork();
    if (pid < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return OG_ERROR;
    }
    if (pid == 0) {
        (void)close(pipefd[0]);
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)dup2(pipefd[1], STDERR_FILENO);
        (void)close(pipefd[1]);
        (void)setenv("DSS_HOME", dss_home, 1);
        execl(dsscmd, dsscmd, "getstatus", (char *)NULL);
        _exit(127);
    }
    (void)close(pipefd[1]);
    uint32 used = 0;
    time_t deadline = time(NULL) + OGBAK_SCHEME_D_PROVIDER_PROBE_TIMEOUT_SEC;
    for (;;) {
        char buf[256] = {0};
        ssize_t read_size = read(pipefd[0], buf, sizeof(buf));
        if (read_size > 0) {
            uint32 copy_size = (uint32)read_size;
            if (copy_size > output_size - used - 1) {
                copy_size = output_size - used - 1;
            }
            if (copy_size > 0) {
                (void)memcpy_s(output + used, output_size - used, buf, copy_size);
                used += copy_size;
                output[used] = '\0';
            }
        }
        if (waitpid(pid, wait_status, WNOHANG) == pid) {
            break;
        }
        if (time(NULL) >= deadline) {
            *timed_out = OG_TRUE;
            ogbak_scheme_d_reap_probe(pid);
            break;
        }
        (void)usleep(100000);
    }
    for (;;) {
        char buf[256] = {0};
        ssize_t read_size = read(pipefd[0], buf, sizeof(buf));
        if (read_size <= 0) {
            break;
        }
        uint32 copy_size = (uint32)read_size;
        if (copy_size > output_size - used - 1) {
            copy_size = output_size - used - 1;
        }
        if (copy_size > 0) {
            (void)memcpy_s(output + used, output_size - used, buf, copy_size);
            used += copy_size;
            output[used] = '\0';
        }
    }
    (void)close(pipefd[0]);
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_getstatus(const ogbak_scheme_d_evidence_t *evidence,
    char *err_buf, uint32 err_size)
{
    char dsscmd[OG_MAX_FILE_PATH_LENGH] = {0};
    if (strcpy_s(dsscmd, sizeof(dsscmd), evidence->expected_dssserver_exe) != EOK) {
        return OG_ERROR;
    }
    char *slash = strrchr(dsscmd, '/');
    if (slash == NULL) {
        return OG_ERROR;
    }
    *(slash + 1) = '\0';
    if (strcat_s(dsscmd, sizeof(dsscmd), "dsscmd") != EOK) {
        return OG_ERROR;
    }
    char output[OG_MAX_CONFIG_LINE_SIZE] = {0};
    int status = 0;
    bool32 timed_out = OG_FALSE;
    if (ogbak_scheme_d_run_dsscmd_getstatus(dsscmd, evidence->expected_dss_home, output, sizeof(output), &status,
        &timed_out) != OG_SUCCESS || timed_out == OG_TRUE || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        ogbak_scheme_d_provider_getstatus_ready(output) != OG_TRUE) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D provider getstatus did not confirm maintenance OPEN readiness; dsscmd=%s status=%d "
            "timeout=%u output=%s",
            dsscmd, status, (uint32)timed_out, output[0] == '\0' ? "<empty>" : output);
        return OG_ERROR;
    }
    printf("[ogbackup]scheme_d=true provider=official_dss_maintenance dsscmd_getstatus=%s\n", output);
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_check_processes(const ogbak_scheme_d_evidence_t *evidence,
    ogbak_scheme_d_provider_t *provider, char *err_buf, uint32 err_size)
{
    if (evidence == NULL || provider == NULL) {
        return OG_ERROR;
    }
    (void)memset_s(provider, sizeof(*provider), 0, sizeof(*provider));
    DIR *dir = opendir("/proc");
    if (dir == NULL) {
        return OG_ERROR;
    }
    uint32 dssserver_count = 0;
    struct passwd *restore_pw = getpwnam(evidence->restore_user);
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
            continue;
        }
        char comm[OG_NAME_BUFFER_SIZE] = {0};
        if (ogbak_scheme_d_read_proc_text(entry->d_name, "comm", comm, sizeof(comm), OG_FALSE) != OG_TRUE) {
            continue;
        }
        while (strlen(comm) > 0 && comm[strlen(comm) - 1] == ' ') {
            comm[strlen(comm) - 1] = '\0';
        }
        if (strcmp(comm, "ogracd") == 0 || strcmp(comm, "cms_server") == 0 || strcmp(comm, "cms") == 0) {
            (void)closedir(dir);
            ogbak_scheme_d_set_error(err_buf, err_size,
                "scheme D blocked process: pid=%s comm=%s", entry->d_name, comm);
            return OG_ERROR;
        }
        if (strcmp(comm, "ogbackup") == 0 && (pid_t)atoi(entry->d_name) != getpid()) {
            (void)closedir(dir);
            ogbak_scheme_d_set_error(err_buf, err_size, "scheme D found another ogbackup process pid=%s",
                entry->d_name);
            return OG_ERROR;
        }
        if (strcmp(comm, "dssserver") != 0) {
            continue;
        }
        dssserver_count++;
        char cmdline[OG_MAX_CONFIG_LINE_SIZE] = {0};
        if (ogbak_scheme_d_read_proc_text(entry->d_name, "cmdline", cmdline, sizeof(cmdline),
            OG_TRUE) != OG_TRUE) {
            continue;
        }
        char exe_path[OG_MAX_FILE_PATH_LENGH] = {0};
        char proc_exe[OG_MAX_FILE_PATH_LENGH] = {0};
        if (snprintf_s(proc_exe, sizeof(proc_exe), sizeof(proc_exe) - 1, "/proc/%s/exe", entry->d_name) == -1 ||
            readlink(proc_exe, exe_path, sizeof(exe_path) - 1) <= 0) {
            continue;
        }
        char parsed_home[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_scheme_d_parse_dssserver_cmdline(cmdline, evidence->expected_dss_home, parsed_home,
            sizeof(parsed_home)) != OG_SUCCESS) {
            continue;
        }
        if (ogbak_scheme_d_realpath_equal(exe_path, evidence->expected_dssserver_exe) != OG_SUCCESS) {
            continue;
        }
        char proc_dir[OG_MAX_FILE_PATH_LENGH] = {0};
        struct stat st;
        if (snprintf_s(proc_dir, sizeof(proc_dir), sizeof(proc_dir) - 1, "/proc/%s", entry->d_name) == -1 ||
            stat(proc_dir, &st) != 0 || restore_pw == NULL || st.st_uid != restore_pw->pw_uid) {
            continue;
        }
        provider->allowed = OG_TRUE;
        (void)strcpy_s(provider->pid, sizeof(provider->pid), entry->d_name);
        (void)strcpy_s(provider->exe, sizeof(provider->exe), exe_path);
        (void)strcpy_s(provider->cmdline, sizeof(provider->cmdline), cmdline);
        (void)strcpy_s(provider->dss_home, sizeof(provider->dss_home), parsed_home);
        (void)strcpy_s(provider->owner, sizeof(provider->owner), evidence->restore_user);
    }
    (void)closedir(dir);
    if (dssserver_count != 1 || provider->allowed != OG_TRUE) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D requires exactly one matching dssserver -M; found=%u allowed=%u expected_dss_home=%s expected_exe=%s",
            dssserver_count, (uint32)provider->allowed, evidence->expected_dss_home,
            evidence->expected_dssserver_exe);
        return OG_ERROR;
    }
    if (ogbak_scheme_d_check_socket(evidence, provider, err_buf, err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (ogbak_scheme_d_getstatus(evidence, err_buf, err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    printf("[ogbackup]scheme_d=true provider=official_dss_maintenance dssserver_pid=%s exe=%s owner=%s "
           "expected_dss_home=%s socket=%s cmdline=%s\n",
        provider->pid, provider->exe, provider->owner, evidence->expected_dss_home, provider->socket_path,
        provider->cmdline);
    return OG_SUCCESS;
}

bool32 ogbak_scheme_d_vg_allowed(const ogbak_scheme_d_evidence_t *evidence, const char *dss_path)
{
    if (evidence == NULL || dss_path == NULL || dss_path[0] != '+') {
        return OG_FALSE;
    }
    char vg[OG_NAME_BUFFER_SIZE] = {0};
    uint32 len = 0;
    while (dss_path[len] != '\0' && dss_path[len] != '/' && len + 1 < sizeof(vg)) {
        vg[len] = dss_path[len];
        len++;
    }
    vg[len] = '\0';
    for (uint32 i = 0; i < evidence->vg_count; i++) {
        if (strcmp(vg, evidence->vg_names[i]) == 0 ||
            (vg[0] == '+' && strcmp(vg + 1, evidence->vg_names[i]) == 0)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

const char *ogbak_scheme_d_file_type_name(uint32 type)
{
    switch (type) {
        case 0:
            return "control";
        case 1:
            return "datafile";
        case 2:
            return "redo";
        case 3:
            return "archive";
        default:
            return "other";
    }
}

static status_t ogbak_scheme_d_fsync_parent(const char *path)
{
    char parent[OG_MAX_FILE_PATH_LENGH] = {0};
    if (strcpy_s(parent, sizeof(parent), path) != EOK) {
        return OG_ERROR;
    }
    char *slash = strrchr(parent, '/');
    if (slash == NULL) {
        return OG_SUCCESS;
    }
    *slash = '\0';
    int fd = open(parent, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        return OG_ERROR;
    }
    (void)fsync(fd);
    (void)close(fd);
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_begin_plan(const char *path, const ogbak_scheme_d_evidence_t *evidence,
    const ogbak_scheme_d_provider_t *provider, ogbak_scheme_d_plan_t *plan, char *err_buf, uint32 err_size)
{
    if (path == NULL || evidence == NULL || provider == NULL || plan == NULL) {
        return OG_ERROR;
    }
    (void)memset_s(plan, sizeof(*plan), 0, sizeof(*plan));
    if (strcpy_s(plan->path, sizeof(plan->path), path) != EOK ||
        snprintf_s(plan->tmp_path, sizeof(plan->tmp_path), sizeof(plan->tmp_path) - 1, "%s.tmp", path) == -1) {
        return OG_ERROR;
    }
    plan->fp = fopen(plan->tmp_path, "w");
    if (plan->fp == NULL) {
        ogbak_scheme_d_set_error(err_buf, err_size, "create scheme D write-plan %s failed errno=%d",
            plan->tmp_path, errno);
        return OG_ERROR;
    }
    (void)fprintf(plan->fp,
        "{\n"
        "  \"plan_version\": %u,\n"
        "  \"scheme_d\": true,\n"
        "  \"provider\": \"official_dss_maintenance\",\n"
        "  \"evidence_path\": \"%s\",\n"
        "  \"evidence_sha256\": \"%s\",\n"
        "  \"snapshot_id\": \"%s\",\n"
        "  \"expected_dss_home\": \"%s\",\n"
        "  \"dssserver_pid\": \"%s\",\n"
        "  \"targets\": [\n",
        OGBAK_SCHEME_D_PLAN_VERSION, evidence->path, evidence->hash, evidence->snapshot_id,
        evidence->expected_dss_home, provider->pid);
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_append_plan_entry(ogbak_scheme_d_plan_t *plan, const char *target, const char *file_type,
    uint64 offset, uint64 length, uint64 existing_size, uint64 written_size, const char *unsupported_reason,
    char *err_buf, uint32 err_size)
{
    if (plan == NULL || plan->fp == NULL || target == NULL || file_type == NULL) {
        return OG_ERROR;
    }
    if (plan->entry_count > 0) {
        (void)fprintf(plan->fp, ",\n");
    }
    bool32 unsupported = (unsupported_reason != NULL && unsupported_reason[0] != '\0') ? OG_TRUE : OG_FALSE;
    if (unsupported == OG_TRUE) {
        plan->has_unsupported = OG_TRUE;
    }
    (void)fprintf(plan->fp,
        "    {\"target\":\"%s\",\"file_type\":\"%s\",\"offset\":%llu,\"length\":%llu,"
        "\"existing_size\":%llu,\"written_size\":%llu,\"create_required\":false,"
        "\"extend_required\":false,\"truncate_required\":false,\"unsupported_reason\":\"%s\"}",
        target, file_type, offset, length, existing_size, written_size,
        unsupported == OG_TRUE ? unsupported_reason : "");
    plan->entry_count++;
    if (unsupported == OG_TRUE) {
        ogbak_scheme_d_set_error(err_buf, err_size, "scheme D write-plan contains unsupported target=%s reason=%s",
            target, unsupported_reason);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_remember_range(ogbak_scheme_d_plan_t *plan, const char *target, uint32 file_id,
    uint64 offset, uint64 length, char *err_buf, uint32 err_size)
{
    if (length == 0 || UINT64_MAX - offset < length) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D write-plan range overflow target=%s offset=%llu length=%llu", target, offset, length);
        return OG_ERROR;
    }
    uint64 end = offset + length;
    for (uint32 i = 0; i < plan->range_count; i++) {
        ogbak_scheme_d_range_t *range = &plan->ranges[i];
        if (strcmp(range->target, target) != 0 || range->file_id != file_id) {
            continue;
        }
        if (!(end < range->start || offset > range->end)) {
            if (offset < range->start) {
                range->start = offset;
            }
            if (end > range->end) {
                range->end = end;
            }
            return OG_SUCCESS;
        }
    }
    if (plan->range_count >= OGBAK_SCHEME_D_MAX_PLAN_RANGES) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D write-plan range capacity exceeded target=%s file_id=%u", target, file_id);
        return OG_ERROR;
    }
    ogbak_scheme_d_range_t *range = &plan->ranges[plan->range_count++];
    if (strcpy_s(range->target, sizeof(range->target), target) != EOK) {
        return OG_ERROR;
    }
    range->file_id = file_id;
    range->start = offset;
    range->end = end;
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_append_plan_range(ogbak_scheme_d_plan_t *plan, const char *target, const char *file_type,
    uint32 file_id, uint64 offset, uint64 length, uint64 existing_size, uint64 written_size,
    uint64 required_min_size, uint64 source_offset, const char *payload_source, char *err_buf, uint32 err_size)
{
    if (plan == NULL || plan->fp == NULL || target == NULL || file_type == NULL) {
        return OG_ERROR;
    }
    if (length == 0 || UINT64_MAX - offset < length || offset + length > required_min_size ||
        required_min_size > existing_size) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D range rejected target=%s offset=%llu length=%llu required_min_size=%llu existing_size=%llu",
            target, offset, length, required_min_size, existing_size);
        return OG_ERROR;
    }
    if (ogbak_scheme_d_remember_range(plan, target, file_id, offset, length, err_buf, err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (plan->entry_count > 0) {
        (void)fprintf(plan->fp, ",\n");
    }
    (void)fprintf(plan->fp,
        "    {\"target\":\"%s\",\"file_type\":\"%s\",\"file_id\":%u,\"offset\":%llu,\"length\":%llu,"
        "\"end\":%llu,\"existing_size\":%llu,\"written_size\":%llu,\"required_min_size\":%llu,"
        "\"source_offset\":%llu,\"payload_source\":\"%s\",\"create_required\":false,"
        "\"extend_required\":false,\"truncate_required\":false,\"unsupported_reason\":\"\"}",
        target, file_type, file_id, offset, length, offset + length, existing_size, written_size,
        required_min_size, source_offset, payload_source == NULL ? "" : payload_source);
    plan->entry_count++;
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_assert_plan_range(const ogbak_scheme_d_plan_t *plan, const char *target, uint32 file_id,
    uint64 offset, uint64 length, char *err_buf, uint32 err_size)
{
    if (plan == NULL || target == NULL || length == 0 || UINT64_MAX - offset < length) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D runtime range assertion invalid target=%s offset=%llu length=%llu",
            target == NULL ? "<null>" : target, offset, length);
        return OG_ERROR;
    }
    uint64 end = offset + length;
    for (uint32 i = 0; i < plan->range_count; i++) {
        const ogbak_scheme_d_range_t *range = &plan->ranges[i];
        if (range->file_id == file_id && strcmp(range->target, target) == 0 &&
            offset >= range->start && end <= range->end) {
            return OG_SUCCESS;
        }
    }
    ogbak_scheme_d_set_error(err_buf, err_size,
        "scheme D runtime write outside approved write-plan range target=%s file_id=%u offset=%llu length=%llu "
        "write_plan_sha256=%s", target, file_id, offset, length, plan->hash);
    return OG_ERROR;
}

status_t ogbak_scheme_d_finish_plan(ogbak_scheme_d_plan_t *plan, char *err_buf, uint32 err_size)
{
    if (plan == NULL || plan->fp == NULL) {
        return OG_ERROR;
    }
    (void)fprintf(plan->fp, "\n  ],\n  \"entry_count\": %u\n}\n", plan->entry_count);
    int fd = fileno(plan->fp);
    if (fflush(plan->fp) != 0 || fsync(fd) != 0 || fclose(plan->fp) != 0) {
        plan->fp = NULL;
        ogbak_scheme_d_set_error(err_buf, err_size, "fsync scheme D write-plan failed: %s", plan->tmp_path);
        return OG_ERROR;
    }
    plan->fp = NULL;
    if (rename(plan->tmp_path, plan->path) != 0 || ogbak_scheme_d_fsync_parent(plan->path) != OG_SUCCESS) {
        ogbak_scheme_d_set_error(err_buf, err_size, "publish scheme D write-plan failed: %s", plan->path);
        return OG_ERROR;
    }
    if (ogbak_scheme_d_sha256_file_content(plan->path, plan->hash, sizeof(plan->hash), err_buf,
        err_size) != OG_SUCCESS) {
        ogbak_scheme_d_set_error(err_buf, err_size, "calculate scheme D write-plan sha256 failed: %s", plan->path);
        return OG_ERROR;
    }
    printf("[ogbackup]scheme_d=true write_plan_path=%s write_plan_sha256=%s entries=%u\n",
        plan->path, plan->hash, plan->entry_count);
    return OG_SUCCESS;
}

void ogbak_scheme_d_abort_plan(ogbak_scheme_d_plan_t *plan)
{
    if (plan == NULL) {
        return;
    }
    if (plan->fp != NULL) {
        (void)fclose(plan->fp);
        plan->fp = NULL;
    }
    if (plan->tmp_path[0] != '\0') {
        (void)remove(plan->tmp_path);
    }
}

static status_t ogbak_scheme_d_join_marker(const char *target_dir, const char *name, char *path, uint32 path_size)
{
    if (target_dir == NULL || name == NULL) {
        return OG_ERROR;
    }
    const char *sep = target_dir[strlen(target_dir) - 1] == '/' ? "" : "/";
    return snprintf_s(path, path_size, path_size - 1, "%s%s%s", target_dir, sep, name) == -1 ?
        OG_ERROR : OG_SUCCESS;
}

static status_t ogbak_scheme_d_write_marker_file(const char *path, const char *content)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return OG_ERROR;
    }
    size_t len = strlen(content);
    status_t status = OG_SUCCESS;
    if (write(fd, content, len) != (ssize_t)len || fsync(fd) != 0) {
        status = OG_ERROR;
    }
    (void)close(fd);
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_fsync_parent(path);
    }
    return status;
}

status_t ogbak_scheme_d_check_unsafe_marker(const char *target_dir, char *err_buf, uint32 err_size)
{
    char unsafe[OG_MAX_FILE_PATH_LENGH] = {0};
    char complete[OG_MAX_FILE_PATH_LENGH] = {0};
    if (ogbak_scheme_d_join_marker(target_dir, OGBAK_SCHEME_D_MARKER_UNSAFE, unsafe,
        sizeof(unsafe)) != OG_SUCCESS ||
        ogbak_scheme_d_join_marker(target_dir, OGBAK_SCHEME_D_MARKER_COMPLETE, complete,
        sizeof(complete)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cm_file_exist(unsafe) && !cm_file_exist(complete)) {
        ogbak_scheme_d_set_error(err_buf, err_size,
            "scheme D unsafe marker exists without complete marker; rollback/reinitialize required: %s", unsafe);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_mark_first_write(const char *target_dir, const ogbak_scheme_d_evidence_t *evidence,
    const ogbak_scheme_d_plan_t *plan, char *err_buf, uint32 err_size)
{
    char first[OG_MAX_FILE_PATH_LENGH] = {0};
    char unsafe[OG_MAX_FILE_PATH_LENGH] = {0};
    if (ogbak_scheme_d_join_marker(target_dir, OGBAK_SCHEME_D_MARKER_FIRST_WRITE, first, sizeof(first)) !=
        OG_SUCCESS ||
        ogbak_scheme_d_join_marker(target_dir, OGBAK_SCHEME_D_MARKER_UNSAFE, unsafe, sizeof(unsafe)) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }
    char content[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};
    time_t now = time(NULL);
    if (snprintf_s(content, sizeof(content), sizeof(content) - 1,
        "scheme_d=true\nstate=WRITING_UNSAFE\nprovider=official_dss_maintenance\nfirst_write_time=%lld\n"
        "snapshot_id=%s\nevidence_sha256=%s\nwrite_plan_path=%s\nwrite_plan_sha256=%s\n",
        (long long)now, evidence->snapshot_id, evidence->hash, plan->path, plan->hash) == -1) {
        return OG_ERROR;
    }
    if (ogbak_scheme_d_write_marker_file(first, content) != OG_SUCCESS ||
        ogbak_scheme_d_write_marker_file(unsafe, content) != OG_SUCCESS) {
        ogbak_scheme_d_set_error(err_buf, err_size, "write scheme D first-write/unsafe marker failed");
        return OG_ERROR;
    }
    printf("[ogbackup]scheme_d=true first_write_marker=%s unsafe_marker=%s write_plan_sha256=%s "
           "snapshot_id=%s\n", first, unsafe, plan->hash, evidence->snapshot_id);
    return OG_SUCCESS;
}

status_t ogbak_scheme_d_mark_complete(const char *target_dir, const ogbak_scheme_d_evidence_t *evidence,
    const ogbak_scheme_d_plan_t *plan, char *err_buf, uint32 err_size)
{
    char complete[OG_MAX_FILE_PATH_LENGH] = {0};
    if (ogbak_scheme_d_join_marker(target_dir, OGBAK_SCHEME_D_MARKER_COMPLETE, complete,
        sizeof(complete)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    char content[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};
    time_t now = time(NULL);
    if (snprintf_s(content, sizeof(content), sizeof(content) - 1,
        "scheme_d=true\nstate=COMPLETE\ncompleted_at=%lld\nsnapshot_id=%s\nevidence_sha256=%s\n"
        "write_plan_path=%s\nwrite_plan_sha256=%s\n",
        (long long)now, evidence->snapshot_id, evidence->hash, plan->path, plan->hash) == -1) {
        return OG_ERROR;
    }
    if (ogbak_scheme_d_write_marker_file(complete, content) != OG_SUCCESS) {
        ogbak_scheme_d_set_error(err_buf, err_size, "write scheme D complete marker failed");
        return OG_ERROR;
    }
    printf("[ogbackup]scheme_d=true complete_marker=%s write_plan_sha256=%s snapshot_id=%s\n",
        complete, plan->hash, evidence->snapshot_id);
    return OG_SUCCESS;
}
