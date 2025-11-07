/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * cms_param.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_param.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_interface.h"
#include "cms_param.h"
#include "cms_mes.h"
#include "cm_config.h"
#include "cms_defs.h"
#include "cm_system.h"
#include "cm_file.h"
#include "cs_pipe.h"
#include "mes_func.h"
#include "mes_config.h"
#include "mes_func.h"
#include "cm_dbs_intf.h"
#include "cms_log.h"
#include "cm_kmc.h"
#include "cm_encrypt.h"
#include "cm_file_iofence.h"


config_item_t g_cms_params[] = {
    // name (30B)               isdefault readonly  defaultvalue value runtime_value description range        datatype
    // comment
    // -------------            --------- --------  ------------ ----- ------------- ----------- -----        --------
    // -----
    { "NODE_ID", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL,
      NULL },
    { "GCC_TYPE", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL,
      NULL },
    { "GCC_HOME", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL,
      NULL },
    { "GCC_DIR", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL,
      NULL },
    { "FS_NAME", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL,
      NULL },
    { "CLUSTER_NAME", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS,
      NULL, NULL },
    { "CMS_LOG", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL,
      NULL },
    { "_IP", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL,
      NULL },
    { "_PORT", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL,
      NULL },
    { "_LOG_BACKUP_FILE_COUNT", OG_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0,128]", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_AUDIT_BACKUP_FILE_COUNT", OG_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0,128]", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_LOG_MAX_FILE_SIZE", OG_TRUE, ATTR_NONE, "10M", NULL, NULL, "-", "[1M,4G]", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_AUDIT_MAX_FILE_SIZE", OG_TRUE, ATTR_NONE, "10M", NULL, NULL, "-", "[1M,4G]", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_LOG_LEVEL", OG_TRUE, ATTR_NONE, "255", NULL, NULL, "-", "[0,-)", "OG_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_LOG_FILE_PERMISSIONS", OG_TRUE, ATTR_NONE, "640", NULL, NULL, "-", "[600-777]", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_LOG_PATH_PERMISSIONS", OG_TRUE, ATTR_NONE, "750", NULL, NULL, "-", "[700-777]", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "WORKER_THREAD_COUNT", OG_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[1,64]", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "UDS_WORKER_THREAD_COUNT", OG_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[1,64]", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_SPLIT_BRAIN", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_DETECT_DISK_TIMEOUT", OG_TRUE, ATTR_NONE, "3600", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_DISK_DETECT_FILE", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_STOP_RERUN_CMS_SCRIPT", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_EXIT_NUM_COUNT_FILE", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_CMS_NODE_FAULT_THRESHOLD", OG_TRUE, ATTR_NONE, "5", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_CMS_MES_THREAD_NUM", OG_TRUE, ATTR_NONE, "5", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_CMS_MES_MAX_SESSION_NUM", OG_TRUE, ATTR_NONE, "40", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_CMS_MES_MESSAGE_POOL_COUNT", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_CMS_MES_MESSAGE_QUEUE_COUNT", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_CMS_MES_MESSAGE_BUFF_COUNT", OG_TRUE, ATTR_NONE, "4096", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_CMS_MES_MESSAGE_CHANNEL_NUM", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_CMS_GCC_BAK", OG_TRUE, ATTR_NONE, "NULL", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_USE_DBSTOR", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_DBSTOR_NAMESPACE", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_CMS_MES_PIPE_TYPE", OG_TRUE, ATTR_NONE, "TCP", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "_CLUSTER_ID", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS,
      NULL, NULL },
    { "_CMS_MES_CRC_CHECK_SWITCH", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "-", "OG_TYPE_BOOLEAN", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_CMS_MES_SSL_SWITCH", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "-", "OG_TYPE_BOOLEAN", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_CMS_MES_SSL_CRT_KEY_PATH", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0,
      EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_CMS_MES_SSL_KEY_PWD", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "KMC_KEY_FILES", OG_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT,
      CFG_INS, NULL, NULL },
    { "SHARED_PATH", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_STRING", NULL, 0, EFFECT_REBOOT, CFG_INS,
      NULL, NULL },
};

cms_param_t g_param;
const cms_param_t *g_cms_param = &g_param;
bool32 g_cms_dbstor_enable = OG_FALSE;

status_t cms_get_cms_home(void)
{
    int32 is_home_exist;

    errno_t ret = strcpy_s(g_param.cms_home, sizeof(g_param.cms_home), getenv(CMS_ENV_CMS_HOME));
    if (ret != EOK) {
        return OG_ERROR;
    }

    is_home_exist = cm_dir_exist(g_param.cms_home);
    if (is_home_exist == OG_FALSE) {
        OG_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, CMS_ENV_CMS_HOME);
        return OG_ERROR;
    }
    is_home_exist = cm_check_exist_special_char(g_param.cms_home, (uint32)strlen(g_param.cms_home));
    if (is_home_exist == OG_TRUE) {
        OG_THROW_ERROR(ERR_INVALID_DIR, CMS_ENV_CMS_HOME);
        return OG_ERROR;
    }
    uint32 path_len = strlen(g_param.cms_home);
    if (path_len > CMS_MAX_PATH_LEN) {
        OG_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, CMS_MAX_PATH_LEN);
        return OG_ERROR;
    }
    cm_trim_home_path(g_param.cms_home, path_len);

    return OG_SUCCESS;
}

static status_t cms_get_gcc_home_type(const char *gcc_home, cms_dev_type_t *type)
{
    status_t ret;
#ifdef _WIN32
    struct _stat stat_buf;
    ret = _stat(gcc_home, &stat_buf);
    if (ret != 0) {
        CMS_LOG_ERR("stat failed.errno=%d,%s.", errno, strerror(errno));
        return OG_FALSE;
    }

    if (_S_IFREG == (stat_buf.st_mode & _S_IFREG)) {
        *type = CMS_DEV_TYPE_FILE;
    } else {
        CMS_LOG_ERR("gcc_home is not file.");
        return OG_ERROR;
    }
#else
    struct stat stat_buf;
    ret = stat(gcc_home, &stat_buf);
    if (ret != 0) {
        CMS_LOG_ERR("stat failed.errno=%d,%s.", errno, strerror(errno));
        return OG_FALSE;
    }

    if (S_ISREG(stat_buf.st_mode)) {
        *type = CMS_DEV_TYPE_FILE;
    } else if (S_ISBLK(stat_buf.st_mode)) {
        *type = CMS_DEV_TYPE_SD;
    } else if (S_ISLNK(stat_buf.st_mode)) {
        char path[CMS_FILE_NAME_BUFFER_SIZE];
        ssize_t nbytes = readlink(gcc_home, path, CMS_MAX_FILE_NAME_LEN);
        if (nbytes == -1) {
            CMS_LOG_ERR("readlink failed.errno=%d,%s.", errno, strerror(errno));
            return OG_ERROR;
        }

        return cms_get_gcc_home_type(path, type);
    } else {
        CMS_LOG_ERR("gcc_home is not file,block device or symbol link.");
        return OG_ERROR;
    }
#endif

    return OG_SUCCESS;
}

static void cms_get_mes_str_config_value(config_t *cfg)
{
    char *pipe_value = cm_get_config_value(cfg, "_CMS_MES_PIPE_TYPE");
    if (pipe_value == NULL || cm_strcmpi(pipe_value, "UC") == 0) {
        g_param.cms_mes_pipe_type = CS_TYPE_UC;
    } else if (cm_strcmpi(pipe_value, "TCP") == 0) {
        g_param.cms_mes_pipe_type = CS_TYPE_TCP;
    } else if (cm_strcmpi(pipe_value, "UC_RDMA") == 0) {
        g_param.cms_mes_pipe_type = CS_TYPE_UC_RDMA;
    } else {
        g_param.cms_mes_pipe_type = CS_TYPE_TCP;
    }
    CMS_LOG_INF("cms get mes config pipe type is %d", g_param.cms_mes_pipe_type);

    char *switch_value = cm_get_config_value(cfg, "_CMS_MES_CRC_CHECK_SWITCH");
    if (switch_value == NULL || cm_strcmpi(switch_value, "TRUE") == 0) {
        g_param.cms_mes_crc_check_switch = OG_TRUE;
    } else if (cm_strcmpi(switch_value, "FALSE") == 0) {
        g_param.cms_mes_crc_check_switch = OG_FALSE;
    } else {
        g_param.cms_mes_crc_check_switch = OG_TRUE;
    }
    CMS_LOG_INF("cms get mes config crc check switch is %d", g_param.cms_mes_crc_check_switch);
}

status_t cms_get_value_is_valid(char *value, uint32 *val_uint32)
{
    if (value == NULL || cm_str2uint32(value, val_uint32) != OG_SUCCESS) {
        return OG_ERROR;
    } else {
        return OG_SUCCESS;
    }
}

void cms_get_mes_config_value(config_t *cfg)
{
    uint32 val_uint32;
    status_t ret;

    char *value = cm_get_config_value(cfg, "_CMS_MES_THREAD_NUM");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_thread_num = val_uint32;
    if (ret != OG_SUCCESS) {
        g_param.cms_mes_thread_num = CMS_MES_THREAD_NUM;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MAX_SESSION_NUM");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_max_session_num = val_uint32;
    if (ret != OG_SUCCESS) {
        g_param.cms_mes_max_session_num = MES_MAX_SESSION_NUM;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_POOL_COUNT");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_pool_count = val_uint32;
    if (ret != OG_SUCCESS) {
        g_param.cms_mes_msg_pool_count = MES_MESSAGE_POOL_COUNT;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_QUEUE_COUNT");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_queue_count = val_uint32;
    if (ret != OG_SUCCESS) {
        g_param.cms_mes_msg_queue_count = MES_MESSAGE_QUEUE_COUNT;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_BUFF_COUNT");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_buff_count = val_uint32;
    if (ret != OG_SUCCESS) {
        g_param.cms_mes_msg_buff_count = MES_MESSAGE_BUFF_COUNT;
    }

    value = cm_get_config_value(cfg, "_CMS_MES_MESSAGE_CHANNEL_NUM");
    ret = cms_get_value_is_valid(value, &val_uint32);
    g_param.cms_mes_msg_channel_num = val_uint32;
    if (ret != OG_SUCCESS) {
        g_param.cms_mes_msg_channel_num = MES_MESSAGE_CHANNEL_NUM;
    }

    cms_get_mes_str_config_value(cfg);
}

static status_t cms_get_mes_ssl_config(config_t *cfg)
{
    char *ssl_switch_value = cm_get_config_value(cfg, "_CMS_MES_SSL_SWITCH");
    if (ssl_switch_value == NULL || cm_strcmpi(ssl_switch_value, "FALSE") == 0) {
        mes_set_ssl_switch(OG_FALSE);
    } else if (cm_strcmpi(ssl_switch_value, "TRUE") == 0) {
        mes_set_ssl_switch(OG_TRUE);
        char *ssl_crt_key_path = cm_get_config_value(cfg, "_CMS_MES_SSL_CRT_KEY_PATH");
        if (ssl_crt_key_path == NULL) {
            return OG_ERROR;
        }
        char cert_dir_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(cert_dir_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, ssl_crt_key_path));
        char ca_file_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(
            snprintf_s(ca_file_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/ca.crt", ssl_crt_key_path));
        char cert_file_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(
            snprintf_s(cert_file_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/mes.crt", ssl_crt_key_path));
        char key_file_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(
            snprintf_s(key_file_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/mes.key", ssl_crt_key_path));
        char crl_file_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(
            snprintf_s(crl_file_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/mes.crl", ssl_crt_key_path));
        char mes_pass_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(
            snprintf_s(mes_pass_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/mes.pass", ssl_crt_key_path));
        OG_RETURN_IFERR(mes_set_ssl_crt_file(cert_dir_path, ca_file_path, cert_file_path, key_file_path, crl_file_path,
                                             mes_pass_path));
        mes_set_ssl_verify_peer(OG_TRUE);
        char *enc_pwd = cm_get_config_value(cfg, "_CMS_MES_SSL_KEY_PWD");
        OG_RETURN_IFERR(mes_set_ssl_key_pwd(enc_pwd));
    } else {
        mes_set_ssl_switch(OG_FALSE);
    }
    return OG_SUCCESS;
}

status_t cms_get_dbstor_config_value(config_t *cfg)
{
    char *use_dbs_value;
    char *gcc_type;
    status_t ret;
    char *namespace_value = NULL;
    // dataPgSize is not used in the cms
    uint32 dataPgSize = OG_MAX_UINT32;

    use_dbs_value = cm_get_config_value(cfg, "_USE_DBSTOR");
    gcc_type = cm_get_config_value(cfg, "GCC_TYPE");
    if (cm_strcmpi(gcc_type, "FILE") == 0 && cm_strcmpi(use_dbs_value, "FALSE") == 0) {
        CMS_LOG_INF("DBStor disabled for FILE");
        ret = cm_dbs_set_cfg(OG_FALSE, dataPgSize, OG_DFLT_CTRL_BLOCK_SIZE, namespace_value, 0, OG_FALSE, 0);
        return ret;
    }
    if (cm_strcmpi(gcc_type, "NFS") == 0 && cm_strcmpi(use_dbs_value, "FALSE") == 0) {
        CMS_LOG_INF("DBStor disabled for NFS");
        ret = cm_dbs_set_cfg(OG_FALSE, dataPgSize, OG_DFLT_CTRL_BLOCK_SIZE, namespace_value, 0, OG_FALSE, 0);
        return ret;
    }

    if (cm_strcmpi(gcc_type, "SD") == 0 && cm_strcmpi(use_dbs_value, "FALSE") == 0) {
        CMS_LOG_INF("DBStor disabled for SD");
        ret = cm_dbs_set_cfg(OG_FALSE, dataPgSize, OG_DFLT_CTRL_BLOCK_SIZE, namespace_value, 0, OG_FALSE, 0);
        return ret;
    }

    namespace_value = cm_get_config_value(cfg, "_DBSTOR_NAMESPACE");
    if (namespace_value == NULL) {
        CMS_LOG_ERR("invalid parameter value of '_DBSTOR_NAMESPACE'");
        return OG_ERROR;
    }

    if (cm_strcmpi(gcc_type, "DBS") == 0 && (use_dbs_value == NULL || cm_strcmpi(use_dbs_value, "TRUE") == 0)) {
        CMS_LOG_INF("Configuring DBStor for DBS");
        cms_set_recv_timeout();

        ret = cm_dbs_set_cfg(OG_TRUE, dataPgSize, OG_DFLT_CTRL_BLOCK_SIZE, namespace_value, 0, OG_FALSE, 0);
        if (ret != OG_SUCCESS) {
            CMS_LOG_ERR("cms set dbstor config failed");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    CMS_LOG_ERR("Invalid parameters for '_USE_DBSTOR': gcc_type=%s, value=%s", gcc_type, use_dbs_value);
    return OG_ERROR;
}

status_t cms_load_param(int64 *time_stamp)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    errno_t ret;
    char *value;
    char *gcc_type;
    uint64 size;
    uint32 val_uint32;
    int64 val_int64;
    OG_RETURN_IFERR(cms_get_cms_home());
    // get config info
    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/cfg/%s", g_param.cms_home,
                     CMS_CFG_FILENAME);
    PRTS_RETURN_IFERR(ret);
    config_t cfg;
    if (cm_load_config(g_cms_params, sizeof(g_cms_params) / sizeof(config_item_t), file_name, &cfg, OG_FALSE) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    value = cm_get_config_value(&cfg, "NODE_ID");
    if (value == NULL || cm_str2uint64(value, &size) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'NODE_ID'");
        return OG_ERROR;
    }
    if (size < 0 || size >= CMS_MAX_NODES) {
        OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value[%lld] of 'NODE_ID'", size);
        return OG_ERROR;
    }
    g_param.node_id = (uint16)size;

    value = cm_get_config_value(&cfg, "FS_NAME");
    if (value == NULL) {
        OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'FS_NAME'");
        return OG_ERROR;
    }
    ret = strncpy_sp(g_param.fs_name, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "GCC_HOME");
    if (value == NULL) {
        OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'GCC_HOME'");
        return OG_ERROR;
    }
    ret = strncpy_sp(g_param.gcc_home, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "CMS_LOG");
    if (value == NULL) {
        OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'CMS_LOG'");
        return OG_ERROR;
    }
    ret = strncpy_sp(g_param.cms_log, CMS_PATH_BUFFER_SIZE, value, OG_MAX_PATH_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "GCC_DIR");
    if (value == NULL) {
        OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'GCC_DIR'");
        return OG_ERROR;
    }
    ret = strncpy_sp(g_param.gcc_dir, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "_DBSTOR_NAMESPACE");
    if (value == NULL) {
        OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of '_DBSTOR_NAMESPACE'");
        return OG_ERROR;
    }
    ret = strncpy_sp(g_param.cluster_name, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "GCC_TYPE");
    if (value == NULL || value[0] == '\0') {
        // g_param.gcc_type = CMS_DEV_TYPE_FILE;
        OG_RETURN_IFERR(cms_get_gcc_home_type(g_param.gcc_home, &g_param.gcc_type));
    } else {
        if (cm_strcmpi(value, "SD") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_SD;
        } else if (cm_strcmpi(value, "FILE") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_FILE;
        } else if (cm_strcmpi(value, "NFS") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_NFS;
        } else if (cm_strcmpi(value, "DBS") == 0) {
            g_param.gcc_type = CMS_DEV_TYPE_DBS;
        } else {
            CMS_LOG_ERR("invalid parameter value of 'GCC_TYPE':%s", value);
            OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'GCC_TYPE':%s", value);
            return OG_ERROR;
        }
    }

    value = cm_get_config_value(&cfg, "_LOG_BACKUP_FILE_COUNT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != OG_SUCCESS) {
        g_param.log_backup_file_count = 10;
    } else if (val_uint32 > OG_MAX_LOG_FILE_COUNT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_LOG_BACKUP_FILE_COUNT", (int64)OG_MAX_LOG_FILE_COUNT);
        return OG_ERROR;
    } else {
        g_param.log_backup_file_count = val_uint32;
    }

    value = cm_get_config_value(&cfg, "_LOG_MAX_FILE_SIZE");
    if (value == NULL || cm_str2size(value, &val_int64) != OG_SUCCESS || val_int64 < 0) {
        g_param.max_log_file_size = CMS_LOGFILE_SIZE;
    } else {
        g_param.max_log_file_size = (uint64)val_int64;
    }

    value = cm_get_config_value(&cfg, "_LOG_LEVEL");
    if (value == NULL || cm_str2int(value, &g_param.log_level) != OG_SUCCESS || g_param.log_level < 0 ||
        g_param.log_level > 255) {
        g_param.log_level = CMS_LOG_LEVEL;
    }

    value = cm_get_config_value(&cfg, "WORKER_THREAD_COUNT");
    if (value == NULL) {
        g_param.worker_thread_count = CMS_DFT_WORKER_THREAD_COUNT;
    } else {
        if (cm_str2size(value, &val_int64) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'WORKER_THREAD_COUNT':%s", value);
            return OG_ERROR;
        }

        if (val_int64 > CMS_MAX_WORKER_THREAD_COUNT || val_int64 < 1) {
            OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'WORKER_THREAD_COUNT':%,expect[1,%d]",
                           value, CMS_MAX_WORKER_THREAD_COUNT);
            return OG_ERROR;
        }

        g_param.worker_thread_count = (uint32)val_int64;
    }

    value = cm_get_config_value(&cfg, "UDS_WORKER_THREAD_COUNT");
    if (value == NULL) {
        g_param.uds_worker_thread_count = CMS_DFT_WORKER_THREAD_COUNT;
    } else {
        if (cm_str2size(value, &val_int64) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'UDS_WORKER_THREAD_COUNT':%s", value);
            return OG_ERROR;
        }

        if (val_int64 > CMS_MAX_WORKER_THREAD_COUNT || val_int64 < 1) {
            OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM,
                           "invalid parameter value of 'UDS_WORKER_THREAD_COUNT':%,expect[1,%d]", value,
                           CMS_MAX_WORKER_THREAD_COUNT);
            return OG_ERROR;
        }

        g_param.uds_worker_thread_count = (uint32)val_int64;
    }

    value = cm_get_config_value(&cfg, "_SPLIT_BRAIN");
    if (value == NULL || cm_strcmpi(value, "FALSE") == 0) {
        g_param.split_brain = CMS_OPEN_WITHOUT_SPLIT_BRAIN;
    } else if (cm_strcmpi(value, "TRUE") == 0) {
        g_param.split_brain = CMS_OPEN_WITH_SPLIT_BRAIN;
    } else {
        CMS_LOG_ERR("invalid parameter value of '_SPLIT_BRAIN':%s", value);
        OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of '_SPLIT_BRAIN':%s", value);
        return OG_ERROR;
    }

    value = cm_get_config_value(&cfg, "_DETECT_DISK_TIMEOUT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != OG_SUCCESS) {
        g_param.detect_disk_timeout = 3600;  // The default timeout period is 3600 seconds.
    } else {
        g_param.detect_disk_timeout = val_uint32;
    }

    value = cm_get_config_value(&cfg, "_DISK_DETECT_FILE");
    if (value == NULL) {
        CMS_LOG_INF("cms disk detect file is NULL.");
    }
    ret = strncpy_sp(g_param.detect_file, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
    MEMS_RETURN_IFERR(ret);

    value = cm_get_config_value(&cfg, "_STOP_RERUN_CMS_SCRIPT");
    if (value != NULL) {
        ret = strncpy_sp(g_param.stop_rerun_script, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
        PRTS_RETURN_IFERR(ret);
    }

    value = cm_get_config_value(&cfg, "_EXIT_NUM_COUNT_FILE");
    if (value != NULL) {
        ret = strncpy_sp(g_param.exit_num_file, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
        PRTS_RETURN_IFERR(ret);
    }

    value = cm_get_config_value(&cfg, "_CMS_NODE_FAULT_THRESHOLD");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != OG_SUCCESS) {
        g_param.cms_node_fault_thr = CMS_NODE_FAULT_THRESHOLD;  // The default cms hb lost_cnt is 5 seconds.
    } else {
        g_param.cms_node_fault_thr = val_uint32;
    }

    value = cm_get_config_value(&cfg, "_CMS_GCC_BAK");
    if (value == NULL || cm_strcmpi(value, "NULL") == 0) {
        ret = strncpy_sp(g_param.cms_gcc_bak, CMS_FILE_NAME_BUFFER_SIZE, g_param.cms_home, CMS_PATH_BUFFER_SIZE);
        MEMS_RETURN_IFERR(ret);
    } else {
        ret = strncpy_sp(g_param.cms_gcc_bak, CMS_FILE_NAME_BUFFER_SIZE, value, CMS_MAX_FILE_NAME_LEN);
        MEMS_RETURN_IFERR(ret);
    }

    bool32 enable = OG_FALSE;
    value = cm_get_config_value(&cfg, "_USE_DBSTOR");
    gcc_type = cm_get_config_value(&cfg, "GCC_TYPE");
    if (cm_strcmpi(gcc_type, "FILE") == 0 && cm_strcmpi(value, "FALSE") == 0) {
        enable = OG_FALSE;
    } else if (cm_strcmpi(gcc_type, "DBS") == 0 && (value == NULL || cm_strcmpi(value, "TRUE") == 0)) {
        enable = OG_TRUE;
        CMS_LOG_INF("DBStor not enabled for DBS");
        cms_set_recv_timeout();
        g_cms_dbstor_enable = OG_TRUE;
    } else if (cm_strcmpi(gcc_type, "NFS") == 0 && cm_strcmpi(value, "FALSE") == 0) {
        enable = OG_FALSE;
        CMS_LOG_INF("DBStor disabled for NFS");
    } else if (cm_strcmpi(gcc_type, "SD") == 0 && cm_strcmpi(value, "FALSE") == 0) {
        enable = OG_FALSE;
        CMS_LOG_INF("DBStor not enabled for SD");
    } else {
        CMS_LOG_ERR("Invalid parameters for '_USE_DBSTOR': gcc_type=%s, value=%s", gcc_type, value);
        return OG_ERROR;
    }
    mes_set_dbstor_enable(enable);
    value = cm_get_config_value(&cfg, "_CLUSTER_ID");
    if (value == NULL) {
        CMS_LOG_ERR("invalid parameter of _CLUSTER_ID");
        return OG_ERROR;
    }
    ret = cms_get_value_is_valid(value, &val_uint32);
    MEMS_RETURN_IFERR(ret);

    if (!enable) {
        value = cm_get_config_value(&cfg, "SHARED_PATH");
        if (value == NULL) {
            CMS_LOG_ERR("invalid parameter value of 'SHARED_PATH'.");
            return OG_ERROR;
        }
        if (cm_set_file_iof_cfg(val_uint32, 1, value) != OG_SUCCESS) {
            CMS_LOG_ERR("cms set file iof cfg failed.");
            return OG_ERROR;
        }
    }

    cms_get_mes_config_value(&cfg);
    if (cms_get_mes_ssl_config(&cfg) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (g_param.cms_mes_pipe_type == CS_TYPE_UC || g_param.cms_mes_pipe_type == CS_TYPE_UC_RDMA || enable) {
        OG_RETURN_IFERR(set_all_inst_lsid(val_uint32, 1));
    }
    OG_RETURN_IFERR(cms_get_dbstor_config_value(&cfg));
    for (int idx = 0; idx < MES_TIME_STAMP_NUM; idx++) {
        time_stamp[idx] = g_mes_config_time[idx];
    }
    return OG_SUCCESS;
}

status_t cms_init_detect_file(char *detect_file_all)
{
    if (strlen(detect_file_all) > CMS_MAX_DETECT_FILE_NAME) {
        printf("detect file is invalid, the file name is too long, len %lu", strlen(detect_file_all));
        return OG_ERROR;
    }
    char *gcc_file = "gcc_file";
    char gcc_dir[CMS_MAX_DETECT_FILE_NAME] = { 0 };
    if (cms_get_gcc_dir(gcc_dir, CMS_MAX_DETECT_FILE_NAME, gcc_file, strlen(gcc_file)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cms_get_detect_file(detect_file_all, strlen(detect_file_all), gcc_dir, strlen(gcc_file)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cms_open_detect_file() != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cms_get_detect_file(char *detect_file_all, uint32 detect_file_all_len, char *gcc_dir, uint32 gcc_dir_len)
{
    char file_be_detected[CMS_MAX_DETECT_FILE_NAME] = { 0 };
    char *split_symbol = ",";
    char *buf = NULL;
    char *file_name = strtok_s(detect_file_all, split_symbol, &buf);
    int detect_file_mark = 0;
    if (file_name == NULL) {
        return OG_ERROR;
    }
    while (file_name) {
        errno_t ret_dir = strcpy_sp(file_be_detected, CMS_MAX_DETECT_FILE_NAME, gcc_dir);
        if (ret_dir != EOK) {
            return OG_ERROR;
        }
        if (g_cms_param->gcc_type == CMS_DEV_TYPE_FILE) {
            if (access(file_be_detected, 0) == -1) {  // 0 indicates whether the file exists.
                return OG_ERROR;
            }
        }
        errno_t ret_file = strcat_sp(file_be_detected, CMS_MAX_DETECT_FILE_NAME, file_name);
        if (ret_file != EOK) {
            return OG_ERROR;
        }
        errno_t ret_detect_file = strcpy_sp(g_param.wait_detect_file[detect_file_mark], CMS_MAX_DETECT_FILE_NAME,
                                            file_be_detected);
        if (ret_detect_file != EOK) {
            return OG_ERROR;
        }
        file_name = strtok_s(NULL, split_symbol, &buf);
        detect_file_mark++;
    }
    g_param.wait_detect_file_num = detect_file_mark;
    return OG_SUCCESS;
}

status_t cms_get_gcc_dir(char *gcc_dir, uint32 gcc_dir_len, char *gcc_file, uint32 gcc_file_len)
{
    char *split_symbol = "/";
    char gcc_home[CMS_MAX_DETECT_FILE_NAME] = { 0 };
    errno_t ret_gcc_home = strcpy_sp(gcc_home, CMS_MAX_DETECT_FILE_NAME, g_cms_param->gcc_home);
    if (ret_gcc_home != EOK) {
        return OG_ERROR;
    }
    errno_t ret_gcc_dir = strcat_sp(gcc_dir, gcc_dir_len, split_symbol);
    if (ret_gcc_dir != EOK) {
        return OG_ERROR;
    }
    char *tmp_buf = NULL;
    char *file_dir = strtok_s(gcc_home, split_symbol, &tmp_buf);
    if (file_dir == NULL) {
        return OG_ERROR;
    }
    // Obtain the directory where the gcc_file file resides and save to gcc_dir.
    while (file_dir) {
        if (strcmp(file_dir, gcc_file) != 0) {
            errno_t ret_gcc_dir_tmp = strcat_sp(gcc_dir, gcc_dir_len, file_dir);
            errno_t ret_symbol = strcat_sp(gcc_dir, gcc_dir_len, split_symbol);
            if (ret_gcc_dir_tmp != EOK || ret_symbol != EOK) {
                return OG_ERROR;
            }
        }
        file_dir = strtok_s(NULL, split_symbol, &tmp_buf);
    }
    return OG_SUCCESS;
}

status_t cms_update_param(const char *param_name, const char *value)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    errno_t ret;

    OG_RETURN_IFERR(cms_get_cms_home());

    // get config info
    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/cfg/%s", g_param.cms_home,
                     CMS_CFG_FILENAME);
    PRTS_RETURN_IFERR(ret);

    config_t cfg;
    if (cm_load_config(g_cms_params, sizeof(g_cms_params) / sizeof(config_item_t), file_name, &cfg, OG_FALSE) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    char *old_value = cm_get_config_value(&cfg, param_name);
    if (old_value == NULL || strcmp(old_value, value) != 0) {
        if (cm_alter_config(&cfg, param_name, value, CONFIG_SCOPE_DISK, OG_TRUE) != OG_SUCCESS) {
            CMS_LOG_ERR("set param failed:%s = %s,errno=%d,%s", param_name, value, errno, strerror(errno));
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}
