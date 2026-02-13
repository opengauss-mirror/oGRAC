/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * cs_ub.c
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_ub.c
 *
 * -------------------------------------------------------------------------
 */

 #include "cm_log.h"
 #include "cs_pipe.h"
 #include "cm_signal.h"
 #include "cm_ubs_mem.h"

 #ifdef __cplusplus
 extern "C" {
 #endif

 #ifndef WIN32

 static void cm_log_for_ubsm(int level, const char *msg)
 {
	 switch(level) {
		 case 0:
			 OG_LOG_DEBUG_INF(msg);
			 break;
		 case 1:
			 OG_LOG_RUN_INF(msg);
			 break;
		 case 2:
			 OG_LOG_RUN_WAR(msg);
			 break;
		 case 3:
			 OG_LOG_RUN_ERR(msg);
			 break;
		 default:
			 OG_LOG_RUN_ERR(msg);
			 break;
	 }
 }
 
 status_t ub_init_ubsm_mem(void)
 {
    OG_LOG_RUN_INF("ubsm_mem init start.");
    ubsmem_options_t ubsmem_options;
    int ret = ubsmem_init_attributes(&ubsmem_options);
    if (ret != UBSM_OK) {
        OG_LOG_RUN_ERR("ubsmem_init_attributes failed. error:%d", ret);
        return ret;
    }
    ret = ubsmem_initialize(&ubsmem_options);
    if (ret != UBSM_OK) {
        OG_LOG_RUN_ERR("ubsmem_initialize failed. error:%d", ret);
        return ret;
    }

    ret = ubsmem_set_extern_logger(cm_log_for_ubsm);
    if (ret != UBSM_OK) {
        OG_LOG_RUN_ERR("ubsmem_set_extern_logger failed. error:%d", ret);
        return ret;
    }

    OG_LOG_RUN_INF("ubsm_mem init success.");
    return OG_SUCCESS;
 }

status_t ub_create_shm_region(uint32 host_id, uint32 inst_count)
 {
    char *host_name = cm_sys_host_name();
    char region_name[MAX_REGION_NAME_DESC_LENGTH] = {0};
    int ret = sprintf_s(region_name, sizeof(region_name), "shm_pool_%d", host_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("Failed to format shm region name, error:%d", ret);
        return OG_ERROR;
    }
    ubsmem_region_attributes_t region;
    region.host_num = inst_count;
    errno_t err = strcpy_s(region.hosts[0].host_name, sizeof(region.hosts[0].host_name), host_name);
    if (err != EOK) {
        OG_LOG_RUN_ERR("Failed to copy host name for shm region, error:%d", err);
        return OG_ERROR;
    }

    region.hosts[0].affinity = true;
    for (int i = 1; i < region.host_num; i++) {
        host_name = strcmp(cm_sys_host_name(), "node01") == 0 ? "node02" : "node01";
        err = strcpy_s(region.hosts[i].host_name, sizeof(region.hosts[i].host_name), host_name);
        if (err != EOK) {
            OG_LOG_RUN_ERR("Failed to copy host name for shm region, error:%d", err);
            return OG_ERROR;
        }
        region.hosts[i].affinity = false;
    }

    ret = ubsmem_create_region(region_name, 0, &region);
    if (ret == UBSM_ERR_ALREADY_EXIST) {
        OG_LOG_RUN_WAR("ubsmem region %s already exist, ret: %d", region_name, ret);
    } else if (ret != EOK) {
        OG_LOG_RUN_ERR("ubsmem_create_region %s failed. error:%d", region_name, ret);
        return OG_ERROR;
    }

    return OG_SUCCESS;
 }

status_t ub_delete_shm_region(uint32 host_id)
 {
    char region_name[MAX_REGION_NAME_DESC_LENGTH] = {0};
    int ret = sprintf_s(region_name, sizeof(region_name), "shm_pool_%d", host_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("Failed to format shm region name. error:%d", ret);
        return OG_ERROR;
    }
    ret = ubsmem_destroy_region(region_name);
    if (ret != EOK) {
        OG_LOG_RUN_ERR("Failed to delete shm region %s failed. error:%d", region_name, ret);
        return OG_ERROR;
    }
    return OG_SUCCESS;
 }

status_t ub_delete_shm(uint32 host_id)
{
    char data_buf_name[MAX_REGION_NAME_DESC_LENGTH] = {0};
    int ret = sprintf_s(data_buf_name, sizeof(data_buf_name), "data_buf_part_%d", host_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("Failed to format data buffer name, error:%d", ret);
        return OG_ERROR;
    }
    ret = ubsmem_shmem_deallocate(data_buf_name);
    if (ret != UBSM_OK) {
        OG_LOG_RUN_ERR("Failed to delete data buffer %s, error:%d", data_buf_name, ret);
        return OG_ERROR;
    }
    OG_LOG_RUN_INF("Successfully delete data buffer %s.", data_buf_name);
    return OG_SUCCESS;
}

 #endif // win32
 
 #ifdef __cplusplus
 }#endif
