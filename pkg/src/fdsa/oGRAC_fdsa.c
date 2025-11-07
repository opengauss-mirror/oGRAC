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
 * oGRAC_fdsa.c
 *
 *
 * IDENTIFICATION
 * src/fdsa/oGRAC_fdsa.c
 *
 * -------------------------------------------------------------------------
 */

#include <dlfcn.h>
#include "cm_log.h"
#include "cm_atomic.h"
#include "cm_thread.h"
#include "oGRAC_fdsa_interface.h"
#include "oGRAC_fdsa.h"
#include "dtc_drc.h"

static uint32_t MY_PID = 0;
bool32 g_enable_fdsa;
uint32 g_ograc_time_out_num = 0;
static atomic32_t g_ograc_io_base_no = 0;
static fdsa_interface_t g_fdsa_interface = { .fdsa_handle = NULL};

static status_t fdsa_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
{
    const char *dlsym_err = NULL;

    *sym_lib_handle = dlsym(lib_handle, symbol);
    dlsym_err = dlerror();
    if (dlsym_err != NULL) {
        OG_THROW_ERROR(ERR_LOAD_SYMBOL, symbol, dlsym_err);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t fdsa_init_lib(void)
{
    fdsa_interface_t *intf = &g_fdsa_interface;
    intf->fdsa_handle = dlopen("libfdsa.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();

    if (intf->fdsa_handle == NULL) {
        OG_LOG_RUN_ERR("failed to load libfdsa.so, maybe lib path error , errno %s", dlopen_err);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_InitCommon",      (void **)(&intf->HEAL_InitCommon)));
    OG_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_RegisterTask",    (void **)(&intf->HEAL_RegisterTask)));
    OG_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_EnableTask",      (void **)(&intf->HEAL_EnableTask)));
    OG_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_DisableTask",     (void **)(&intf->HEAL_DisableTask)));
    OG_RETURN_IFERR(fdsa_load_symbol(intf->fdsa_handle, "HEAL_UnregisterTask",  (void **)(&intf->HEAL_UnregisterTask)));

    OG_LOG_RUN_INF("load libfdsa.so done");
    return OG_SUCCESS;
}

static void fdsa_close_lib(void)
{
    fdsa_interface_t *intf = &g_fdsa_interface;
    if (intf->fdsa_handle != NULL) {
        (void)dlclose(intf->fdsa_handle);
    }
}

uint32 GetFdsaIoNo()
{
    uint32 ioNo = (uint32)cm_atomic32_inc(&g_ograc_io_base_no);
    return ioNo;
}

status_t AddIo2FdsaHashTable(io_id_t io_id)
{
    if (!g_enable_fdsa) {
        return OG_ERROR;
    }
    drc_res_ctx_t *ogx = DRC_RES_CTX;
    drc_res_pool_t *io_pool = &ogx->local_io_map.res_pool;
    if (io_pool->inited == OG_FALSE) {
        return OG_ERROR;
    }
    uint32 idx = drc_res_pool_alloc_item(io_pool);
    if (idx == OG_INVALID_ID32) {
        return OG_ERROR;
    }
    drc_res_bucket_t *bucket = drc_get_buf_map_bucket(&ogx->local_io_map, io_id.fdsa_type, io_id.io_no);
    cm_spin_lock(&bucket->lock, NULL);
    drc_local_io *local_io = (drc_local_io *)DRC_GET_RES_ADDR_BY_ID(io_pool, idx);
    local_io->io_id.io_no = io_id.io_no;
    local_io->io_id.fdsa_type = io_id.fdsa_type;
    local_io->idx = idx;
    local_io->start_time = g_timer()->now;
    drc_res_map_add(bucket, idx, &local_io->next);
    cm_spin_unlock(&bucket->lock);
    OG_LOG_DEBUG_INF("[OGRAC_FDSA] add io to bucket successed, io_no(%u) fdsa_type(%u).",
        local_io->io_id.io_no, local_io->io_id.fdsa_type);
    return OG_SUCCESS;
}

status_t RemovetIoFromFdsaHashtable(io_id_t io_id)
{
    if (!g_enable_fdsa) {
        return OG_ERROR;
    }
    drc_res_ctx_t *ogx = DRC_RES_CTX;
    drc_res_bucket_t *bucket = drc_get_buf_map_bucket(&ogx->local_io_map, io_id.fdsa_type, io_id.io_no);
    cm_spin_lock(&bucket->lock, NULL);
    drc_local_io *local_io = (drc_local_io *)drc_res_map_lookup(&ogx->local_io_map, bucket, (char*)&io_id);
    if (local_io == NULL) {
        knl_panic(0);
    }
    drc_res_map_remove(&ogx->local_io_map, bucket, (char*)&io_id);
    drc_res_pool_free_item(&ogx->local_io_map.res_pool, local_io->idx);
    cm_spin_unlock(&bucket->lock);
    OG_LOG_DEBUG_INF("[OGRAC_FDSA] remove io from bucket successed, io_no(%u) fdsa_type(%u).",
        local_io->io_id.io_no, local_io->io_id.fdsa_type);
    return OG_SUCCESS;
}

static bool32 CheckIoTimeOut(drc_res_bucket_t *bucket)
{
    cm_spin_lock(&bucket->lock, NULL);
    uint32 idx = bucket->first;
    drc_res_ctx_t *ogx = DRC_RES_CTX;
    for (uint32 i = 0; i < bucket->count; i++) {
        drc_local_io *res = DRC_GET_RES_ADDR_BY_ID(&ogx->local_io_map.res_pool, idx);
        uint64 curTime = g_timer()->now;
        if (curTime - res->start_time > OGRAC_IO_TIME_OUT_ONCE) {
            OG_LOG_RUN_ERR("[OGRAC_FDSA] Io cost too long, io_id(%u), fdsa_type(%u), start_time(%llu) now_time(%llu)",
                res->io_id.io_no, res->io_id.fdsa_type, res->start_time, curTime);
            cm_spin_unlock(&bucket->lock);
            cm_fync_logfile(); // flush log
            return OG_FALSE;
        }
        if (curTime - res->start_time > OGRAC_IO_TIME_OUT) {
            OG_LOG_RUN_ERR("[OGRAC_FDSA] Io cost too long, io_id(%u), fdsa_type(%u), start_time(%llu) now_time(%llu)",
                res->io_id.io_no, res->io_id.fdsa_type, res->start_time, curTime);
            g_ograc_time_out_num++;
        }
        idx = *(uint32*)res;
    }
    cm_spin_unlock(&bucket->lock);
    if (g_ograc_time_out_num >= OGRAC_IO_TIME_OUT_LIMIT_MAX_NUM) {
        OG_LOG_RUN_ERR("[OGRAC_FDSA] Time out io num reach (%u), OGRAC EXIT", g_ograc_time_out_num);
        cm_fync_logfile(); // flush log
        return OG_FALSE;
    }
    return OG_TRUE;
}

static void FdsaCheckCallback(HEAL_CBRETURN_S *healCbreturn, void *arg)
{
    drc_res_ctx_t *ogx = DRC_RES_CTX;
    OG_LOG_DEBUG_INF("[OGRAC_FDSA] FdsaCheckCallback start");

    for (uint32 i = 0; i < ogx->local_io_map.bucket_num; i++) {
        if (CheckIoTimeOut(&ogx->local_io_map.buckets[i]) == OG_FALSE) {
            OG_LOG_RUN_ERR("[OGRAC_FDSA] CheckIoTimeFun failed");
            healCbreturn->bResult = OG_FALSE;
            g_ograc_time_out_num = 0;
            return;
        }
    }
    healCbreturn->bResult = OG_TRUE;
    g_ograc_time_out_num = 0;
    OG_LOG_DEBUG_INF("[OGRAC_FDSA] FdsaCheckCallback successed");
    return;
}

status_t InitoGRACFdsa(void)
{
    int32_t ret = OG_SUCCESS;
    fdsa_interface_t *intf = &g_fdsa_interface;
    OG_LOG_RUN_INF("[OGRAC_FDSA] InitFdsa start");

    // 动态加载libfdsa.so
    if (fdsa_init_lib() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to init lib.");
        return OG_ERROR;
    }

    // 注册初始化fdsa自愈任务
    HEAL_REGPARAM_S healRegParam = { 0 };
    healRegParam.pCheckCB = FdsaCheckCallback;
    healRegParam.pCollectCB = NULL;
    healRegParam.pHealCB = NULL;

    MEMS_RETURN_IFERR(strcpy_s(healRegParam.szName, FDSA_BUFFER_SIZE_32, OGRAC_FDSA_HEAL_TASK));
    healRegParam.uiCheckFailTimes = 1;                             // 连续检测失败1次后进行自愈
    healRegParam.uiCheckPeriod = OGRAC_FDSA_CHECK_CYCLE_TIME;        // 检查周期
    healRegParam.eRecoverLever = HEAL_RECOVER_PROCESS_IMMEDIATELY; // 自愈策略等级

    ret = intf->HEAL_InitCommon(); // 自愈HEAL模块初始化
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OGRAC_FDSA] Init Fdsa heal task (%d) fail", ret);
        return OG_ERROR;
    }
#ifndef _WIN32
    ret = intf->HEAL_RegisterTask(&healRegParam, (uint16_t)MY_PID, __FUNCTION__, __LINE__); // 自愈任务注册
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OGRAC_FDSA] Register Fdsa heal task (%d) fail", ret);
        return OG_ERROR;
    }
    ret = intf->HEAL_EnableTask(OGRAC_FDSA_HEAL_TASK, (uint16_t)MY_PID, __FUNCTION__, __LINE__);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OGRAC_FDSA] Enable Fdsa heal task (%d) fail", ret);
        return OG_ERROR;
    }
#endif
    OG_LOG_RUN_INF("[OGRAC_FDSA] InitCLiCsIoFdsa successed");
    return OG_SUCCESS;
}

status_t DeInitoGRACFdsa(void)
{
    int32_t ret = OG_SUCCESS;
    fdsa_interface_t *intf = &g_fdsa_interface;
    OG_LOG_RUN_INF("[OGRAC_FDSA] DeInitCsIoFdsa start");
#ifndef _WIN32
    ret = intf->HEAL_DisableTask(OGRAC_FDSA_HEAL_TASK, (uint16_t)MY_PID, __FUNCTION__, __LINE__);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OGRAC_FDSA] Stop Fdsa heal task %d fail", ret);
        return OG_ERROR;
    }

    ret = intf->HEAL_UnregisterTask(OGRAC_FDSA_HEAL_TASK, NULL, NULL, (uint16_t)MY_PID, __FUNCTION__, __LINE__); //自愈任务注销
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OGRAC_FDSA] Cancel Fdsa heal task %d fail", ret);
        return OG_ERROR;
    }
#endif
    fdsa_close_lib();
    OG_LOG_RUN_INF("[OGRAC_FDSA] DeInitCsIoFdsa successed");
    return OG_SUCCESS;
}
