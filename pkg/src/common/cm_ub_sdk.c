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
 * cm_ub_sdk.c
 *        UB shared memory library loader: dlopen()/dlsym() the ubsmem_* API so
 *        that oGRAC can be built and started on machines without the UB SDK.
 *
 * IDENTIFICATION
 * pkg/src/common/cm_ub_sdk.c
 *
 * -------------------------------------------------------------------------
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cm_log.h"
#include "cm_ub_sdk.h"
#include "cm_ubs_mem.h"

#ifndef MODULE_ID
#define MODULE_ID CLUSTER
#endif

#ifndef IN_CONTAINER

typedef int (*ubsmem_init_attributes_f)(ubsmem_options_t *opts);
typedef int (*ubsmem_initialize_f)(const ubsmem_options_t *opts);
typedef int (*ubsmem_finalize_f)(void);
typedef int (*ubsmem_set_logger_level_f)(int level);
typedef int (*ubsmem_set_extern_logger_f)(void (*func)(int level, const char *msg));
typedef int (*ubsmem_lookup_regions_f)(ubsmem_regions_t *regions);
typedef int (*ubsmem_create_region_f)(const char *region_name, size_t size,
    const ubsmem_region_attributes_t *reg_attr);
typedef int (*ubsmem_lookup_region_f)(const char *region_name, ubsmem_region_desc_t *region_desc);
typedef int (*ubsmem_destroy_region_f)(const char *region_name);
typedef int (*ubsmem_shmem_allocate_f)(const char *region_name, const char *name, size_t size, mode_t mode,
    uint64_t flags);
typedef int (*ubsmem_shmem_deallocate_f)(const char *name);
typedef int (*ubsmem_shmem_map_f)(void *addr, size_t length, int prot, int flags, const char *name, off_t offset,
    void **local_ptr);
typedef int (*ubsmem_shmem_unmap_f)(void *local_ptr, size_t length);
typedef int (*ubsmem_shmem_set_ownership_f)(const char *name, void *start, size_t length, int prot);
typedef int (*ubsmem_shmem_lock_f)(const char *name);
typedef int (*ubsmem_shmem_list_lookup_f)(const char *prefix, ubsmem_shmem_desc_t *shm_list, uint32_t *shm_cnt);
typedef int (*ubsmem_shmem_lookup_f)(const char *name, ubsmem_shmem_info_t *shm_info);
typedef int (*ubsmem_shmem_attach_f)(const char *name);
typedef int (*ubsmem_lease_malloc_f)(const char *region_name, size_t size, ubsmem_distance_t mem_distance,
    uint64_t flags, void **local_ptr);
typedef int (*ubsmem_lease_free_f)(void *local_ptr);
typedef int (*ubsmem_lookup_cluster_statistic_f)(ubsmem_cluster_info_t *info);
typedef int (*ubsmem_shmem_faults_register_f)(shmem_faults_func registerFunc);
typedef int (*ubsmem_local_nid_query_f)(uint32_t *nid);

typedef struct st_ub_sdk_api {
    void *handle;
    bool32 ready;
    ubsmem_init_attributes_f init_attributes;
    ubsmem_initialize_f initialize;
    ubsmem_finalize_f finalize;
    ubsmem_set_logger_level_f set_logger_level;
    ubsmem_set_extern_logger_f set_extern_logger;
    ubsmem_lookup_regions_f lookup_regions;
    ubsmem_create_region_f create_region;
    ubsmem_lookup_region_f lookup_region;
    ubsmem_destroy_region_f destroy_region;
    ubsmem_shmem_allocate_f shmem_allocate;
    ubsmem_shmem_deallocate_f shmem_deallocate;
    ubsmem_shmem_map_f shmem_map;
    ubsmem_shmem_unmap_f shmem_unmap;
    ubsmem_shmem_set_ownership_f shmem_set_ownership;
    ubsmem_shmem_lock_f shmem_write_lock;
    ubsmem_shmem_lock_f shmem_read_lock;
    ubsmem_shmem_lock_f shmem_unlock;
    ubsmem_shmem_list_lookup_f shmem_list_lookup;
    ubsmem_shmem_lookup_f shmem_lookup;
    ubsmem_shmem_attach_f shmem_attach;
    ubsmem_shmem_attach_f shmem_detach;
    ubsmem_lease_malloc_f lease_malloc;
    ubsmem_lease_free_f lease_free;
    ubsmem_lookup_cluster_statistic_f lookup_cluster_statistic;
    ubsmem_shmem_faults_register_f shmem_faults_register;
    ubsmem_local_nid_query_f local_nid_query;
} ub_sdk_api_t;

static ub_sdk_api_t g_ub_sdk = {0};

typedef struct st_ub_sdk_symbol {
    const char *name;
    void **slot;
} ub_sdk_symbol_t;

bool32 cm_ub_sdk_ready(void)
{
    return g_ub_sdk.ready;
}

void cm_ub_sdk_unload(void)
{
    if (g_ub_sdk.handle != NULL) {
        (void)dlclose(g_ub_sdk.handle);
    }
    errno_t err = memset_s(&g_ub_sdk, sizeof(g_ub_sdk), 0, sizeof(g_ub_sdk));
    if (SECUREC_UNLIKELY(err != EOK)) {
        OG_LOG_RUN_ERR("[UB] reset the loader state failed, error:%d", err);
    }
}

status_t cm_ub_sdk_load(void)
{
    if (g_ub_sdk.ready == OG_TRUE) {
        return OG_SUCCESS;
    }

    const char *path = getenv(UB_SDK_LIB_ENV);
    if (path == NULL || path[0] == '\0') {
        path = UB_SDK_LIB_DEFAULT;
    }
    if (access(path, R_OK) != 0) {
        OG_LOG_RUN_WAR("[UB] shared memory library %s is not readable, UB support stays disabled", path);
        return OG_ERROR;
    }

    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        OG_LOG_RUN_ERR("[UB] dlopen %s failed: %s", path, dlerror());
        return OG_ERROR;
    }
    g_ub_sdk.handle = handle;

    ub_sdk_symbol_t symbols[] = {
        { "ubsmem_init_attributes", (void **)&g_ub_sdk.init_attributes },
        { "ubsmem_initialize", (void **)&g_ub_sdk.initialize },
        { "ubsmem_finalize", (void **)&g_ub_sdk.finalize },
        { "ubsmem_set_logger_level", (void **)&g_ub_sdk.set_logger_level },
        { "ubsmem_set_extern_logger", (void **)&g_ub_sdk.set_extern_logger },
        { "ubsmem_lookup_regions", (void **)&g_ub_sdk.lookup_regions },
        { "ubsmem_create_region", (void **)&g_ub_sdk.create_region },
        { "ubsmem_lookup_region", (void **)&g_ub_sdk.lookup_region },
        { "ubsmem_destroy_region", (void **)&g_ub_sdk.destroy_region },
        { "ubsmem_shmem_allocate", (void **)&g_ub_sdk.shmem_allocate },
        { "ubsmem_shmem_deallocate", (void **)&g_ub_sdk.shmem_deallocate },
        { "ubsmem_shmem_map", (void **)&g_ub_sdk.shmem_map },
        { "ubsmem_shmem_unmap", (void **)&g_ub_sdk.shmem_unmap },
        { "ubsmem_shmem_set_ownership", (void **)&g_ub_sdk.shmem_set_ownership },
        { "ubsmem_shmem_write_lock", (void **)&g_ub_sdk.shmem_write_lock },
        { "ubsmem_shmem_read_lock", (void **)&g_ub_sdk.shmem_read_lock },
        { "ubsmem_shmem_unlock", (void **)&g_ub_sdk.shmem_unlock },
        { "ubsmem_shmem_list_lookup", (void **)&g_ub_sdk.shmem_list_lookup },
        { "ubsmem_shmem_lookup", (void **)&g_ub_sdk.shmem_lookup },
        { "ubsmem_shmem_attach", (void **)&g_ub_sdk.shmem_attach },
        { "ubsmem_shmem_detach", (void **)&g_ub_sdk.shmem_detach },
        { "ubsmem_lease_malloc", (void **)&g_ub_sdk.lease_malloc },
        { "ubsmem_lease_free", (void **)&g_ub_sdk.lease_free },
        { "ubsmem_lookup_cluster_statistic", (void **)&g_ub_sdk.lookup_cluster_statistic },
        { "ubsmem_shmem_faults_register", (void **)&g_ub_sdk.shmem_faults_register },
        { "ubsmem_local_nid_query", (void **)&g_ub_sdk.local_nid_query },
    };

    size_t num = sizeof(symbols) / sizeof(symbols[0]);
    for (size_t i = 0; i < num; i++) {
        *(symbols[i].slot) = dlsym(handle, symbols[i].name);
        if (*(symbols[i].slot) == NULL) {
            OG_LOG_RUN_ERR("[UB] resolve %s in %s failed, UB support stays disabled", symbols[i].name, path);
            cm_ub_sdk_unload();
            return OG_ERROR;
        }
    }

    g_ub_sdk.ready = OG_TRUE;
    OG_LOG_RUN_INF("[UB] shared memory library %s loaded", path);
    return OG_SUCCESS;
}

#define UB_SDK_CALL(fn, ...) ((g_ub_sdk.ready == OG_TRUE) ? (g_ub_sdk.fn(__VA_ARGS__)) : UBSM_ERR_UNIMPL)

int ubsmem_init_attributes(ubsmem_options_t *opts)
{
    return UB_SDK_CALL(init_attributes, opts);
}

int ubsmem_initialize(const ubsmem_options_t *opts)
{
    return UB_SDK_CALL(initialize, opts);
}

int ubsmem_finalize(void)
{
    return UB_SDK_CALL(finalize);
}

int ubsmem_set_logger_level(int level)
{
    return UB_SDK_CALL(set_logger_level, level);
}

int ubsmem_set_extern_logger(void (*func)(int level, const char *msg))
{
    return UB_SDK_CALL(set_extern_logger, func);
}

int ubsmem_lookup_regions(ubsmem_regions_t *regions)
{
    return UB_SDK_CALL(lookup_regions, regions);
}

int ubsmem_create_region(const char *region_name, size_t size, const ubsmem_region_attributes_t *reg_attr)
{
    return UB_SDK_CALL(create_region, region_name, size, reg_attr);
}

int ubsmem_lookup_region(const char *region_name, ubsmem_region_desc_t *region_desc)
{
    return UB_SDK_CALL(lookup_region, region_name, region_desc);
}

int ubsmem_destroy_region(const char *region_name)
{
    return UB_SDK_CALL(destroy_region, region_name);
}

int ubsmem_shmem_allocate(const char *region_name, const char *name, size_t size, mode_t mode, uint64_t flags)
{
    return UB_SDK_CALL(shmem_allocate, region_name, name, size, mode, flags);
}

int ubsmem_shmem_deallocate(const char *name)
{
    return UB_SDK_CALL(shmem_deallocate, name);
}

int ubsmem_shmem_map(void *addr, size_t length, int prot, int flags, const char *name, off_t offset, void **local_ptr)
{
    return UB_SDK_CALL(shmem_map, addr, length, prot, flags, name, offset, local_ptr);
}

int ubsmem_shmem_unmap(void *local_ptr, size_t length)
{
    return UB_SDK_CALL(shmem_unmap, local_ptr, length);
}

int ubsmem_shmem_set_ownership(const char *name, void *start, size_t length, int prot)
{
    return UB_SDK_CALL(shmem_set_ownership, name, start, length, prot);
}

int ubsmem_shmem_write_lock(const char *name)
{
    return UB_SDK_CALL(shmem_write_lock, name);
}

int ubsmem_shmem_read_lock(const char *name)
{
    return UB_SDK_CALL(shmem_read_lock, name);
}

int ubsmem_shmem_unlock(const char *name)
{
    return UB_SDK_CALL(shmem_unlock, name);
}

int ubsmem_shmem_list_lookup(const char *prefix, ubsmem_shmem_desc_t *shm_list, uint32_t *shm_cnt)
{
    return UB_SDK_CALL(shmem_list_lookup, prefix, shm_list, shm_cnt);
}

int ubsmem_shmem_lookup(const char *name, ubsmem_shmem_info_t *shm_info)
{
    return UB_SDK_CALL(shmem_lookup, name, shm_info);
}

int ubsmem_shmem_attach(const char *name)
{
    return UB_SDK_CALL(shmem_attach, name);
}

int ubsmem_shmem_detach(const char *name)
{
    return UB_SDK_CALL(shmem_detach, name);
}

int ubsmem_lease_malloc(const char *region_name, size_t size, ubsmem_distance_t mem_distance, uint64_t flags,
    void **local_ptr)
{
    return UB_SDK_CALL(lease_malloc, region_name, size, mem_distance, flags, local_ptr);
}

int ubsmem_lease_free(void *local_ptr)
{
    return UB_SDK_CALL(lease_free, local_ptr);
}

int ubsmem_lookup_cluster_statistic(ubsmem_cluster_info_t *info)
{
    return UB_SDK_CALL(lookup_cluster_statistic, info);
}

int ubsmem_shmem_faults_register(shmem_faults_func registerFunc)
{
    return UB_SDK_CALL(shmem_faults_register, registerFunc);
}

int ubsmem_local_nid_query(uint32_t *nid)
{
    return UB_SDK_CALL(local_nid_query, nid);
}

#else /* IN_CONTAINER: cm_ubs_mock_mem.c provides the ubsmem_* API */

bool32 cm_ub_sdk_ready(void)
{
    return OG_TRUE;
}

void cm_ub_sdk_unload(void)
{
}

status_t cm_ub_sdk_load(void)
{
    return OG_SUCCESS;
}

#endif /* IN_CONTAINER */
