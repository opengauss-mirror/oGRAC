/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd. All rights reserved.
 * This file is part of the oGRAC project.
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
 * cm_ubs_mock_mem.c
 *
 *
 * IDENTIFICATION
 *      src/common/cm_ubs_mock_mem.c
 *
 * -------------------------------------------------------------------------
 */


#ifdef IN_CONTAINER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>

#include "cm_log.h"
#include "cm_ubs_mem.h"

#ifndef MODULE_ID
#define MODULE_ID CLUSTER
#endif

#ifdef __cplusplus
extern "C" {
#endif
#define BASE_PATH "/dev/shm/ub"
#define MAX_SHM_NAME_MOCK_LEN (MAX_REGION_NAME_DESC_LENGTH+MAX_SHM_NAME_LENGTH)

/* -------------------------------------------------
 * Global init state
 * ------------------------------------------------- */
static int g_initialized = 0;
static mode_t io_mode = 0755;
/* -------------------------------------------------
 * Init attributes
 * ------------------------------------------------- */
SHMEM_API int ubsmem_init_attributes(ubsmem_options_t *ubsm_shmem_opts)
{
    if (!ubsm_shmem_opts) {
        return -1;
    }
    memset(ubsm_shmem_opts, 0, sizeof(*ubsm_shmem_opts));
    return 0;
}

/* -------------------------------------------------
 * Initialize base path
 * ------------------------------------------------- */
SHMEM_API int ubsmem_initialize(const ubsmem_options_t *ubsm_shmem_opts)
{
    (void)ubsm_shmem_opts;

    if (g_initialized) return 0;

    int ret = mkdir(BASE_PATH, io_mode);
    if (ret == -1) {
        if (errno == EEXIST) {
            OG_LOG_RUN_INF("mkdir base %s already exist\n", BASE_PATH);
        } else {
            OG_LOG_RUN_ERR("mkdir base %s failed: %s\n", BASE_PATH, strerror(errno));
            return -1;
        }
    }
    g_initialized = 1;
    return 0;
}

/* -------------------------------------------------
 * Finalize
 * ------------------------------------------------- */
SHMEM_API int ubsmem_finalize(void)
{
    g_initialized = 0;
    if (rmdir(BASE_PATH) == -1) {
        OG_LOG_RUN_ERR("mkdir base %s failed: %s\n", BASE_PATH, strerror(errno));
        return -1;
    }
    return 0;
}

/* -------------------------------------------------
 * Create region (directory)
 * ------------------------------------------------- */
SHMEM_API int ubsmem_create_region(
    const char *region_name,
    size_t size,
    const ubsmem_region_attributes_t *reg_attr)
{
    (void)size;
    (void)reg_attr;

    if (!g_initialized) return -1;

    char path[MAX_SHM_NAME_MOCK_LEN];
    if (snprintf(path, MAX_SHM_NAME_MOCK_LEN, "%s/%s", BASE_PATH, region_name) == -1) {
        return -1;
    }

    int ret = mkdir(path, io_mode);
    if (ret == -1) {
        if (errno == EEXIST) {
            OG_LOG_RUN_INF("mkdir path %s already exist\n", path);
        } else {
            OG_LOG_RUN_ERR("mkdir path %s failed: %s\n", path, strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* -------------------------------------------------
 * Destroy region (remove directory)
 * ------------------------------------------------- */
SHMEM_API int ubsmem_destroy_region(const char *region_name)
{
    char path[MAX_SHM_NAME_MOCK_LEN];
    if (snprintf(path, MAX_SHM_NAME_MOCK_LEN, "%s/%s", BASE_PATH, region_name) == -1) {
        return -1;
    }
    if (rmdir(path) == -1) {
        OG_LOG_RUN_ERR("destroy region %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

/* -------------------------------------------------
 * Allocate (ftruncate)
 * ret = ubsmem_shmem_allocate(region_name, data_buf_name, remote_buf_size, 0600,
 * UBSM_FLAG_WR_DELAY_COMP | UBSM_FLAG_ONLY_IMPORT_NONCACHE);
 * ------------------------------------------------- */
SHMEM_API int ubsmem_shmem_allocate(
    const char *region_name,
    const char *name,
    size_t size,
    mode_t mode,
    uint64_t flags)
{
    (void)flags;

    char path[MAX_SHM_NAME_MOCK_LEN];
    if (snprintf(path, MAX_SHM_NAME_MOCK_LEN, "%s/%s/%s", BASE_PATH, region_name, name) == -1) {
        return -1;
    }

    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, mode);
    if (fd == -1 && errno != EEXIST) {
        OG_LOG_RUN_ERR("open file %s failed: %s\n", path, strerror(errno));
        return -1;
    }

    if (ftruncate(fd, size) == -1) {
        OG_LOG_RUN_ERR("ftruncate %s failed: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/* -------------------------------------------------
 * Deallocate (remove file)
 * ------------------------------------------------- */
SHMEM_API int ubsmem_shmem_deallocate(const char *name)
{
    char path[MAX_SHM_NAME_MOCK_LEN];
    // Be very careful here! In oGRAC, this function is called with data_buf_name.
    // i.e. without region name. Here we need to add it back.
    const char* region_name = (strchr(name, '0') != NULL) ? "shm_pool_0" : "shm_pool_1";
    if (snprintf(path, MAX_SHM_NAME_MOCK_LEN, "%s/%s/%s", BASE_PATH, region_name, name) == -1) {
        return -1;
    }

    if (unlink(path) == -1) {
        OG_LOG_RUN_ERR("deallocate %s failed: %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}

/* -------------------------------------------------
 * Map (mmap)
 * E.g. ret = ubsmem_shmem_map(start_temp, data_buf_size,
 *   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
        data_buf_name, 0, (void **)&(remote_sga->remote_buf_addr[node_id]));
 * ------------------------------------------------- */
SHMEM_API int ubsmem_shmem_map(
    void *addr,
    size_t length,
    int prot,
    int flags,
    const char *name,
    off_t offset,
    void **local_ptr)
{
    char path[MAX_SHM_NAME_MOCK_LEN];
    // Be very careful here! In oGRAC, this function is called with data_buf_name, i.e. without region name.
    // ubsmem functions probably saved the current region. Here we need to add region name back.
    // It is hard coded for 2 nodes now.
    const char* region_name = (strchr(name, '0') != NULL) ? "shm_pool_0" : "shm_pool_1";
    if (snprintf(path, MAX_SHM_NAME_MOCK_LEN, "%s/%s/%s", BASE_PATH, region_name, name) == -1) {
        return -1;
    }

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        OG_LOG_RUN_ERR("open fd %s in mmap failed: %s\n", path, strerror(errno));
        return -1;
    }
    // Notice: using fixed addr + MAP_FIXED flag instead of NULL is very dangerous!
    void *map = mmap(addr, length, prot, flags, fd, offset);
    if (map == MAP_FAILED) {
        OG_LOG_RUN_ERR("mmap failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    *local_ptr = map;

    // fd can be closed after mmap
    close(fd);
    return 0;
}

/* -------------------------------------------------
 * Unmap
 * ------------------------------------------------- */
SHMEM_API int ubsmem_shmem_unmap(void *local_ptr, size_t length)
{
    if (munmap(local_ptr, length) == -1) {
        OG_LOG_RUN_ERR("munmap failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
SHMEM_API int ubsmem_set_logger_level(int level) { return 0;}

SHMEM_API int ubsmem_set_extern_logger(void (*func)(int level, const char *msg)) { return 0;}

SHMEM_API int ubsmem_lookup_regions(ubsmem_regions_t* regions) { return 0;}

SHMEM_API int ubsmem_lookup_region(const char *region_name, ubsmem_region_desc_t *region_desc) { return 0;}

SHMEM_API int ubsmem_shmem_set_ownership(const char *name, void *start, size_t length, int prot) { return 0;}

SHMEM_API int ubsmem_shmem_write_lock(const char *name) { return 0;}
SHMEM_API int ubsmem_shmem_read_lock(const char *name) { return 0;}
SHMEM_API int ubsmem_shmem_unlock(const char *name) { return 0;}

SHMEM_API int ubsmem_shmem_list_lookup(const char *prefix,
    ubsmem_shmem_desc_t *shm_list, uint32_t *shm_cnt) { return 0;}
SHMEM_API int ubsmem_shmem_lookup(const char *name, ubsmem_shmem_info_t *shm_info) { return 0;}
SHMEM_API int ubsmem_shmem_attach(const char *name) { return 0;}
SHMEM_API int ubsmem_shmem_detach(const char *name) { return 0;}

SHMEM_API int ubsmem_lease_malloc(const char *region_name, size_t size,
    ubsmem_distance_t mem_distance, uint64_t flags, void **local_ptr) { return 0;}

SHMEM_API int ubsmem_lease_free(void *local_ptr) { return 0;}

SHMEM_API int ubsmem_lookup_cluster_statistic(ubsmem_cluster_info_t* info) { return 0;}

SHMEM_API int ubsmem_shmem_faults_register(shmem_faults_func registerFunc) { return 0;}

SHMEM_API int ubsmem_local_nid_query(uint32_t* nid) { return 0;}

#ifdef __cplusplus
}
#endif

#endif // IN_CONTAINER