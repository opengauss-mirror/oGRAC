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
 * dtc_shmem_scn.c
 *
 * Multi-slot SCN in a dedicated ubsmem region (not GBP/remote SGA).
 * GET reads local slot; SET/INC fan-out raise to peer slots.
 *
 * IDENTIFICATION
 * src/cluster/dtc_shmem_scn.c
 *
 * -------------------------------------------------------------------------
 */
#ifndef WIN32
#include <pwd.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#endif
#include "knl_cluster_module.h"
#include "dtc_drc.h"
#include "dtc_shmem_scn.h"
#include "cm_utils.h"
#include "cm_system.h"
#include "cm_memory.h"
#include "cm_ubs_mem.h"
#include "knl_context.h"
#include "srv_instance.h"

#ifndef WIN32
volatile uint64 *g_ub_global_scn = NULL;
#endif

#define SHMEM_SCN_ALIGN_128M ((uint64)SIZE_M(128))
#define SHMEM_SCN_SHM_SIZE (((uint64)(SHMEM_SCN_SIZE) + SHMEM_SCN_ALIGN_128M - 1) & ~(SHMEM_SCN_ALIGN_128M - 1))
#define SHMEM_SCN_ALLOC_FLAGS (UBSM_FLAG_WR_DELAY_COMP | UBSM_FLAG_ONLY_IMPORT_NONCACHE)
#define SHMEM_SCN_DEALLOC_RETRY 30
#define SHMEM_SCN_DEALLOC_WAIT_MS 1000

CM_STATIC_ASSERT(sizeof(shmem_scn_slot_t) == SHMEM_SCN_SIZE);
CM_STATIC_ASSERT(SHMEM_SCN_NAME_LEN == MAX_REGION_NAME_DESC_LENGTH);
CM_STATIC_ASSERT(SHMEM_SCN_NAME_LEN == MAX_SHM_NAME_LENGTH);

static bool32 shmem_scn_enabled(void)
{
    return (g_instance != NULL && g_instance->kernel.attr.enable_ubsmem) ? OG_TRUE : OG_FALSE;
}

static inline shmem_scn_mgr_t *shmem_scn_mgr(void)
{
    return &DRC_RES_CTX->shmem_scn_mgr;
}

static uint32 shmem_scn_node_count(void)
{
    uint32 node_count;

    if (g_instance == NULL) {
        return 0;
    }

    node_count = g_instance->kernel.db.ctrl.core.node_count;
    if (node_count == 0 || node_count > OG_MAX_INSTANCES) {
        return 0;
    }
    return node_count;
}

static knl_scn_t shmem_scn_read_local(void)
{
    if (g_instance == NULL) {
        return KNL_INVALID_SCN;
    }

    return KNL_GET_SCN(&g_instance->kernel.scn);
}

static void shmem_scn_raise_local(knl_scn_t scn)
{
    knl_scn_t local_scn;

    if (g_instance == NULL) {
        return;
    }

    local_scn = KNL_GET_SCN(&g_instance->kernel.scn);
    if (scn > local_scn) {
        KNL_SET_SCN(&g_instance->kernel.scn, scn);
    }
}

uint32 shmem_scn_get_owner_id(void)
{
    if (g_instance == NULL) {
        return OG_INVALID_ID32;
    }
    return g_instance->kernel.id;
}

bool32 shmem_scn_is_owner(void)
{
    if (!shmem_scn_enabled() || g_instance == NULL) {
        return OG_FALSE;
    }
    return (shmem_scn_mgr()->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;
}

static void shmem_scn_publish(shmem_scn_slot_t *slot, uint32 owner_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();

    mgr->global_scn_slot = slot;
    mgr->owner_id = owner_id;
#ifndef WIN32
    CM_MFENCE;
    g_ub_global_scn = &slot->value;
#endif
}

static void shmem_scn_unpublish(void)
{
#ifndef WIN32
    g_ub_global_scn = NULL;
    CM_MFENCE;
#endif
    shmem_scn_mgr()->global_scn_slot = NULL;
    shmem_scn_mgr()->owner_id = OG_INVALID_ID32;
}

void shmem_scn_invalidate_cache(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    shmem_scn_slot_t *slot = mgr->global_scn_slot;
    knl_scn_t ub_scn;

    if (slot != NULL) {
        ub_scn = (knl_scn_t)ub_atomic_read_u64(&slot->value);
        OG_LOG_RUN_INF("[SHMEM-SCN] invalidate local scn slot, self=%u, scn=%llu", mgr->owner_id, (uint64)ub_scn);
        shmem_scn_raise_local(ub_scn);
    }

    shmem_scn_unpublish();
}

#ifndef WIN32
static status_t shmem_scn_format_names(uint32 node_id, char *region_name, uint32 region_len, char *shm_name,
    uint32 shm_len)
{
    struct passwd *pwd;
    int ret;

    pwd = getpwuid(getuid());
    if (pwd == NULL || pwd->pw_name == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] getpwuid failed, uid=%d", getuid());
        return OG_ERROR;
    }

    ret = sprintf_s(region_name, region_len, "region_scn_%s_%u", pwd->pw_name, node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] sprintf region name fail, return error:%d", ret);
        return OG_ERROR;
    }

    ret = sprintf_s(shm_name, shm_len, "shm_scn_%s_%u", pwd->pw_name, node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] sprintf shm name fail, return error:%d", ret);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t shmem_scn_build_region_attr(ubsmem_region_attributes_t *region_attr)
{
    ubsmem_regions_t regions;
    char *host_name;
    int ret;
    int i;

    ret = ubsmem_lookup_regions(&regions);
    if (ret != UBSM_OK || regions.num <= 0) {
        return OG_ERROR;
    }

    *region_attr = regions.region[0];
    host_name = cm_sys_host_name();
    for (i = 0; i < region_attr->host_num; i++) {
        region_attr->hosts[i].affinity =
            (host_name != NULL && strcmp(region_attr->hosts[i].host_name, host_name) == 0);
    }
    return OG_SUCCESS;
}

static status_t shmem_scn_map_node(uint32 node_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    char region_name[SHMEM_SCN_NAME_LEN] = { 0 };
    char shm_name[SHMEM_SCN_NAME_LEN] = { 0 };
    void *addr = NULL;
    int ret;

    if (node_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    if (mgr->map_success[node_id] == OG_TRUE && mgr->map_addr[node_id] != NULL) {
        return OG_SUCCESS;
    }

    if (node_id == g_instance->kernel.id && mgr->local_shm_name[0] != '\0') {
        MEMS_RETURN_IFERR(strcpy_s(shm_name, sizeof(shm_name), mgr->local_shm_name));
    } else if (shmem_scn_format_names(node_id, region_name, sizeof(region_name), shm_name, sizeof(shm_name)) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    ret = ubsmem_shmem_map(NULL, (size_t)mgr->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_name, 0, &addr);
    if (ret != UBSM_OK) {
        if (g_instance != NULL && node_id == g_instance->kernel.id) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] Failed to map local %s, return error:%d", shm_name, ret);
        } else {
            OG_LOG_DEBUG_INF("[SHMEM-SCN] map peer %s node=%u not ready, ret=%d", shm_name, node_id, ret);
        }
        return OG_ERROR;
    }

    mgr->map_addr[node_id] = (char *)addr;
    mgr->map_success[node_id] = OG_TRUE;
    OG_LOG_RUN_INF("[SHMEM-SCN] mapped %s on node_id %u, addr=%p, size=%llu", shm_name, node_id, addr, mgr->shm_size);
    return OG_SUCCESS;
}

static void shmem_scn_unmap_node(uint32 node_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    int ret;

    if (node_id >= OG_MAX_INSTANCES || mgr->map_success[node_id] != OG_TRUE || mgr->map_addr[node_id] == NULL) {
        return;
    }

    ret = ubsmem_shmem_unmap(mgr->map_addr[node_id], (size_t)mgr->shm_size);
    if (ret != UBSM_OK) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] unmap node %u addr=%p failed, error:%d", node_id, mgr->map_addr[node_id], ret);
    } else {
        OG_LOG_RUN_INF("[SHMEM-SCN] unmap node %u addr=%p success", node_id, mgr->map_addr[node_id]);
    }

    mgr->map_addr[node_id] = NULL;
    mgr->map_success[node_id] = OG_FALSE;
}

static status_t shmem_scn_create_local_with_hosts(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id = g_instance->kernel.id;
    uint32 inst_count = shmem_scn_node_count();
    status_t status;

    if (inst_count == 0) {
        inst_count = 2;
    }

    /* Create a dedicated region name via ub_create_shm_region-like hosts, then allocate SCN shm into it.
     * Use region_scn_* naming; temporarily create region by copying GBP helper pattern. */
    {
        const char *local_host = cm_sys_host_name();
        const char *cluster_hosts = g_instance->kernel.attr.ubs_cluster_hosts;
        ubsmem_region_attributes_t region;
        char host_buf[OG_MAX_INSTANCES][MAX_HOST_NAME_DESC_LENGTH];
        uint32 filled = 0;
        char tmp[OG_HOST_NAME_BUFFER_SIZE * 16];
        char *saveptr = NULL;
        char *token;
        errno_t err;
        int ret;
        uint32 i;

        err = strncpy_s(tmp, sizeof(tmp), cluster_hosts, strlen(cluster_hosts));
        if (err != EOK) {
            return OG_ERROR;
        }
        token = strtok_s(tmp, ",", &saveptr);
        while (token != NULL && filled < OG_MAX_INSTANCES) {
            while (*token == ' ' || *token == '\t') {
                token++;
            }
            if (*token != '\0') {
                err = strncpy_s(host_buf[filled], sizeof(host_buf[filled]), token, MAX_HOST_NAME_DESC_LENGTH - 1);
                if (err != EOK) {
                    return OG_ERROR;
                }
                filled++;
            }
            token = strtok_s(NULL, ",", &saveptr);
        }
        if (filled == 0) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] no hosts parsed from UBS_CLUSTER_HOSTS");
            return OG_ERROR;
        }
        if (inst_count > filled) {
            inst_count = filled;
        }

        region.host_num = (int)inst_count;
        err = strcpy_s(region.hosts[0].host_name, sizeof(region.hosts[0].host_name), local_host);
        if (err != EOK) {
            return OG_ERROR;
        }
        region.hosts[0].affinity = true;
        for (i = 1; i < inst_count; i++) {
            const char *remote = NULL;
            uint32 h;
            for (h = 0; h < filled; h++) {
                if (strcmp(host_buf[h], local_host) != 0) {
                    remote = host_buf[h];
                    break;
                }
            }
            if (remote == NULL) {
                remote = host_buf[i % filled];
            }
            err = strcpy_s(region.hosts[i].host_name, sizeof(region.hosts[i].host_name), remote);
            if (err != EOK) {
                return OG_ERROR;
            }
            region.hosts[i].affinity = false;
        }

        ret = ubsmem_create_region(mgr->local_region_name, 0, &region);
        if (ret != UBSM_OK && ret != UBSM_ERR_ALREADY_EXIST) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] create region %s via hosts failed, ret=%d", mgr->local_region_name, ret);
            return OG_ERROR;
        }
        status = OG_SUCCESS;
    }

    (void)self_id;
    return status;
}

static status_t shmem_scn_create_local(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id = g_instance->kernel.id;
    ubsmem_region_attributes_t region_attr;
    int ret;
    int alloc_ret;

    if (shmem_scn_format_names(self_id, mgr->local_region_name, sizeof(mgr->local_region_name), mgr->local_shm_name,
        sizeof(mgr->local_shm_name)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (shmem_scn_build_region_attr(&region_attr) == OG_SUCCESS) {
        ret = ubsmem_create_region(mgr->local_region_name, 0, &region_attr);
        if (ret != UBSM_OK && ret != UBSM_ERR_ALREADY_EXIST) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] create region %s failed, ret=%d", mgr->local_region_name, ret);
            return OG_ERROR;
        }
    } else if (shmem_scn_create_local_with_hosts() != OG_SUCCESS) {
        return OG_ERROR;
    }

    alloc_ret = ubsmem_shmem_allocate(mgr->local_region_name, mgr->local_shm_name, mgr->shm_size, 0600,
        SHMEM_SCN_ALLOC_FLAGS);
    if (alloc_ret == UBSM_ERR_ALREADY_EXIST) {
        OG_LOG_RUN_WAR("[SHMEM-SCN] shm %s already exist, ret: %d", mgr->local_shm_name, alloc_ret);
    } else if (alloc_ret != UBSM_OK) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] allocate shm %s failed, ret: %d, region=%s, size=%llu", mgr->local_shm_name,
            alloc_ret, mgr->local_region_name, mgr->shm_size);
        return OG_ERROR;
    }

    mgr->local_created = OG_TRUE;

    if (shmem_scn_map_node(self_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (alloc_ret == UBSM_OK) {
        MEMS_RETURN_IFERR(memset_s(mgr->map_addr[self_id], SHMEM_SCN_SIZE, 0, SHMEM_SCN_SIZE));
    }

    OG_LOG_RUN_INF("[SHMEM-SCN] local shm ready, region=%s, shm=%s, size=%llu, addr=%p", mgr->local_region_name,
        mgr->local_shm_name, mgr->shm_size, mgr->map_addr[self_id]);
    return OG_SUCCESS;
}

static void shmem_scn_deallocate_local(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    int ret;
    uint32 i;

    if (mgr->local_created != OG_TRUE || mgr->local_shm_name[0] == '\0') {
        return;
    }

    for (i = 0; i < SHMEM_SCN_DEALLOC_RETRY; i++) {
        ret = ubsmem_shmem_deallocate(mgr->local_shm_name);
        if (ret == UBSM_OK) {
            OG_LOG_RUN_INF("[SHMEM-SCN] deallocate %s success", mgr->local_shm_name);
            return;
        }
        if (ret != UBSM_ERR_IN_USING) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] deallocate %s failed, error:%d", mgr->local_shm_name, ret);
            return;
        }
        OG_LOG_RUN_WAR("[SHMEM-SCN] deallocate %s IN_USING, retry %u", mgr->local_shm_name, i);
        cm_sleep(SHMEM_SCN_DEALLOC_WAIT_MS);
    }

    OG_LOG_RUN_ERR("[SHMEM-SCN] deallocate %s still IN_USING after %u retries", mgr->local_shm_name,
        SHMEM_SCN_DEALLOC_RETRY);
}

status_t shmem_scn_ensure_ub_mapped(uint32 node_id)
{
    return shmem_scn_map_node(node_id);
}

static void shmem_scn_try_map_peers(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    uint32 node_count;
    uint32 i;

    if (g_instance == NULL) {
        return;
    }

    self_id = g_instance->kernel.id;
    node_count = shmem_scn_node_count();
    if (node_count == 0) {
        return;
    }

    for (i = 0; i < node_count; i++) {
        if (i == self_id) {
            continue;
        }
        if (mgr->map_success[i] == OG_TRUE && mgr->map_addr[i] != NULL) {
            continue;
        }
        (void)shmem_scn_map_node(i);
    }
}

static void shmem_scn_raise_peer_slot(uint32 node_id, uint64 scn)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    shmem_scn_slot_t *slot;

    if (node_id >= OG_MAX_INSTANCES || mgr->map_success[node_id] != OG_TRUE || mgr->map_addr[node_id] == NULL) {
        return;
    }

    slot = (shmem_scn_slot_t *)mgr->map_addr[node_id];
    ub_atomic_raise_u64(&slot->value, scn);
}

void shmem_scn_fanout_raise(uint64 scn)
{
    uint32 self_id;
    uint32 node_count;
    uint32 i;

    if (!shmem_scn_enabled() || scn == 0 || g_instance == NULL) {
        return;
    }

    self_id = g_instance->kernel.id;
    node_count = shmem_scn_node_count();
    if (node_count == 0) {
        return;
    }

    for (i = 0; i < node_count; i++) {
        if (i == self_id) {
            continue;
        }
        shmem_scn_raise_peer_slot(i, scn);
    }
}

void shmem_scn_bind(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    shmem_scn_slot_t *slot;
    knl_scn_t local_scn;
    uint64 ub_scn = 0;
    uint64 merged = 0;
    bool32 was_active;

    if (!shmem_scn_enabled() || g_instance == NULL) {
        return;
    }

    self_id = g_instance->kernel.id;
    if (self_id >= OG_MAX_INSTANCES) {
        return;
    }

    if (mgr->map_success[self_id] != OG_TRUE || mgr->map_addr[self_id] == NULL) {
        return;
    }

    slot = (shmem_scn_slot_t *)mgr->map_addr[self_id];
    local_scn = shmem_scn_read_local();
    was_active = (mgr->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;

    slot->owner_node = self_id;
    ub_scn = ub_atomic_read_u64(&slot->value);
    merged = MAX((uint64)local_scn, ub_scn);
    ub_atomic_raise_u64(&slot->value, merged);

    shmem_scn_raise_local((knl_scn_t)merged);
    shmem_scn_publish(slot, self_id);
    OG_LOG_RUN_INF("[SHMEM-SCN] %s local scn shm, self=%u, addr=%p, value=%llu", was_active ? "rebind" : "bind",
        self_id, slot, merged);
}
#else
status_t shmem_scn_ensure_ub_mapped(uint32 node_id)
{
    (void)node_id;
    return OG_ERROR;
}

static void shmem_scn_unmap_node(uint32 node_id)
{
    (void)node_id;
}

static status_t shmem_scn_create_local(void)
{
    return OG_SUCCESS;
}

static void shmem_scn_deallocate_local(void)
{
}

void shmem_scn_bind(void)
{
}

static void shmem_scn_try_map_peers(void)
{
}

void shmem_scn_fanout_raise(uint64 scn)
{
    (void)scn;
}
#endif

static bool32 shmem_scn_is_local_bound(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    shmem_scn_slot_t *slot;

    if (g_instance == NULL) {
        return OG_FALSE;
    }

    self_id = g_instance->kernel.id;
    if (self_id >= OG_MAX_INSTANCES) {
        return OG_FALSE;
    }

    if (mgr->global_scn_slot == NULL || mgr->owner_id != self_id) {
        return OG_FALSE;
    }

    if (mgr->map_success[self_id] != OG_TRUE || mgr->map_addr[self_id] == NULL) {
        return OG_FALSE;
    }

    slot = (shmem_scn_slot_t *)mgr->map_addr[self_id];
    return (slot == mgr->global_scn_slot) ? OG_TRUE : OG_FALSE;
}

static status_t shmem_scn_ensure_local_bound(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;

    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (g_instance == NULL) {
        return OG_ERROR;
    }

    /* Already published to the current local map: skip bind/rebind. */
    if (shmem_scn_is_local_bound()) {
        return OG_SUCCESS;
    }

    self_id = g_instance->kernel.id;
    if (shmem_scn_ensure_ub_mapped(self_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    shmem_scn_bind();
    if (mgr->global_scn_slot == NULL) {
        return OG_ERROR;
    }

    shmem_scn_try_map_peers();
    return OG_SUCCESS;
}

status_t shmem_scn_rebind_if_needed(void)
{
    return shmem_scn_ensure_local_bound();
}

static void shmem_scn_reset_mgr(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();

    MEMS_RETVOID_IFERR(memset_s(mgr, sizeof(shmem_scn_mgr_t), 0, sizeof(shmem_scn_mgr_t)));
    mgr->owner_id = OG_INVALID_ID32;
    mgr->shm_size = SHMEM_SCN_SHM_SIZE;
}

status_t shmem_scn_init(void)
{
    shmem_scn_reset_mgr();
    shmem_scn_unpublish();
    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    /* ubsmem is initialized by ub_init_ubsm_mem() in dtc_startup; reuse it. */
    if (shmem_scn_create_local() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] create local shm failed");
        shmem_scn_cleanup();
        return OG_ERROR;
    }

    shmem_scn_bind();
    if (shmem_scn_mgr()->global_scn_slot == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] bind local scn slot failed");
        shmem_scn_cleanup();
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[SHMEM-SCN] init dedicated multi-slot local scn=%llu, peer fan-out deferred",
        (uint64)shmem_scn_read_local());
    return OG_SUCCESS;
}

void shmem_scn_cleanup(void)
{
    shmem_scn_mgr_t *mgr;
    uint32 i;
    int ret;

    if (g_instance == NULL || DRC_RES_CTX == NULL) {
        return;
    }

    mgr = shmem_scn_mgr();
    shmem_scn_invalidate_cache();

    for (i = 0; i < OG_MAX_INSTANCES; i++) {
        shmem_scn_unmap_node(i);
    }

    shmem_scn_deallocate_local();
#ifndef WIN32
    if (mgr->local_region_name[0] != '\0') {
        ret = ubsmem_destroy_region(mgr->local_region_name);
        if (ret != UBSM_OK) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] destroy region %s failed, ret=%d", mgr->local_region_name, ret);
        }
        mgr->local_region_name[0] = '\0';
    }
#endif
    mgr->local_created = OG_FALSE;
    mgr->local_shm_name[0] = '\0';
}

status_t shmem_scn_sync_to_ub(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    knl_scn_t scn;

    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (shmem_scn_ensure_local_bound() != OG_SUCCESS || mgr->global_scn_slot == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] sync local multi-slot failed, local scn=%llu", (uint64)shmem_scn_read_local());
        return OG_ERROR;
    }

    /* Peer map is not retried on the hot path once local is bound. */
    shmem_scn_try_map_peers();

    scn = KNL_GET_UB_SCN(&g_instance->kernel.scn);
    shmem_scn_fanout_raise((uint64)scn);
    OG_LOG_RUN_INF("[SHMEM-SCN] sync multi-slot done, self=%u, value=%llu", mgr->owner_id, (uint64)scn);
    return OG_SUCCESS;
}

status_t shmem_scn_ensure_ready(void)
{
    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (shmem_scn_ensure_local_bound() != OG_SUCCESS || shmem_scn_mgr()->global_scn_slot == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] local scn slot not ready before open");
        return OG_ERROR;
    }

    shmem_scn_try_map_peers();
    return OG_SUCCESS;
}

bool32 shmem_scn_ready(void)
{
    if (!shmem_scn_enabled()) {
        return OG_TRUE;
    }

    return (shmem_scn_mgr()->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;
}

bool32 shmem_scn_need_broadcast(void)
{
#ifndef WIN32
    return (g_ub_global_scn == NULL) ? OG_TRUE : OG_FALSE;
#else
    return OG_TRUE;
#endif
}
