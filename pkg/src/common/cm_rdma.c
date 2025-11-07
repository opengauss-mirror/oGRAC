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
 * cm_rdma.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_rdma.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_rdma.h"
#include "cm_log.h"
#include "cm_error.h"
#ifndef WIN32
#include <dlfcn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32

static rdma_socket_procs_t g_rdma_lib_handle = { .rdma_useble = OG_FALSE, .rdma_handle = NULL };

rdma_socket_procs_t *rdma_global_handle(void)
{
    return &g_rdma_lib_handle;
}

static status_t rdma_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
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

status_t rdma_init_lib(void)
{
    rdma_socket_procs_t *procs = rdma_global_handle();
    procs->rdma_handle = dlopen("librdmacm.so", RTLD_LAZY);
    if (procs->rdma_handle == NULL) {
        OG_LOG_RUN_WAR("failed to load librdmacm.so, maybe no rdma driver, or lib path error");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsocket",      (void **)(&procs->socket)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rbind",        (void **)(&procs->bind)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rlisten",      (void **)(&procs->listen)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "raccept",      (void **)(&procs->accept)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rconnect",     (void **)(&procs->connect)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rshutdown",    (void **)(&procs->shutdown)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rclose",       (void **)(&procs->close)));

    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rrecv",        (void **)(&procs->recv)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rrecvfrom",    (void **)(&procs->recvfrom)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rrecvmsg",     (void **)(&procs->recvmsg)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsend",        (void **)(&procs->send)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsendto",      (void **)(&procs->sendto)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsendmsg",     (void **)(&procs->sendmsg)));

    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rread",        (void **)(&procs->read)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rreadv",       (void **)(&procs->readv)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rwrite",       (void **)(&procs->write)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rwritev",      (void **)(&procs->writev)));

    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rpoll",        (void **)(&procs->poll)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rselect",      (void **)(&procs->select)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rgetpeername", (void **)(&procs->getpeername)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rgetsockname", (void **)(&procs->getsockname)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsetsockopt",  (void **)(&procs->setsockopt)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rgetsockopt",  (void **)(&procs->getsockopt)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rfcntl",       (void **)(&procs->fcntl)));

    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "riomap",       (void **)(&procs->iomap)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "riounmap",     (void **)(&procs->iounmap)));
    OG_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "riowrite",     (void **)(&procs->iowrite)));

    procs->rdma_useble = OG_TRUE;
    OG_LOG_RUN_INF("load librdmacm.so done");

    return OG_SUCCESS;
}

void rdma_close_lib(void)
{
    rdma_socket_procs_t *rdma_procs = rdma_global_handle();
    if (rdma_is_inited(rdma_procs)) {
        (void)dlclose(rdma_procs->rdma_handle);
        MEMS_RETVOID_IFERR(memset_s(rdma_procs, sizeof(rdma_socket_procs_t), 0, sizeof(rdma_socket_procs_t)));
    }
}

#else

status_t rdma_init_lib()
{
    return OG_SUCCESS;
}

void rdma_close_lib()
{
    return;
}

#endif      // win32

#ifdef __cplusplus
}
#endif
