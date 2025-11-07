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
 * srv_lsnr.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_lsnr.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_lsnr.h"
#include "srv_agent.h"
#include "srv_instance.h"
#include "srv_replica.h"
#include "srv_emerg.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t srv_check_tcp_ip(cs_pipe_t *pipe)
{
    char ipstr[CM_MAX_IP_LEN];
    status_t status;
    bool32 check_res = OG_FALSE;
    (void)cm_inet_ntop((struct sockaddr *)&pipe->link.tcp.remote.addr, ipstr, CM_MAX_IP_LEN);
    status = cm_check_remote_ip(GET_WHITE_CTX, ipstr, &check_res);
    if (status == OG_ERROR || !check_res) {
        OG_THROW_ERROR(ERR_TCP_INVALID_IPADDRESS, ipstr);
        sql_audit_log_ddos(ipstr);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t srv_tcp_app_connect_action(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    if (g_instance->kernel.switch_ctrl.request != SWITCH_REQ_NONE) {
        cs_tcp_disconnect(&pipe->link.tcp);
        OG_THROW_ERROR(ERR_SESSION_CLOSED, "server is doing switch request");
        return OG_ERROR;
    }

    if (srv_check_tcp_ip(pipe) != OG_SUCCESS) {
        cs_tcp_disconnect(&pipe->link.tcp);
        return OG_ERROR;
    }

    if (srv_create_session(pipe) != OG_SUCCESS) {
        cs_tcp_disconnect(&pipe->link.tcp);
        OG_THROW_ERROR(ERR_CREATE_AGENT, "agent");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t srv_tcp_replica_connect_action(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    if (srv_create_replica_session(pipe) != OG_SUCCESS) {
        cs_tcp_disconnect(&pipe->link.tcp);
        OG_THROW_ERROR(ERR_CREATE_AGENT, "replica agent");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t srv_uds_connect_action(uds_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    status_t status;

    if (lsnr->is_emerg) {
        status = srv_create_emerg_session(pipe);
    } else {
        if (g_instance->kernel.switch_ctrl.request != SWITCH_REQ_NONE) {
            cs_uds_disconnect(&pipe->link.uds);
            OG_THROW_ERROR(ERR_SESSION_CLOSED, "server is doing switch request");
            return OG_ERROR;
        }
        status = srv_create_session(pipe);
    }

    if (status != OG_SUCCESS) {
        OG_LOG_RUN_ERR("UDS connect, create %s session failed", lsnr->is_emerg ? "emerg" : "user");
        cs_uds_disconnect(&pipe->link.uds);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t srv_start_replica_lsnr(void)
{
    status_t status = OG_SUCCESS;

    g_instance->lsnr.tcp_replica.type = LSNR_TYPE_REPLICA;
    if (g_instance->lsnr.tcp_replica.port != 0) {
        status = cs_start_tcp_lsnr(&g_instance->lsnr.tcp_replica, srv_tcp_replica_connect_action, OG_TRUE);
        if (status != OG_SUCCESS) {
            OG_LOG_RUN_ERR("failed to start lsnr for REPL_ADDR");
        }
    }

    return status;
}

status_t srv_start_lsnr(void)
{
    status_t status;

    g_instance->lsnr.tcp_service.type = LSNR_TYPE_SERVICE;
    status = cs_start_tcp_lsnr(&g_instance->lsnr.tcp_service, srv_tcp_app_connect_action, OG_FALSE);
    if (status != OG_SUCCESS) {
        OG_LOG_RUN_ERR("failed to start lsnr for LSNR_ADDR");
        return status;
    }

    status = srv_start_replica_lsnr();
    if (status != OG_SUCCESS) {
        cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
        return status;
    }

    g_instance->lsnr.uds_service.type = LSNR_TYPE_UDS;
    status = cs_start_uds_lsnr(&g_instance->lsnr.uds_service, srv_uds_connect_action);
    if (status != OG_SUCCESS) {
        cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_replica);
        cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
        OG_LOG_RUN_ERR("failed to start lsnr for UDS");
        return status;
    }

    return OG_SUCCESS;
}

void srv_pause_lsnr(lsnr_type_t type)
{
    switch (type) {
        case LSNR_TYPE_SERVICE:
            cs_pause_tcp_lsnr(&g_instance->lsnr.tcp_service);
            break;
        case LSNR_TYPE_REPLICA:
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_pause_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            break;
        case LSNR_TYPE_UDS:
            cs_pause_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
        default:
            cs_pause_tcp_lsnr(&g_instance->lsnr.tcp_service);
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_pause_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            cs_pause_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
    }

    return;
}

void srv_resume_lsnr(lsnr_type_t type)
{
    switch (type) {
        case LSNR_TYPE_SERVICE:
            cs_resume_tcp_lsnr(&g_instance->lsnr.tcp_service);
            break;
        case LSNR_TYPE_REPLICA:
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_resume_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            break;
        case LSNR_TYPE_UDS:
            cs_resume_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
        default:
            cs_resume_tcp_lsnr(&g_instance->lsnr.tcp_service);
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_resume_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            cs_resume_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
    }

    return;
}

void srv_stop_lsnr(lsnr_type_t type)
{
    switch (type) {
        case LSNR_TYPE_SERVICE:
            cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
            break;
        case LSNR_TYPE_REPLICA:
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            break;
        case LSNR_TYPE_UDS:
            cs_stop_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
        default:
            cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_service);
            if (g_instance->lsnr.tcp_replica.port != 0) {
                cs_stop_tcp_lsnr(&g_instance->lsnr.tcp_replica);
            }
            cs_stop_uds_lsnr(&g_instance->lsnr.uds_service);
            break;
    }

    return;
}

#ifdef __cplusplus
}
#endif
