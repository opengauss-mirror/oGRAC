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
 * srv_replica.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_replica.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_replica.h"
#include "cm_file.h"
#include "cm_thread.h"
#include "cs_pipe.h"
#include "srv_agent.h"
#include "srv_instance.h"

typedef enum en_replica_type {
    REPLICA_LRCV = 0,
    REPLICA_LFTC,
    REPLICA_BACKUP,
    REPLICA_INVALID,
} replica_type_t;

static void srv_clear_lrcv_ctx(lrcv_context_t *lrcv)
{
    cm_spin_lock(&lrcv->lock, NULL);
    cm_aligned_free(&lrcv->send_buf.read_buf);
    cm_aligned_free(&lrcv->extend_buf.read_buf);
    cm_aligned_free(&lrcv->recv_buf.read_buf);
    cm_aligned_free(&lrcv->d_ctx.compressed_buf);
    (void)ZSTD_freeDCtx(lrcv->d_ctx.zstd_dctx);

    if (lrcv->state == REP_STATE_DEMOTE_REQUEST || lrcv->state == REP_STATE_WAITING_DEMOTE) {
        lrcv->state = REP_STATE_DEMOTE_FAILED;
    } else {
        lrcv->state = REP_STATE_NORMAL;
    }

    if (lrcv->status != LRCV_NEED_REPAIR) {
        lrcv->status = LRCV_DISCONNECTED;
        lrcv->peer_role = PEER_UNKNOWN;
    }

    errno_t err = memset_sp(&lrcv->wait_info, sizeof(log_switch_wait_info_t), 0, sizeof(log_switch_wait_info_t));
    knl_securec_check(err);
    lrcv->reset_asn = OG_INVALID_ASN;
    lrcv->peer_repl_port = 0;
    lrcv->role_spec_building = OG_FALSE;
    lrcv->is_building = OG_FALSE;
    lrcv->pipe = NULL;
    lrcv->session = NULL;
    cm_spin_unlock(&lrcv->lock);
}

static void srv_init_lftc_ctx(session_t *session, lftc_srv_ctx_t *ogx)
{
    agent_t *agent = session->agent;

    ogx->thread = agent->thread;
    ogx->session = &session->knl_session;
    ogx->pipe = session->pipe;
    ogx->file_ctx.msg_buf.alloc_buf = NULL;
    ogx->file_ctx.msg_buf.aligned_buf = NULL;
    ogx->cmp_ctx.compress_buf.alloc_buf = NULL;
    ogx->cmp_ctx.compress_buf.aligned_buf = NULL;
    ogx->file_ctx.handle = INVALID_FILE_HANDLE;
}

static void srv_clear_lftc_ctx(lftc_srv_ctx_t *ogx)
{
    cm_close_file(ogx->file_ctx.handle);
    ogx->file_ctx.handle = INVALID_FILE_HANDLE;

    cm_aligned_free(&ogx->file_ctx.msg_buf);
    cm_aligned_free(&ogx->cmp_ctx.compress_buf);
    CM_FREE_PTR(ogx);
}

static void srv_process_lrcv_host(lrcv_context_t *lrcv, text_t *host_text)
{
    lrcv->host_changed = OG_TRUE;
    uint32 host_len = (uint32)strlen(lrcv->primary_host);
    errno_t err;

    if (host_len == 0 || (host_len == host_text->len && strncmp(host_text->str, lrcv->primary_host, host_len) == 0)) {
        lrcv->host_changed = OG_FALSE;
    }

    err = strncpy_s(lrcv->primary_host, OG_HOST_NAME_BUFFER_SIZE, host_text->str, host_text->len);
    knl_securec_check(err);
}

static status_t srv_init_lrcv_ctx(session_t *session, text_t *host_text)
{
    agent_t *agent = session->agent;
    knl_session_t *knl_session = &session->knl_session;
    lrcv_context_t *ogx = &knl_session->kernel->lrcv_ctx;
    database_t *db = &knl_session->kernel->db;

    if (DB_IS_PRIMARY(db)) {
        if (db->status != DB_STATUS_NOMOUNT) {
            OG_THROW_ERROR(ERR_DATABASE_ALREADY_MOUNT);
            return OG_ERROR;
        }
    } else {
        if (knl_failover_triggered(session->knl_session.kernel)) {
            OG_THROW_ERROR(ERR_FAILOVER_IN_PROGRESS);
            return OG_ERROR;
        }
    }

    if (lrcv_buf_alloc(&session->knl_session, ogx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    srv_process_lrcv_host(ogx, host_text);

    ogx->sid = knl_session->id;
    ogx->thread = agent->thread;
    ogx->session = knl_session;
    ogx->pipe = session->pipe;
    ogx->send_pack = session->send_pack;
    ogx->recv_pack = session->recv_pack;
    ogx->timeout = knl_session->kernel->attr.repl_wait_timeout;
    ogx->state = REP_STATE_NORMAL;

    return OG_SUCCESS;
}

static status_t srv_replica_prepare_lrcv(session_t *session, text_t *host_text)
{
    knl_instance_t *kernel = (knl_instance_t *)session->knl_session.kernel;
    lrcv_context_t *ogx = &kernel->lrcv_ctx;

    if (!cm_spin_try_lock(&ogx->lock)) {
        OG_THROW_ERROR(ERR_DB_TOO_MANY_PRIMARY, "can not start log receiver thread concurrently");
        return OG_ERROR;
    }

    if (ogx->session != NULL) {
        cm_spin_unlock(&ogx->lock);
        if (DB_IS_CASCADED_PHYSICAL_STANDBY(&kernel->db) && ogx->status > LRCV_DISCONNECTED) {
            OG_THROW_ERROR(ERR_CASCADED_STANDBY_CONNECTED);
        } else {
            OG_THROW_ERROR(ERR_DB_TOO_MANY_PRIMARY, "another primary database has connected");
        }
        return OG_ERROR;
    }

    if (srv_init_lrcv_ctx(session, host_text) != OG_SUCCESS) {
        cm_spin_unlock(&ogx->lock);
        return OG_ERROR;
    }

    cm_spin_unlock(&ogx->lock);
    return OG_SUCCESS;
}

static status_t srv_get_converted_host(const char *src_host, char *dest_host, uint32 size)
{
    char ipstr[CM_MAX_IP_LEN];
    sock_addr_t sock_addr;

    OG_RETURN_IFERR(cm_ipport_to_sockaddr(src_host, 0, &sock_addr));
    MEMS_RETURN_IFERR(strncpy_s(dest_host, size, cm_inet_ntop((struct sockaddr *)&sock_addr.addr, ipstr, CM_MAX_IP_LEN),
        OG_HOST_NAME_BUFFER_SIZE - 1));

    return OG_SUCCESS;
}

static status_t srv_check_remote_host(session_t *session, text_t *host_text)
{
    arch_attr_t *log_attr = NULL;
    char ipstr[CM_MAX_IP_LEN];
    char service_host[OG_HOST_NAME_BUFFER_SIZE] = { 0 };
    char *trust_host = g_instance->kernel.attr.repl_trust_host;
    bool32 received_peer_host = OG_TRUE;

    if (host_text->len == 0) {
        received_peer_host = OG_FALSE;
        MEMS_RETURN_IFERR(strncpy_s(host_text->str, OG_HOST_NAME_BUFFER_SIZE,
            cm_inet_ntop((struct sockaddr *)&session->pipe->link.tcp.remote.addr, ipstr, CM_MAX_IP_LEN),
            OG_HOST_NAME_BUFFER_SIZE - 1));
        host_text->len = (uint32)strlen(host_text->str);
    }

    for (int i = 0; i <= OG_MAX_PHYSICAL_STANDBY; i++) {
        log_attr = &g_instance->kernel.attr.arch_attr[i];
        if (log_attr->used && log_attr->dest_mode == LOG_ARCH_DEST_SERVICE) {
            if (!received_peer_host) {
                OG_RETURN_IFERR(srv_get_converted_host(log_attr->service.host, service_host, OG_HOST_NAME_BUFFER_SIZE));
            } else {
                MEMS_RETURN_IFERR(strncpy_s(service_host, OG_HOST_NAME_BUFFER_SIZE, log_attr->service.host,
                    strlen(log_attr->service.host)));
            }
            if (cm_strcmpni(host_text->str, service_host, OG_HOST_NAME_BUFFER_SIZE) == 0) {
                return OG_SUCCESS;
            }
        }
    }

    if (cm_strnstri(trust_host, (uint32)strlen(trust_host), host_text->str, host_text->len) != NULL) {
        return OG_SUCCESS;
    }

    OG_LOG_DEBUG_ERR("Replica agent error, remote ip [%s] not configured in archive destination, nor in trust hosts",
        host_text->str);
    OG_THROW_ERROR(ERR_REPLICA_AGENT, host_text->str);
    return OG_ERROR;
}

static inline status_t srv_check_repl_type(session_t *session, const char *user, replica_type_t *replica_type,
    text_t *host_text)
{
    if (!strncmp(user, "REP_LOGIN_REPL", OG_NAME_BUFFER_SIZE)) {
        OG_RETURN_IFERR(srv_replica_prepare_lrcv(session, host_text));
        *replica_type = REPLICA_LRCV;
        return OG_SUCCESS;
    }

    if (!strncmp(user, "REP_LOGIN_FAL", OG_NAME_BUFFER_SIZE)) {
        *replica_type = REPLICA_LFTC;
        return OG_SUCCESS;
    }

    if (!strncmp(user, "REP_LOGIN_BACKUP", OG_NAME_BUFFER_SIZE)) {
        *replica_type = REPLICA_BACKUP;
        return OG_SUCCESS;
    }

    OG_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
    return OG_ERROR;
}

static inline status_t srv_replica_wait_msg(session_t *session, date_t logon_time)
{
    bool32 ready = OG_FALSE;
    uint32 time_elapsed;

    do {
        time_elapsed = (uint32)((g_timer()->now - logon_time) / MICROSECS_PER_SECOND);
        if (time_elapsed >= g_instance->session_pool.unauth_session_expire_time || session->knl_session.killed) {
            OG_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(srv_process_single_session_cs_wait(session, &ready));
    } while (!ready && !session->agent->thread.closed);

    return OG_SUCCESS;
}

static status_t srv_repl_check_passwd_file(session_t *session, dc_user_t *dc_user, text_t *password)
{
    uint32 len;
    text_t text;
    salt_cipher_t salt_cipher;
    char scramble_buf[OG_ENCRYPTION_SIZE];
    uchar decode_buf[OG_ENCRYPTION_SIZE];
    uchar s_plain_pwd[OG_PASSWORD_BUFFER_SIZE];
    SENSI_INFO char c_plain_pwd[OG_PASSWORD_BUFFER_SIZE];
    uchar salted_pwd[OG_SCRAM256KEYSIZE];
    char pwd_cipher[OG_PASSWORD_BUFFER_SIZE];
    scram_data_t *scram_data = NULL;

    text.str = (char *)scramble_buf;
    text.len = 0;

    MEMS_RETURN_IFERR(memcpy_s(text.str, sizeof(scramble_buf), session->challenge, OG_SCRAM256KEYSIZE));
    text.len += OG_SCRAM256KEYSIZE;

    len = cm_base64_decode(dc_user->desc.password, OG_PASSWORD_BUFFER_SIZE, s_plain_pwd, OG_PASSWORD_BUFFER_SIZE);
    if (len != OG_SCRAM256MAXSIZE) {
        return OG_ERROR;
    }

    scram_data = (scram_data_t *)s_plain_pwd;

    MEMS_RETURN_IFERR(
        memcpy_s(text.str + text.len, sizeof(scramble_buf) - text.len, scram_data->salt, OG_KDF2SALTSIZE));
    text.len += OG_KDF2SALTSIZE;

    if (cm_pwd_fetch_plain(g_instance->home, c_plain_pwd, sizeof(c_plain_pwd)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (knl_try_update_repl_cipher(&session->knl_session, c_plain_pwd) != OG_SUCCESS) {
        return OG_ERROR;
    }

    salt_cipher.salted_pwd = salted_pwd;
    salt_cipher.salted_pwd_len = sizeof(salted_pwd);
    salt_cipher.cipher = pwd_cipher;
    salt_cipher.cipher_len = sizeof(pwd_cipher);
    if (knl_encrypt_login_passwd(c_plain_pwd, &text, CM_GET_ITERATION(scram_data), &salt_cipher) != OG_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(c_plain_pwd, sizeof(c_plain_pwd), 0, sizeof(c_plain_pwd)));
        return OG_ERROR;
    }
    pwd_cipher[salt_cipher.cipher_len] = '\0';

    MEMS_RETURN_IFERR(memset_s(c_plain_pwd, sizeof(c_plain_pwd), 0, sizeof(c_plain_pwd)));

    len = cm_base64_decode(pwd_cipher, (uint32)strlen(pwd_cipher), decode_buf, OG_ENCRYPTION_SIZE);
    if (len == 0 || len != password->len) {
        return OG_ERROR;
    }

    if (memcmp(decode_buf, password->str, len) != 0) {
        return OG_ERROR;
    }

    /* update server_key */
    uint32 server_key_len = sizeof(session->server_key);
    if (cm_encrypt_HMAC(salted_pwd, salt_cipher.salted_pwd_len, (uchar *)OG_SERVER_KEY, (uint32)strlen(OG_SERVER_KEY),
        session->server_key, &server_key_len) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t srv_repl_check_passwd(session_t *session, text_t *password)
{
    dc_user_t *user = NULL;
    text_t plain_user_name;

    cm_str2text(session->db_user, &plain_user_name);

    if (dc_open_user_direct(&session->knl_session, &plain_user_name, &user) != OG_SUCCESS) {
        cm_reset_error();
        return OG_ERROR;
    }

    /* Check the cipher file */
    if (srv_repl_check_passwd_file(session, user, password) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Replica agent check failed from cipher file");
        return OG_ERROR;
    }

    OG_LOG_DEBUG_INF("Replica agent check successfully from cipher file");
    return OG_SUCCESS;
}

static status_t srv_process_replauth_login(session_t *session, replica_type_t *replica_type, text_t *host_text)
{
    text_t text;
    text_t cipher_text;
    char password[OG_PASSWORD_BUFFER_SIZE];
    char repl_name[OG_NAME_BUFFER_SIZE];
    uchar server_sign[OG_HMAC256MAXSIZE];
    cs_packet_t *recv_pack = NULL;
    cs_packet_t *send_pack = NULL;

    CM_POINTER(session);
    session->sql_audit.action = SQL_AUDIT_ACTION_LOGIN;
    session->is_auth = OG_FALSE;
    recv_pack = &session->agent->recv_pack;
    send_pack = &session->agent->send_pack;

    /* 1. user */
    OG_RETURN_IFERR(cs_get_text(recv_pack, &text));
    OG_RETURN_IFERR(cm_text2str(&text, session->db_user, sizeof(session->db_user)));

    /* 2. pwd */
    OG_RETURN_IFERR(cs_get_text(recv_pack, &text));
    OG_RETURN_IFERR(cm_text2str(&text, password, sizeof(password)));

    /* 3. repl name */
    OG_RETURN_IFERR(cs_get_text(recv_pack, &text));
    OG_RETURN_IFERR(cm_text2str(&text, repl_name, sizeof(repl_name)));

    /* Support pwd encryption since v2 */
    cm_str_upper(session->db_user);
    cipher_text.str = password;
    cipher_text.len = sizeof(password);
    if (srv_check_challenge(session, password, (uchar *)cipher_text.str, &cipher_text.len) != OG_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(password, sizeof(password), 0, sizeof(password)));
        OG_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return OG_ERROR;
    }

    /* Check password */
    if (srv_repl_check_passwd(session, &cipher_text) != OG_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(password, sizeof(password), 0, sizeof(password)));
        OG_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(password, sizeof(password), 0, sizeof(password)));

    if (srv_check_repl_type(session, repl_name, replica_type, host_text) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cs_get_version(&session->agent->recv_pack) < CS_VERSION_19) {
        return OG_SUCCESS;
    }

    /* server signature */
    uint32 key_len = sizeof(server_sign);
    if (cm_encrypt_HMAC(session->server_key, OG_HMAC256MAXSIZE, session->challenge, sizeof(session->challenge),
        server_sign, &key_len) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return OG_ERROR;
    }
    text.str = (char *)server_sign;
    text.len = key_len;
    OG_RETURN_IFERR(cs_put_text(send_pack, &text));

    return OG_SUCCESS;
}

static status_t srv_replica_process_login_cmd(session_t *session, replica_type_t *replica_type, text_t *host_text)
{
    text_t text;
    text_t tenant_text;
    dc_tenant_t *tenant = NULL;

    cs_init_get(&session->agent->recv_pack);
    cs_init_set(&session->agent->send_pack, CS_LOCAL_VERSION);

    if ((uint32)session->agent->recv_pack.head->cmd == CS_CMD_REP_LOGIN) {
        if (g_instance->kernel.attr.repl_auth) {
            OG_LOG_DEBUG_ERR("repl_auth is set, user and passwd authentication is required");
            OG_THROW_ERROR(ERR_CLT_INVALID_ATTR, "repl auth", "true (check user and passwd in replication)");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(cs_get_text(&session->agent->recv_pack, &text));
        OG_RETURN_IFERR(cm_text2str(&text, session->db_user, sizeof(session->db_user)));
        if (cm_strchr(&text, '$') != NULL) {
            (void)cm_fetch_text(&text, '$', 0, &tenant_text);
            OG_RETURN_IFERR(cm_text2str(&tenant_text, session->curr_tenant, sizeof(session->curr_tenant)));
            OG_RETURN_IFERR(dc_open_tenant(&session->knl_session, &tenant_text, &tenant));
            session->curr_tenant_id = tenant->desc.id;
            dc_close_tenant(&session->knl_session, tenant->desc.id);
        } else {
            OG_RETURN_IFERR(cm_text2str(&g_tenantroot, session->curr_tenant, sizeof(session->curr_tenant)));
            session->curr_tenant_id = SYS_TENANTROOT_ID;
        }
        session->sql_audit.action = SQL_AUDIT_ACTION_LOGIN;
        OG_RETURN_IFERR(srv_check_repl_type(session, session->db_user, replica_type, host_text));
    } else if ((uint32)session->agent->recv_pack.head->cmd == CS_CMD_REPAUTH_LOGIN) {
        if (cs_get_version(&session->agent->recv_pack) < CS_VERSION_19 && g_instance->kernel.attr.repl_scram_auth) {
            OG_LOG_DEBUG_ERR("SCRAM authentication is required, but peer node does not support it");
            OG_THROW_ERROR(ERR_UNSUPPORT_FUNC, "SCRAM authentication is", "on peer node");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(srv_process_replauth_login(session, replica_type, host_text));
    } else {
        OG_LOG_DEBUG_ERR("Replica agent error, command is not repl login");
        OG_THROW_ERROR(ERR_REPL_PORT_ACCESS);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t srv_replica_process_host_cmd(session_t *session, text_t *host_text)
{
    host_text->len = 0;

    if ((uint32)session->agent->recv_pack.head->cmd == CS_CMD_REPL_HOST) {
        text_t text;

        cs_init_get(&session->agent->recv_pack);
        cs_init_set(&session->agent->send_pack, CS_LOCAL_VERSION);
        OG_RETURN_IFERR(cs_get_text(&session->agent->recv_pack, &text));

        if (text.len > 0) {
            MEMS_RETURN_IFERR(strncpy_s(host_text->str, OG_HOST_NAME_BUFFER_SIZE, text.str, text.len));
            host_text->len = text.len;
        }
        OG_RETURN_IFERR(srv_return_success(session));
        OG_RETURN_IFERR(srv_replica_wait_msg(session, g_timer()->now));
        OG_RETURN_IFERR(cs_read(session->pipe, &session->agent->recv_pack, OG_TRUE));
    }
    return OG_SUCCESS;
}

static status_t srv_replica_process_login(session_t *session, replica_type_t *replica_type)
{
    char peer_host[OG_HOST_NAME_BUFFER_SIZE] = { 0 };
    text_t text;
    cm_str2text(peer_host, &text);
    bool32 repl_auth = OG_FALSE;

    session->is_auth = OG_FALSE;
    session->sender = &g_instance->sql.sender;

    sql_audit_init(&session->sql_audit);

    OG_RETURN_IFERR(srv_replica_wait_msg(session, g_timer()->now));
    OG_RETURN_IFERR(srv_diag_proto_type(session));

    OG_RETURN_IFERR(srv_replica_wait_msg(session, g_timer()->now));
    OG_RETURN_IFERR(cs_read(session->pipe, &session->agent->recv_pack, OG_TRUE));

    // check repl_auth
    if ((uint32)session->agent->recv_pack.head->cmd == CS_CMD_AUTH_CHECK) {
        cs_init_get(&session->agent->recv_pack);
        cs_init_set(&session->agent->send_pack, CS_LOCAL_VERSION);
        OG_RETURN_IFERR(cs_get_int32(&session->agent->recv_pack, (int32 *)&repl_auth));
        if (g_instance->kernel.attr.repl_auth != repl_auth) {
            OG_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
            return OG_ERROR;
        }

        OG_RETURN_IFERR(srv_return_success(session));
        OG_RETURN_IFERR(srv_replica_wait_msg(session, g_timer()->now));
        OG_RETURN_IFERR(cs_read(session->pipe, &session->agent->recv_pack, OG_TRUE));
    }

    // process handshake
    cs_init_get(&session->agent->recv_pack);
    cs_init_set(&session->agent->send_pack, CS_LOCAL_VERSION);
    if ((uint32)session->agent->recv_pack.head->cmd != CS_CMD_HANDSHAKE) {
        OG_LOG_DEBUG_ERR("Replica agent error, first command is not handshake");
        OG_THROW_ERROR(ERR_ACCOUNT_AUTH_FAILED);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(srv_process_handshake(session));
    OG_RETURN_IFERR(srv_return_success(session));

    OG_RETURN_IFERR(srv_replica_wait_msg(session, g_timer()->now));
    OG_RETURN_IFERR(cs_read(session->pipe, &session->agent->recv_pack, OG_TRUE));

    // process auth_init
    if ((uint32)session->agent->recv_pack.head->cmd == CS_CMD_AUTH_INIT) {
        cs_init_get(&session->agent->recv_pack);
        cs_init_set(&session->agent->send_pack, CS_LOCAL_VERSION);
        OG_RETURN_IFERR(srv_process_auth_init(session));
        OG_RETURN_IFERR(srv_return_success(session));
        OG_RETURN_IFERR(srv_replica_wait_msg(session, g_timer()->now));
        OG_RETURN_IFERR(cs_read(session->pipe, &session->agent->recv_pack, OG_TRUE));
    }

    // process peer local host
    OG_RETURN_IFERR(srv_replica_process_host_cmd(session, &text));
    OG_RETURN_IFERR(srv_check_remote_host(session, &text));

    OG_RETURN_IFERR(srv_replica_process_login_cmd(session, replica_type, &text));

    session->is_auth = OG_TRUE;
    session->auth_status = AUTH_STATUS_LOGON;

    return OG_SUCCESS;
}

static void srv_replica_thread_exit(thread_t *thread, session_t *session)
{
    OG_LOG_DEBUG_INF("replica thread closed");
    agent_t *agent = session->agent;
    cm_release_thread(thread);
    srv_unbind_sess_agent(session, agent);
    srv_release_session(session);
    srv_free_agent_res(agent, OG_TRUE);
    CM_FREE_PTR(agent);
}

static void srv_replica_proc(agent_t *agent, replica_type_t replica_type)
{
    lftc_srv_ctx_t *lftc_ctx = NULL;

    switch (replica_type) {
        case REPLICA_LRCV:
            if (lrcv_proc(&g_instance->kernel.lrcv_ctx) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Log receiver server error, thread exit");
            }
            srv_clear_lrcv_ctx(&g_instance->kernel.lrcv_ctx);
            break;
        case REPLICA_LFTC:
            OG_BREAK_IF_ERROR(lftc_srv_ctx_alloc(&lftc_ctx));
            srv_init_lftc_ctx(agent->session, lftc_ctx);
            if (lftc_srv_proc(&agent->session->knl_session, lftc_ctx) != OG_SUCCESS) {
                OG_LOG_RUN_WAR("LFTC server error, thread exit");
            }
            srv_clear_lftc_ctx(lftc_ctx);
            break;
        case REPLICA_BACKUP:
            if (bak_build_backup(&agent->session->knl_session, agent->session->pipe, &agent->send_pack,
                &agent->recv_pack) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Remote backup failed, thread exit");
            }
            break;
        default:
            break;
    }
}

static void srv_replica_agent_entry(thread_t *thread)
{
    replica_type_t replica_type = REPLICA_INVALID;
    agent_t *agent = (agent_t *)thread->argument;
    session_t *session = agent->session;

    session->knl_session.status = SESSION_ACTIVE;
    session->knl_session.canceled = OG_FALSE;
    session->knl_session.spid = cm_get_current_thread_id();

    cs_init_packet(&agent->recv_pack, OG_FALSE);
    cs_init_packet(&agent->send_pack, OG_FALSE);
    cs_init_get(&agent->recv_pack);
    cs_init_set(&agent->send_pack, CS_LOCAL_VERSION);

    if (srv_replica_process_login(session, &replica_type) != OG_SUCCESS) {
        if (replica_type == REPLICA_LRCV) {
            srv_clear_lrcv_ctx(&g_instance->kernel.lrcv_ctx);
        }
        (void)srv_return_error(session);
        srv_replica_thread_exit(thread, session);
        return;
    }

    if (srv_return_success(session) != OG_SUCCESS) {
        if (replica_type == REPLICA_LRCV) {
            srv_clear_lrcv_ctx(&g_instance->kernel.lrcv_ctx);
        }
        srv_replica_thread_exit(thread, session);
        return;
    }

    srv_replica_proc(agent, replica_type);
    srv_replica_thread_exit(thread, session);
}

static status_t srv_set_replhost_with_lsnrhost(void)
{
    text_t name_text;
    config_item_t *item = NULL;
    tcp_lsnr_t *lsnr = &g_instance->lsnr.tcp_service;
    tcp_lsnr_t *repl = &g_instance->lsnr.tcp_replica;

    cm_str2text("REPL_ADDR", &name_text);
    item = cm_get_config_item(&g_instance->config, &name_text, OG_FALSE);
    if (item == NULL) {
        return OG_ERROR;
    }

    if (strlen(item->runtime_value) != 0) {
        return OG_SUCCESS;
    }

    for (int32 i = 0; i < OG_MAX_LSNR_HOST_COUNT; i++) {
        if (lsnr->socks[i] == CS_INVALID_SOCKET) {
            repl->host[i][0] = '\0';
            continue;
        }

        MEMS_RETURN_IFERR(strncpy_s(repl->host[i], CM_MAX_IP_LEN, lsnr->host[i], strlen(lsnr->host[i])));
    }

    return OG_SUCCESS;
}

status_t srv_modify_replica(handle_t session, text_t *host, uint16 replica_port, char ip_arr[][CM_MAX_IP_LEN])
{
    tcp_lsnr_t *repl = &g_instance->lsnr.tcp_replica;
    char old_host[OG_MAX_LSNR_HOST_COUNT][CM_MAX_IP_LEN] = { 0 };
    uint16 old_port = repl->port;
    bool32 old_repl_off = repl->thread.closed;
    knl_session_t *se = &((session_t *)session)->knl_session;
    database_t *db = &se->kernel->db;

    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        OG_LOG_RUN_WAR("modify repl only works in mount or open state.");
        return OG_ERROR;
    }

    if (!old_repl_off) {
        srv_stop_lsnr(LSNR_TYPE_REPLICA);
        lsnd_close_all_thread(se);
        for (int32 i = 0; i < OG_MAX_LSNR_HOST_COUNT; i++) {
            MEMS_RETURN_IFERR(strncpy_s(old_host[i], CM_MAX_IP_LEN, repl->host[i], strlen(repl->host[i])));
        }
    }

    if (host->len != 0) {
        for (int32 i = 0; i < OG_MAX_LSNR_HOST_COUNT; i++) {
            repl->host[i][0] = '\0';
            MEMS_RETURN_IFERR(strncpy_s(repl->host[i], CM_MAX_IP_LEN, ip_arr[i], strlen(ip_arr[i])));
        }
    } else {
        OG_RETURN_IFERR(srv_set_replhost_with_lsnrhost());
    }
    repl->port = replica_port;

    if (srv_start_replica_lsnr() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("failed to start repl lsnr on port : %u", repl->port);
        if (!old_repl_off) {
            for (int32 i = 0; i < OG_MAX_LSNR_HOST_COUNT; i++) {
                MEMS_RETURN_IFERR(strncpy_s(repl->host[i], CM_MAX_IP_LEN, old_host[i], strlen(old_host[i])));
            }
            repl->port = old_port;
            if (srv_start_replica_lsnr() != OG_SUCCESS) {
                OG_LOG_RUN_ERR("failed to restart repl lsnr on port : %u", repl->port);
            }
        }
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

void srv_stop_replica(handle_t session)
{
    knl_session_t *se = &((session_t *)session)->knl_session;

    srv_stop_lsnr(LSNR_TYPE_REPLICA);
    lsnd_close_all_thread(se);
}

status_t srv_create_replica_session(cs_pipe_t *cs_pipe)
{
    session_t *session = NULL;
    uint32 stack_size;
    status_t status;
    errno_t rc_memzero;

    if (!g_instance->kernel.is_ssl_initialized) {
        OG_LOG_DEBUG_ERR("ssl has not been initialized, replica session can not be created temporarily");
        return OG_ERROR;
    }

    stack_size = (uint32)g_instance->kernel.attr.thread_stack_size;

    agent_t *agent = (agent_t *)malloc(sizeof(agent_t));
    if (agent == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(agent_t), "replcia agent");
        return OG_ERROR;
    }

    rc_memzero = memset_s(agent, sizeof(agent_t), 0, sizeof(agent_t));
    if (rc_memzero != EOK) {
        CM_FREE_PTR(agent);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (rc_memzero));
        return OG_ERROR;
    }

    agent->session = NULL;

    do {
        status = srv_alloc_agent_res(agent);
        OG_BREAK_IF_ERROR(status);

        status = srv_alloc_session(&session, cs_pipe, SESSION_TYPE_REPLICA);
        OG_BREAK_IF_ERROR(status);

        (void)cm_inet_ntop((struct sockaddr *)&cs_pipe->link.tcp.remote.addr, session->os_host,
            OG_HOST_NAME_BUFFER_SIZE);
        srv_bind_sess_agent(session, agent);

        status = cm_create_thread(srv_replica_agent_entry, stack_size, agent, &agent->thread);
        OG_BREAK_IF_ERROR(status);
    } while (0);

    if (status == OG_SUCCESS) {
        return OG_SUCCESS;
    }

    if (session != NULL) {
        srv_unbind_sess_agent(session, agent);
        srv_release_session(session);
    }
    srv_free_agent_res(agent, OG_TRUE);
    CM_FREE_PTR(agent);
    return OG_ERROR;
}
