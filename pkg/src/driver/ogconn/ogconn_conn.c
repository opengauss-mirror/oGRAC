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
 * ogconn_conn.c
 *
 *
 * IDENTIFICATION
 * src/driver/ogconn/ogconn_conn.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogconn_conn.h"
#include "ogconn_balance.h"
#include "ogconn_stmt.h"
#include "ogconn_fetch.h"
#include "ogconn_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Used in free sensitive info string */
#define securec_free(m)                                              \
    do {                                                             \
        if ((m) != NULL) {                                           \
            errno_t rc_memzero = EOK;                                \
            if (strlen(m) > 0) {                                     \
                rc_memzero = memset_s((m), strlen(m), 0, strlen(m)); \
            }                                                        \
            free(m);                                                 \
            (m) = NULL;                                              \
            MEMS_RETURN_IFERR(rc_memzero);                           \
        }                                                            \
    } while (0)

static status_t clt_query(clt_conn_t *conn, const text_t *sql);
static status_t clt_get_conn_attr(clt_conn_t *conn, int32 attr, void *data, uint32 len, uint32 *attr_len);
static inline void clt_load_default_options(clt_options_t *options)
{
    MEMS_RETVOID_IFERR(memset_s(options, sizeof(clt_options_t), 0, sizeof(clt_options_t)));
    options->connect_timeout = (int32)OG_CONNECT_TIMEOUT / OG_TIME_THOUSAND;
    options->socket_timeout = -1;
    options->l_onoff = 1;
    options->l_linger = 1;

    // Enable SSL by default
    options->ssl_mode = OGCONN_SSL_PREFERRED;
    options->client_flag = CS_FLAG_CLIENT_SSL;
}

status_t ogconn_alloc_conn(ogconn_conn_t *pconn)
{
    clt_conn_t **conn = (clt_conn_t **)pconn;
    uint32 malloc_len = sizeof(clt_conn_t);
    clt_conn_t *connection = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    connection = (clt_conn_t *)malloc(malloc_len);
    if (connection == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)malloc_len, "new connection");
        return OG_ERROR;
    }

    errno_t rc_memzero = memset_s(connection, malloc_len, 0, malloc_len);
    if (rc_memzero != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        free(connection);
        return OG_ERROR;
    }

    cm_ptlist_init(&connection->stmts);
    cm_create_list(&connection->query.ids, sizeof(uint32));

    clt_load_default_options(&connection->options);
    cm_init_session_nlsparams(&connection->nls_params);
    connection->exit_commit = OG_TRUE;
    connection->num_width = (uint32)OG_MAX_DEC_OUTPUT_PREC;
    connection->local_charset = OG_DEFAULT_LOCAL_CHARSET;
    connection->server_version = CS_LOCAL_VERSION;
    connection->call_version = CS_LOCAL_VERSION;
    connection->options.app_kind = (uint16)CLIENT_KIND_CTCONN_GENERIC;
    connection->shd_rw_split = OGCONN_SHD_RW_SPLIT_NONE;
    connection->server_info.server_max_pack_size = OG_MAX_ALLOWED_PACKET_SIZE;
    cm_create_list2(&connection->pack_list, CLT_CONN_PACK_EXTEND_STEP, MAX_LIST_EXTENTS, sizeof(clt_packet_t));

    connection->pipe.connect_timeout = (int32)OG_CONNECT_TIMEOUT;
    connection->pipe.socket_timeout = -1;
    connection->pipe.l_onoff = 1;
    connection->pipe.l_linger = 1;
    connection->pipe.link.tcp.sock = CS_INVALID_SOCKET;
    connection->pipe.link.tcp.closed = OG_TRUE;
    connection->pipe.link.ssl.tcp.sock = CS_INVALID_SOCKET;
    connection->pipe.link.ssl.tcp.closed = OG_TRUE;

    connection->alter_set_info.commit_batch = OG_INVALID_ID16;
    connection->alter_set_info.commit_nowait = OG_INVALID_ID16;
    connection->alter_set_info.lock_wait_timeout = OG_INVALID_ID32;
    connection->alter_set_info.nologging_enable = OG_INVALID_ID8;

    *conn = connection;
    return OG_SUCCESS;
}

static void clt_disconnect(clt_conn_t *conn)
{
    uint32 i;
    clt_stmt_t *stmt = NULL;

    decrease_cluster_count(conn);

    for (i = 0; i < conn->stmts.count; i++) {
        stmt = (clt_stmt_t *)cm_ptlist_get(&conn->stmts, i);
        if (stmt != NULL) {
            clt_free_stmt(stmt);
        }
    }

    // query_stmt != NULL already free it in conn->stmts
    conn->query.query_stmt = NULL;
    conn->query.pos = 0;

    if (conn->ready) {
        // logout
        cs_packet_t *req_pack = &(conn->pack);
        cs_init_set(req_pack, conn->call_version);
        req_pack->head->cmd = CS_CMD_LOGOUT;
        (void)clt_remote_call(conn, req_pack, req_pack);
        conn->ready = OG_FALSE;
        conn->server_version = CS_LOCAL_VERSION;
        conn->call_version = CS_LOCAL_VERSION;
    }

    cs_try_free_packet_buffer(&conn->pack);

    cs_disconnect(&conn->pipe);
    CM_FREE_PTR(conn->options.user);
    CM_FREE_PTR(conn->options.host);
    CM_FREE_PTR(conn->options.server_path);
    CM_FREE_PTR(conn->options.client_path);
}

void ogconn_disconnect(ogconn_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;

    if (SECUREC_UNLIKELY(conn == NULL)) {
        OG_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "connection");
        return;
    }

    OG_RETVOID_IFERR(clt_lock_conn(conn));
    clt_disconnect(conn);
    clt_unlock_conn(conn);
    return;
}

static void clt_ssl_free(clt_conn_t *conn)
{
    if (conn->ssl_connector != NULL) {
        cs_ssl_free_context((ssl_ctx_t *)conn->ssl_connector);
        conn->ssl_connector = NULL;
    }

    CM_FREE_PTR(conn->options.ssl_ca);
    CM_FREE_PTR(conn->options.ssl_cert);
    CM_FREE_PTR(conn->options.ssl_key);

    if (conn->options.ssl_keypwd != NULL) {
        size_t len = strlen(conn->options.ssl_keypwd);
        errno_t rc_memzero = memset_s(conn->options.ssl_keypwd, len, 0, len);
        if (rc_memzero != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        }
        CM_FREE_PTR(conn->options.ssl_keypwd);
    }

    CM_FREE_PTR(conn->options.ssl_crl);
    CM_FREE_PTR(conn->options.ssl_cipher);
}

static void clt_free_pack_list(clt_conn_t *conn)
{
    for (uint32 i = 0; i < conn->pack_list.count; i++) {
        clt_packet_t *clt_pack = (clt_packet_t *)cm_list_get(&conn->pack_list, i);
        cs_try_free_packet_buffer(&clt_pack->pack);
    }
    cm_destroy_list(&conn->pack_list);
}

static void clt_free_conn(clt_conn_t *conn)
{
    if (conn->ready == OG_TRUE) {
        clt_disconnect(conn);
    }

    cm_destroy_ptlist(&conn->stmts);
    cm_destroy_list(&conn->query.ids);
    clt_ssl_free(conn);
    clt_free_pack_list(conn);
    CM_FREE_PTR(conn->options.server_path);
    CM_FREE_PTR(conn->options.client_path);
    CM_FREE_PTR(conn);
}

void ogconn_free_conn(ogconn_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;

    if (conn == NULL) {
        return;
    }

    if (clt_lock_conn(conn) != OG_SUCCESS) {
        return;
    }

    clt_free_conn(conn);
    return;
}

static status_t clt_update_conn_opt(clt_conn_t *conn, const char *url, const char *user)
{
    if (conn->pipe.type == CS_TYPE_TCP) {
        text_t text_url;
        text_t host_part;
        text_t port_part;
        cm_str2text((char *)url, &text_url);
        (void)cm_split_rtext(&text_url, ':', '\0', &host_part, &port_part);

        conn->options.user = clt_strdup(user);
        if (conn->options.user == NULL) {
            cs_disconnect(&conn->pipe);
            CLT_THROW_ERROR(conn, ERR_CLT_OBJECT_IS_NULL, "user");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(clt_strndup(host_part.str, host_part.len, &(conn->options.host)));
        if (conn->options.host == NULL) {
            cs_disconnect(&conn->pipe);
            CM_FREE_PTR(conn->options.user);
            CLT_THROW_ERROR(conn, ERR_CLT_OBJECT_IS_NULL, "host");
            return OG_ERROR;
        }

        if (cm_text2uint32(&port_part, &conn->options.port) != OG_SUCCESS) {
            cs_disconnect(&conn->pipe);
            CM_FREE_PTR(conn->options.user);
            CM_FREE_PTR(conn->options.host);
            return OG_ERROR;
        }
    }

    if (conn->pipe.type == CS_TYPE_DOMAIN_SCOKET) {
        conn->options.user = clt_strdup(user);
        if (conn->options.user == NULL) {
            cs_disconnect(&conn->pipe);
            CLT_THROW_ERROR(conn, ERR_CLT_OBJECT_IS_NULL, "user");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

/**
Check if SSL can be establishes.

@param  conn        the connection handle
@retval OG_SUCCESS  success
@retval OG_ERROR    failure
*/
static status_t clt_ssl_check(clt_conn_t *conn)
{
    conn->client_flag = conn->options.client_flag;
    if (conn->pipe.type == CS_TYPE_DOMAIN_SCOKET) {
        conn->client_flag &= ~CS_FLAG_CLIENT_SSL;
        return OG_SUCCESS;
    }
    /* Don't fallback on unencrypted connection if SSL required */
    if (conn->options.ssl_mode >= OGCONN_SSL_REQUIRED && !(conn->server_capabilities & CS_FLAG_CLIENT_SSL)) {
        CLT_THROW_ERROR(conn, ERR_SSL_NOT_SUPPORT);
        return OG_ERROR;
    }

    /*
    If the ssl_mode is VERIFY_CA or VERIFY_IDENTIFY, make sure that the
    connection doesn't succeed without providing the CA certificate.
    */
    if (conn->options.ssl_mode > OGCONN_SSL_REQUIRED && !conn->options.ssl_ca) {
        CLT_THROW_ERROR(conn, ERR_SSL_CA_REQUIRED);
        return OG_ERROR;
    }

    /*
    Attempt SSL connection if ssl_mode != OGCONN_SSL_DISABLED and the
    server supports SSL. Fallback on unencrypted connection otherwise.
    */
    if (conn->options.ssl_mode != OGCONN_SSL_DISABLED && (conn->server_capabilities & CS_FLAG_CLIENT_SSL)) {
        conn->client_flag |= CS_FLAG_CLIENT_SSL;
    } else {
        conn->client_flag &= ~CS_FLAG_CLIENT_SSL;
    }
    return OG_SUCCESS;
}

static status_t clt_remote_wait(clt_conn_t *conn)
{
    bool32 ready = OG_FALSE;
    cs_pipe_t *pipe = &conn->pipe;

    if (cs_wait(pipe, CS_WAIT_FOR_READ, OG_HANDSHAKE_TIMEOUT, &ready) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    if (!ready) {
        CLT_THROW_ERROR(conn, ERR_SOCKET_TIMEOUT, OG_HANDSHAKE_TIMEOUT / OG_TIME_THOUSAND_UN);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/**
Establishes SSL from a connected socket

@param  conn        the connection handle
@retval OG_SUCCESS  success
@retval OG_ERROR    failure
*/
static status_t clt_ssl_establish(clt_conn_t *conn)
{
    ssl_verify_t mode;
    ssl_config_t para;
    ssl_ctx_t *ssl_fd = NULL;
    const char *cert_err = NULL;
    clt_options_t *options = &conn->options;

    MEMS_RETURN_IFERR(memset_s(&para, sizeof(ssl_config_t), 0, sizeof(ssl_config_t)));

    para.ca_file = options->ssl_ca;
    para.cert_file = options->ssl_cert;
    para.key_file = options->ssl_key;
    para.crl_file = options->ssl_crl;
    para.key_password = options->ssl_keypwd;
    para.cipher = options->ssl_cipher;
    para.verify_peer = OG_TRUE;

    /* Check certificate file access permission */
    if (cs_ssl_verify_file_stat(para.ca_file) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }
    if (cs_ssl_verify_file_stat(para.cert_file) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }
    if (cs_ssl_verify_file_stat(para.key_file) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    if (cs_ssl_verify_file_stat(para.crl_file) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    /* Create the ssl connector - init SSL and load certs */
    ssl_fd = cs_ssl_create_connector_fd(&para);

    /* We should erase it for security issue */
    securec_free(options->ssl_keypwd);

    if (ssl_fd == NULL) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }
    conn->ssl_connector = (uchar *)ssl_fd;

    /* Connect to the server */
    if (cs_ssl_connect(ssl_fd, &conn->pipe) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    /* Verify server cert */
    if (options->ssl_mode > OGCONN_SSL_REQUIRED) {
        mode = (options->ssl_mode == OGCONN_SSL_VERIFY_CA) ? VERIFY_CERT : VERIFY_SUBJECT;
        if (cs_ssl_verify_certificate(&conn->pipe.link.ssl, mode, conn->options.host, &cert_err) != OG_SUCCESS) {
            CLT_THROW_ERROR(conn, ERR_SSL_VERIFY_CERT, cert_err);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t clt_send_auth_init(clt_conn_t *conn, const char *user, const char *tenant, const uchar *client_key,
    uint32 key_len, uint32 version)
{
    text_t text;
    cs_packet_t *send_pack = &conn->pack;

    cs_init_set(send_pack, version);
    send_pack->head->cmd = CS_CMD_AUTH_INIT;
    send_pack->head->flags = 0;
    if (conn->interactive_clt) {
        send_pack->head->flags |= CS_FLAG_INTERACTIVE_CLT;
    }
    if (conn->client_flag & CS_FLAG_CLIENT_SSL) {
        send_pack->head->flags |= CS_FLAG_CLIENT_SSL;
    }

    // 1. write username
    cm_str2text((char *)user, &text);
    OG_RETURN_IFERR(cs_put_text(send_pack, &text));
    // 2. write client_key
    cm_str2text_safe((char *)client_key, key_len, &text);
    OG_RETURN_IFERR(cs_put_text(send_pack, &text));

    // Attention: if add message in a higher version, please use conn->server_version
    if (conn->server_version >= CS_VERSION_18) {
        // 3. tenant name
        cm_str2text((char *)tenant, &text);
        OG_RETURN_IFERR(cs_put_text(send_pack, &text));
    }

    // send AUTH_INIT request
    if (cs_write(&conn->pipe, send_pack) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t clt_ssl_handshake_safe(clt_conn_t *conn, const char *user, const char *tenant, const uchar *client_key,
    uint32 key_len, uint32 version)
{
    uint32 ssl_notify;
    uint32 size;

    // tell server whether SSL channel is required
    OG_RETURN_IFERR(cs_put_int32(&conn->pack, conn->client_flag));
    if (cs_write(&conn->pipe, &conn->pack) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    if (conn->client_flag & CS_FLAG_CLIENT_SSL) {
        // wait for handshake notify
        if (clt_remote_wait(conn) != OG_SUCCESS) {
            return OG_ERROR;
        }
        // read handshake notify
        if (cs_read_bytes(&conn->pipe, (char *)&ssl_notify, sizeof(uint32), (int32 *)&size) != OG_SUCCESS) {
            clt_copy_local_error(conn);
            return OG_ERROR;
        }

        if (sizeof(ssl_notify) != size || ssl_notify == 0) {
            return OG_ERROR;
        }

        OG_RETURN_IFERR(clt_ssl_establish(conn));
    }

    // wait for handshake reply
    if (clt_remote_wait(conn) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // read handshake reply
    if (cs_read(&conn->pipe, &conn->pack, OG_TRUE) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    cs_init_get(&conn->pack);
    if (CS_HAS_EXEC_ERROR(&conn->pack)) {
        OG_RETURN_IFERR(cs_get_int32(&conn->pack, &conn->error_code));
        OG_RETURN_IFERR(cs_get_int16(&conn->pack, (int16 *)(&conn->loc.line)));
        OG_RETURN_IFERR(cs_get_int16(&conn->pack, (int16 *)(&conn->loc.column)));
        OG_RETURN_IFERR(clt_get_error_message(conn, &conn->pack, conn->message));
        return OG_ERROR;
    }

    // send auth_init request
    return clt_send_auth_init(conn, user, tenant, client_key, key_len, version);
}

static status_t clt_ssl_handshake(clt_conn_t *conn, const char *user, const uchar *client_key, uint32 key_len)
{
    text_t text;
    uint32 ssl_notify;
    uint32 size;

    // 1. write username
    cm_str2text((char *)user, &text);
    OG_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    // 2. write client_flag
    OG_RETURN_IFERR(cs_put_int32(&conn->pack, conn->client_flag));
    // 3. write client_key
    text.str = (char *)client_key;
    text.len = key_len;
    OG_RETURN_IFERR(cs_put_text(&conn->pack, &text));

    // send handshake packet
    if (cs_write(&conn->pipe, &conn->pack) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    // change to SSL layer if supported
    if (conn->client_flag & CS_FLAG_CLIENT_SSL) {
        // wait for handshake notify
        if (clt_remote_wait(conn) != OG_SUCCESS) {
            return OG_ERROR;
        }
        // read handshake notify
        if (cs_read_bytes(&conn->pipe, (char *)&ssl_notify, sizeof(uint32), (int32 *)&size) != OG_SUCCESS) {
            clt_copy_local_error(conn);
            return OG_ERROR;
        }

        if (sizeof(ssl_notify) != size || ssl_notify == 0) {
            return OG_ERROR;
        }

        OG_RETURN_IFERR(clt_ssl_establish(conn));
    }
    return OG_SUCCESS;
}

static status_t clt_encrypt_login_passwd(const char *plain_text, text_t *scramble_key, uint32 iter_count,
    uchar *salted_pwd, uint32 *salted_pwd_len, char *rsp_str, uint32 *rsp_len)
{
    uchar client_scram[2 * OG_MAX_CHALLENGE_LEN + OG_HMAC256MAXSIZE];
    uchar client_key[OG_HMAC256MAXSIZE];
    uchar stored_key[OG_HMAC256MAXSIZE];
    uchar client_sign[OG_HMAC256MAXSIZE];
    uint32 sign_key_len;
    uint32 key_len;
    uint32 stored_key_len;

    // verify scramble data
    sign_key_len = OG_MAX_CHALLENGE_LEN * 2;
    if ((scramble_key->len != sign_key_len + OG_KDF2SALTSIZE) || (*salted_pwd_len < OG_KDF2KEYSIZE)) {
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(
        memcpy_s(client_scram, 2 * OG_MAX_CHALLENGE_LEN + OG_HMAC256MAXSIZE, scramble_key->str, sign_key_len));

    // salted_pwd
    if (cm_encrypt_KDF2((uchar *)plain_text, (uint32)strlen(plain_text), (uchar *)(scramble_key->str + sign_key_len),
        OG_KDF2SALTSIZE, iter_count, salted_pwd, OG_KDF2KEYSIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    *salted_pwd_len = OG_KDF2KEYSIZE;

    // client_key
    key_len = OG_HMAC256MAXSIZE;
    if (cm_encrypt_HMAC(salted_pwd, OG_KDF2KEYSIZE, (uchar *)OG_CLIENT_KEY, (uint32)strlen(OG_CLIENT_KEY), client_key,
        &key_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    // stored_key
    stored_key_len = OG_HMAC256MAXSIZE;
    if (cm_generate_sha256(client_key, key_len, stored_key, &stored_key_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    // signature
    key_len = OG_HMAC256MAXSIZE;
    if (cm_encrypt_HMAC(stored_key, stored_key_len, (uchar *)scramble_key->str, sign_key_len, client_sign, &key_len) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }
    // generate client_proof
    for (uint32 i = 0; i < OG_HMAC256MAXSIZE; ++i) {
        client_scram[i + sign_key_len] = (uchar)(client_key[i] ^ client_sign[i]);
    }

    // encode client_proof with base64
    return cm_base64_encode(client_scram, sizeof(client_scram), rsp_str, rsp_len);
}

static status_t clt_do_login(clt_conn_t *conn, const char *user, const char *password, const char *tenant)
{
    text_t text;
    char proc[OG_BUFLEN_1K];

    // 1. user
    cm_str2text((char *)user, &text);
    OG_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    // 2. pwd
    cm_str2text((char *)password, &text);
    OG_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    // 3. hostname
    cm_str2text(cm_sys_host_name(), &text);
    OG_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    // 4. sys user
    cm_str2text(cm_sys_user_name(), &text);
    OG_RETURN_IFERR(cs_put_text(&conn->pack, &text));

    // 5. sys program
    PRTS_RETURN_IFERR(sprintf_s(proc, (OG_BUFLEN_1K - 1), "[%llu]%s", cm_sys_pid(), cm_sys_program_name()));

    cm_str2text(proc, &text);
    OG_RETURN_IFERR(cs_put_text(&conn->pack, &text));

    // 6. is_coord
    if (CS_IS_CN_CONNECTION(conn->pack.options)) {
        OG_RETURN_IFERR(cs_put_int16(&conn->pack, (uint16)CS_IS_CN_CONNECTION(conn->pack.options)));
    } else {
        OG_RETURN_IFERR(cs_put_int16(&conn->pack, (uint16)CS_IS_CN_IN_ALTER_PWD(conn->pack.options)));
    }

    // 7. timezone
    OG_RETURN_IFERR(cs_put_int16(&conn->pack, cm_get_local_tzoffset()));
    conn->local_sessiontz = cm_get_local_tzoffset();

    if (conn->call_version >= CS_VERSION_6) {
        // 8. client kind
        OG_RETURN_IFERR(cs_put_int16(&conn->pack, conn->options.app_kind));
    }

    if (conn->call_version >= CS_VERSION_12) {
        // 9. shard rw split flag
        OG_RETURN_IFERR(cs_put_int16(&conn->pack, (uint16)conn->shd_rw_split));
    }

    if (conn->call_version >= CS_VERSION_18) {
        // 10. tenant name
        cm_str2text((char *)tenant, &text);
        OG_RETURN_IFERR(cs_put_text(&conn->pack, &text));
    }

    return OG_SUCCESS;
}

static status_t clt_login(clt_conn_t *conn, const char *user, const char *password, const char *tenant,
    text_t *server_sign)
{
    cs_init_packet(&conn->pack, conn->pipe.options);
    cs_init_set(&conn->pack, conn->call_version);
    conn->pack.head->cmd = CS_CMD_LOGIN;
    conn->pack.head->flags = conn->interactive_clt ? CS_FLAG_INTERACTIVE_CLT : 0;
    if (conn->remote_as_sysdba) {
        conn->pack.head->flags |= OG_FLAG_REMOTE_AS_SYSDBA;
    }

    OG_RETURN_IFERR(clt_do_login(conn, user, password, tenant));

    OG_RETURN_IFERR(clt_remote_call(conn, &conn->pack, &conn->pack));

    /* erase the security Information */
    cs_init_get(&conn->pack);

    PRTS_RETURN_IFERR(sprintf_s(conn->message, OG_MESSAGE_BUFFER_SIZE, "connected."));
    OG_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->sid));
    OG_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->serial));
    OG_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_info.locator_size));
    OG_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_info.server_charset));

    if (conn->server_info.server_charset >= CHARSET_MAX) {
        CLT_SET_ERROR(conn, ERR_INVALID_CHARSET, "invalid server charset id: %d", conn->server_info.server_charset);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(clt_set_conn_transcode_func(conn));
    // server signature
    OG_RETURN_IFERR(cs_get_text(&conn->pack, server_sign));

    if (conn->call_version >= CS_VERSION_10) {
        OG_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_info.server_max_pack_size));
    }
    conn->pack.max_buf_size = conn->server_info.server_max_pack_size;

    // db role
    if (conn->call_version >= CS_VERSION_15) {
        OG_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_info.db_role));
    }

    if (CS_HAS_MORE(&conn->pack)) {
        OG_RETURN_IFERR(clt_get_error_message(conn, &conn->pack, conn->message));
    }

    return OG_SUCCESS;
}

static status_t clt_verify_server_signature(uchar *salted_pwd, uint32 salted_pwd_len, text_t *scramble_key,
    text_t *server_sign)
{
    uchar server_key[OG_HMAC256MAXSIZE];
    uchar c_server_sign[OG_HMAC256MAXSIZE];
    uint32 server_key_len;
    uint32 sign_key_len;
    uint32 key_len;

    sign_key_len = OG_MAX_CHALLENGE_LEN * 2;
    if (scramble_key->len < sign_key_len) {
        return OG_ERROR;
    }
    // server_key
    server_key_len = sizeof(server_key);
    if (cm_encrypt_HMAC(salted_pwd, salted_pwd_len, (uchar *)OG_SERVER_KEY, (uint32)strlen(OG_SERVER_KEY), server_key,
        &server_key_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    // server_signature
    key_len = sizeof(c_server_sign);
    if (cm_encrypt_HMAC(server_key, server_key_len, (uchar *)scramble_key->str, sign_key_len, c_server_sign,
        &key_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    // check
    if (key_len != server_sign->len || memcmp(c_server_sign, server_sign->str, key_len) != 0) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t clt_do_handshake(clt_conn_t *conn, const char *user, SENSI_INFO const char *passwd, const char *tenant,
    uint32 version)
{
    text_t scramble_key;
    text_t server_sign;
    uchar scram_buf[OG_MAX_CHALLENGE_LEN * 2 + OG_KDF2SALTSIZE];
    uchar salted_pwd[OG_SCRAM256KEYSIZE];
    char pwd_cipher[OG_PASSWORD_BUFFER_SIZE];
    uchar client_key[OG_MAX_CHALLENGE_LEN];
    uint32 key_len;
    uint32 salted_pwd_len;
    uint32 iter_count;

    // before handshake set has_auth to false
    conn->has_auth = OG_FALSE;

    // check ssl
    conn->server_capabilities = 0;
    if (conn->pipe.options & CSO_CLIENT_SSL) {
        conn->server_capabilities |= CS_FLAG_CLIENT_SSL;
    }
    OG_RETURN_IFERR(clt_ssl_check(conn));

    // clean up options flags
    conn->pipe.options &= ~CSO_CLIENT_SSL;

    // prepare handshake packet
    cs_init_packet(&conn->pack, conn->pipe.options);
    conn->pack.max_buf_size = conn->server_info.server_max_pack_size;

    cs_init_set(&conn->pack, version);
    conn->pack.head->cmd = CS_CMD_HANDSHAKE;
    conn->pack.head->flags = 0;
    if (conn->interactive_clt) {
        conn->pack.head->flags |= CS_FLAG_INTERACTIVE_CLT;
    }
    if (conn->client_flag & CS_FLAG_CLIENT_SSL) {
        conn->pack.head->flags |= CS_FLAG_CLIENT_SSL;
    }

    // generate client challenge key
    OG_RETURN_IFERR(cm_rand(client_key, OG_MAX_CHALLENGE_LEN));

    // establish SSL channel first since v9.0
    if (conn->server_version >= CS_VERSION_9) {
        OG_RETURN_IFERR(clt_ssl_handshake_safe(conn, user, tenant, client_key, OG_MAX_CHALLENGE_LEN, version));
    } else {
        OG_RETURN_IFERR(clt_ssl_handshake(conn, user, client_key, OG_MAX_CHALLENGE_LEN));
    }

    // wait for handshake/auth_init ack
    if (clt_remote_wait(conn) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // read handshake ack
    if (cs_read(&conn->pipe, &conn->pack, OG_TRUE) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    cs_init_get(&conn->pack);
    if (CS_HAS_EXEC_ERROR(&conn->pack)) {
        OG_RETURN_IFERR(cs_get_int32(&conn->pack, &conn->error_code));
        OG_RETURN_IFERR(cs_get_int16(&conn->pack, (int16 *)(&conn->loc.line)));
        OG_RETURN_IFERR(cs_get_int16(&conn->pack, (int16 *)(&conn->loc.column)));
        OG_RETURN_IFERR(clt_get_error_message(conn, &conn->pack, conn->message));
        return OG_ERROR;
    }

    // 1. server_capabilities
    OG_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_capabilities));
    // 2. server version
    OG_RETURN_IFERR(cs_get_int32(&conn->pack, (int32 *)&conn->server_version));
    // 3. scramble key
    OG_RETURN_IFERR(cs_get_text(&conn->pack, &scramble_key));
    // 4. iteration
    if (cs_get_int32(&conn->pack, (int32 *)&iter_count) != OG_SUCCESS) {
        cm_reset_error();
        iter_count = OG_KDF2DEFITERATION;
    }
    if (iter_count > OG_KDF2MAXITERATION || iter_count < OG_KDF2MINITERATION) {
        CLT_THROW_ERROR(conn, ERR_INVALID_ENCRYPTION_ITERATION, OG_KDF2MINITERATION, OG_KDF2MAXITERATION);
        return OG_ERROR;
    }

    // verify client key
    if (scramble_key.len < sizeof(client_key) || memcmp(scramble_key.str, client_key, sizeof(client_key)) != 0) {
        CLT_THROW_ERROR(conn, ERR_TCP_PKT_VERIFY, "client key");
        return OG_ERROR;
    }
    // negotiate protocol version
    conn->call_version = (version > conn->server_version) ? conn->server_version : version;

    // before handshake set has_auth to false
    conn->has_auth = OG_TRUE;

    // 5. encrypt pwd with scramble_key
    key_len = sizeof(pwd_cipher);
    salted_pwd_len = sizeof(salted_pwd);
    if (clt_encrypt_login_passwd(passwd, &scramble_key, iter_count, salted_pwd, &salted_pwd_len, pwd_cipher,
        &key_len) != OG_SUCCESS) {
        CLT_THROW_ERROR(conn, ERR_GENERATE_CIPHER);
        return OG_ERROR;
    }
    pwd_cipher[key_len] = '\0';

    // backup scram_key
    if (scramble_key.len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(scram_buf, sizeof(scram_buf), scramble_key.str, scramble_key.len));
    }
    scramble_key.str = (char *)scram_buf;

    // send login request
    OG_RETURN_IFERR(clt_login(conn, user, pwd_cipher, tenant, &server_sign));

    // verify signature
    if (clt_verify_server_signature(salted_pwd, salted_pwd_len, &scramble_key, &server_sign) != OG_SUCCESS) {
        CLT_THROW_ERROR(conn, ERR_TCP_PKT_VERIFY, "server signature");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t clt_connect(clt_conn_t *conn, const char *url, const char *user, const char *password, const char *tenant,
    uint32 version)
{
    /* disconnect conn if was connected */
    if (conn->ready == OG_TRUE) {
        clt_disconnect(conn);
    }

    /* create socket to server */
    if (cs_connect(url, &conn->pipe, NULL, conn->options.server_path, conn->options.client_path) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }
    conn->node_type = conn->pipe.node_type;

    /* update conn options */
    OG_RETURN_IFERR(clt_update_conn_opt(conn, url, user));

    /* do handshake to server with user and pwd */
    if (clt_do_handshake(conn, user, password, tenant, version) != OG_SUCCESS) {
        cs_disconnect(&conn->pipe);
        CM_FREE_PTR(conn->options.user);
        CM_FREE_PTR(conn->options.host);
        return OG_ERROR;
    }

    conn->ready = OG_TRUE;
    return OG_SUCCESS;
}

static status_t ogconn_set_shd_socket_timeout(clt_conn_t *conn, const void *data)
{
    status_t status;
    text_t tmp_text;
    text_t sql_text;
    char sql[OG_MAX_ALSET_SOCKET] = { 0 };
    MEMS_RETURN_IFERR(strcat_s(sql, OG_MAX_ALSET_SOCKET, "ALTER SESSION SET SHD_SOCKET_TIMEOUT = "));
    char buf[OG_MAX_INT32_STRLEN + 1];
    tmp_text.str = buf;
    cm_int2text(*(int32 *)data, &tmp_text);
    MEMS_RETURN_IFERR(strcat_s(sql, OG_MAX_ALSET_SOCKET, tmp_text.str));
    cm_str2text(sql, &sql_text);
    status = clt_query(conn, &sql_text);
    return status;
}

/* split url and tenant */
static void ogconn_try_fetch_url_tenant(const char *str, text_t *url, text_t *tenant)
{
    cm_str2text((char *)str, tenant);
    (void)cm_fetch_rtext(tenant, '/', 0, url);
}

status_t ogconn_connect_inner(ogconn_conn_t pconn, const char *url, const char *user, const char *password, uint32
    version)
{
    status_t status = OG_SUCCESS;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    text_t cls_url = { 0 };
    text_t tenant = { 0 };
    char url_buf[CM_UNIX_DOMAIN_PATH_LEN + OG_STR_RESERVED_LEN];
    char tenant_buf[OG_TENANT_BUFFER_SIZE];

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    if (SECUREC_UNLIKELY(url == NULL || user == NULL || CM_IS_EMPTY_STR(password))) {
        CLT_THROW_ERROR(conn, ERR_CLT_OBJECT_IS_NULL, "url or user or password");
        return OG_ERROR;
    }
    ogconn_try_fetch_url_tenant(url, &cls_url, &tenant);
    if (tenant.len > OG_TENANT_NAME_LEN) {
        CLT_THROW_ERROR(conn, ERR_NAME_TOO_LONG, "tenant", tenant.len, OG_TENANT_NAME_LEN);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_text2str(&cls_url, url_buf, CM_UNIX_DOMAIN_PATH_LEN + OG_STR_RESERVED_LEN));
    cm_text2str_with_upper(&tenant, tenant_buf, OG_TENANT_BUFFER_SIZE);

    OG_RETURN_IFERR(clt_lock_conn(conn));
    // cluster url: ip:port,ip:port,ip:port...
    if (cm_char_in_text(',', &cls_url)) {
        char ssl_keypwd[OG_MAX_SSL_KEYPWD] = { 0 };
        if (conn->options.ssl_keypwd != NULL) {
            status = clt_get_conn_attr(conn, OGCONN_ATTR_SSL_KEYPWD, ssl_keypwd, sizeof(ssl_keypwd), NULL);
        }

        if (status == OG_SUCCESS) {
            status = clt_cluster_connect(conn, &cls_url, user, password, ssl_keypwd, tenant_buf);
        }

        if (memset_s(ssl_keypwd, OG_MAX_SSL_KEYPWD, 0, OG_MAX_SSL_KEYPWD) != EOK) {
            status = OG_ERROR;
        }
    } else {
        status = clt_connect(conn, url_buf, user, password, tenant_buf, version);
    }
    if (status == OG_SUCCESS && conn->node_type == CS_TYPE_CN) {
        int32 data = conn->options.socket_timeout;
        if (data != -1) {
            status = ogconn_set_shd_socket_timeout(conn, &data);
        }
    }
    clt_unlock_conn(conn);
    return status;
}

status_t ogconn_connect(ogconn_conn_t pconn, const char *url, const char *user, const char *password)
{
    return ogconn_connect_inner(pconn, url, user, password, CS_LOCAL_VERSION);
}

static inline status_t clt_check_input_onoff_num(clt_conn_t *conn, const void *data, int32 *attr_value)
{
    *attr_value = *(int32 *)data;

    if (*attr_value == 0 || *attr_value == 1) {
        return OG_SUCCESS;
    }

    CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "input number", (uint32)*attr_value);
    return OG_ERROR;
}

static status_t clt_set_conn_local_charset(clt_conn_t *conn, text_t *charset)
{
    uint16 charset_id = cm_get_charset_id_ex(charset);
    if (charset_id == OG_INVALID_ID16) {
        CLT_SET_ERROR(conn, ERR_INVALID_CHARSET, "unsupported charset %.*s", charset->len, charset->str);
        return OG_ERROR;
    }

    conn->local_charset = charset_id;

    return clt_set_conn_transcode_func(conn);
}

static status_t clt_set_conn_nls(clt_conn_t *conn, nlsparam_id_t id, const void *data, uint32 len)
{
    char alter_sql[MAX_SET_NLS_SQL];
    text_t nlsval;
    text_t sql_text;

    nlsval.str = (char *)data;
    nlsval.len = len;

    cm_trim_text(&nlsval);

    if ((uint32)id >= NLS__MAX_PARAM_NUM) {
        CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "nls param id", (uint32)id);
        return OG_ERROR;
    }

    if (nlsval.len >= MAX_NLS_PARAM_LENGTH) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, g_nlsparam_items[id].key.str);
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR(sprintf_s(alter_sql, MAX_SET_NLS_SQL, "alter session set %s = '%s'", g_nlsparam_items[id].key.str,
        T2S(&nlsval)));

    sql_text.str = alter_sql;
    sql_text.len = (uint32)strlen(alter_sql);

    return clt_query(conn, &sql_text);
}

#define OG_MIN_NUMWIDTH (uint32)6
#define OG_MAX_NUMWIDTH (uint32)OG_MAX_DEC_OUTPUT_ALL_PREC

status_t clt_set_conn_attr(clt_conn_t *conn, int32 attr, const void *data, uint32 len)
{
    uint32 i32_attr;
    int32 attr_value;
    text_t text;

    switch (attr) {
        case OGCONN_ATTR_AUTO_COMMIT:
            OG_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->auto_commit = (uint8)attr_value;
            break;

        case OGCONN_ATTR_EXIT_COMMIT:
            OG_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->exit_commit = (uint8)attr_value;
            break;

        case OGCONN_ATTR_SERVEROUTPUT:
            OG_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->serveroutput = (uint8)attr_value;
            break;

        case OGCONN_ATTR_REMOTE_AS_SYSDBA:
            OG_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->remote_as_sysdba = (uint8)attr_value;
            break;

        case OGCONN_ATTR_CHARSET_TYPE:
            text.str = (char *)data;
            text.len = len;
            OG_RETURN_IFERR(clt_set_conn_local_charset(conn, &text));
            break;

        case OGCONN_ATTR_NUM_WIDTH:
            i32_attr = *(uint32 *)data;
            if (i32_attr < OG_MIN_NUMWIDTH || i32_attr > OG_MAX_NUMWIDTH) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "numwidth option", i32_attr);
                return OG_ERROR;
            }
            conn->num_width = i32_attr;
            break;

        case OGCONN_ATTR_NLS_CALENDAR:
        case OGCONN_ATTR_NLS_CHARACTERSET:
        case OGCONN_ATTR_NLS_COMP:
        case OGCONN_ATTR_NLS_CURRENCY:
            return OG_SUCCESS;

        case OGCONN_ATTR_NLS_DATE_FORMAT:
            return clt_set_conn_nls(conn, (nlsparam_id_t)(attr - OGCONN_ATTR_NLS_CALENDAR), data, len);

        case OGCONN_ATTR_NLS_DATE_LANGUAGE:
        case OGCONN_ATTR_NLS_DUAL_CURRENCY:
        case OGCONN_ATTR_NLS_ISO_CURRENCY:
        case OGCONN_ATTR_NLS_LANGUAGE:
        case OGCONN_ATTR_NLS_LENGTH_SEMANTICS:
        case OGCONN_ATTR_NLS_NCHAR_CHARACTERSET:
        case OGCONN_ATTR_NLS_NCHAR_CONV_EXCP:
        case OGCONN_ATTR_NLS_NUMERIC_CHARACTERS:
        case OGCONN_ATTR_NLS_RDBMS_VERSION:
        case OGCONN_ATTR_NLS_SORT:
        case OGCONN_ATTR_NLS_TERRITORY:
            return OG_SUCCESS;

        case OGCONN_ATTR_NLS_TIMESTAMP_FORMAT:
        case OGCONN_ATTR_NLS_TIMESTAMP_TZ_FORMAT:
        case OGCONN_ATTR_NLS_TIME_FORMAT:
        case OGCONN_ATTR_NLS_TIME_TZ_FORMAT:
            return clt_set_conn_nls(conn, (nlsparam_id_t)(attr - OGCONN_ATTR_NLS_CALENDAR), data, len);

        case OGCONN_ATTR_INTERACTIVE_MODE:
            OG_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->interactive_clt = (uint8)attr_value;
            break;

        case OGCONN_ATTR_SSL_CA:
            CM_FREE_PTR(conn->options.ssl_ca);
            OG_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_ca)));
            break;

        case OGCONN_ATTR_SSL_CERT:
            CM_FREE_PTR(conn->options.ssl_cert);
            OG_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_cert)));
            break;

        case OGCONN_ATTR_SSL_KEY:
            CM_FREE_PTR(conn->options.ssl_key);
            OG_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_key)));
            break;

        case OGCONN_ATTR_SSL_MODE:
            conn->options.ssl_mode = *(ogconn_ssl_mode_t *)data;
            break;

        case OGCONN_ATTR_SSL_CRL:
            CM_FREE_PTR(conn->options.ssl_crl);
            OG_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_crl)));
            break;

        case OGCONN_ATTR_SSL_KEYPWD:
            securec_free(conn->options.ssl_keypwd);
            OG_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_keypwd)));
            break;

        case OGCONN_ATTR_SSL_CIPHER:
            CM_FREE_PTR(conn->options.ssl_cipher);
            OG_RETURN_IFERR(clt_strndup(data, len, &(conn->options.ssl_cipher)));
            break;

        case OGCONN_ATTR_CONNECT_TIMEOUT:
            attr_value = *(int32 *)data;
            if (attr_value < 0 && attr_value != -1) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "connect timeout value", (uint32)attr_value);
                return OG_ERROR;
            }
            conn->options.connect_timeout = attr_value;
            conn->pipe.connect_timeout = (attr_value == -1) ? attr_value : attr_value * OG_TIME_THOUSAND;
            break;

        case OGCONN_ATTR_SOCKET_TIMEOUT:
            attr_value = *(int32 *)data;
            if (attr_value < 0 && attr_value != -1) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "socket timeout value", (uint32)attr_value);
                return OG_ERROR;
            }
            conn->options.socket_timeout = attr_value;
            conn->pipe.socket_timeout = (attr_value == -1) ? attr_value : attr_value * OG_TIME_THOUSAND;
            break;

        case OGCONN_ATTR_APP_KIND:
            attr_value = *(int16 *)data;
            if (attr_value <= CLIENT_KIND_UNKNOWN || attr_value >= CLIENT_KIND_TAIL) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "app kind value", (uint32)attr_value);
                return OG_ERROR;
            }
            conn->options.app_kind = (int16)attr_value;
            break;

        case OGCONN_ATTR_UDS_SERVER_PATH:
            CM_FREE_PTR(conn->options.server_path);
            OG_RETURN_IFERR(clt_strndup(data, len, &(conn->options.server_path)));
            break;

        case OGCONN_ATTR_UDS_CLIENT_PATH:
            CM_FREE_PTR(conn->options.client_path);
            OG_RETURN_IFERR(clt_strndup(data, len, &(conn->options.client_path)));
            break;

        case OGCONN_ATTR_FLAG_WITH_TS:
            OG_RETURN_IFERR(clt_check_input_onoff_num(conn, data, &attr_value));
            conn->flag_with_ts = (uint8)attr_value;
            break;

        case OGCONN_ATTR_SHD_RW_FLAG:
            attr_value = *(int32 *)data;
            if (attr_value < OGCONN_SHD_RW_SPLIT_NONE || attr_value > OGCONN_SHD_RW_SPLIT_ROA) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "shard rw split flag", (int32)attr_value);
                return OG_ERROR;
            }
            conn->shd_rw_split = (uint8)attr_value;
            break;

        case OGCONN_ATTR_SOCKET_L_ONOFF:
            attr_value = *(int32 *)data;
            conn->options.l_onoff = attr_value;
            conn->pipe.l_onoff = attr_value;
            break;

        case OGCONN_ATTR_SOCKET_L_LINGER:
            attr_value = *(int32 *)data;
            conn->options.l_linger = attr_value;
            conn->pipe.l_linger = attr_value;
            break;

        case OGCONN_ATTR_AUTOTRACE:
            attr_value = *(int32 *)data;
            conn->autotrace = (uint8)attr_value;
            break;

        default:
            CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "connection attribute id", (uint32)attr);
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t ogconn_set_conn_attr(ogconn_conn_t pconn, int32 attr, const void *data, uint32 len)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_CLT(conn, data, "value of connection attribute to set");

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_set_conn_attr(conn, attr, data, len);
    clt_unlock_conn(conn);
    return status;
}

void ogconn_set_autocommit(ogconn_conn_t pconn, bool32 auto_commit)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    int32 attr_value;

    OG_RETVOID_IFTRUE(SECUREC_UNLIKELY(conn == NULL));

    OG_RETVOID_IFERR(clt_check_input_onoff_num(conn, &auto_commit, &attr_value));
    conn->auto_commit = (uint8)attr_value;
}

static status_t ogconn_get_conn_nls(clt_conn_t *conn, nlsparam_id_t id, const void *data, uint32 len, uint32 *attr_len)
{
    text_t nlsfmt;
    conn->nls_params.param_geter(&conn->nls_params, id, &nlsfmt);
    if (len <= 1 || len <= nlsfmt.len) {
        CLT_THROW_ERROR(conn, ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch nls fmt");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_text2str(&nlsfmt, (char *)data, len));
    if (attr_len != NULL) {
        *attr_len = nlsfmt.len;
    }
    return OG_SUCCESS;
}

uint32 ogconn_get_call_version(ogconn_conn_t conn)
{
    return (conn == NULL) ? CS_LOCAL_VERSION : ((struct st_clt_conn *)conn)->call_version;
}

uint32 ogconn_get_shd_node_type(ogconn_conn_t conn)
{
    return (conn == NULL) ? CS_RESERVED : ((struct st_clt_conn *)conn)->node_type;
}

static status_t ogconn_get_attr_string(const char *attr, void *data, uint32 len, uint32 *attr_len)
{
    uint32 temp_attr_len;

    if (CM_IS_EMPTY_STR(attr)) {
        temp_attr_len = 0;
    } else {
        temp_attr_len = (uint32)strlen(attr);
        if (temp_attr_len >= len) {
            OG_THROW_ERROR(ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch conn attr data");
            return OG_ERROR;
        }

        MEMS_RETURN_IFERR(strncpy_s((char *)data, len, attr, strlen(attr)));
    }

    if (attr_len != NULL) {
        *attr_len = temp_attr_len;
    }
    *((char *)data + temp_attr_len) = '\0';
    return OG_SUCCESS;
}

static status_t clt_query_conn_dbtimezone(clt_conn_t *conn)
{
    uint32 row = 0;
    char *data = NULL;
    uint32 size = 0;
    uint32 is_null = 0;
    text_t text;

    char *alter_sql = NULL;
    text_t sql_text;
    status_t status = OG_ERROR;
    bool32 src_stmt_null = (conn->query.query_stmt == NULL) ? OG_TRUE : OG_FALSE;

    do {
        if (conn->call_version >= CS_VERSION_8) {
            alter_sql = "SELECT DBTIMEZONE FROM SYS.DV_INSTANCE";
        } else {
            alter_sql = "SELECT DBTIMEZONE FROM SYS.V$INSTANCE";
        }

        sql_text.str = alter_sql;
        sql_text.len = (uint32)strlen(alter_sql);

        if (OG_SUCCESS != clt_query(conn, &sql_text)) {
            cm_reset_error();
            conn->error_code = OG_SUCCESS;
            conn->message[0] = '\0';

            alter_sql = "SELECT DBTIMEZONE";

            sql_text.str = alter_sql;
            sql_text.len = (uint32)strlen(alter_sql);

            OG_BREAK_IF_ERROR(clt_query(conn, &sql_text));
        }

        /* fetch result */
        OG_BREAK_IF_ERROR(clt_fetch(conn->query.query_stmt, &row, OG_FALSE));
        OG_BREAK_IF_ERROR(clt_get_column_by_id(conn->query.query_stmt, 0, (void **)&data, &size, &is_null));

        /* save this value */
        text.str = data;
        text.len = size;

        OG_BREAK_IF_ERROR(cm_text2tzoffset(&text, &conn->server_info.server_dbtimezone));
        status = OG_SUCCESS;
    } while (0);

    if (src_stmt_null) {
        clt_free_stmt(conn->query.query_stmt);
        conn->query.query_stmt = NULL;
    }

    return status;
}

static status_t clt_query_conn_lastinsertid(clt_conn_t *conn)
{
    char *alter_sql = "SELECT LAST_INSERT_ID()";
    text_t sql_text;
    char *data = NULL;
    status_t status = OG_ERROR;
    bool32 src_stmt_null = (conn->query.query_stmt == NULL) ? OG_TRUE : OG_FALSE;

    do {
        sql_text.str = alter_sql;
        sql_text.len = (uint32)strlen(alter_sql);

        OG_BREAK_IF_ERROR(clt_query(conn, &sql_text));

        /* fetch result */
        OG_BREAK_IF_ERROR(clt_fetch(conn->query.query_stmt, NULL, OG_FALSE));
        OG_BREAK_IF_ERROR(clt_get_column_by_id(conn->query.query_stmt, 0, (void **)&data, NULL, NULL));

        conn->last_insert_id = *(int64 *)data;
        status = OG_SUCCESS;
    } while (0);

    if (src_stmt_null) {
        clt_free_stmt(conn->query.query_stmt);
        conn->query.query_stmt = NULL;
    }

    return status;
}

static status_t clt_get_charset_name(clt_conn_t *conn, charset_type_t charset, char *data, uint32 len, uint32 *attr_len)
{
    const char *charset_name = NULL;
    uint32 charset_len;

    if (len < CLT_CHARSET_NAME_SIZE) {
        CLT_THROW_ERROR(conn, ERR_CLT_BUF_SIZE_TOO_SMALL, "fetch charset name");
        return OG_ERROR;
    }

    charset_name = cm_get_charset_name(charset);
    if (data == NULL || charset_name == NULL) {
        OG_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "charset");
        return OG_ERROR;
    }

    charset_len = (uint32)strlen(charset_name);
    MEMS_RETURN_IFERR(strncpy_s(data, len, charset_name, charset_len));

    if (attr_len != NULL) {
        *attr_len = charset_len;
    }
    *(data + charset_len) = '\0';

    return OG_SUCCESS;
}

static status_t clt_get_conn_attr(clt_conn_t *conn, int32 attr, void *data, uint32 len, uint32 *attr_len)
{
    switch (attr) {
        case OGCONN_ATTR_AUTO_COMMIT:
            *(uint32 *)data = conn->auto_commit ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_XACT_STATUS:
            *(uint32 *)data = conn->xact_status;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_EXIT_COMMIT:
            *(uint32 *)data = conn->exit_commit ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_SERVEROUTPUT:
            *(uint32 *)data = conn->serveroutput ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_REMOTE_AS_SYSDBA:
            *(uint32 *)data = conn->remote_as_sysdba ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_CHARSET_TYPE:
            return clt_get_charset_name(conn, (charset_type_t)conn->local_charset, (char *)data, len, attr_len);

        case OGCONN_ATTR_NUM_WIDTH:
            *(uint32 *)data = (uint32)conn->num_width;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_NLS_CHARACTERSET:
            if (!conn->ready) {
                CLT_THROW_ERROR(conn, ERR_CLT_INVALID_ATTR, "NLS character set", "connection is not established");
                return OG_ERROR;
            }
            return clt_get_charset_name(conn, (charset_type_t)conn->server_info.server_charset, (char *)data, len,
                attr_len);

        case OGCONN_ATTR_NLS_CALENDAR:
        case OGCONN_ATTR_NLS_COMP:
        case OGCONN_ATTR_NLS_CURRENCY:
            return OG_SUCCESS;

        case OGCONN_ATTR_NLS_DATE_FORMAT:
            return ogconn_get_conn_nls(conn, (nlsparam_id_t)(attr - OGCONN_ATTR_NLS_CALENDAR), data, len, attr_len);

        case OGCONN_ATTR_NLS_DATE_LANGUAGE:
        case OGCONN_ATTR_NLS_DUAL_CURRENCY:
        case OGCONN_ATTR_NLS_ISO_CURRENCY:
        case OGCONN_ATTR_NLS_LANGUAGE:
        case OGCONN_ATTR_NLS_LENGTH_SEMANTICS:
        case OGCONN_ATTR_NLS_NCHAR_CHARACTERSET:
        case OGCONN_ATTR_NLS_NCHAR_CONV_EXCP:
        case OGCONN_ATTR_NLS_NUMERIC_CHARACTERS:
        case OGCONN_ATTR_NLS_RDBMS_VERSION:
        case OGCONN_ATTR_NLS_SORT:
        case OGCONN_ATTR_NLS_TERRITORY:
            return OG_SUCCESS;

        case OGCONN_ATTR_NLS_TIMESTAMP_FORMAT:
        case OGCONN_ATTR_NLS_TIMESTAMP_TZ_FORMAT:
        case OGCONN_ATTR_NLS_TIME_FORMAT:
        case OGCONN_ATTR_NLS_TIME_TZ_FORMAT:
            return ogconn_get_conn_nls(conn, (nlsparam_id_t)(attr - OGCONN_ATTR_NLS_CALENDAR), data, len, attr_len);

        case OGCONN_ATTR_DBTIMEZONE:
            return clt_query_conn_dbtimezone(conn);

        case OGCONN_ATTR_LOB_LOCATOR_SIZE:
            *(uint32 *)data = (uint32)conn->server_info.locator_size;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_SSL_CA:
            return ogconn_get_attr_string(conn->options.ssl_ca, data, len, attr_len);
        case OGCONN_ATTR_SSL_CERT:
            return ogconn_get_attr_string(conn->options.ssl_cert, data, len, attr_len);
        case OGCONN_ATTR_SSL_KEY:
            return ogconn_get_attr_string(conn->options.ssl_key, data, len, attr_len);
        case OGCONN_ATTR_SSL_KEYPWD:
            return ogconn_get_attr_string(conn->options.ssl_keypwd, data, len, attr_len);
        case OGCONN_ATTR_SSL_CRL:
            return ogconn_get_attr_string(conn->options.ssl_crl, data, len, attr_len);
        case OGCONN_ATTR_SSL_CIPHER:
            return ogconn_get_attr_string(conn->options.ssl_cipher, data, len, attr_len);
        case OGCONN_ATTR_SSL_MODE:
            *(uint32 *)data = (uint32)conn->options.ssl_mode;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_CONNECT_TIMEOUT:
            *(int32 *)data = conn->options.connect_timeout;
            if (attr_len != NULL) {
                *attr_len = sizeof(int32);
            }
            break;

        case OGCONN_ATTR_SOCKET_TIMEOUT:
            *(int32 *)data = conn->options.socket_timeout;
            if (attr_len != NULL) {
                *attr_len = sizeof(int32);
            }
            break;
        case OGCONN_ATTR_APP_KIND:
            *(int16 *)data = conn->options.app_kind;
            if (attr_len != NULL) {
                *attr_len = sizeof(int16);
            }
            break;

        case OGCONN_ATTR_INTERACTIVE_MODE:
            *(uint8 *)data = conn->interactive_clt;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint8);
            }
            break;

        case OGCONN_ATTR_UDS_SERVER_PATH:
            return ogconn_get_attr_string(conn->options.server_path, data, len, attr_len);

        case OGCONN_ATTR_UDS_CLIENT_PATH:
            return ogconn_get_attr_string(conn->options.client_path, data, len, attr_len);

        case OGCONN_ATTR_TIMESTAMP_SIZE:
        case OGCONN_ATTR_TIMESTAMP_LTZ_SIZE:
            *(uint32 *)data = sizeof(timestamp_t);
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_TIMESTAMP_TZ_SIZE:
            *(uint32 *)data = sizeof(timestamp_tz_t);
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_FLAG_WITH_TS:
            *(uint32 *)data = conn->flag_with_ts ? 1 : 0;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_SHD_RW_FLAG:
            *(uint32 *)data = conn->shd_rw_split;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        case OGCONN_ATTR_LAST_INSERT_ID:
            OG_BREAK_IF_ERROR(clt_query_conn_lastinsertid(conn));
            *(int64 *)data = conn->last_insert_id;
            if (attr_len != NULL) {
                *attr_len = sizeof(int64);
            }
            break;

        case OGCONN_ATTR_SOCKET_L_ONOFF:
            *(int32 *)data = conn->options.l_onoff;
            if (attr_len != NULL) {
                *attr_len = sizeof(int32);
            }
            break;

        case OGCONN_ATTR_SOCKET_L_LINGER:
            *(int32 *)data = conn->options.l_linger;
            if (attr_len != NULL) {
                *attr_len = sizeof(int32);
            }
            break;
        case OGCONN_ATTR_AUTOTRACE:
            *(uint32 *)data = conn->autotrace;
            if (attr_len != NULL) {
                *attr_len = sizeof(uint32);
            }
            break;

        default:
            CLT_THROW_ERROR(conn, ERR_CLT_INVALID_VALUE, "connection attribute id", (uint32)attr);
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t ogconn_get_conn_attr(ogconn_conn_t pconn, int32 attr, void *data, uint32 len, uint32 *attr_len)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_CLT(conn, data, "value of connection attribute to get");

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_get_conn_attr(conn, attr, data, len, attr_len);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_cancel(clt_conn_t *conn, uint32 sid)
{
    cs_packet_t *req_pack;
    cs_packet_t *ack_pack;

    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_CANCEL;
    OG_RETURN_IFERR(cs_put_int32(req_pack, sid));
    return clt_remote_call(conn, req_pack, ack_pack);
}

status_t ogconn_cancel(ogconn_conn_t pconn, uint32 sid)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_cancel(conn, sid);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_commit(clt_conn_t *conn)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_COMMIT;

    if (clt_remote_call(conn, req_pack, ack_pack) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t ogconn_commit(ogconn_conn_t pconn)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_commit(conn);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_rollback(clt_conn_t *conn)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_ROLLBACK;

    return clt_remote_call(conn, req_pack, ack_pack);
}

status_t ogconn_rollback(ogconn_conn_t pconn)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_rollback(conn);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_query_single(clt_stmt_t *stmt, const text_t *sql)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;
    cs_execute_req_t *req = NULL;
    uint32 req_offset;
    uint32 sql_size;
    uint32 total_size;

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->cache_pack->pack;

    /* request content is "cs_execute_req_t + sql" */
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_QUERY;
    OG_BIT_RESET(req_pack->head->flags, CS_FLAG_WITH_TS);

    OG_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_execute_req_t), &req_offset));
    req = (cs_execute_req_t *)CS_RESERVE_ADDR(req_pack, req_offset);
    req->stmt_id = stmt->stmt_id;
    req->paramset_size = 1;
    req->prefetch_rows = clt_prefetch_rows(stmt);
    req->auto_commit = stmt->conn->auto_commit;
    req->reserved = 0;
    cs_putted_execute_req(req_pack, req_offset);

    total_size = sql_size = sql->len;

    do {
        OG_RETURN_IFERR(ogconn_write_sql(stmt, sql->str, total_size, &sql_size, req_pack));
        OG_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

        cs_init_set(req_pack, stmt->conn->call_version);
    } while (sql_size > 0);

    /* response content is "cs_prepare_ack_t + cs_execute_ack_t" */
    OG_RETURN_IFERR(clt_try_receive_pl_proc_data(stmt, ack_pack));

    OG_RETURN_IFERR(clt_get_prepare_ack(stmt, ack_pack, sql));

    OG_RETURN_IFERR(clt_try_process_feedback(stmt, ack_pack));
    OG_RETURN_IFERR(clt_get_execute_ack(stmt));

    stmt->status = CLI_STMT_EXECUTED;
    return OG_SUCCESS;
}

status_t ogconn_query_fetch(ogconn_conn_t pconn, uint32 *rows)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;
    uint32 temp_rows = 0;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    stmt = conn->query.query_stmt;
    OGCONN_CHECK_OBJECT_NULL_CLT(conn, stmt, "query statement");

    OG_RETURN_IFERR(clt_lock_conn(conn));

    if (clt_prepare_stmt_pack(stmt) != OG_SUCCESS) {
        clt_unlock_conn(conn);
        return OG_ERROR;
    }

    status = clt_fetch(stmt, &temp_rows, OG_FALSE);

    if (temp_rows == 0) {
        clt_recycle_stmt_pack(stmt);
    }

    if (SECUREC_LIKELY(rows != NULL)) {
        *rows = temp_rows;
    }

    clt_unlock_conn(conn);
    return status;
}

uint32 ogconn_query_get_affected_rows(ogconn_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;

    if (SECUREC_UNLIKELY(conn == NULL)) {
        return 0;
    }

    stmt = conn->query.query_stmt;
    return (stmt != NULL) ? stmt->affected_rows : 0;
}

uint32 ogconn_query_get_column_count(ogconn_conn_t pconn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;

    if (SECUREC_UNLIKELY(conn == NULL)) {
        return 0;
    }

    stmt = conn->query.query_stmt;
    return (stmt != NULL) ? stmt->column_count : 0;
}

status_t ogconn_query_describe_column(ogconn_conn_t pconn, uint32 id, ogconn_column_desc_t *desc)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    stmt = conn->query.query_stmt;
    OGCONN_CHECK_OBJECT_NULL_CLT(conn, stmt, "query statement");

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_desc_column_by_id(stmt, id, desc);
    clt_unlock_conn(conn);
    return status;
}

status_t ogconn_query_get_column(ogconn_conn_t pconn, uint32 id, void **data, uint32 *size, uint32 *is_null)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    clt_stmt_t *stmt = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    stmt = conn->query.query_stmt;
    OGCONN_CHECK_OBJECT_NULL_CLT(conn, stmt, "query statement");

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_get_column_by_id(stmt, id, data, size, is_null);
    clt_unlock_conn(conn);
    return status;
}

static void ogconn_reset_query(clt_conn_t *conn)
{
    clt_query_t *query = &conn->query;
    clt_stmt_t *sub_stmt = NULL;
    uint32 stmt_id;
    uint32 i;

    for (i = 0; i < query->ids.count; i++) {
        stmt_id = *(uint32 *)cm_list_get(&query->ids, i);
        sub_stmt = (clt_stmt_t *)cm_ptlist_get(&conn->stmts, stmt_id);
        if (sub_stmt != NULL) {
            clt_free_stmt(sub_stmt);
        }
    }

    cm_destroy_list(&query->ids);
    cm_create_list(&query->ids, sizeof(uint32));
    query->pos = 0;
}

static status_t clt_query(clt_conn_t *conn, const text_t *sql)
{
    clt_stmt_t *stmt = NULL;

    if (conn->query.ids.count > 0) {
        ogconn_reset_query(conn);
    }

    if (!conn->query.query_stmt) {
        if (clt_alloc_stmt(conn, &stmt) != OG_SUCCESS) {
            return OG_ERROR;
        }
        conn->query.query_stmt = stmt;
    }
    OG_RETURN_IFERR(clt_prepare_stmt_pack(conn->query.query_stmt));
    return clt_query_single(conn->query.query_stmt, sql);
}

status_t ogconn_query(ogconn_conn_t pconn, const char *sql)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;
    text_t sql_text;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_CLT(conn, sql, "sql");

    sql_text.str = (char *)sql;
    sql_text.len = (uint32)strlen(sql);

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_query(conn, &sql_text);
    clt_unlock_conn(conn);
    return status;
}

static status_t clt_query_multiple(clt_conn_t *conn, const char *sql)
{
    text_t exec_sql;
    text_t sub_sql;
    clt_stmt_t *sub_stmt = NULL;
    bool32 rs_exists = OG_FALSE;
    uint32 *stmt_id = NULL;
    status_t ret = OG_SUCCESS;

    exec_sql.str = (char *)sql;
    exec_sql.len = (uint32)strlen(sql);

    if (conn->query.ids.count > 0) {
        ogconn_reset_query(conn);
    }

    while (cm_fetch_subsql(&exec_sql, &sub_sql)) {
        ret = clt_alloc_stmt(conn, &sub_stmt);
        OG_BREAK_IF_ERROR(ret);

        ret = clt_prepare_stmt_pack(sub_stmt);
        OG_BREAK_IF_ERROR(ret);

        ret = clt_query_single(sub_stmt, &sub_sql);
        OG_BREAK_IF_ERROR(ret);

        ret = clt_get_stmt_attr(sub_stmt, OGCONN_ATTR_RESULTSET_EXISTS, &rs_exists, sizeof(uint32), NULL);
        OG_BREAK_IF_ERROR(ret);

        // keep substmt of select for fetch data after query done
        if (rs_exists) {
            ret = cm_list_new(&conn->query.ids, (void **)&stmt_id);
            OG_BREAK_IF_ERROR(ret);

            *stmt_id = sub_stmt->id;
        } else {
            clt_free_stmt(sub_stmt);
        }

        sub_stmt = NULL;
    }

    if (sub_stmt != NULL) {
        clt_free_stmt(sub_stmt);
    }

    return ret;
}

status_t ogconn_query_multiple(ogconn_conn_t pconn, const char *sql)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_CLT(conn, sql, "sql");

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = clt_query_multiple(conn, sql);
    clt_unlock_conn(conn);
    return status;
}

#ifdef __cplusplus
}
#endif
