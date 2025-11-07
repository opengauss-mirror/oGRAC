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
 * ogconn_xa.c
 *
 *
 * IDENTIFICATION
 * src/driver/ogconn/ogconn_xa.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogconn_common.h"
#include "ogconn_shard.h"
#include "cs_protocol.h"

#define XID_LEN(xid) ((uint64)(((ogconn_xid_t *)0)->data) + (xid)->gtrid_len + (xid)->bqual_len)
#define XID_BASE16_LEN(xid) (((uint64)((ogconn_xid_t *)0)->data) + (xid)->gtrid_len * 2 + (xid)->bqual_len * 2)
#define OG_MAX_BQUAL_LEN 64
#define OG_MAX_GTRID_LEN 64
#define OG_BASE16_ONE_BYTE_LEN 2

/*
 * The same as Kernel SCN type which is a 64 bit value divided into three parts as follow:
 *
 * uint64 SCN = |--second--|--usecond--|--serial--|
 * uint64 SCN = |---32bit--|---20bit---|--12bit---|
 */
#define CLT_TIMESEQ_TO_SCN(time_val, init_time, seq) \
    (((uint64)((time_val)->tv_sec - (init_time)) << 32) | ((uint64)(time_val)->tv_usec << 12) | (seq))
#define CLT_SCN_TO_TIMESEQ(scn, time_val, init_time)                                          \
    do {                                                                                      \
        ((time_val)->tv_sec) = (long)((((scn) >> 32) & 0x00000000ffffffffULL) + (init_time)); \
        ((time_val)->tv_usec) = (long)(((scn) >> 12) & 0x00000000000fffffULL);                \
    } while (0)

/* ********************************************************************** */
/* XA interface                                                         */
/* ********************************************************************** */
static inline int32 og_pack_xid(cs_packet_t *pack, ogconn_xid_t *xid)
{
    if (xid->gtrid_len == 0 || xid->gtrid_len > OG_MAX_GTRID_LEN || xid->bqual_len > OG_MAX_BQUAL_LEN) {
        OG_THROW_ERROR_EX(ERR_XA_INVALID_XID, "gtrid len: %d, bqual len: %d", (int)xid->gtrid_len, (int)xid->bqual_len);
        return OG_ERROR;
    }

    uint32 data_len = (uint32)(CM_ALIGN4(XID_BASE16_LEN(xid)));
    CM_CHECK_SEND_PACK_FREE(pack, sizeof(uint32) + data_len);

    (void)cs_put_int32(pack, (uint32)(XID_BASE16_LEN(xid)));

    // format ID
    *(uint64 *)CS_WRITE_ADDR(pack) = cs_format_endian_i64(pack->options, xid->fmt_id);
    pack->head->size += sizeof(uint64);

    // global transaction and branch ID length
    CS_WRITE_ADDR(pack)[0] = xid->gtrid_len * OG_BASE16_ONE_BYTE_LEN;
    CS_WRITE_ADDR(pack)[1] = xid->bqual_len * OG_BASE16_ONE_BYTE_LEN;
    pack->head->size += 2;

    // global transaction ID
    binary_t bin = { (uint8 *)xid->data, xid->gtrid_len };
    (void)cm_bin2str(&bin, OG_FALSE, CS_WRITE_ADDR(pack), CS_REMAIN_SIZE(pack));
    pack->head->size += xid->gtrid_len * OG_BASE16_ONE_BYTE_LEN;

    // branch ID
    if (xid->bqual_len == 0) {
        return OG_SUCCESS;
    }
    bin.bytes = (uint8 *)&xid->data[xid->gtrid_len];
    bin.size = xid->bqual_len;
    (void)cm_bin2str(&bin, OG_FALSE, CS_WRITE_ADDR(pack), CS_REMAIN_SIZE(pack));
    pack->head->size += xid->bqual_len * OG_BASE16_ONE_BYTE_LEN;
    pack->head->size = CM_ALIGN4(pack->head->size);
    return OG_SUCCESS;
}

static inline int32 ogconn_xa_start_core(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 timeout, uint64 flags)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_START;

    OG_RETURN_IFERR(og_pack_xid(packet, xid));
    OG_RETURN_IFERR(cs_put_int64(packet, timeout));
    OG_RETURN_IFERR(cs_put_int64(packet, flags));

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != OG_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return OG_ERROR;
    }
    CLT_CONN(conn)->xact_status = OGCONN_XACT_OPEN;
    CLT_CONN(conn)->auto_commit_xa_backup = CLT_CONN(conn)->auto_commit;
    CLT_CONN(conn)->auto_commit = OG_FALSE;
    return OG_SUCCESS;
}

int32 ogconn_xa_start(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 timeout, uint64 flags)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int ret = ogconn_xa_start_core(conn, xid, timeout, flags);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static int32 ogconn_xa_end_core(ogconn_conn_t conn, uint64 flags)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_END;

    OG_RETURN_IFERR(cs_put_int64(packet, flags));

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != OG_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return OG_ERROR;
    }
    CLT_CONN(conn)->xact_status = OGCONN_XACT_END;
    CLT_CONN(conn)->auto_commit = CLT_CONN(conn)->auto_commit_xa_backup;
    return OG_SUCCESS;
}

int32 ogconn_xa_end(ogconn_conn_t conn, uint64 flags)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_xa_end_core(conn, flags);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ogconn_xa_commit_phase(uint8 cmd, ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags, struct
    timeval *ts)
{
    uint64 scn;
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = cmd;

    OG_RETURN_IFERR(og_pack_xid(packet, xid));
    OG_RETURN_IFERR(cs_put_int64(packet, flags));
    if (ts != NULL) {
        packet->head->flags |= CS_FLAG_WITH_TS;
        scn = CLT_TIMESEQ_TO_SCN(ts, CM_GTS_BASETIME, 1);
        OG_RETURN_IFERR(cs_put_scn(packet, &scn));
    }

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != OG_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return OG_ERROR;
    }

    cs_init_get(packet);
    if (CS_XACT_WITH_TS(packet->head->flags)) {
        OG_RETURN_IFERR(cs_get_scn(packet, &scn));
        CLT_SCN_TO_TIMESEQ(scn, ts, CM_GTS_BASETIME);
    }

    return OG_SUCCESS;
}

static inline int32 ogconn_xa_prepare_core(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags, struct timeval *ts)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;
    int32 errcode;

    OG_RETURN_IFERR(ogconn_xa_commit_phase(CS_CMD_XA_PREPARE, conn, xid, flags, ts));
    CLT_CONN(conn)->xact_status = OGCONN_XACT_PHASE1;
    OG_RETURN_IFERR(cs_get_int32(packet, &errcode));
    if (errcode != 0) {
        OG_THROW_ERROR(errcode);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

int32 ogconn_xa_prepare(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags, struct timeval *ts)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_xa_prepare_core(conn, xid, flags, ts);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ogconn_xa_commit_core(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags, struct timeval *ts)
{
    OG_RETURN_IFERR(ogconn_xa_commit_phase(CS_CMD_XA_COMMIT, conn, xid, flags, ts));
    CLT_CONN(conn)->xact_status = OGCONN_XACT_END;
    return OG_SUCCESS;
}

int32 ogconn_xa_commit(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags, struct timeval *ts)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_xa_commit_core(conn, xid, flags, ts);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ogconn_xa_rollback_core(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_ROLLBACK;

    OG_RETURN_IFERR(og_pack_xid(packet, xid));
    OG_RETURN_IFERR(cs_put_int64(packet, flags));

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != OG_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return OG_ERROR;
    }
    CLT_CONN(conn)->xact_status = OGCONN_XACT_END;
    return OG_SUCCESS;
}

int32 ogconn_xa_rollback(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_xa_rollback_core(conn, xid, flags);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ogconn_xact_status_core(ogconn_conn_t conn, ogconn_xid_t *xid, ogconn_xact_status_t *status)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_STATUS;

    OG_RETURN_IFERR(og_pack_xid(packet, xid));

    if (clt_remote_call(CLT_CONN(conn), packet, packet) != OG_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return OG_ERROR;
    }

    cs_init_get(packet);
    return cs_get_int32(packet, (int32 *)status);
}

int32 ogconn_xact_status(ogconn_conn_t conn, ogconn_xid_t *xid, ogconn_xact_status_t *status)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    OGCONN_CHECK_OBJECT_NULL_GS(status, "XA STATUS");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_xact_status_core(conn, xid, status);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 og_pack_knl_xid(cs_packet_t *pack, text_t *xid)
{
    CM_CHECK_SEND_PACK_FREE(pack, sizeof(uint32) + CM_ALIGN4(xid->len));

    (void)cs_put_int32(pack, xid->len);
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        *(uint64 *)xid->str = cs_reverse_int64(*(uint64 *)xid->str);
    }
    MEMS_RETURN_IFERR(memcpy_s(CS_WRITE_ADDR(pack), CS_REMAIN_SIZE(pack), xid->str, xid->len));
    pack->head->size += CM_ALIGN4(xid->len);

    return OG_SUCCESS;
}

static inline int32 ogconn_async_xa_rollback_core(ogconn_conn_t conn, text_t *xid, uint64 flags)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = CS_CMD_XA_ROLLBACK;

    CS_SERIAL_NUMBER_INC(CLT_CONN(conn), packet);
    OG_RETURN_IFERR(og_pack_knl_xid(packet, xid));
    OG_RETURN_IFERR(cs_put_int64(packet, flags));

    if (cs_write(&CLT_CONN(conn)->pipe, packet) != OG_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return OG_ERROR;
    }
    CLT_CONN(conn)->xact_status = OGCONN_XACT_END;
    return OG_SUCCESS;
}

int32 ogconn_async_xa_rollback(ogconn_conn_t conn, const text_t *xid, uint64 flags)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_async_xa_rollback_core(conn, (text_t *)xid, flags);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ogconn_xa_async_commit_phase(uint8 cmd, ogconn_conn_t conn, text_t *xid, uint64 flags, uint64 *scn)
{
    cs_packet_t *packet = &CLT_CONN(conn)->pack;

    cs_init_set(packet, CLT_CONN(conn)->call_version);
    packet->head->cmd = cmd;

    CS_SERIAL_NUMBER_INC(CLT_CONN(conn), packet);
    OG_RETURN_IFERR(og_pack_knl_xid(packet, xid));
    OG_RETURN_IFERR(cs_put_int64(packet, flags));

    if (scn != NULL) {
        packet->head->flags |= CS_FLAG_WITH_TS;
        OG_RETURN_IFERR(cs_put_scn(packet, scn));
    }

    if (cs_write(&CLT_CONN(conn)->pipe, packet) != OG_SUCCESS) {
        clt_copy_local_error(CLT_CONN(conn));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static inline int32 ogconn_async_xa_prepare_core(ogconn_conn_t conn, text_t *xid, uint64 flags, uint64 *scn)
{
    OG_RETURN_IFERR(ogconn_xa_async_commit_phase(CS_CMD_XA_PREPARE, conn, xid, flags, scn));
    CLT_CONN(conn)->xact_status = OGCONN_XACT_PHASE1;
    return OG_SUCCESS;
}

int32 ogconn_async_xa_prepare(ogconn_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_async_xa_prepare_core(conn, (text_t *)xid, flags, scn);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ogconn_async_xa_commit_core(ogconn_conn_t conn, text_t *xid, uint64 flags, uint64 *scn)
{
    OG_RETURN_IFERR(ogconn_xa_async_commit_phase(CS_CMD_XA_COMMIT, conn, xid, flags, scn));
    CLT_CONN(conn)->xact_status = OGCONN_XACT_END;
    return OG_SUCCESS;
}

int32 ogconn_async_xa_commit(ogconn_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_GS(xid, "XID");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_async_xa_commit_core(conn, (text_t *)xid, flags, scn);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ogconn_async_xa_prepare_ack_core(ogconn_conn_t conn, uint64 *ack_scn)
{
    int32 errcode;
    cs_packet_t *pack = &CLT_CONN(conn)->pack;

    OG_RETURN_IFERR(clt_async_get_ack(CLT_CONN(conn), pack));

    cs_init_get(pack);
    if (CS_XACT_WITH_TS(pack->head->flags)) {
        OG_RETURN_IFERR(cs_get_scn(pack, ack_scn));
    }
    OG_RETURN_IFERR(cs_get_int32(pack, &errcode));
    if (errcode != 0) {
        OG_THROW_ERROR(errcode);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

int32 ogconn_async_xa_prepare_ack(ogconn_conn_t conn, uint64 *ack_scn)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_async_xa_prepare_ack_core(conn, ack_scn);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

static inline int32 ogconn_async_xa_commit_ack_core(ogconn_conn_t conn, uint64 *ack_scn)
{
    cs_packet_t *pack = &CLT_CONN(conn)->pack;

    OG_RETURN_IFERR(clt_async_get_ack(CLT_CONN(conn), pack));

    cs_init_get(pack);
    if (CS_XACT_WITH_TS(pack->head->flags)) {
        OG_RETURN_IFERR(cs_get_scn(pack, ack_scn));
    }
    return OG_SUCCESS;
}

int32 ogconn_async_xa_commit_ack(ogconn_conn_t conn, uint64 *ack_scn)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = ogconn_async_xa_commit_ack_core(conn, ack_scn);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}

int32 ogconn_async_xa_rollback_ack(ogconn_conn_t conn)
{
    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");
    clt_reset_error((clt_conn_t *)conn);
    OG_RETURN_IFERR(clt_lock_conn(CLT_CONN(conn)));
    int32 ret = clt_async_get_ack(CLT_CONN(conn), &CLT_CONN(conn)->pack);
    clt_unlock_conn(CLT_CONN(conn));
    return ret;
}
