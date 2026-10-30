#include "knl_tran.h"
#include "dtc_txn_hot.h"
#include "dtc_drc.h"
#include "dtc_context.h"
#include "dtc_remote_buffer.h"
#include "dtc_shmem_scn.h"
#include "knl_database.h"
#include "rc_reform.h"

#define DTC_TXN_HOT_WAIT_FLUSH_INTERVAL 1  /* unit: ms */

typedef struct st_dtc_txn_hot_stat_internal {
    atomic_t info_hot;
    atomic_t info_remote;
    atomic_t snapshot_hot;
    atomic_t snapshot_remote;
    atomic_t info_resolve_fail;
} dtc_txn_hot_stat_internal_t;

static dtc_txn_hot_stat_internal_t g_dtc_txn_hot_stat;

void dtc_txn_hot_stat_inc(dtc_txn_hot_stat_type_t type)
{
    switch (type) {
        case DTC_TXN_HOT_STAT_INFO_HOT:
            (void)cm_atomic_inc(&g_dtc_txn_hot_stat.info_hot);
            break;
        case DTC_TXN_HOT_STAT_INFO_REMOTE:
            (void)cm_atomic_inc(&g_dtc_txn_hot_stat.info_remote);
            break;
        case DTC_TXN_HOT_STAT_SNAPSHOT_HOT:
            (void)cm_atomic_inc(&g_dtc_txn_hot_stat.snapshot_hot);
            break;
        case DTC_TXN_HOT_STAT_SNAPSHOT_REMOTE:
            (void)cm_atomic_inc(&g_dtc_txn_hot_stat.snapshot_remote);
            break;
        case DTC_TXN_HOT_STAT_INFO_RESOLVE_FAIL:
            (void)cm_atomic_inc(&g_dtc_txn_hot_stat.info_resolve_fail);
            break;
        default:
            break;
    }
}

void dtc_txn_hot_stat_get(dtc_txn_hot_stat_t *stat)
{
    if (stat == NULL) {
        return;
    }
    stat->info_hot = (uint64)cm_atomic_get(&g_dtc_txn_hot_stat.info_hot);
    stat->info_remote = (uint64)cm_atomic_get(&g_dtc_txn_hot_stat.info_remote);
    stat->snapshot_hot = (uint64)cm_atomic_get(&g_dtc_txn_hot_stat.snapshot_hot);
    stat->snapshot_remote = (uint64)cm_atomic_get(&g_dtc_txn_hot_stat.snapshot_remote);
    stat->info_resolve_fail = (uint64)cm_atomic_get(&g_dtc_txn_hot_stat.info_resolve_fail);
}

static inline dtc_txn_hot_hdr_t *hot_hdr(remote_sga_t *sga, uint32 inst)
{
    if (inst >= OG_MAX_INSTANCES || sga->remote_buf_addr[inst] == NULL || sga->txn_hot_offset == 0) return NULL;
    return (dtc_txn_hot_hdr_t *)(sga->remote_buf_addr[inst] + sga->txn_hot_offset);
}

static inline dtc_txn_hot_t *hot_slot(remote_sga_t *sga, uint32 inst, uint32 index)
{
    dtc_txn_hot_hdr_t *h = hot_hdr(sga, inst);
    if (h == NULL || index >= h->txn_cap_per_inst) return NULL;
    char *base = sga->remote_buf_addr[inst] + sga->txn_hot_offset + h->header_size;
    return (dtc_txn_hot_t *)base + index;
}

static inline uint64 hot_layout_fingerprint(uint64 offset, uint64 size, uint32 segs, uint32 cap, uint32 page_size)
{
    return offset ^ (size << 7) ^ ((uint64)segs << 32) ^ cap ^ ((uint64)page_size << 16);
}

static bool32 hot_header_valid(knl_session_t *session, remote_sga_t *sga, dtc_txn_hot_hdr_t *h)
{
    uint32 segs = session->kernel->attr.undo_segments;
    uint32 total_cap = (uint32)(session->kernel->attr.tran_buf_size / sizeof(tx_item_t));
    uint32 cap;
    uint64 offset;
    uint64 size;

    if (h == NULL || segs == 0 || total_cap == 0 || total_cap % segs != 0) {
        return OG_FALSE;
    }
    cap = total_cap / segs;
    offset = CM_CALC_ALIGN(drc_get_shmem_scn_offset(sga) + SHMEM_SCN_SIZE, 64);
    size = sizeof(dtc_txn_hot_hdr_t) + (uint64)total_cap * sizeof(dtc_txn_hot_t);

    return h->magic == DTC_TXN_HOT_MAGIC && h->layout_ver == DTC_TXN_HOT_LAYOUT_VER &&
        h->header_size == sizeof(dtc_txn_hot_hdr_t) && h->hot_slot_size == sizeof(dtc_txn_hot_t) &&
        h->undo_segments == segs && h->capacity_per_seg == cap && h->txn_cap_per_inst == total_cap &&
        h->page_size == session->kernel->attr.page_size && h->txn_hot_offset == offset &&
        h->region_size == size && sga->txn_hot_offset == offset && sga->txn_hot_region_size == size &&
        h->layout_fingerprint == hot_layout_fingerprint(offset, size, segs, cap,
            session->kernel->attr.page_size);
}

bool32 dtc_txn_hot_enabled(knl_session_t *session)
{
    return (session != NULL && DB_IS_CLUSTER(session) && session->kernel->attr.enable_ubsmem) ? OG_TRUE : OG_FALSE;
}

static inline uint64 hot_pack(uint32 xnum, uint16 rmid, uint8 status, uint8 progress)
{
    return (uint64)xnum | ((uint64)rmid << 32) | ((uint64)status << 48) | ((uint64)progress << 56);
}

static void hot_publish_locked(dtc_txn_hot_t *slot, txn_t *txn, tx_item_t *item, uint64 end_lsn)
{
    uint64 slot_end_lsn;

    if (txn->status == (uint8)XACT_BEGIN) {
        slot_end_lsn = 0;
    } else if (end_lsn != 0) {
        slot_end_lsn = end_lsn;
    } else {
        slot_end_lsn = (uint64)cm_atomic_get(&slot->end_lsn);
    }

    (void)cm_atomic_inc(&slot->seq);
    CM_MFENCE;
    (void)cm_atomic_set(&slot->scn, (int64)txn->scn);
    (void)cm_atomic_set(&slot->pack, (int64)hot_pack(txn->xnum, item->rmid, txn->status, item->in_progress));
    (void)cm_atomic_set(&slot->end_lsn, (int64)slot_end_lsn);
    CM_MFENCE;
    (void)cm_atomic_inc(&slot->seq);
}

void dtc_txn_hot_publish_item_locked(knl_session_t *session, tx_item_t *item, txn_t *txn, uint64 end_lsn)
{
    remote_sga_t *sga;
    dtc_txn_hot_hdr_t *h;
    undo_set_t *set;
    undo_t *undo;
    tx_id_t id;
    uint32 index;
    if (!dtc_txn_hot_enabled(session) || item == NULL || txn == NULL ||
        XMAP_INST_ID(item->xmap) != session->kernel->id) {
        return;
    }
    sga = &DRC_RES_CTX->remote_sga;
    h = hot_hdr(sga, session->kernel->id);
    if (!hot_header_valid(session, sga, h)) {
        OG_LOG_RUN_ERR("[TXN_HOT] publish skipped: invalid header, inst_id=%u, header=%p",
            session->kernel->id, (void *)h);
        return;
    }
    set = UNDO_SET(session, session->kernel->id);
    id = tx_xmap_get_txid(session, item->xmap);
    if (id.seg_id >= h->undo_segments) {
        OG_LOG_RUN_ERR("[TXN_HOT] publish skipped: invalid seg_id=%u, undo_segments=%u",
            id.seg_id, h->undo_segments);
        return;
    }
    undo = &set->undos[id.seg_id];
    if (undo->capacity != h->capacity_per_seg || id.item_id >= h->capacity_per_seg) {
        OG_LOG_RUN_ERR("[TXN_HOT] publish skipped: capacity mismatch or invalid item_id, seg_id=%u, "
            "item_id=%u, undo_capacity=%u, hot_capacity=%u",
            id.seg_id, id.item_id, undo->capacity, h->capacity_per_seg);
        return;
    }
    index = id.seg_id * h->capacity_per_seg + id.item_id;
    dtc_txn_hot_t *slot = hot_slot(sga, session->kernel->id, index);
    if (slot == NULL) return;
    hot_publish_locked(slot, txn, item, end_lsn);
}

void dtc_txn_hot_publish_item(knl_session_t *session, tx_item_t *item, txn_t *txn, uint64 end_lsn)
{
    if (!dtc_txn_hot_enabled(session) || item == NULL || txn == NULL) {
        return;
    }
    cm_spin_lock(&item->lock, &session->stat->spin_stat.stat_txn);
    dtc_txn_hot_publish_item_locked(session, item, txn, end_lsn);
    cm_spin_unlock(&item->lock);
}

static uint64 hot_region_size_bytes(uint32 undo_segments, uint64 tran_buf_size)
{
    uint32 total_cap;
    uint32 cap;

    if (undo_segments == 0 || tran_buf_size < sizeof(tx_item_t)) {
        return 0;
    }
    total_cap = (uint32)(tran_buf_size / sizeof(tx_item_t));
    if (total_cap == 0 || total_cap % undo_segments != 0) {
        return 0;
    }
    cap = total_cap / undo_segments;
    return sizeof(dtc_txn_hot_hdr_t) + (uint64)cap * undo_segments * sizeof(dtc_txn_hot_t);
}

uint64 dtc_txn_hot_pool_layout_end(const remote_sga_t *sga, uint32 undo_segments, uint64 tran_buf_size)
{
    uint64 layout_end = drc_get_shmem_scn_offset(sga) + SHMEM_SCN_SIZE;
    uint64 hot_size = hot_region_size_bytes(undo_segments, tran_buf_size);

    if (hot_size == 0) {
        return layout_end;
    }
    return CM_CALC_ALIGN(layout_end, 64) + hot_size;
}

void dtc_txn_hot_rebuild(knl_session_t *session, undo_set_t *set, uint32 lseg_no, uint32 rseg_no)
{
    uint32 seg, id;
    if (!dtc_txn_hot_enabled(session) || set == NULL || set->inst_id != session->kernel->id) {
        return;
    }
    for (seg = lseg_no; seg < rseg_no; seg++) {
        undo_t *undo = &set->undos[seg];
        for (id = 0; id < undo->capacity; id++) {
            dtc_txn_hot_t *slot;
            txn_t *txn = txn_addr(session, undo->items[id].xmap);

            slot = hot_slot(&DRC_RES_CTX->remote_sga, session->kernel->id, seg * undo->capacity + id);
            if (slot != NULL) {
                hot_publish_locked(slot, txn, &undo->items[id], 0);
            }
        }
    }
    if (rseg_no == session->kernel->attr.undo_segments) {
        (void)shmem_scn_rebind_if_needed();
    }
}

typedef struct st_txn_hot_read {
    txn_snapshot_t snap;
    uint64 end_lsn;
} txn_hot_read_t;

static status_t hot_read(dtc_txn_hot_t *slot, txn_hot_read_t *out)
{
    uint64 s0, s1, pack;
    uint32 retry = 0;
    do {
        s0 = cm_atomic_get(&slot->seq);
        if (s0 & 1) continue;
        CM_MFENCE;
        out->snap.scn = cm_atomic_get(&slot->scn);
        pack = cm_atomic_get(&slot->pack);
        out->end_lsn = (uint64)cm_atomic_get(&slot->end_lsn);
        CM_MFENCE;
        s1 = cm_atomic_get(&slot->seq);
        if (s0 == s1) {
            out->snap.xnum = (uint32)pack;
            out->snap.rmid = (uint16)(pack >> 32);
            out->snap.status = (uint8)(pack >> 48);
            out->snap.in_progress = (uint8)(pack >> 56);
            return OG_SUCCESS;
        }
    } while (++retry <= DTC_TXN_HOT_MAX_RETRY);
    return OG_ERROR;
}

static bool32 hot_need_wait_flush_log(xid_t xid, const txn_snapshot_t *snap, const txn_info_t *info)
{
    if (info->status == (uint8)XACT_BEGIN) {
        return OG_FALSE;
    }
    /* one-generation reuse: old xid END is inferred from the next BEGIN slot. */
    if (xid.xnum + 1 == snap->xnum && snap->status == (uint8)XACT_BEGIN) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static status_t hot_wait_flush_log(knl_session_t *session, uint8 owner, uint64 end_lsn)
{
    remote_sga_t *sga = &DRC_RES_CTX->remote_sga;
    cluster_view_t view;
    uint64 flush_lsn;

    if (end_lsn == 0) {
        return OG_ERROR;
    }
    /* node_flush_lsn is not maintained in no-CMS mode */
    if (DB_CLUSTER_NO_CMS) {
        return OG_ERROR;
    }
    if (!sga->map_success[owner] && dtc_mmap_remote_data_buf(sga, owner) != OG_SUCCESS) {
        return OG_ERROR;
    }

    rc_get_cluster_view(&view, OG_FALSE);
    if (!rc_bitmap64_exist(&view.bitmap, owner)) {
        return OG_ERROR;
    }

    knl_begin_session_wait(session, DTC_WAIT_PEER_FLUSH_LSN, OG_TRUE);
    for (;;) {
        flush_lsn = drc_get_node_flush_lsn(sga, owner);
        if (flush_lsn >= end_lsn) {
            knl_end_session_wait(session, DTC_WAIT_PEER_FLUSH_LSN);
            return OG_SUCCESS;
        }

        if (RC_REFORM_IN_PROGRESS) {
            knl_end_session_wait(session, DTC_WAIT_PEER_FLUSH_LSN);
            return OG_ERROR;
        }

        rc_get_cluster_view(&view, OG_FALSE);
        if (!rc_bitmap64_exist(&view.bitmap, owner)) {
            knl_end_session_wait(session, DTC_WAIT_PEER_FLUSH_LSN);
            return OG_ERROR;
        }

        cm_sleep(DTC_TXN_HOT_WAIT_FLUSH_INTERVAL);
    }
}

status_t dtc_txn_hot_region_init(remote_sga_t *sga)
{
    uint32 self = g_instance->kernel.id;
    uint32 segs = g_instance->kernel.attr.undo_segments;
    uint32 total_cap = (uint32)(g_instance->kernel.attr.tran_buf_size / sizeof(tx_item_t));
    uint32 cap = (segs == 0) ? 0 : total_cap / segs;
    uint64 size = hot_region_size_bytes(segs, g_instance->kernel.attr.tran_buf_size);
    dtc_txn_hot_hdr_t *h;
    if (sga == NULL || sga->remote_buf_addr[self] == NULL || segs == 0 || cap == 0 || cap * segs != total_cap) return OG_ERROR;
    sga->txn_hot_offset = CM_CALC_ALIGN(drc_get_shmem_scn_offset(sga) + SHMEM_SCN_SIZE, 64);
    if (sga->txn_hot_offset + size > sga->remote_total_pool_size) return OG_ERROR;
    h = hot_hdr(sga, self);
    knl_reset_large_memory((char *)h, size);
    h->magic = DTC_TXN_HOT_MAGIC; h->layout_ver = DTC_TXN_HOT_LAYOUT_VER;
    h->header_size = sizeof(dtc_txn_hot_hdr_t); h->hot_slot_size = sizeof(dtc_txn_hot_t);
    h->undo_segments = segs; h->capacity_per_seg = cap; h->txn_cap_per_inst = cap * segs;
    h->page_size = g_instance->kernel.attr.page_size; h->txn_hot_offset = sga->txn_hot_offset; h->region_size = size;
    h->layout_fingerprint = hot_layout_fingerprint(sga->txn_hot_offset, size, segs, cap, h->page_size);
    sga->txn_hot_region_size = size;
    sga->remote_pool_reserve_offset = sga->txn_hot_offset + size;
    (void)shmem_scn_rebind_if_needed();
    return OG_SUCCESS;
}

static status_t hot_get_info_from_snapshot(knl_session_t *session, bool32 is_scan, xid_t xid,
    const txn_snapshot_t *snapshot, txn_info_t *info)
{
    info->xid.xmap = xid.xmap;
    info->xid.xnum = snapshot->xnum;
    info->is_owscn = OG_FALSE;

    if (xid.xnum == snapshot->xnum) {
        if (snapshot->status == (uint8)XACT_PHASE1 || snapshot->status == (uint8)XACT_PHASE2) {
            info->scn = snapshot->scn;
            info->status = (uint8)snapshot->status;
        } else if (snapshot->status != (uint8)XACT_END || (snapshot->in_progress && !is_scan)) {
            info->scn = DB_CURR_SCN(session);
            info->status = (uint8)XACT_BEGIN;
        } else {
            info->scn = snapshot->scn;
            info->status = (uint8)XACT_END;
        }
    } else if (xid.xnum + 1 == snapshot->xnum && snapshot->status == (uint8)XACT_BEGIN) {
        info->scn = snapshot->scn;
        info->status = (uint8)XACT_END;
    } else {
        dtc_txn_hot_stat_inc(DTC_TXN_HOT_STAT_INFO_RESOLVE_FAIL);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t hot_fetch_by_xmap(knl_session_t *session, xmap_t xmap, uint8 owner, txn_hot_read_t *out)
{
    remote_sga_t *sga = &DRC_RES_CTX->remote_sga;
    dtc_txn_hot_hdr_t *h;
    dtc_txn_hot_t *slot;
    tx_id_t id = tx_xmap_get_txid(session, xmap);

    if (!dtc_txn_hot_enabled(session) || owner >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }
    (void)shmem_scn_rebind_if_needed();
    if (!sga->map_success[owner] && dtc_mmap_remote_data_buf(sga, owner) != OG_SUCCESS) {
        return OG_ERROR;
    }
    h = hot_hdr(sga, owner);
    if (!hot_header_valid(session, sga, h) || id.seg_id >= h->undo_segments ||
        id.item_id >= h->capacity_per_seg) {
        return OG_ERROR;
    }
    slot = hot_slot(sga, owner, id.seg_id * h->capacity_per_seg + id.item_id);
    if (slot == NULL || hot_read(slot, out) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t dtc_get_txn_snapshot_from_hot(knl_session_t *session, xmap_t xmap, uint8 owner,
    txn_snapshot_t *snapshot)
{
    txn_hot_read_t hot_read_out;

    if (hot_fetch_by_xmap(session, xmap, owner, &hot_read_out) != OG_SUCCESS) {
        return OG_ERROR;
    }
    *snapshot = hot_read_out.snap;
    dtc_txn_hot_stat_inc(DTC_TXN_HOT_STAT_SNAPSHOT_HOT);
    return OG_SUCCESS;
}

status_t dtc_get_txn_info_from_hot(knl_session_t *session, bool32 is_scan, xid_t xid, uint8 owner, txn_info_t *info)
{
    txn_hot_read_t hot_read_out;
    txn_snapshot_t *snap = &hot_read_out.snap;

    if (hot_fetch_by_xmap(session, xid.xmap, owner, &hot_read_out) != OG_SUCCESS) {
        return OG_ERROR;
    }
    /* A slot that has advanced by more than one generation cannot identify
     * this xid from HOT safely; let the MES path resolve the old transaction. */
    if (xid.xnum > snap->xnum ||
        (snap->xnum > xid.xnum && snap->xnum - xid.xnum > 1)) {
        return OG_ERROR;
    }
    if (hot_get_info_from_snapshot(session, is_scan, xid, snap, info) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (hot_need_wait_flush_log(xid, snap, info) &&
        hot_wait_flush_log(session, owner, hot_read_out.end_lsn) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (info->status == XACT_BEGIN) {
        info->scn = DB_CURR_SCN(session);
    } else if (DB_IS_PRIMARY(&session->kernel->db) && info->status == XACT_END && !info->is_owscn) {
        DB_SET_CURR_SCN(session, info->scn);
    }
    dtc_txn_hot_stat_inc(DTC_TXN_HOT_STAT_INFO_HOT);
    return OG_SUCCESS;
}
