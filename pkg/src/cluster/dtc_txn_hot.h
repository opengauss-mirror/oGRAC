#ifndef DTC_TXN_HOT_H
#define DTC_TXN_HOT_H

#include "cm_atomic.h"
#include "knl_tran.h"
typedef struct st_remote_sga remote_sga_t;

#define DTC_TXN_HOT_MAGIC 0x544E4832U
#define DTC_TXN_HOT_LAYOUT_VER 3U
#define DTC_TXN_HOT_MAX_RETRY 32U

typedef struct st_dtc_txn_hot {
    atomic_t seq;
    atomic_t scn;
    atomic_t pack;
    atomic_t end_lsn;
    uint8 padding[32];
} dtc_txn_hot_t;

typedef struct st_dtc_txn_hot_hdr {
    uint32 magic;
    uint32 layout_ver;
    uint32 header_size;
    uint32 hot_slot_size;
    uint32 undo_segments;
    uint32 capacity_per_seg;
    uint32 txn_cap_per_inst;
    uint32 page_size;
    uint64 txn_hot_offset;
    uint64 region_size;
    uint64 layout_fingerprint;
    atomic_t ready;
} dtc_txn_hot_hdr_t;

typedef enum en_dtc_txn_hot_stat_type {
    DTC_TXN_HOT_STAT_INFO_HOT = 0,
    DTC_TXN_HOT_STAT_INFO_REMOTE,
    DTC_TXN_HOT_STAT_SNAPSHOT_HOT,
    DTC_TXN_HOT_STAT_SNAPSHOT_REMOTE,
    DTC_TXN_HOT_STAT_INFO_RESOLVE_FAIL,
    DTC_TXN_HOT_STAT_CEIL
} dtc_txn_hot_stat_type_t;

typedef struct st_dtc_txn_hot_stat {
    uint64 info_hot;
    uint64 info_remote;
    uint64 snapshot_hot;
    uint64 snapshot_remote;
    uint64 info_resolve_fail;
} dtc_txn_hot_stat_t;

status_t dtc_txn_hot_region_init(remote_sga_t *remote_sga);
uint64 dtc_txn_hot_pool_layout_end(const remote_sga_t *sga, uint32 undo_segments, uint64 tran_buf_size);
void dtc_txn_hot_rebuild(knl_session_t *session, undo_set_t *undo_set, uint32 lseg_no, uint32 rseg_no);
void dtc_txn_hot_publish_item_locked(knl_session_t *session, tx_item_t *item, txn_t *txn, uint64 end_lsn);
void dtc_txn_hot_publish_item(knl_session_t *session, tx_item_t *item, txn_t *txn, uint64 end_lsn);
status_t dtc_get_txn_info_from_hot(knl_session_t *session, bool32 is_scan, xid_t xid,
    uint8 owner_inst, txn_info_t *txn_info);
status_t dtc_get_txn_snapshot_from_hot(knl_session_t *session, xmap_t xmap, uint8 owner_inst,
    txn_snapshot_t *snapshot);
bool32 dtc_txn_hot_enabled(knl_session_t *session);
void dtc_txn_hot_stat_inc(dtc_txn_hot_stat_type_t type);
void dtc_txn_hot_stat_get(dtc_txn_hot_stat_t *stat);

#endif
