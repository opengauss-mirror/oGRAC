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
 * knl_ckpt.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_ckpt.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_persist_module.h"
#include "knl_ckpt.h"
#include "cm_log.h"
#include "cm_file.h"
#include "knl_buflatch.h"
#include "knl_ctrl_restore.h"
#include "zstd.h"
#include "knl_space_ddl.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "dtc_dcs.h"
#include "dtc_ckpt.h"

#define NEED_SYNC_LOG_INFO(ogx) ((ogx)->timed_task != CKPT_MODE_IDLE || (ogx)->trigger_task == CKPT_TRIGGER_FULL)

#define CKPT_WAIT_ENABLE_MS 2
#define CKPT_FLUSH_WAIT_MS 10
extern dtc_rcy_replay_paral_node_t g_replay_paral_mgr;
static uint8 g_page_clean_finish_flag[PAGE_CLEAN_MAX_BYTES] = {0};
bool32 g_crc_verify = 0;

void ckpt_proc(thread_t *thread);
void dbwr_proc(thread_t *thread);
static status_t ckpt_perform(knl_session_t *session, ckpt_stat_items_t *stat);
static void ckpt_page_clean(knl_session_t *session, ckpt_stat_items_t *stat);

static inline void init_ckpt_part_group(knl_session_t *session)
{
    if (cm_dbs_is_enable_dbs() == OG_FALSE || cm_dbs_is_enable_batch_flush() == OG_FALSE) {
        return;
    }
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ogx = &kernel->ckpt_ctx;
    for (uint32 i = 0; i < cm_dbs_get_part_num(); i++) {
        ogx->ckpt_part_group[i].count = 0;
    }
}

static inline uint64 ckpt_stat_time_diff(uint64 begin_time, uint64 end_time)
{
    if (end_time > begin_time) {
        return (end_time - begin_time);
    }
    return 0;
}

static inline void ckpt_param_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ogx = &kernel->ckpt_ctx;

    ogx->dbwr_count = kernel->attr.dbwr_processes;
    ogx->double_write = kernel->attr.enable_double_write;
}

status_t dbwr_aio_init(knl_session_t *session, dbwr_context_t *dbwr)
{
    knl_instance_t *kernel = session->kernel;
    errno_t ret;

    if (!session->kernel->attr.enable_asynch) {
        return OG_SUCCESS;
    }

    ret = memset_sp(&dbwr->async_ctx.aio_ctx, sizeof(cm_io_context_t), 0, sizeof(cm_io_context_t));
    knl_securec_check(ret);

    if (cm_aio_setup(&kernel->aio_lib, OG_CKPT_GROUP_SIZE(session), &dbwr->async_ctx.aio_ctx) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[CKPT]: setup asynchronous I/O context failed, errno %d", errno);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t dbwr_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ogx = &kernel->ckpt_ctx;
    dbwr_context_t *dbwr = NULL;
    errno_t ret;

    for (uint32 i = 0; i < ogx->dbwr_count; i++) {
        dbwr = &ogx->dbwr[i];
        dbwr->dbwr_trigger = OG_FALSE;
        dbwr->session = kernel->sessions[SESSION_ID_DBWR];
        ret = memset_sp(&dbwr->datafiles, OG_MAX_DATA_FILES * sizeof(int32), 0xFF, OG_MAX_DATA_FILES * sizeof(int32));
        knl_securec_check(ret);
#ifdef WIN32
        dbwr->sem = CreateSemaphore(NULL, 0, 1, NULL);
#else
        sem_init(&dbwr->sem, 0, 0);

        if (dbwr_aio_init(session, dbwr) != OG_SUCCESS) {
            return OG_ERROR;
        }
#endif  // WIN32
    }

    return OG_SUCCESS;
}

status_t ckpt_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ogx = &kernel->ckpt_ctx;
    errno_t ret;

    ret = memset_sp(ogx, sizeof(ckpt_context_t), 0, sizeof(ckpt_context_t));
    knl_securec_check(ret);

    ckpt_param_init(session);

    cm_init_cond(&ogx->ckpt_cond);

    ogx->group.buf = kernel->attr.ckpt_buf;
    ogx->ckpt_enabled = OG_TRUE;
    ogx->trigger_task = CKPT_MODE_IDLE;
    ogx->timed_task = CKPT_MODE_IDLE;
    ogx->trigger_finish_num = 0;
    ogx->stat.proc_wait_cnt = 0;
    ogx->full_trigger_active_num = 0;
    ogx->dw_file = -1;
    ogx->batch_end = NULL;
    ogx->clean_end = NULL;
    ogx->ckpt_blocked = OG_FALSE;
    OG_INIT_SPIN_LOCK(ogx->disable_lock);
    ogx->disable_cnt = 0;
    ogx->ckpt_enable_update_point = OG_TRUE;
    ogx->disable_update_point_cnt = 0;

    if (dbwr_init(session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (kernel->attr.enable_asynch) {
        if (DB_IS_CLUSTER(session)) {
            ogx->group.iocbs_buf = (char *)malloc(OG_CKPT_GROUP_SIZE(session) * CM_IOCB_LENTH_EX);
        } else {
            ogx->group.iocbs_buf = (char *)malloc(OG_CKPT_GROUP_SIZE(session) * CM_IOCB_LENTH);
        }

        if (ogx->group.iocbs_buf == NULL) {
            OG_LOG_RUN_ERR("[CKPT] iocb malloc fail");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

void ckpt_load(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ogx = &kernel->ckpt_ctx;

    ogx->lrp_point = dtc_my_ctrl(session)->lrp_point;

    ogx->edp_group.count = 0;
    ogx->remote_edp_group.count = 0;
    ogx->remote_edp_clean_group.count = 0;
    ogx->local_edp_clean_group.count = 0;
    ogx->edp_group.lock = 0;
    ogx->remote_edp_group.lock = 0;
    ogx->remote_edp_clean_group.lock = 0;
    ogx->local_edp_clean_group.lock = 0;
}

void ckpt_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ogx = &kernel->ckpt_ctx;

#ifndef WIN32
    ogx->thread.closed = OG_TRUE;
#endif

    cm_close_thread(&ogx->thread);
    for (uint32 i = 0; i < ogx->dbwr_count; i++) {
#ifndef WIN32
        ogx->dbwr[i].thread.closed = OG_TRUE;
        ogx->dbwr[i].dbwr_trigger = OG_TRUE;
        (void)sem_post(&ogx->dbwr[i].sem);
#endif
        cm_close_thread(&ogx->dbwr[i].thread);
    }
    cm_close_file(ogx->dw_file);
    ogx->dw_file = OG_INVALID_HANDLE;
#ifndef WIN32
    if (ogx->group.iocbs_buf != NULL) {
        free(ogx->group.iocbs_buf);
        ogx->group.iocbs_buf = NULL;
    }
#endif
}

static void ckpt_update_log_point(knl_session_t *session)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_point_t last_point = session->kernel->redo_ctx.curr_point;

    /*
     * when recovering file in mount status, ckpt can't update log point because there are only dirty pages
     * of the file to recover in queue.
     */
    if (IS_FILE_RECOVER(session)) {
        return;
    }

    if (ogx->queue.count != 0) {
        dtc_node_ctrl_t *ctrl = dtc_my_ctrl(session);
        cm_spin_lock(&ogx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
        ctrl->rcy_point = ogx->queue.first->trunc_point;
        if (DB_IS_CLUSTER(session) && log_cmp_point(&ogx->lrp_point, &ctrl->rcy_point) < 0) {
            ogx->lrp_point = ctrl->rcy_point;
            ctrl->lrp_point = ctrl->rcy_point;
        }
        cm_spin_unlock(&ogx->queue.lock);
        return;
    }

    /*
     * We can not directly set rcy_point to lrp_point when ckpt queue is empty.
     * Because it doesn't mean all dirty pages have been flushed to disk.
     * Only after database has finished recovery job can we set rcy_point to lrp_point,
     * which means database status is ready or recover_for_restore has been set to true.
     */
    if (!DB_NOT_READY(session) || session->kernel->db.recover_for_restore) {
        if (RCY_IGNORE_CORRUPTED_LOG(rcy) && last_point.lfn < ogx->lrp_point.lfn) {
            dtc_my_ctrl(session)->rcy_point = last_point;
            return;
        }

        /*
         * Logical logs do not generate dirty pages, so lfn of lrp_point could be less than trunc_point_snapshot_lfn
         * probablely. In this scenario, we should set rcy_point to lrp_point still.
         */
        if (DB_IS_READONLY(session) && ogx->trunc_point_snapshot.lfn < ogx->lrp_point.lfn) {
            dtc_my_ctrl(session)->rcy_point = ogx->trunc_point_snapshot;
            return;
        }

        if (log_cmp_point(&(dtc_my_ctrl(session)->rcy_point), &(ogx->lrp_point)) <= 0) {
            dtc_my_ctrl(session)->rcy_point = ogx->lrp_point;
            dtc_my_ctrl(session)->consistent_lfn = ogx->lrp_point.lfn;
        }
    }
}

void ckpt_update_log_point_slave_role(knl_session_t *session)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    uint32 curr_node_idx = 0;
 
    /*
     * when recovering file in mount status, ckpt can't update log point because there are only dirty pages
     * of the file to recover in queue.
     */
    if (IS_FILE_RECOVER(session)) {
        return;
    }

    if (ogx->trigger_task == CKPT_TRIGGER_FULL_STANDBY) {
        for (uint32 i = 0; i < g_dtc->profile.node_count; i++) {
            dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, i);
            if (DB_IS_CLUSTER(session) && log_cmp_point(&g_replay_paral_mgr.rcy_point[i], &ctrl->rcy_point) > 0) {
                ctrl->rcy_point = g_replay_paral_mgr.rcy_point[i];
                if (dtc_save_ctrl(session, i) != OG_SUCCESS) {
                    KNL_SESSION_CLEAR_THREADID(session);
                    CM_ABORT(0, "ABORT INFO: save core control file failed when ckpt update log point");
                }
            }
            OG_LOG_RUN_INF("[CKPT_TRIGGER_FULL_STANDBY] node: %d, ctrl->lfn: %llu, ctrl->lsn: %llu, g_replay_paral_mgr.lfn: %llu, g_replay_paral_mgr.lsn: %llu",
                           i, (uint64)ctrl->rcy_point.lfn, ctrl->rcy_point.lsn,
                               (uint64)g_replay_paral_mgr.rcy_point[i].lfn, g_replay_paral_mgr.rcy_point[i].lsn);
        }
        return;
    }

    if (ogx->queue.count != 0) {
        cm_spin_lock(&ogx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
        curr_node_idx = ogx->queue.first->curr_node_idx;
        dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, curr_node_idx);
        ctrl->rcy_point = ogx->queue.first->trunc_point;
        cm_spin_unlock(&ogx->queue.lock);

        if (dtc_save_ctrl(session, curr_node_idx) != OG_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "ABORT INFO: save core control file failed when ckpt update log point");
        }
    }
}

void ckpt_reset_point(knl_session_t *session, log_point_t *point)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ogx = &kernel->ckpt_ctx;

    dtc_my_ctrl(session)->rcy_point = *point;
    ogx->lrp_point = *point;
    dtc_my_ctrl(session)->lrp_point = *point;

    dtc_my_ctrl(session)->consistent_lfn = point->lfn;
}

static status_t ckpt_save_ctrl(knl_session_t *session)
{
    if (session->kernel->attr.clustered) {
        return dtc_save_ctrl(session, session->kernel->id);
    }

    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}
static void ckpt_remove_clean_page(knl_session_t *session, buf_set_t *set, buf_lru_list_t *page_list)
{
    buf_ctrl_t *shift = NULL;
    cm_spin_lock(&set->write_list.lock, NULL);
    buf_ctrl_t *ctrl = set->write_list.lru_last;
    cm_spin_unlock(&set->write_list.lock);

    while (ctrl != NULL) {
        shift = ctrl;
        ctrl = ctrl->prev;
        if (shift->bucket_id == OG_INVALID_ID32 || (!shift->is_dirty && !shift->is_marked)) {
            buf_stash_marked_page(set, page_list, shift);
        }
    }
}

static void ckpt_remove_clean_page_all_set(knl_session_t *session)
{
    buf_context_t *ogx = &session->kernel->buf_ctx;
    buf_set_t *set = NULL;
    buf_lru_list_t page_list;
    for (uint32 i = 0; i < ogx->buf_set_count; i++) {
        set = &ogx->buf_set[i];
        if (set->write_list.count == 0) {
            continue;
        }

        page_list = g_init_list_t;
        ckpt_remove_clean_page(session, set, &page_list);
        buf_reset_cleaned_pages(set, &page_list);
    }
}

static void ckpt_block_and_wait_enable(ckpt_context_t *ogx)
{
    while (!ogx->ckpt_enabled) {
        ogx->ckpt_blocked = OG_TRUE;
        cm_sleep(CKPT_WAIT_ENABLE_MS);
    }

    ogx->ckpt_blocked = OG_FALSE;
}

static void ckpt_wait_enable_update_point(ckpt_context_t *ogx)
{
    while (ogx->ckpt_enable_update_point == OG_FALSE)
    {
        cm_sleep(CKPT_WAIT_ENABLE_MS);
    }
}
/*
 * trigger full checkpoint to promote rcy point to current point
 */
static void ckpt_full_checkpoint(knl_session_t *session, ckpt_stat_items_t *stat)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    ogx->batch_end = NULL;
    OG_LOG_RUN_INF("start trigger full checkpoint, expect process pages %d", ogx->queue.count);
    uint64 curr_flush_count = stat->flush_pages;
    uint64 curr_clean_edp_count = stat->clean_edp_count;
    uint64 task_begin = KNL_NOW(session);
    stat->ckpt_begin_time = (date_t)task_begin;
    for (;;) {
        if (ogx->thread.closed || (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master() == OG_FALSE)) {
            break;
        }

        buf_ctrl_t *ckpt_first = ogx->queue.first;
        if (ogx->batch_end == NULL) {
            ogx->batch_end = ogx->queue.last;
        }

        if (ckpt_perform(session, stat) != OG_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: redo log task flush redo file failed.");
        }

        uint64 task_perform = KNL_NOW(session);
        stat->perform_us += ckpt_stat_time_diff(task_begin, task_perform);
        ckpt_block_and_wait_enable(ogx);
        ckpt_wait_enable_update_point(ogx);
        uint64 task_wait_1 = KNL_NOW(session);
        stat->wait_us += ckpt_stat_time_diff(task_perform, task_wait_1);
        if (!DB_IS_PRIMARY(&session->kernel->db)) {
            ckpt_update_log_point_slave_role(session);
        } else {
            ckpt_update_log_point(session);
            // Save log point
            if (ckpt_save_ctrl(session) != OG_SUCCESS) {
                KNL_SESSION_CLEAR_THREADID(session);
                CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
            }
        }
        
        uint64 task_save_ctrl_1 = KNL_NOW(session);
        stat->save_contrl_us += ckpt_stat_time_diff(task_wait_1, task_save_ctrl_1);
        log_recycle_file(session, &dtc_my_ctrl(session)->rcy_point);
        OG_LOG_DEBUG_INF("[CKPT] Set rcy point to [%u-%u/%u/%llu] in ctrl for instance %u",
                         dtc_my_ctrl(session)->rcy_point.rst_id, dtc_my_ctrl(session)->rcy_point.asn,
                         dtc_my_ctrl(session)->rcy_point.block_id, (uint64)dtc_my_ctrl(session)->rcy_point.lfn,
                         session->kernel->id);

        /* backup some core ctrl info on datafile head */
        if (ctrl_backup_core_log_info(session) != OG_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: backup core control info failed when perform checkpoint");
        }
        uint64 task_backup = KNL_NOW(session);
        stat->backup_us += ckpt_stat_time_diff(task_save_ctrl_1, task_backup);
        /* maybe someone has been blocked by full ckpt when alloc buffer ctrl */
        if (ckpt_first == ogx->queue.first) {
            ckpt_page_clean(session, stat);
        }
        uint64 task_recycle = KNL_NOW(session);
        stat->recycle_us += ckpt_stat_time_diff(task_backup, task_recycle);
        if (ogx->batch_end != NULL) {
            if (ogx->edp_group.count != 0) {
                uint32 sleep_time = (ogx->edp_group.count / (OG_CKPT_GROUP_SIZE(session) / 2 + 1) + 1) * 3 *
                    CKPT_WAIT_MS;
                cm_sleep(sleep_time);
            }
            continue;
        }
        uint64 task_wait = KNL_NOW(session);
        stat->wait_us += ckpt_stat_time_diff(task_recycle, task_wait);
        if (ckpt_save_ctrl(session) != OG_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        }
        uint64 task_save_ctrl_2 = KNL_NOW(session);
        stat->save_contrl_us += ckpt_stat_time_diff(task_wait, task_save_ctrl_2);
        break;
    }
    ckpt_remove_clean_page_all_set(session);
    uint64 task_end = KNL_NOW(session);
    stat->task_us += ckpt_stat_time_diff(task_begin, task_end);
    stat->task_count++;
    OG_LOG_RUN_INF("Finish trigger full checkpoint, Flush pages %llu, Clean edp count %llu, cost time(us) %llu",
        stat->flush_pages - curr_flush_count,
        stat->clean_edp_count - curr_clean_edp_count, task_end - task_begin);
}

/*
 * trigger inc checkpoint to flush page on ckpt-q as soon as possible
 */
static void ckpt_inc_checkpoint(knl_session_t *session, ckpt_stat_items_t *stat)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    if (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master() == OG_FALSE) {
        return;
    }
    uint64 task_begin = KNL_NOW(session);
    stat->ckpt_begin_time = (date_t)task_begin;
    if (ckpt_perform(session, stat) != OG_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: redo log task flush redo file failed.");
    }
    uint64 task_perform = KNL_NOW(session);
    stat->perform_us += ckpt_stat_time_diff(task_begin, task_perform);
    ckpt_block_and_wait_enable(ogx);
    uint64 task_wait = KNL_NOW(session);
    stat->wait_us += ckpt_stat_time_diff(task_perform, task_wait);
    if (ogx->ckpt_enable_update_point == OG_TRUE)
    {
        if (!DB_IS_PRIMARY(&session->kernel->db)) {
            ckpt_update_log_point_slave_role(session);
        } else {
            ckpt_update_log_point(session);
            // save log point first
            if (ckpt_save_ctrl(session) != OG_SUCCESS) {
                KNL_SESSION_CLEAR_THREADID(session);
                CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
            }
        }
    }
    uint64 task_save_ctrl_1 = KNL_NOW(session);
    stat->save_contrl_us += ckpt_stat_time_diff(task_wait, task_save_ctrl_1);
    log_recycle_file(session, &dtc_my_ctrl(session)->rcy_point);
    OG_LOG_DEBUG_INF("[CKPT] Set rcy point to [%u-%u/%u/%llu] in ctrl for instance %u",
                     dtc_my_ctrl(session)->rcy_point.rst_id, dtc_my_ctrl(session)->rcy_point.asn,
                     dtc_my_ctrl(session)->rcy_point.block_id, (uint64)dtc_my_ctrl(session)->rcy_point.lfn,
                     session->kernel->id);
    uint64 task_recycle = KNL_NOW(session);
    stat->recycle_us += ckpt_stat_time_diff(task_save_ctrl_1, task_recycle);
    /* backup some core info on datafile head: only back up core log info for full ckpt and timed task */
    if (NEED_SYNC_LOG_INFO(ogx) && ctrl_backup_core_log_info(session) != OG_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: backup core control info failed when perform checkpoint");
    }
    uint64 task_backup = KNL_NOW(session);
    stat->backup_us += ckpt_stat_time_diff(task_recycle, task_backup);
    if (ckpt_save_ctrl(session) != OG_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
    }
    uint64 task_end = KNL_NOW(session);
    stat->save_contrl_us += ckpt_stat_time_diff(task_backup, task_end);
    stat->task_us += ckpt_stat_time_diff(task_begin, task_end);
    stat->task_count++;
}

void ckpt_pop_page(knl_session_t *session, ckpt_context_t *ogx, buf_ctrl_t *ctrl)
{
    cm_spin_lock(&ogx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    ogx->queue.count--;

    if (ogx->queue.count == 0) {
        ogx->queue.first = NULL;
        ogx->queue.last = NULL;
    } else {
        if (ctrl->ckpt_prev != NULL) {
            ctrl->ckpt_prev->ckpt_next = ctrl->ckpt_next;
        }

        if (ctrl->ckpt_next != NULL) {
            ctrl->ckpt_next->ckpt_prev = ctrl->ckpt_prev;
        }

        if (ogx->queue.last == ctrl) {
            ogx->queue.last = ctrl->ckpt_prev;
        }

        if (ogx->queue.first == ctrl) {
            ogx->queue.first = ctrl->ckpt_next;
        }
    }

    knl_panic_log(ctrl->in_ckpt == OG_TRUE, "ctrl is not in ckpt, panic info: page %u-%u type %u", ctrl->page_id.file,
                  ctrl->page_id.page, ctrl->page->type);
    ctrl->ckpt_prev = NULL;
    ctrl->ckpt_next = NULL;
    ctrl->in_ckpt = OG_FALSE;

    cm_spin_unlock(&ogx->queue.lock);
}

static void ckpt_assign_trigger_task(knl_session_t *session, trigger_task_t *task_desc)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    uint64_t snap_num = 0;
    
    /* To ensure the trigger_task action is valid, we use white list for debugging */
    for (;;) {
        cm_spin_lock(&ogx->lock, &session->stat->spin_stat.stat_ckpt);
        if (ogx->trigger_task == CKPT_MODE_IDLE && ogx->ckpt_enabled) {
            /* We don not assign inc trigger if there is full_trigger running or waiting */
            if (task_desc->mode != CKPT_TRIGGER_INC || ogx->full_trigger_active_num == 0) {
                snap_num = ogx->trigger_finish_num;
                ogx->trigger_task = task_desc->mode;
                cm_spin_unlock(&ogx->lock);
                break; // success
            }
        }
        cm_spin_unlock(&ogx->lock);

        if (!task_desc->guarantee) {
            return;
        }

        if (task_desc->join && task_desc->mode == ogx->trigger_task) {
             /* task with join should not be set with wait, so directly return. */
            return;
        }
        
        /* We will try again until success.
         * Doing the next try when contition satisfied to decrease lock competition.
         */
        while (ogx->trigger_task != CKPT_MODE_IDLE || !ogx->ckpt_enabled) {
            cm_sleep(1);
        }
    }

    cm_release_cond_signal(&ogx->ckpt_cond); /* send a signal whatever */

    /* Wait for task finished.
     * Note that this is only meaningful for inc and full ckpt task,
     * while clean task always comes with no wait.
     */
    while (task_desc->wait && snap_num == ogx->trigger_finish_num) {
        cm_release_cond_signal(&ogx->ckpt_cond);
        cm_sleep(1);
    }
}

static inline status_t ckpt_assign_timed_task(knl_session_t *session, ckpt_context_t *ogx, ckpt_mode_t mode)
{
    knl_panic (mode == CKPT_TIMED_CLEAN || mode == CKPT_TIMED_INC);

    cm_spin_lock(&ogx->lock, &session->stat->spin_stat.stat_ckpt);
    /* Using lock to ensure corretness in case another
     * thread doing somthing with ckpt_enabled flag.
     */
    if (SECUREC_UNLIKELY(!ogx->ckpt_enabled)) {
        cm_spin_unlock(&ogx->lock);
        return OG_ERROR;
    }
    ogx->timed_task = mode;
    cm_spin_unlock(&ogx->lock);
    return OG_SUCCESS;
}

void ckpt_trigger(knl_session_t *session, bool32 wait, ckpt_mode_t mode)
{
    if (!DB_TO_RECOVERY(session)) {
        return;
    }

    /*
     * The task flags are set to achieve the effects of legacy use.
     * With guarantee flag, we will keep trying until successfully assign the task.
     */
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    trigger_task_t task;
    task.guarantee = OG_FALSE;
    task.join = OG_TRUE;
    task.wait = wait;

    if (mode == CKPT_TRIGGER_FULL || mode == CKPT_TRIGGER_FULL_STANDBY) {
        task.guarantee = OG_TRUE;
        task.join = OG_FALSE;
        (void)cm_atomic_inc(&ogx->full_trigger_active_num);
    }
    
    task.mode = mode;
    ckpt_assign_trigger_task(session, &task);
}

static void ckpt_do_trigger_task(knl_session_t *session, ckpt_context_t *ogx, date_t *clean_time, date_t *ckpt_time)
{
    if (ogx->trigger_task == CKPT_MODE_IDLE) {
        return;
    }

    knl_panic (CKPT_IS_TRIGGER(ogx->trigger_task));
    ckpt_stat_items_t *stat = &ogx->stat.stat_items[ogx->trigger_task];
    switch (ogx->trigger_task) {
        case CKPT_TRIGGER_FULL:
            ckpt_full_checkpoint(session, stat);

            (void)cm_atomic_dec(&ogx->full_trigger_active_num);
            *ckpt_time = KNL_NOW(session);
            break;
        case CKPT_TRIGGER_FULL_STANDBY:
            ckpt_full_checkpoint(session, stat);

            (void)cm_atomic_dec(&ogx->full_trigger_active_num);
            *ckpt_time = KNL_NOW(session);
            break;
        case CKPT_TRIGGER_INC:
            ckpt_inc_checkpoint(session, stat);
            *ckpt_time = KNL_NOW(session);
            break;
        case CKPT_TRIGGER_CLEAN:
            ckpt_page_clean(session, stat);
            *clean_time = KNL_NOW(session);
            stat->task_count++;
            break;
        default:
            /* Not possible, for grammar compliance with switch clause */
            break;
    }

    cm_spin_lock(&ogx->lock, &session->stat->spin_stat.stat_ckpt);
    ogx->trigger_finish_num++;
    ogx->trigger_task = CKPT_MODE_IDLE;
    cm_spin_unlock(&ogx->lock);
}


static void ckpt_do_timed_task(knl_session_t *session, ckpt_context_t *ogx, date_t *clean_time, date_t *ckpt_time)
{
    if (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master() == OG_FALSE) {
        return;
    }
    knl_attr_t *attr = &session->kernel->attr;
    ckpt_stat_items_t *stat;
    if (attr->page_clean_period != 0 &&
        KNL_NOW(session) - (*clean_time) >= (date_t)attr->page_clean_period * MILLISECS_PER_SECOND) {
        if (ckpt_assign_timed_task(session, ogx, CKPT_TIMED_CLEAN) == OG_SUCCESS) {
            stat = &ogx->stat.stat_items[CKPT_TIMED_CLEAN];
            ckpt_page_clean(session, stat);
            *clean_time = KNL_NOW(session);
            stat->task_count++;
            ogx->timed_task = CKPT_MODE_IDLE;
        }
    }

    if (ogx->queue.count + ogx->remote_edp_group.count >= attr->ckpt_interval ||
        ogx->remote_edp_group.count + ogx->local_edp_clean_group.count >= OG_CKPT_EDP_GROUP_SIZE(session) ||
        KNL_NOW(session) - (*ckpt_time) >= (date_t)attr->ckpt_timeout * MICROSECS_PER_SECOND) {
        if (ckpt_assign_timed_task(session, ogx, CKPT_TIMED_INC) == OG_SUCCESS) {
            stat = &ogx->stat.stat_items[CKPT_TIMED_INC];
            ckpt_inc_checkpoint(session, stat);
            *ckpt_time = KNL_NOW(session);
            ogx->timed_task = CKPT_MODE_IDLE;
        }
    }
}

/*
 * ckpt thread handles buffer page clean and full/inc ckpt on following condition:
 * 1.trigger of page clean, inc/full ckpt.
 * 2.page clean or inc ckpt timeout.
 * 3.count of dirty pages on ckpt queue is up to threshold.
 */
void ckpt_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    knl_attr_t *attr = &session->kernel->attr;
    date_t ckpt_time = 0;
    date_t clean_time = 0;

    cm_set_thread_name("ckpt");
    OG_LOG_RUN_INF("ckpt thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    knl_attach_cpu_core();
    while (!thread->closed) {
        /* If the database has come to recovery stage, we will break and go to normal schedul once
         * a trigger task is received.
         */
        if (DB_TO_RECOVERY(session) && ogx->trigger_task != CKPT_MODE_IDLE) {
            break;
        }
        cm_sleep(CKPT_WAIT_MS);
    }

    while (!thread->closed) {
        ckpt_do_trigger_task(session, ogx, &clean_time, &ckpt_time);
        ckpt_do_timed_task(session, ogx, &clean_time, &ckpt_time);

        /* quickly go to the next schdule if there is trigger task */
        if (ogx->trigger_task != CKPT_MODE_IDLE) {
            continue;
        }

        /* Quicly go the next schedul if dirty queue satisfies timed schedule */
        if (ogx->queue.count >= attr->ckpt_interval && ogx->ckpt_enabled) {
            continue;
        }

         /* For performance consideration,  we may don't want the timed task runing too frequently
          * in large-memory environment.
          * So we wait for a short time (default to 100ms with parameter), in which we can still
          * respond trigger task.
          * If one want the time task scheduled timely, he can set the parameter to 0.
          */
        uint32 timed_task_delay_ms = session->kernel->attr.ckpt_timed_task_delay;
        (void)cm_wait_cond(&ogx->ckpt_cond, timed_task_delay_ms);
        if (ogx->trigger_task != CKPT_MODE_IDLE) {
            continue;
        }

        /*
         * Using condition wait may missing the singal, but can avoid stucking with
         * disordered system time and always return on time out.
         * Besides, we can keep on releasing signal after triggering to make sure
         * the signal is not missed.
         */
        (void)cm_wait_cond(&ogx->ckpt_cond, CKPT_WAIT_MS);
        ogx->stat.proc_wait_cnt++;
    }

    OG_LOG_RUN_INF("ckpt thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

bool32 ckpt_try_latch_ctrl(knl_session_t *session, buf_ctrl_t *ctrl)
{
    uint32 times = 0;
    uint32 wait_ticks = 0;
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ogx = &kernel->ckpt_ctx;
    
    for (;;) {
        if (ogx->ckpt_enabled == OG_FALSE) {
            return OG_FALSE;
        }
        while (ctrl->is_readonly) {
            if (ogx->ckpt_enabled == OG_FALSE) {
                return OG_FALSE;
            }
            if (wait_ticks >= CKPT_LATCH_WAIT) {
                return OG_FALSE;
            }
            times++;
            if (times > OG_SPIN_COUNT) {
                cm_spin_sleep();
                times = 0;
                wait_ticks++;
                continue;
            }
        }

        // in checkpoint, we don't increase the ref_num.
        if (!buf_latch_timed_s(session, ctrl, CKPT_LATCH_TIMEOUT, OG_FALSE, OG_TRUE)) {
            return OG_FALSE;
        }

        if (!ctrl->is_readonly) {
            return OG_TRUE;
        }
        buf_unlatch(session, ctrl, OG_FALSE);
    }
}

status_t ckpt_checksum(knl_session_t *session, ckpt_context_t *ogx)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    page_head_t *page = (page_head_t *)(ogx->group.buf + DEFAULT_PAGE_SIZE(session) * ogx->group.count);

    if (cks_level == (uint32)CKS_FULL) {
        if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) != OG_INVALID_CHECKSUM
            && !page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
            OG_LOG_RUN_ERR("[CKPT] page corrupted(file %u, page %u).checksum level %s, page size %u, cks %u",
                AS_PAGID_PTR(page->id)->file, AS_PAGID_PTR(page->id)->page, knl_checksum_level(cks_level),
                PAGE_SIZE(*page), PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)));
            return OG_ERROR;
        }
    } else if (cks_level == (uint32)CKS_OFF) {
        PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) = OG_INVALID_CHECKSUM;
    } else if (g_crc_verify == OG_TRUE && cks_level == (uint32)CKS_TYPICAL) {
        datafile_t *df = DATAFILE_GET(session, AS_PAGID(page->id).file);
        space_t *space = SPACE_GET(session, df->space_id);
        if (IS_SYSTEM_SPACE(space) || IS_SYSAUX_SPACE(space)) {
            status_t ret = OG_SUCCESS;
            SYNC_POINT_GLOBAL_START(OGRAC_CKPT_CHECKSUM_VERIFY_FAIL, &ret, OG_ERROR);
            ret = !page_verify_checksum(page, DEFAULT_PAGE_SIZE(session));
            SYNC_POINT_GLOBAL_END;
            if (ret != OG_SUCCESS) {
                knl_panic_log(0, "sys or sysaux page checksum verify invalid, panic info: page %u-%u type %u",
                              AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);
            }
        }
    } else {
        page_calc_checksum(page, DEFAULT_PAGE_SIZE(session));
    }

    return OG_SUCCESS;
}

static uint32 ckpt_get_neighbors(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t *first)
{
    knl_attr_t *attr = &session->kernel->attr;
    datafile_t *df = NULL;
    space_t *space = NULL;
    page_id_t page_id;
    uint32 start_id;
    uint32 load_count;

    *first = ctrl->page_id;

    if (!attr->ckpt_flush_neighbors) {
        return 1;
    }

    if (ctrl->page->type == PAGE_TYPE_UNDO) {
        return session->kernel->attr.undo_prefetch_page_num;
    }

    page_id = ctrl->page_id;
    df = DATAFILE_GET(session, page_id.file);
    space = SPACE_GET(session, df->space_id);
    start_id = spc_first_extent_id(session, space, page_id);
    if (page_id.page >= start_id) {
        first->page = page_id.page - ((page_id.page - start_id) % space->ctrl->extent_size);
        first->aligned = 0;
        load_count = MAX(space->ctrl->extent_size, BUF_MAX_PREFETCH_NUM / 2);
    } else {
        load_count = 1;
    }

    return load_count;
}

static inline bool32 page_encrypt_enable(knl_session_t *session, space_t *space, page_head_t *page)
{
    if (page->type == PAGE_TYPE_UNDO) {
        return undo_valid_encrypt(session, page);
    }

    if (SPACE_IS_ENCRYPT(space) && page_type_suport_encrypt(page->type)) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

status_t ckpt_encrypt(knl_session_t *session, ckpt_context_t *ogx)
{
    page_head_t *page = (page_head_t *)(ogx->group.buf + DEFAULT_PAGE_SIZE(session) * ogx->group.count);
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->id)->file)->space_id);
    if (!page_encrypt_enable(session, space, page)) {
        return OG_SUCCESS;
    }

    if (page_encrypt(session, page, space->ctrl->encrypt_version, space->ctrl->cipher_reserve_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

#ifdef LOG_DIAG
static status_t ckpt_verify_decrypt(knl_session_t *session, ckpt_context_t *ogx)
{
    page_head_t *page = (page_head_t *)(ogx->group.buf + DEFAULT_PAGE_SIZE(session) * ogx->group.count);
    page_id_t page_id = AS_PAGID(page->id);
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, page_id.file)->space_id);

    char *copy_page = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    errno_t ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    if (((page_head_t *)copy_page)->encrypted) {
        if (page_decrypt(session, (page_head_t *)copy_page) != OG_SUCCESS) {
            knl_panic_log(0, "decrypt verify failed![AFTER ENCRYPT]AFTER CKPT CHECKSUM! ,DECRYPT IMMEDEATLY ERROR: "
                "page_info: page %u, file %u, page_type %u, encrypted %u,"
                "space->ctrl->cipher_reserve_size: %u ",
                page_id.page, page_id.file, page->type, page->encrypted, space->ctrl->cipher_reserve_size);
        }
    }
    cm_pop(session->stack);
    return OG_SUCCESS;
}
#endif

static void ckpt_unlatch_group(knl_session_t *session, page_id_t first, uint32 start, uint32 end)
{
    page_id_t page_id;
    buf_ctrl_t *to_flush_ctrl = NULL;

    page_id.file = first.file;

    for (uint32 i = start; i < end; i++) {
        page_id.page = first.page + i;
        to_flush_ctrl = buf_find_by_pageid(session, page_id);
        knl_panic_log(to_flush_ctrl != NULL, "ctrl missed in buffer, panic info: group head %u-%u, missed %u-%u",
            first.file, first.page, first.file, first.page + i);
        buf_unlatch(session, to_flush_ctrl, OG_FALSE);
    }
}

page_id_t page_first_group_id(knl_session_t *session, page_id_t page_id)
{
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    page_id_t first;
    uint32 start_id;

    start_id = spc_first_extent_id(session, space, page_id);

    knl_panic_log(page_id.page >= start_id, "page %u-%u before space first extent %u-%u", page_id.file, page_id.page,
        page_id.file, start_id);
    first.page = page_id.page - ((page_id.page - start_id) % PAGE_GROUP_COUNT);
    first.file = page_id.file;
    first.aligned = 0;

    return first;
}

bool32 buf_group_compressible(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_ctrl_t *to_compress_ctrl = NULL;
    page_id_t first;
    page_id_t page_id;

    first = page_first_group_id(session, ctrl->page_id);
    if (!IS_SAME_PAGID(first, ctrl->page_id)) {
        OG_LOG_RUN_ERR("group incompressible, first: %d-%d != current: %d-%d", first.file, first.page,
            ctrl->page_id.file, ctrl->page_id.page);
        return OG_FALSE;
    }

    page_id.file = first.file;
    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        page_id.page = first.page + i;
        to_compress_ctrl = buf_find_by_pageid(session, page_id);
        /* as a page group is alloc and release as a whole, so we consider a page group
         * which members are not all in buffer is incompressible */
        if (to_compress_ctrl == NULL || !page_compress(session, to_compress_ctrl->page_id)) {
            OG_LOG_RUN_ERR("group incompressible, member: %d, current: %d-%d", i,
                ctrl->page_id.file, ctrl->page_id.page);
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

bool32 ckpt_try_latch_group(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_ctrl_t *to_compress_ctrl = NULL;
    page_id_t first;
    page_id_t page_id;

    first = page_first_group_id(session, ctrl->page_id);
    page_id.file = first.file;

    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        page_id.page = first.page + i;
        to_compress_ctrl = buf_find_by_pageid(session, page_id);
        /* in the following scenario, ctrl may be null
         * 1.for noread, PAGE_GROUP_COUNT's pages are added to segment in log_atomic_op
         * 2.page is reused, PAGE_GROUP_COUNT's pages are formatted in log_atomic_op
         * so we consider group has NULL member as an exception */
        knl_panic_log(to_compress_ctrl != NULL, "ctrl missed in buffer, panic info: group head %u-%u, missed %u-%u",
            first.file, first.page, first.file, first.page + i);
        if (!ckpt_try_latch_ctrl(session, to_compress_ctrl)) {
            ckpt_unlatch_group(session, first, 0, i);
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}
 
static void ckpt_copy_item(knl_session_t *session, buf_ctrl_t *ctrl, buf_ctrl_t *to_flush_ctrl)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    errno_t ret;

    knl_panic_log(IS_SAME_PAGID(to_flush_ctrl->page_id, AS_PAGID(to_flush_ctrl->page->id)),
        "to_flush_ctrl's page_id and to_flush_ctrl page's id are not same, panic info: page_id %u-%u type %u, "
        "page id %u-%u type %u", to_flush_ctrl->page_id.file, to_flush_ctrl->page_id.page,
        to_flush_ctrl->page->type, AS_PAGID(to_flush_ctrl->page->id).file,
        AS_PAGID(to_flush_ctrl->page->id).page, to_flush_ctrl->page->type);
    knl_panic_log(CHECK_PAGE_PCN(to_flush_ctrl->page), "page pcn is abnormal, panic info: page %u-%u type %u",
        to_flush_ctrl->page_id.file, to_flush_ctrl->page_id.page, to_flush_ctrl->page->type);

    /* this is not accurate, does not matter */
    if (ogx->trunc_lsn < to_flush_ctrl->page->lsn) {
        ogx->trunc_lsn = to_flush_ctrl->page->lsn;
    }

    if (ogx->consistent_lfn < to_flush_ctrl->lastest_lfn) {
        ogx->consistent_lfn = to_flush_ctrl->lastest_lfn;
    }

    /* DEFAULT_PAGE_SIZE is 8192,  ogx->group.count <= OG_CKPT_GROUP_SIZE(4096), integers cannot cross bounds */
    ret = memcpy_sp(ogx->group.buf + DEFAULT_PAGE_SIZE(session) * ogx->group.count, DEFAULT_PAGE_SIZE(session),
        to_flush_ctrl->page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    if (to_flush_ctrl == ogx->batch_end) {
        ogx->batch_end = to_flush_ctrl->ckpt_prev;
    }

    if (to_flush_ctrl->in_ckpt) {
        ckpt_pop_page(session, ogx, to_flush_ctrl);
    }

    to_flush_ctrl->is_marked = 1;
    CM_MFENCE;
    to_flush_ctrl->is_dirty = 0;
    to_flush_ctrl->is_remote_dirty = 0;

    ogx->group.items[ogx->group.count].ctrl = to_flush_ctrl;
    ogx->group.items[ogx->group.count].buf_id = ogx->group.count;
    ogx->group.items[ogx->group.count].need_punch = OG_FALSE;

    ckpt_put_to_part_group(session, ogx, to_flush_ctrl);
}

static status_t ckpt_ending_prepare(knl_session_t *session, ckpt_context_t *ogx)
{
    /* must before checksum calc */
    if (ckpt_encrypt(session, ogx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (ckpt_checksum(session, ogx) != OG_SUCCESS) {
        return OG_ERROR;
    }
#ifdef LOG_DIAG
    if (ckpt_verify_decrypt(session, ogx) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("ERROR: ckpt verify decrypt failed. ");
        return OG_ERROR;
    }
#endif

    return OG_SUCCESS;
}

status_t ckpt_prepare_compress(knl_session_t *session, ckpt_context_t *ogx, buf_ctrl_t *curr_ctrl,
    buf_ctrl_t *ctrl_next, bool8 *ctrl_next_is_flushed, bool8 *need_exit)
{
    page_id_t first_page_id;
    page_id_t to_flush_pageid;
    buf_ctrl_t *to_flush_ctrl = NULL;

    ogx->has_compressed = OG_TRUE;

    if (ogx->group.count + PAGE_GROUP_COUNT > OG_CKPT_GROUP_SIZE(session)) {
        *need_exit = OG_TRUE;
        return OG_SUCCESS;
    }

    if (!ckpt_try_latch_group(session, curr_ctrl)) {
        return OG_SUCCESS;
    }

    first_page_id = page_first_group_id(session, curr_ctrl->page_id);
    to_flush_pageid = first_page_id;
    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        to_flush_pageid.page = first_page_id.page + i;

        /* get ctrl */
        if (IS_SAME_PAGID(to_flush_pageid, curr_ctrl->page_id)) {
            to_flush_ctrl = curr_ctrl;
        } else {
            to_flush_ctrl = buf_find_by_pageid(session, to_flush_pageid);
        }

        /* not a flushable page */
        if (to_flush_ctrl == NULL) {
            continue;
        }

        /* we should retain items for clean pages in page group, as a result, it may lead to lower io capacity */
        if (to_flush_ctrl->is_marked) {
            /* this ctrl has been added to ckpt group, so skip it */
            if (to_flush_ctrl->in_ckpt == OG_FALSE) {
                buf_unlatch(session, to_flush_ctrl, OG_FALSE);
                continue;
            }
            ckpt_unlatch_group(session, first_page_id, i, PAGE_GROUP_COUNT);
            *need_exit = OG_TRUE;
            return OG_SUCCESS;
        }

        ckpt_copy_item(session, curr_ctrl, to_flush_ctrl);

        if (to_flush_ctrl == ctrl_next) {
            *ctrl_next_is_flushed = OG_TRUE;
        }

        buf_unlatch(session, to_flush_ctrl, OG_FALSE);

        if (ckpt_ending_prepare(session, ogx) != OG_SUCCESS) {
            ckpt_unlatch_group(session, first_page_id, i + 1, PAGE_GROUP_COUNT);
            return OG_ERROR;
        }

        ogx->group.count++;

        if (ogx->group.count >= OG_CKPT_GROUP_SIZE(session)) {
            *need_exit = OG_TRUE;
            return OG_SUCCESS;
        }
    }

    return OG_SUCCESS;
}

static status_t ckpt_prepare_normal(knl_session_t *session, ckpt_context_t *ogx, buf_ctrl_t *curr_ctrl,
    buf_ctrl_t *ctrl_next, bool8 *ctrl_next_is_flushed, bool8 *need_exit)
{
    page_id_t first_page_id;
    page_id_t to_flush_pageid;
    buf_ctrl_t *to_flush_ctrl = NULL;
    uint32 count;

    ogx->stat.ckpt_total_neighbors_times++;
    ogx->stat.ckpt_curr_neighbors_times++;

    count = ckpt_get_neighbors(session, curr_ctrl, &first_page_id);
    to_flush_pageid = first_page_id;
    for (uint32 i = 0; i < count; i++) {
        to_flush_pageid.page = first_page_id.page + i;

        /* get ctrl */
        if (IS_SAME_PAGID(to_flush_pageid, curr_ctrl->page_id)) {
            to_flush_ctrl = curr_ctrl;
        } else {
            to_flush_ctrl = buf_find_by_pageid(session, to_flush_pageid);
        }

        /* not a flushable page */
        if (to_flush_ctrl == NULL || to_flush_ctrl->in_ckpt == OG_FALSE) {
            continue;
        }

        /* skip compress page when flush non-compress page's neighbors */
        if (page_compress(session, to_flush_ctrl->page_id)) {
            continue;
        }

        if (!ckpt_try_latch_ctrl(session, to_flush_ctrl)) {
            continue;
        }

        if (DB_IS_CLUSTER(session)) {
            if (to_flush_ctrl->is_edp) {
                OG_LOG_DEBUG_INF("[CKPT]checkpoint find edp [%u-%u], count(%d)", to_flush_ctrl->page_id.file,
                                 to_flush_ctrl->page_id.page, ogx->edp_group.count);
                knl_panic(DCS_BUF_CTRL_NOT_OWNER(session, to_flush_ctrl));
                buf_unlatch(session, to_flush_ctrl, OG_FALSE);
                if (!dtc_add_to_edp_group(session, &ogx->edp_group, OG_CKPT_GROUP_SIZE(session), to_flush_ctrl->page_id,
                                          to_flush_ctrl->page->lsn)) {
                    *need_exit = OG_TRUE;
                    break;
                }
                continue;
            }

            if (to_flush_ctrl->in_ckpt == OG_FALSE) {
                buf_unlatch(session, to_flush_ctrl, OG_FALSE);
                continue;
            }

            knl_panic(DCS_BUF_CTRL_IS_OWNER(session, to_flush_ctrl));
            if (to_flush_ctrl->is_remote_dirty &&
                !dtc_add_to_edp_group(session, &ogx->remote_edp_clean_group, OG_CKPT_GROUP_SIZE(session),
                    to_flush_ctrl->page_id,
                                      to_flush_ctrl->page->lsn)) {
                buf_unlatch(session, to_flush_ctrl, OG_FALSE);
                *need_exit = OG_TRUE;
                break;
            }
        }

        /*
        * added to ckpt->queue again during we flush it,
        * end this prepare, we can not handle two copies of same page
        */
        if (to_flush_ctrl->is_marked) {
            buf_unlatch(session, to_flush_ctrl, OG_FALSE);
            *need_exit = OG_TRUE;
            return OG_SUCCESS;
        }

        ckpt_copy_item(session, curr_ctrl, to_flush_ctrl);

        if (to_flush_ctrl == ctrl_next) {
            *ctrl_next_is_flushed = OG_TRUE;
        }

        buf_unlatch(session, to_flush_ctrl, OG_FALSE);

        if (ckpt_ending_prepare(session, ogx) != OG_SUCCESS) {
            return OG_ERROR;
        }

        ogx->stat.ckpt_total_neighbors_len++;
        ogx->stat.ckpt_curr_neighbors_len++;
        ogx->group.count++;

        if (ogx->group.count >= OG_CKPT_GROUP_SIZE(session)) {
            *need_exit = OG_TRUE;
            return OG_SUCCESS;
        }
    }

    return OG_SUCCESS;
}

static status_t ckpt_prepare_pages(knl_session_t *session, ckpt_context_t *ogx, ckpt_stat_items_t *stat)
{
    buf_ctrl_t *ctrl_next = NULL;
    buf_ctrl_t *ctrl = NULL;
    bool8 ctrl_next_is_flushed = OG_FALSE;
    bool8 need_exit = OG_FALSE;

    ogx->group.count = 0;
    ogx->edp_group.count = 0;
    init_ckpt_part_group(session);
    if (DB_IS_CLUSTER(session)) {
        dcs_ckpt_remote_edp_prepare(session, ogx);
        dcs_ckpt_clean_local_edp(session, ogx, stat);
        dtc_calculate_rcy_redo_size(session, ctrl);
    }

    if (ogx->queue.count == 0 || ogx->group.count >= OG_CKPT_GROUP_SIZE(session)) {
        return OG_SUCCESS;
    }

    ogx->trunc_lsn = 0;
    ogx->consistent_lfn = 0;
    ogx->has_compressed = OG_FALSE;
    ogx->stat.ckpt_curr_neighbors_times = 0;
    ogx->stat.ckpt_curr_neighbors_len = 0;
    ctrl = ogx->queue.first;
    while (ctrl != NULL) {
        ctrl_next = ctrl->ckpt_next;
        ctrl_next_is_flushed = OG_FALSE;
        if (page_compress(session, ctrl->page_id)) {
            knl_panic(!DB_IS_CLUSTER(session));  // not support compress in cluster for now
            if (ckpt_prepare_compress(session, ogx, ctrl, ctrl_next, &ctrl_next_is_flushed, &need_exit) != OG_SUCCESS) {
                return OG_ERROR;
            }
        } else {
            if (ckpt_prepare_normal(session, ogx, ctrl, ctrl_next, &ctrl_next_is_flushed, &need_exit) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }

        if (need_exit) {
            break;
        }

        ctrl = ctrl_next_is_flushed ? ogx->queue.first : ctrl_next;
        /* prevent that dirty page count is less than OG_CKPT_GROUP_SIZE,
           in the same time there is one page is latched. */
        if (!ogx->ckpt_enabled) {
            break;
        }
    }

    if (ogx->stat.ckpt_curr_neighbors_times != 0) {
        ogx->stat.ckpt_last_neighbors_len = (ogx->stat.ckpt_curr_neighbors_len / ogx->stat.ckpt_curr_neighbors_times);
    }

    return OG_SUCCESS;
}

static inline void ckpt_unlatch_datafiles(datafile_t **df, uint32 count, int32 size)
{
    if (cm_dbs_is_enable_dbs() == OG_TRUE && size == OG_UDFLT_VALUE_BUFFER_SIZE) {
        return;
    }

    for (uint32 i = 0; i < count; i++) {
        cm_unlatch(&df[i]->block_latch, NULL);
    }
}

static void ckpt_latch_datafiles(knl_session_t *session, datafile_t **df, uint64 *offset, int32 size, uint32 count)
{
    // dbstor can ensure that atomicity of read and write when page size is smaller than 8K
    if (cm_dbs_is_enable_dbs() == OG_TRUE && size == OG_UDFLT_VALUE_BUFFER_SIZE) {
        return;
    }

    uint64 end_pos = 0;
    uint32 i = 0;
    for (;;) {
        for (i = 0; i < count; i++) {
            end_pos = offset[i] + (uint64)size;

            if (!cm_latch_timed_s(&df[i]->block_latch, 1, OG_FALSE, NULL)) {
                /* latch fail need release them and try again from first page */
                ckpt_unlatch_datafiles(df, i, size);
                cm_sleep(1);
                break;
            }
            if (spc_datafile_is_blocked(session, df[i], (uint64)offset[i], end_pos)) {
                /* one page is backing up, need try again from fisrt page */
                ckpt_unlatch_datafiles(df, i + 1, size);
                cm_sleep(1);
                break;
            }
        }
        if (i == count) {
            return;
        }
    }
}

void dbwr_compress_checksum(knl_session_t *session, page_head_t *page)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;

    if (cks_level == (uint32)CKS_OFF) {
        COMPRESS_PAGE_HEAD(page)->checksum = OG_INVALID_CHECKSUM;
    } else {
        page_compress_calc_checksum(page, DEFAULT_PAGE_SIZE(session));
    }
}

static void dbwr_construct_group(knl_session_t *session, dbwr_context_t *dbwr, uint32 begin,
    uint32 compressed_size, const char *zbuf)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    uint32 remaining_size;
    uint32 actual_size;
    uint32 zsize;
    page_head_t *page = NULL;
    buf_ctrl_t *ctrl = NULL;
    uint32 buf_id;
    uint32 offset;
    uint32 slot;
    errno_t ret;

    remaining_size = compressed_size;
    
    /* +---------+----------+---------------------+
    *  |page_head|group_head| zip data            |
    *  +---------+----------+---------------------+
    *  */
    slot = begin;
    zsize = COMPRESS_PAGE_VALID_SIZE(session);
    offset = 0;
    do {
        if (remaining_size > zsize) {
            actual_size = zsize;
        } else {
            actual_size = remaining_size;
        }

        ctrl = ogx->group.items[slot].ctrl;
        buf_id = ogx->group.items[slot].buf_id;
        page = (page_head_t *)(ogx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        ret = memcpy_sp((char *)page + DEFAULT_PAGE_SIZE(session) - zsize, actual_size,
                        (char *)zbuf + offset, actual_size);
        knl_securec_check(ret);
        knl_panic_log(IS_SAME_PAGID(ctrl->page_id, AS_PAGID(page->id)), "the ctrl's page_id and page->id are not same, "
            "panic info: ctrl page %u-%u type %u curr page %u-%u", ctrl->page_id.file, ctrl->page_id.page, page->type,
            AS_PAGID(page->id).file, AS_PAGID(page->id).page);
        knl_panic_log(page_compress(session, AS_PAGID(page->id)), "the page is incompressible, panic info: "
            "type %u curr page %u-%u", page->type, AS_PAGID(page->id).file, AS_PAGID(page->id).page);
        COMPRESS_PAGE_HEAD(page)->compressed_size = compressed_size;
        COMPRESS_PAGE_HEAD(page)->compress_algo = COMPRESS_ZSTD;
        COMPRESS_PAGE_HEAD(page)->group_cnt = GROUP_COUNT_8;
        COMPRESS_PAGE_HEAD(page)->unused = 0;
        page->compressed = 1;
        dbwr_compress_checksum(session, page);
        remaining_size -= actual_size;
        offset += actual_size;
        slot++;
    } while (remaining_size != 0);

    while (slot <= begin + PAGE_GROUP_COUNT - 1) {
        ogx->group.items[slot].need_punch = OG_TRUE;
        ctrl = ogx->group.items[slot].ctrl;
        knl_panic_log(page_compress(session, ctrl->page_id), "the page is incompressible, panic info: "
            "curr page %u-%u", ctrl->page_id.file, ctrl->page_id.page);
        slot++;
    }
}

static status_t dbwr_compress_group(knl_session_t *session, dbwr_context_t *dbwr, uint32 begin, char *zbuf, char *src)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    page_head_t *page = NULL;
    uint32 buf_id;
    uint32 compressed_size;
    errno_t ret;

    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        buf_id = ogx->group.items[i + begin].buf_id;
        page = (page_head_t *)(ogx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        ret = memcpy_sp(src + DEFAULT_PAGE_SIZE(session) * i, DEFAULT_PAGE_SIZE(session), page,
                        DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
    }
    compressed_size = ZSTD_compress((char *)zbuf, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, src,
        DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, ZSTD_DEFAULT_COMPRESS_LEVEL);
    if (ZSTD_isError(compressed_size)) {
        OG_THROW_ERROR(ERR_COMPRESS_ERROR, "zstd", compressed_size, ZSTD_getErrorName(compressed_size));
        return OG_ERROR;
    }

    if (SECUREC_LIKELY(compressed_size <= COMPRESS_GROUP_VALID_SIZE(session))) {
        dbwr_construct_group(session, dbwr, begin, compressed_size, zbuf);
    }

    return OG_SUCCESS;
}

/* we devide ckpt group into two groups,one is pages which would be punched,the other is pages wihch would be submit */
static status_t dbwr_compress_prepare(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    page_head_t *page = NULL;
    uint32 buf_id;
    uint32 skip_cnt;
    errno_t ret;
    pcb_assist_t src_pcb_assist;
    pcb_assist_t zbuf_pcb_assist;
    uint16 i;

    if (pcb_get_buf(session, &src_pcb_assist) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (pcb_get_buf(session, &zbuf_pcb_assist) != OG_SUCCESS) {
        pcb_release_buf(session, &src_pcb_assist);
        return OG_ERROR;
    }

    ret = memset_sp(zbuf_pcb_assist.aligned_buf, DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT, 0,
        DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT);
    knl_securec_check(ret);

    for (i = dbwr->begin; i <= dbwr->end; i = i + skip_cnt) {
        buf_id = ogx->group.items[i].buf_id;
        page = (page_head_t *)(ogx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        skip_cnt = 1;
        if (!page_compress(session, AS_PAGID(page->id))) {
            continue;
        }
        knl_panic(AS_PAGID(page->id).page % PAGE_GROUP_COUNT == 0);
        if (dbwr_compress_group(session, dbwr, i, zbuf_pcb_assist.aligned_buf,
            src_pcb_assist.aligned_buf) != OG_SUCCESS) {
            pcb_release_buf(session, &src_pcb_assist);
            pcb_release_buf(session, &zbuf_pcb_assist);
            return OG_ERROR;
        }
        skip_cnt = PAGE_GROUP_COUNT;
    }

    pcb_release_buf(session, &src_pcb_assist);
    pcb_release_buf(session, &zbuf_pcb_assist);
    return OG_SUCCESS;
}

static status_t dbwr_async_io_write(knl_session_t *session, cm_aio_iocbs_t *aio_cbs, ckpt_context_t *ogx,
                                    dbwr_context_t *dbwr, uint32 size)
{
    struct timespec timeout = { 0, 200 };
    int32 aio_ret;
    uint32 buf_id;
    uint32 cb_id;
    page_head_t *page = NULL;
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    cm_aio_lib_t *lib_ctx = &session->kernel->aio_lib;
    int32 event_num = (int32)dbwr->io_cnt;
    ckpt_sort_item *item = NULL;
    cb_id = 0;
    uint32 idx = 0;
    errno_t ret;
    datafile_t *df = NULL;
    uint32 write_size;

    ret = memset_sp(dbwr->flags, sizeof(dbwr->flags), 0, sizeof(dbwr->flags));
    knl_securec_check(ret);

    for (uint16 i = dbwr->begin; i <= dbwr->end; i++) {
        item = &ogx->group.items[i];
        if (item->need_punch) {
            if (cm_file_punch_hole(*asyncio_ctx->handles[idx], (int64)asyncio_ctx->offsets[idx], size) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[CKPT] failed to punch datafile %s", asyncio_ctx->datafiles[idx]->ctrl->name);
                return OG_ERROR;
            }
        } else {
            buf_id = ogx->group.items[i].buf_id;
            page = (page_head_t *)(ogx->group.buf + ((uint64)buf_id) * size);
            knl_panic(item->ctrl != NULL);
            knl_panic(IS_SAME_PAGID(item->ctrl->page_id, AS_PAGID(page->id)));
            if (asyncio_ctx->datafiles[idx]->ctrl->type == DEV_TYPE_RAW) {
                cm_iocb_ex_t *iocb_ex = (cm_iocb_ex_t *)aio_cbs->iocbs;
                iocb_ex[cb_id].handle = *asyncio_ctx->handles[idx];
                iocb_ex[cb_id].offset = (int64)asyncio_ctx->offsets[idx];
                aio_cbs->iocb_ptrs[cb_id] = &iocb_ex[cb_id].obj;
                int ret = cm_aio_dss_prep_write(aio_cbs->iocb_ptrs[cb_id], *asyncio_ctx->handles[idx], (void *)page,
                                                size, (int64)asyncio_ctx->offsets[idx]);
                knl_panic_log(ret == 0, "[CKPT] ABORT INFO:failed to write page by dss aio");
                OG_LOG_DEBUG_INF("[CKPT] prepare write datafile %u handle is %llu.", cb_id, iocb_ex[cb_id].handle);
            } else {
                aio_cbs->iocb_ptrs[cb_id] = &aio_cbs->iocbs[cb_id];
                cm_aio_prep_write(aio_cbs->iocb_ptrs[cb_id], *asyncio_ctx->handles[idx], (void *)page, size,
                                  (int64)asyncio_ctx->offsets[idx]);
            }
            knl_panic(asyncio_ctx->offsets[idx] == (uint64)item->ctrl->page_id.page * PAGE_SIZE(*page));
            cb_id++;

            df = asyncio_ctx->datafiles[idx];
            dbwr->flags[df->ctrl->id] = OG_TRUE;
        }
        idx++;
    }
    knl_panic(cb_id == dbwr->io_cnt);
    aio_ret = lib_ctx->io_submit(dbwr->async_ctx.aio_ctx, (long)event_num, aio_cbs->iocb_ptrs);
    if (aio_ret != event_num) {
        OG_LOG_RUN_ERR("[CKPT] failed to submit by async io, error code: %d, aio_ret: %d", errno, aio_ret);
        return OG_ERROR;
    }

    while (event_num > 0) {
        ret = memset_sp(aio_cbs->events, sizeof(cm_io_event_t) * event_num, 0, sizeof(cm_io_event_t) * event_num);
        knl_securec_check(ret);
        aio_ret = lib_ctx->io_getevents(dbwr->async_ctx.aio_ctx, 1, event_num, aio_cbs->events, &timeout);
        if (aio_ret < 0) {
            if (errno == EINTR || aio_ret == -EINTR) {
                continue;
            }
            OG_LOG_RUN_ERR("[CKPT] failed to getevent by async io, error code: %d, aio_ret: %d", errno, aio_ret);
            return OG_ERROR;
        }
        for (int32 i = 0; i < aio_ret; i++) {
            write_size = aio_cbs->events[i].obj->u.c.nbytes;
            if (aio_cbs->events[i].res != write_size) {
                OG_LOG_RUN_ERR("[CKPT] failed to write by event, res: %ld, size: %u", aio_cbs->events[i].res, write_size);
                return OG_ERROR;
            }
            cm_iocb_ex_t *iocb_ex = (cm_iocb_ex_t *)aio_cbs->events[i].obj;
            OG_LOG_DEBUG_INF("[CKPT] post write datafile %u, aio_ret: %u, handle: %llu, offset: %llu.",
                i, aio_ret, iocb_ex->handle, iocb_ex->offset);
            ret = cm_aio_dss_post_write(&iocb_ex->obj, iocb_ex->handle, aio_cbs->events[i].obj->u.c.nbytes,
                iocb_ex->offset);
            knl_panic_log(ret == 0, "[CKPT] failed to post write by async io, error code: %d, aio_idx: %d", ret, i);
        }
        event_num = event_num - aio_ret;
    }

    return dbwr_fdatasync(session, dbwr);
}

static status_t dbwr_flush_async_io(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    page_id_t *page_id = NULL;
    page_head_t *page = NULL;
    uint32 buf_offset;
    uint32 buf_id;
    cm_aio_iocbs_t aio_cbs;
    ckpt_sort_item *item = NULL;

    if (ogx->has_compressed) {
        if (dbwr_compress_prepare(session, dbwr) != OG_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if (err_code != ERR_ALLOC_MEMORY) {
                return OG_ERROR;
            }
            /* if there is not enough memory, no compression is performed */
            cm_reset_error();
        }
    }

    dbwr->io_cnt = dbwr->end - dbwr->begin + 1; // page count need to io ,init by all page count first.
    uint32 latch_cnt = 0; // to recode page count need to latch.
    for (uint16 i = dbwr->begin; i <= dbwr->end; i++) {
        buf_id = ogx->group.items[i].buf_id;
        page = (page_head_t *)(ogx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        item = &ogx->group.items[i];
        if (item->need_punch) {
            dbwr->io_cnt--; // remove punch hole page count from all page count.
        }
        knl_panic(item->ctrl != NULL);
        knl_panic(IS_SAME_PAGID(item->ctrl->page_id, AS_PAGID(page->id)));

        page_id = AS_PAGID_PTR(page->id);
        asyncio_ctx->datafiles[latch_cnt] = DATAFILE_GET(session, page_id->file);
        asyncio_ctx->handles[latch_cnt] = &dbwr->datafiles[page_id->file];
        asyncio_ctx->offsets[latch_cnt] = (uint64)page_id->page * DEFAULT_PAGE_SIZE(session);
        knl_panic(page_compress(session, AS_PAGID(page)) || CHECK_PAGE_PCN(page));

        if (*asyncio_ctx->handles[latch_cnt] == -1) {
            if (spc_open_datafile(session, asyncio_ctx->datafiles[latch_cnt],
                asyncio_ctx->handles[latch_cnt]) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[CKPT] failed to open datafile %s", asyncio_ctx->datafiles[latch_cnt]->ctrl->name);
                return OG_ERROR;
            }
        }
        latch_cnt++;
    }

    if (DB_IS_CLUSTER(session)) {
        buf_offset = dbwr->begin * CM_IOCB_LENTH_EX;
        aio_cbs.iocbs = (cm_iocb_t *)(ogx->group.iocbs_buf + buf_offset);
        buf_offset += sizeof(cm_iocb_ex_t) * dbwr->io_cnt;
    } else {
        buf_offset = dbwr->begin * CM_IOCB_LENTH;
        aio_cbs.iocbs = (cm_iocb_t *)(ogx->group.iocbs_buf + buf_offset);
        buf_offset += sizeof(cm_iocb_t) * dbwr->io_cnt;
    }

    aio_cbs.events = (cm_io_event_t *)(ogx->group.iocbs_buf + buf_offset);
    buf_offset += sizeof(cm_io_event_t) * dbwr->io_cnt;
    aio_cbs.iocb_ptrs = (cm_iocb_t**)(ogx->group.iocbs_buf + buf_offset);

    ckpt_latch_datafiles(session, asyncio_ctx->datafiles, asyncio_ctx->offsets, DEFAULT_PAGE_SIZE(session), latch_cnt);
    if (dbwr_async_io_write(session, &aio_cbs, ogx, dbwr, DEFAULT_PAGE_SIZE(session)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CKPT] failed to write datafile by async io");
        ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt, DEFAULT_PAGE_SIZE(session));
        return OG_ERROR;
    }
    ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt, DEFAULT_PAGE_SIZE(session));

    for (uint16 i = dbwr->begin; i <= dbwr->end; i++) {
        ogx->group.items[i].ctrl->is_marked = 0;
    }

    return OG_SUCCESS;
}

static status_t dbwr_sync_pg_pool(knl_session_t *session, dbwr_context_t *dbwr, uint32 part_id)
{
    database_t *db = &session->kernel->db;

    for (uint32 i = 0; i < OG_MAX_DATA_FILES; i++) {
        if (dbwr->flags[i]) {
            if (cm_sync_device_by_part(dbwr->datafiles[i], part_id) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("failed to fdatasync datafile %s, part_id %d", db->datafiles[i].ctrl->name, part_id);
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t dbwr_async_io_write_dbs(knl_session_t *session, ckpt_context_t *ogx, dbwr_context_t *dbwr, uint32 size)
{
    uint32 buf_id;
    page_head_t *page = NULL;
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    errno_t ret;
    datafile_t *df = NULL;
    uint32 begin = 0;
    uint32 end = 0;

    ret = memset_sp(dbwr->flags, sizeof(dbwr->flags), 0, sizeof(dbwr->flags));
    knl_securec_check(ret);
    while (begin < dbwr->io_cnt) {
        end = MIN(begin + session->kernel->attr.batch_flush_capacity, dbwr->io_cnt);
        for (uint16 i = begin; i < end; i++) {
            uint32 group_idx = ogx->ckpt_part_group[dbwr->id].item_index[i];
            buf_id = ogx->group.items[group_idx].buf_id;
            page = (page_head_t *)(ogx->group.buf + ((uint64)buf_id) * size);
            if (cm_aio_prep_write_by_part(*asyncio_ctx->handles[i], (int64)asyncio_ctx->offsets[i], page, size,
                dbwr->id)) {
                return OG_ERROR;
            }

            df = asyncio_ctx->datafiles[i];
            dbwr->flags[df->ctrl->id] = OG_TRUE;
        }
        if (dbwr_sync_pg_pool(session, dbwr, dbwr->id) != OG_SUCCESS) {
            return OG_ERROR;
        }
        for (uint16 i = begin; i < end; i++) {
            uint32 group_index = ogx->ckpt_part_group[dbwr->id].item_index[i];
            ogx->group.items[group_index].ctrl->is_marked = 0;
        }
        begin = end;
    }

    return OG_SUCCESS;
}

static status_t dbwr_flush_async_dbs(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    page_id_t *page_id = NULL;
    page_head_t *page = NULL;
    uint32 buf_id;
    uint32 group_index;
    if (ogx->has_compressed) {
        knl_panic_log(0, "not support page compressed when flush dbs");
    }

    dbwr->io_cnt = ogx->ckpt_part_group[dbwr->id].count; // page count need to io ,init by all page count first.
    uint32 latch_cnt = 0;                                // to recode page count need to latch.
    for (uint16 i = 0; i < dbwr->io_cnt; i++) {
        group_index = ogx->ckpt_part_group[dbwr->id].item_index[i];
        buf_id = ogx->group.items[group_index].buf_id;
        page = (page_head_t *)(ogx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));

        page_id = AS_PAGID_PTR(page->id);
        asyncio_ctx->datafiles[latch_cnt] = DATAFILE_GET(session, page_id->file);
        asyncio_ctx->handles[latch_cnt] = &dbwr->datafiles[page_id->file];
        asyncio_ctx->offsets[latch_cnt] = (uint64)page_id->page * DEFAULT_PAGE_SIZE(session);
        knl_panic(CHECK_PAGE_PCN(page));

        if (spc_open_datafile(session, asyncio_ctx->datafiles[latch_cnt], asyncio_ctx->handles[latch_cnt]) !=
            OG_SUCCESS) {
            OG_LOG_RUN_ERR("[CKPT] failed to open datafile %s", asyncio_ctx->datafiles[latch_cnt]->ctrl->name);
            return OG_ERROR;
        }
        latch_cnt++;
    }

    ckpt_latch_datafiles(session, asyncio_ctx->datafiles, asyncio_ctx->offsets, DEFAULT_PAGE_SIZE(session), latch_cnt);
    if (dbwr_async_io_write_dbs(session, ogx, dbwr, DEFAULT_PAGE_SIZE(session)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CKPT] failed to write datafile by async io");
        ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt, DEFAULT_PAGE_SIZE(session));
        return OG_ERROR;
    }
    ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt, DEFAULT_PAGE_SIZE(session));
    return OG_SUCCESS;
}

static status_t ckpt_double_write(knl_session_t *session, ckpt_context_t *ogx)
{
    database_t *db = &session->kernel->db;
    datafile_t *df = DATAFILE_GET(session, db->ctrl.core.dw_file_id);
    timeval_t tv_begin;
    timeval_t tv_end;
    int64 offset;
    dtc_node_ctrl_t *node = dtc_my_ctrl(session);

    (void)cm_gettimeofday(&tv_begin);

    if (ogx->dw_ckpt_start + ogx->group.count > DW_DISTRICT_END(session->kernel->id)) {
        ogx->dw_ckpt_start = DW_DISTRICT_BEGIN(session->kernel->id);
    }

    ogx->dw_ckpt_end = ogx->dw_ckpt_start + ogx->group.count;
    knl_panic(ogx->dw_ckpt_start >= DW_DISTRICT_BEGIN(session->kernel->id));
    knl_panic(ogx->dw_ckpt_end <= DW_DISTRICT_END(session->kernel->id));
    knl_panic(df->file_no == 0);  // first sysaux file

    offset = (uint64)ogx->dw_ckpt_start * DEFAULT_PAGE_SIZE(session);
    /* DEFAULT_PAGE_SIZE is 8192, ogx->group.count <= OG_CKPT_GROUP_SIZE(4096), can not cross bounds */
    if (spc_write_datafile(session, df, &ogx->dw_file, offset, ogx->group.buf,
                           ogx->group.count * DEFAULT_PAGE_SIZE(session)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CKPT] failed to write datafile %s", df->ctrl->name);
        return OG_ERROR;
    }

    if (db_fdatasync_file(session, ogx->dw_file) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CKPT] failed to fdatasync datafile %s", (char *)DATAFILE_GET(session, 0));
        return OG_ERROR;
    }

    cm_spin_lock(&db->ctrl_lock, NULL);
    node->dw_start = ogx->dw_ckpt_start;
    node->dw_end = ogx->dw_ckpt_end;
    cm_spin_unlock(&db->ctrl_lock);

    (void)cm_gettimeofday(&tv_end);
    ogx->stat.double_writes++;
    ogx->stat.double_write_time += (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end);

    return OG_SUCCESS;
}

static int32 ckpt_buforder_comparator(const void *pa, const void *pb)
{
    const ckpt_sort_item *a = (const ckpt_sort_item *) pa;
    const ckpt_sort_item *b = (const ckpt_sort_item *) pb;

    /* compare fileid */
    if (a->ctrl->page_id.file < b->ctrl->page_id.file) {
        return -1;
    } else if (a->ctrl->page_id.file > b->ctrl->page_id.file) {
        return 1;
    }

    /* compare page */
    if (a->ctrl->page_id.page < b->ctrl->page_id.page) {
        return -1;
    } else if (a->ctrl->page_id.page > b->ctrl->page_id.page) {
        return 1;
    }

    /* equal pageid is impossible */
    return 0;
}

static inline void ckpt_flush_sort(knl_session_t *session, ckpt_context_t *ogx)
{
    qsort(ogx->group.items, ogx->group.count, sizeof(ckpt_sort_item), ckpt_buforder_comparator);
}


static uint32 ckpt_adjust_dbwr(knl_session_t *session, buf_ctrl_t *ctrl)
{
    page_id_t first;

    first = page_first_group_id(session, ctrl->page_id);

    return (PAGE_GROUP_COUNT - (ctrl->page_id.page - first.page + 1));
}

/* flush [begin, end - 1] */
static inline status_t ckpt_flush(knl_session_t *session, ckpt_context_t *ogx, uint32 begin, uint32 end)
{
    uint32 pages_each_wr = (end - begin - 1) / ogx->dbwr_count + 1;
    uint32 curr_page = begin;
    uint32 i;
    uint32 trigger_count = 0;
    buf_ctrl_t *ctrl = NULL;
    uint32 cnt;
    for (i = 0; i < ogx->dbwr_count; i++) {
        ogx->dbwr[i].begin = curr_page;
        curr_page += pages_each_wr;
        if (curr_page >= end) {
            curr_page = end;
        }
        
        /* if the last page is compressed page, take all its grouped pages to this dbwr  */
        ctrl = ogx->group.items[curr_page - 1].ctrl;
        if (page_compress(session, ctrl->page_id)) {
            cnt = ckpt_adjust_dbwr(session, ctrl);
            curr_page += cnt;
            knl_panic(curr_page <= end);
        }

        ogx->dbwr[i].end = curr_page - 1;
        ogx->dbwr[i].dbwr_trigger = OG_TRUE;
        trigger_count++;
#ifdef WIN32
        ReleaseSemaphore(ogx->dbwr[i].sem, 1, NULL);
#else
        (void)sem_post(&ogx->dbwr[i].sem);
#endif  // WIN32

        if (curr_page >= end) {
            break;
        }
    }

    for (i = 0; i < trigger_count; i++) {
        while (ogx->dbwr[i].dbwr_trigger) {
            cm_sleep(1);
        }
    }
    return OG_SUCCESS;
}

static inline void ckpt_delay(knl_session_t *session, uint32 ckpt_io_capacity)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;

    /* max capacity, skip sleep */
    if (ogx->group.count == ckpt_io_capacity) {
        return;
    }

    cm_sleep(1000); /* 1000ms */
}

static uint32 ckpt_get_dirty_ratio(knl_session_t *session)
{
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    buf_set_t *set = NULL;
    uint64 total_pages;

    set = &buf_ctx->buf_set[0];
    total_pages = (uint64)set->capacity * buf_ctx->buf_set_count;

    return (uint32)ceil((double)ckpt_ctx->queue.count / ((double)total_pages) * OG_PERCENT);
}

static uint32 ckpt_adjust_io_capacity(knl_session_t *session)
{
    knl_attr_t *attr = &session->kernel->attr;
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    uint32 ckpt_io_capacity = attr->ckpt_io_capacity;
    atomic_t curr_io_read = cm_atomic_get(&session->kernel->total_io_read);

    /* adjust io capacity */
    if (ogx->trigger_task != CKPT_MODE_IDLE) {
        /* triggered, max capacity */
        ckpt_io_capacity = ogx->group.count;
    } else if (ogx->prev_io_read == curr_io_read || /* no read, max capacity */
               ckpt_get_dirty_ratio(session) > OG_MAX_BUF_DIRTY_PCT) {
        ckpt_io_capacity = ogx->group.count;
    } else {
        /* normal case */
        ckpt_io_capacity = attr->ckpt_io_capacity;
    }

    ogx->prev_io_read = curr_io_read;

    return ckpt_io_capacity;
}

static status_t ckpt_flush_by_part(knl_session_t *session, ckpt_context_t *ogx)
{
    for (uint32 i = 0; i < cm_dbs_get_part_num(); i++) {
        if (ogx->ckpt_part_group[i].count == 0) {
            continue;
        }
        ogx->dbwr[i].dbwr_trigger = OG_TRUE;
        ogx->dbwr[i].id = i;
        (void)sem_post(&ogx->dbwr[i].sem);
    }

    for (uint32 i = 0; i < cm_dbs_get_part_num(); i++) {
        ogx->stat.part_stat[i].cur_flush_pages = ogx->ckpt_part_group[i].count;
        ogx->stat.part_stat[i].flush_pagaes += ogx->ckpt_part_group[i].count;
        if (ogx->ckpt_part_group[i].count > ogx->stat.part_stat[i].max_flush_pages) {
            ogx->stat.part_stat[i].max_flush_pages = ogx->ckpt_part_group[i].count;
        } else if (ogx->ckpt_part_group[i].count < ogx->stat.part_stat[i].max_flush_pages) {
            ogx->stat.part_stat[i].min_flush_pages = ogx->ckpt_part_group[i].count;
        }
        if (ogx->ckpt_part_group[i].count == 0) {
            ogx->stat.part_stat[i].zero_flush_times += 1;
            continue;
        }
        while (ogx->dbwr[i].dbwr_trigger) {
            cm_sleep(1);
        }
        ogx->stat.part_stat[i].flush_times++;
    }
    return OG_SUCCESS;
}

static status_t ckpt_flush_pages(knl_session_t *session)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    uint32 ckpt_io_capacity;
    uint32 begin;
    uint32 end;
    timeval_t tv_begin;
    timeval_t tv_end;
    buf_ctrl_t *ctrl_border = NULL;

    if (cm_dbs_is_enable_dbs() && cm_dbs_is_enable_batch_flush()) {
        (void)cm_gettimeofday(&tv_begin);
        status_t ret = ckpt_flush_by_part(session, ogx);
        ogx->stat.disk_writes += ogx->group.count;
        (void)cm_gettimeofday(&tv_end);
        ogx->stat.disk_write_time += (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end);
        return ret;
    }

    ckpt_io_capacity = ckpt_adjust_io_capacity(session);
    ckpt_flush_sort(session, ogx);

    begin = 0;
    while (begin < ogx->group.count) {
        end = MIN(begin + ckpt_io_capacity, ogx->group.count);
 
        ctrl_border = ogx->group.items[end - 1].ctrl; // if compressed, taking all the group
        if (page_compress(session, ctrl_border->page_id)) {
            end += ckpt_adjust_dbwr(session, ctrl_border);
            knl_panic(end <= ogx->group.count);
        }

        (void)cm_gettimeofday(&tv_begin);
        if (ckpt_flush(session, ogx, begin, end) != OG_SUCCESS) {
            return OG_ERROR;
        }

        (void)cm_gettimeofday(&tv_end);
        ogx->stat.disk_writes += end - begin;
        ogx->stat.disk_write_time += (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end);
        ckpt_delay(session, ckpt_io_capacity);
        
        begin  = end;
    }

    /* check */
#ifdef LOG_DIAG
    buf_ctrl_t *ctrl = NULL;

    for (uint32 i = 0; i < ogx->group.count; i++) {
        ctrl = ogx->group.items[i].ctrl;
        knl_panic_log(ctrl->is_marked == 0, "ctrl is marked, panic info: page %u-%u type %u", ctrl->page_id.file,
                      ctrl->page_id.page, ctrl->page->type);
    }
#endif

    return OG_SUCCESS;
}

/*
 * we need to do following jobs before flushing pages:
 * 1.flush redo log to update lrp point.
 * 2.double write pages to be flushed if need.
 * 3.back up log info in core ctrl to log file.
 */
static status_t ckpt_flush_prepare(knl_session_t *session, ckpt_context_t *ogx)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;

    if (log_flush(session, &ogx->lrp_point, &ogx->lrp_scn, NULL) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!DB_NOT_READY(session) && !DB_IS_READONLY(session)) {
        if (DB_IS_RAFT_ENABLED(session->kernel)) {
            raft_wait_for_log_flush(session, (uint64)ogx->lrp_point.lfn);
        } else if (session->kernel->lsnd_ctx.standby_num > 0) {
            lsnd_wait(session, (uint64)ogx->lrp_point.lfn, NULL);
        }
    }

    if ((ogx->group.count != 0) && ogx->double_write) {
        if (ckpt_double_write(session, ogx) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (DB_IS_PRIMARY(&session->kernel->db)) {
        dtc_node_ctrl_t *ctrl = dtc_my_ctrl(session);
        ctrl->lrp_point = ogx->lrp_point;
        ctrl->scn = ogx->lrp_scn;
        ctrl->lsn = DB_CURR_LSN(session);
        ctrl->lfn = session->kernel->lfn;
        if (ctrl->consistent_lfn < ogx->consistent_lfn) {
            ctrl->consistent_lfn = ogx->consistent_lfn;
        }

        if (DB_IS_RAFT_ENABLED(session->kernel) && (session->kernel->raft_ctx.status >= RAFT_STATUS_INITED)) {
            raft_context_t *raft_ctx = &session->kernel->raft_ctx;
            cm_spin_lock(&raft_ctx->raft_write_disk_lock, NULL);
            core->raft_flush_point = raft_ctx->raft_flush_point;
            cm_spin_unlock(&raft_ctx->raft_write_disk_lock);

            if (db_save_core_ctrl(session) != OG_SUCCESS) {
                return OG_ERROR;
            }

            knl_panic(session->kernel->raft_ctx.saved_raft_flush_point.lfn <= core->raft_flush_point.lfn &&
                session->kernel->raft_ctx.saved_raft_flush_point.raft_index <= core->raft_flush_point.raft_index);
                session->kernel->raft_ctx.saved_raft_flush_point = core->raft_flush_point;
        } else {
            if (dtc_save_ctrl(session, session->kernel->id) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }

        /* backup some core info on datafile head: only back up core log info for full ckpt & timed task */
        if (NEED_SYNC_LOG_INFO(ogx) && ctrl_backup_core_log_info(session) != OG_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: backup core control info failed when perform checkpoint");
        }
    }
    
    return OG_SUCCESS;
}

/*
 * steps to perform checkpoint:
 * 1.prepare dirty pages and copy to ckpt group.
 * 2.flush redo log and double write dirty pages.
 * 3.flush pages to disk.
 */
static status_t ckpt_perform(knl_session_t *session, ckpt_stat_items_t *stat)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;

    if (ckpt_prepare_pages(session, ogx, stat) != OG_SUCCESS) {
        return OG_ERROR;
    }

    dcs_notify_owner_for_ckpt(session, ogx);
    stat->flush_pages += ogx->group.count;

    if (DB_IS_PRIMARY(&session->kernel->db)) {
        ckpt_get_trunc_point(session, &ogx->trunc_point_snapshot);
    } else {
        ckpt_get_trunc_point_slave_role(session, &ogx->trunc_point_snapshot, &ogx->curr_node_idx);
    }

    if ((ogx->group.count == 0) && !dtc_need_empty_ckpt(session)) {
        dcs_clean_edp(session, ogx);
        return OG_SUCCESS;
    }

    if (ckpt_flush_prepare(session, ogx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogx->group.count != 0) {
        if (ckpt_flush_pages(session) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    dcs_clean_edp(session, ogx);

    ogx->group.count = 0;
    ogx->dw_ckpt_start = ogx->dw_ckpt_end;
    dtc_my_ctrl(session)->ckpt_id++;
    dtc_my_ctrl(session)->dw_start = ogx->dw_ckpt_start;

    if (dtc_save_ctrl(session, session->kernel->id) != OG_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
    }

    return OG_SUCCESS;
}

void ckpt_enque_page(knl_session_t *session)
{
    ckpt_context_t *ckpt = &session->kernel->ckpt_ctx;
    ckpt_queue_t *queue = &ckpt->queue;
    uint32 i;

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_ckpt_queue);

    if (queue->count == 0) {
        queue->first = session->dirty_pages[0];
        session->dirty_pages[0]->ckpt_prev = NULL;
    } else {
        queue->last->ckpt_next = session->dirty_pages[0];
        session->dirty_pages[0]->ckpt_prev = queue->last;
    }

    queue->last = session->dirty_pages[session->dirty_count - 1];
    queue->last->ckpt_next = NULL;
    queue->count += session->dirty_count;

    /** set log truncate point for every dirty page in current session */
    for (i = 0; i < session->dirty_count; i++) {
        knl_panic(session->dirty_pages[i]->in_ckpt == OG_FALSE);
        if (!DB_IS_PRIMARY(&session->kernel->db)) {
            session->dirty_pages[i]->curr_node_idx = queue->curr_node_idx;
        }
        session->dirty_pages[i]->trunc_point = queue->trunc_point;
        session->dirty_pages[i]->in_ckpt = OG_TRUE;
    }

    cm_spin_unlock(&queue->lock);

    session->stat->disk_writes += session->dirty_count;
    session->dirty_count = 0;
}

void ckpt_enque_one_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    ckpt_context_t *ckpt = &session->kernel->ckpt_ctx;
    ckpt_queue_t *queue = &ckpt->queue;

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_ckpt_queue);

    if (queue->count == 0) {
        queue->first = ctrl;
        ctrl->ckpt_prev = NULL;
    } else {
        queue->last->ckpt_next = ctrl;
        ctrl->ckpt_prev = queue->last;
    }

    queue->last = ctrl;
    queue->last->ckpt_next = NULL;
    queue->count++;

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        ctrl->curr_node_idx = queue->curr_node_idx;
    }
    ctrl->trunc_point = queue->trunc_point;
    ctrl->in_ckpt = OG_TRUE;
    cm_spin_unlock(&queue->lock);
}

bool32 ckpt_check(knl_session_t *session)
{
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;

    if (ckpt_ctx->trigger_task == CKPT_MODE_IDLE && ckpt_ctx->queue.count == 0) {
        return OG_TRUE;
    } else {
        return OG_FALSE;
    }
}

void ckpt_set_trunc_point(knl_session_t *session, log_point_t *point)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    cm_spin_lock(&ogx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    ogx->queue.trunc_point = *point;
    cm_spin_unlock(&ogx->queue.lock);
}

void ckpt_set_trunc_point_slave_role(knl_session_t *session, log_point_t *point, uint32 curr_node_idx)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    if (log_cmp_point(&ogx->queue.trunc_point, point) > 0)
    {
        return;
    }
    cm_spin_lock(&ogx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    ogx->queue.trunc_point = *point;
    ogx->queue.curr_node_idx = curr_node_idx;
    g_replay_paral_mgr.rcy_point[curr_node_idx] =
        log_cmp_point(&g_replay_paral_mgr.rcy_point[curr_node_idx], point) > 0 ?
        g_replay_paral_mgr.rcy_point[curr_node_idx] :
        *point;
    cm_spin_unlock(&ogx->queue.lock);
}

void ckpt_get_trunc_point(knl_session_t *session, log_point_t *point)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;

    cm_spin_lock(&ogx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    *point = ogx->queue.trunc_point;
    cm_spin_unlock(&ogx->queue.lock);
}

void ckpt_get_trunc_point_slave_role(knl_session_t *session, log_point_t *point, uint32 *curr_node_idx)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
 
    cm_spin_lock(&ogx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    *point = ogx->queue.trunc_point;
    *curr_node_idx = ogx->queue.curr_node_idx;
    cm_spin_unlock(&ogx->queue.lock);
}

status_t dbwr_save_page(knl_session_t *session, dbwr_context_t *dbwr, page_head_t *page)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    int32 *handle = &dbwr->datafiles[page_id->file];
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);

    knl_panic (!page_compress(session, *page_id));
    knl_panic (page->type != PAGE_TYPE_PUNCH_PAGE);
    knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
        page_id->page, page->type);

    if (spc_write_datafile(session, df, handle, offset, page, PAGE_SIZE(*page)) != OG_SUCCESS) {
        spc_close_datafile(df, handle);
        OG_LOG_RUN_ERR("[CKPT] failed to write datafile %s", df->ctrl->name);
        return OG_ERROR;
    }

    if (!dbwr->flags[page_id->file]) {
        dbwr->flags[page_id->file] = OG_TRUE;
    }

    return OG_SUCCESS;
}

status_t dbwr_fdatasync(knl_session_t *session, dbwr_context_t *dbwr)
{
    database_t *db = &session->kernel->db;

    for (uint32 i = 0; i < OG_MAX_DATA_FILES; i++) {
        if (dbwr->flags[i]) {
            if (cm_fdatasync_device(db->datafiles[i].ctrl->type, dbwr->datafiles[i]) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("failed to fdatasync datafile %s", db->datafiles[i].ctrl->name);
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

static status_t dbwr_write_or_punch(knl_session_t *session, ckpt_sort_item *item, int32 *handle, datafile_t *df,
    page_head_t *page)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);

    if (!page_compress(session, *page_id)) {
        knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
            page_id->page, page->type);
    }

    if (item->need_punch) {
        knl_panic(page_compress(session, *page_id));
        if (cm_file_punch_hole(*handle, (uint64)offset, PAGE_SIZE(*page)) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[CKPT] failed to punch datafile compress %s", df->ctrl->name);
            return OG_ERROR;
        }
    } else if (page->type == PAGE_TYPE_PUNCH_PAGE) {
        knl_panic(!page_compress(session, *page_id));
        if (cm_file_punch_hole(*handle, (uint64)offset, PAGE_SIZE(*page)) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[CKPT] failed to punch datafile normal %s", df->ctrl->name);
            return OG_ERROR;
        }
    } else {
        if (cm_write_device(df->ctrl->type, *handle, offset, page, PAGE_SIZE(*page)) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[CKPT] failed to write datafile %s", df->ctrl->name);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}
    
static status_t dbwr_save_page_by_id(knl_session_t *session, dbwr_context_t *dbwr, uint16 begin, uint16 *saved_cnt)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    uint32 buf_id = ogx->group.items[begin].buf_id;
    page_head_t *page = (page_head_t *)(ogx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));

    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    int32 *handle = &dbwr->datafiles[page_id->file];
    int64 offset = (int64)page_id->page * DEFAULT_PAGE_SIZE(session);
    uint16 sequent_cnt = page_compress(session, *page_id) ? PAGE_GROUP_COUNT : 1;
    uint64 end_pos = (uint64)offset + sequent_cnt * DEFAULT_PAGE_SIZE(session);
    *saved_cnt = 0;

    if (*handle == -1) {
        if (spc_open_datafile(session, df, handle) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[SPACE] failed to open datafile %s", df->ctrl->name);
            return OG_ERROR;
        }
    }

    for (;;) {
        cm_latch_s(&df->block_latch, OG_INVALID_ID32, OG_FALSE, NULL);
        if (!spc_datafile_is_blocked(session, df, (uint64)offset, end_pos)) {
            break;
        }
        cm_unlatch(&df->block_latch, NULL);
        cm_sleep(1);
    }

    for (uint16 i = begin; i < begin + sequent_cnt; i++) {
        buf_ctrl_t *ctrl = ogx->group.items[i].ctrl;
        buf_id = ogx->group.items[i].buf_id;
        page = (page_head_t *)(ogx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE(session));
        knl_panic_log(ctrl != NULL, "ctrl is NULL, panic info: page %u-%u type %u", AS_PAGID(page->id).file,
            AS_PAGID(page->id).page, page->type);
        knl_panic_log(IS_SAME_PAGID(ctrl->page_id, AS_PAGID(page->id)), "ctrl's page_id and page's id are not same, "
            "panic info: ctrl_page %u-%u type %u, page %u-%u type %u", ctrl->page_id.file,
            ctrl->page_id.page, ctrl->page->type, AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);

        if (dbwr_write_or_punch(session, &ogx->group.items[i], handle, df, page) != OG_SUCCESS) {
            cm_unlatch(&df->block_latch, NULL);
            spc_close_datafile(df, handle);
            return OG_ERROR;
        }

        ctrl->is_marked = 0;
    }

    if (!dbwr->flags[page_id->file]) {
        dbwr->flags[page_id->file] = OG_TRUE;
    }

    cm_unlatch(&df->block_latch, NULL);
    *saved_cnt = sequent_cnt;
    return OG_SUCCESS;
}

static status_t dbwr_flush_sync_io(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    uint16 saved_cnt;

    errno_t ret = memset_sp(dbwr->flags, sizeof(dbwr->flags), 0, sizeof(dbwr->flags));
    knl_securec_check(ret);

    if (ogx->has_compressed) {
        if (dbwr_compress_prepare(session, dbwr) != OG_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if (err_code != ERR_ALLOC_MEMORY) {
                return OG_ERROR;
            }
            /* if there is not enough memory, no compression is performed */
            cm_reset_error();
        }
    }

    for (uint16 i = dbwr->begin; i <= dbwr->end; i += saved_cnt) {
        if (dbwr_save_page_by_id(session, dbwr, i, &saved_cnt) != OG_SUCCESS) {
            return OG_ERROR;
        }
        knl_panic(saved_cnt == 1 || saved_cnt == PAGE_GROUP_COUNT);
    }

    if (session->kernel->attr.enable_fdatasync) {
        return dbwr_fdatasync(session, dbwr);
    }
    return OG_SUCCESS;
}

static status_t dbwr_flush(knl_session_t *session, dbwr_context_t *dbwr)
{
    if (cm_dbs_is_enable_dbs() && cm_dbs_is_enable_batch_flush()) {
        if (dbwr_flush_async_dbs(session, dbwr) != OG_SUCCESS) {
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
#ifndef WIN32
    if (session->kernel->attr.enable_asynch) {
        if (dbwr_flush_async_io(session, dbwr) != OG_SUCCESS) {
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
#endif

    if (dbwr_flush_sync_io(session, dbwr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

void dbwr_end(knl_session_t *session, dbwr_context_t *dbwr)
{
    for (uint32 i = 0; i < OG_MAX_DATA_FILES; i++) {
        datafile_t *df = DATAFILE_GET(session, i);
        cm_close_device(df->ctrl->type, &dbwr->datafiles[i]);
        dbwr->datafiles[i] = OG_INVALID_HANDLE;
    }
}

static void dbwr_aio_destroy(knl_session_t *session, dbwr_context_t *dbwr)
{
#ifndef WIN32
    knl_instance_t *kernel = session->kernel;

    if (!session->kernel->attr.enable_asynch) {
        return;
    }

    (void)cm_aio_destroy(&kernel->aio_lib, dbwr->async_ctx.aio_ctx);
#endif
}

void dbwr_proc(thread_t *thread)
{
    dbwr_context_t *dbwr = (dbwr_context_t *)thread->argument;
    knl_session_t *session = dbwr->session;
    status_t status;

    cm_set_thread_name("dbwr");
    OG_LOG_RUN_INF("dbwr thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    knl_attach_cpu_core();
    while (!thread->closed) {
#ifdef WIN32
        if (WaitForSingleObject(dbwr->sem, 5000) == WAIT_TIMEOUT) {
            continue;
        }
#else
        struct timespec wait_time;
        long nsecs;
        (void)clock_gettime(CLOCK_REALTIME, &wait_time);
        nsecs = wait_time.tv_nsec + 500 * NANOSECS_PER_MILLISEC; // 500ms
        wait_time.tv_sec += nsecs / (int32)NANOSECS_PER_SECOND;
        wait_time.tv_nsec = nsecs % (int32)NANOSECS_PER_SECOND;

        if (sem_timedwait(&dbwr->sem, &wait_time) == -1) {
            continue;
        }
#endif  // WIN32
        if (thread->closed) {
            break;
        }
        // if enable dbstor batch flush, dbwr->begin and dbwr->end will unuse
        knl_panic(dbwr->end >= dbwr->begin || (cm_dbs_is_enable_dbs() && cm_dbs_is_enable_batch_flush()));
        knl_panic(dbwr->dbwr_trigger);

        status = dbwr_flush(session, dbwr);
        if (status != OG_SUCCESS) {
            OG_LOG_ALARM(WARN_FLUSHBUFFER, "'instance-name':'%s'}", session->kernel->instance_name);
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT_REASONABLE(0, "[CKPT] ABORT INFO: db flush fail");
        }
        dbwr->dbwr_trigger = OG_FALSE;
    }

    dbwr_end(session, dbwr);
    dbwr_aio_destroy(session, dbwr);
    OG_LOG_RUN_INF("dbwr thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

static status_t ckpt_read_doublewrite_pages(knl_session_t *session, uint32 node_id)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    int64 offset;
    datafile_t *df;
    uint32 dw_file_id = knl_get_dbwrite_file_id(session);

    offset = (int64)ogx->dw_ckpt_start * DEFAULT_PAGE_SIZE(session);
    df = DATAFILE_GET(session, dw_file_id);

    knl_panic(ogx->dw_ckpt_start >= DW_DISTRICT_BEGIN(node_id));
    knl_panic(ogx->dw_ckpt_end <= DW_DISTRICT_END(node_id));
    knl_panic(df->ctrl->id == dw_file_id);  // first sysware file

    ogx->group.count = ogx->dw_ckpt_end - ogx->dw_ckpt_start;
    /* DEFAULT_PAGE_SIZE is 8192, ogx->group.count <= OG_CKPT_GROUP_SIZE(4096), can not cross bounds */
    if (spc_read_datafile(session, df, &ogx->dw_file, offset, ogx->group.buf,
        ogx->group.count * DEFAULT_PAGE_SIZE(session)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CKPT] failed to open datafile %s", df->ctrl->name);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t ckpt_recover_decompress(knl_session_t *session, int32 *handle, page_head_t *page,
    const char *read_buf, char *org_group)
{
    const uint32 group_size = DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    status_t status = OG_SUCCESS;
    page_head_t *org_page = NULL;
    uint32 size;
    errno_t ret;

    if (((page_head_t *)read_buf)->compressed) {
        if (buf_check_load_compress_group(session, *page_id, read_buf) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (buf_decompress_group(session, org_group, read_buf, &size) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (size != group_size) {
            return OG_ERROR;
        }
    } else {
        ret = memcpy_s(org_group, group_size, read_buf, group_size);
        knl_securec_check(ret);
    }

    for (uint32 i = 0; i < PAGE_GROUP_COUNT; i++) {
        org_page = (page_head_t *)((char *)org_group + i * DEFAULT_PAGE_SIZE(session));
        if (!CHECK_PAGE_PCN(org_page) || (PAGE_CHECKSUM(org_page, DEFAULT_PAGE_SIZE(session)) == OG_INVALID_CHECKSUM) ||
            !page_verify_checksum(org_page, DEFAULT_PAGE_SIZE(session))) {
            OG_LOG_RUN_INF("[CKPT] datafile %s page corrupted(file %u, page %u), recover from doublewrite page",
                df->ctrl->name, page_id->file, page_id->page + i);
            status = OG_ERROR;
        }
    }

    return status;
}

static status_t ckpt_recover_one(knl_session_t *session, int32 *handle, page_head_t *page, page_head_t *org_page,
    bool32 force_recover)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    space_t *space = SPACE_GET(session, df->space_id);
    status_t status;

    if (!force_recover) {
        if (CHECK_PAGE_PCN(org_page) && (PAGE_CHECKSUM(org_page, DEFAULT_PAGE_SIZE(session)) != OG_INVALID_CHECKSUM) &&
            page_verify_checksum(org_page, DEFAULT_PAGE_SIZE(session))) {
            if (org_page->lsn >= page->lsn) {
                return OG_SUCCESS;
            }
            OG_LOG_RUN_INF(
                "[CKPT] datafile %s page (file %u, page %u) found older data with lsn %llu than doublewrite %llu",
                df->ctrl->name, page_id->file, page_id->page, org_page->lsn, page->lsn);

            if (!(CHECK_PAGE_PCN(page) && (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) != OG_INVALID_CHECKSUM) &&
                  page_verify_checksum(page, DEFAULT_PAGE_SIZE(session)))) {
                OG_LOG_RUN_INF("[CKPT] datafile %s page (file %u, page %u) is newer in dbwr but is corrupted.",
                               df->ctrl->name, page_id->file, page_id->page);
                return OG_SUCCESS;
            }
        }
        OG_LOG_RUN_INF("[CKPT] datafile %s page corrupted(file %u, page %u), recover from doublewrite page",
            df->ctrl->name, page_id->file, page_id->page);
    }

    knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
        page_id->page, page->type);
    knl_panic_log((PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) == OG_INVALID_CHECKSUM) ||
        page_verify_checksum(page, DEFAULT_PAGE_SIZE(session)), "checksum is wrong, panic info: page %u-%u type %u",
        page_id->file, page_id->page, page->type);

    status = spc_write_datafile(session, df, handle, offset, page, DEFAULT_PAGE_SIZE(session));
    if (status != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CKPT] failed to write datafile %s, file %u, page %u", df->ctrl->name, page_id->file,
            page_id->page);
    } else {
        status = db_fdatasync_file(session, *handle);
        if (status != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[CKPT] failed to fdatasync datafile %s", df->ctrl->name);
        }
    }

    if (status != OG_SUCCESS) {
        if (spc_auto_offline_space(session, space, df)) {
            status = OG_SUCCESS;
        }
    }

    return status;
}

static status_t ckpt_recover_compress_group(knl_session_t *session, ckpt_context_t *ogx, uint32 slot)
{
    rcy_sort_item_t *item = &ogx->rcy_items[slot];
    page_head_t *page = item->page;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    space_t *space = SPACE_GET(session, df->space_id);
    int32 handle = -1;
    char *read_buf = NULL;
    char *src = NULL;
    char *org_group = NULL;
    uint32 size;
    status_t status = OG_SUCCESS;

    knl_panic_log(page_id->page % PAGE_GROUP_COUNT == 0, "panic info: page %u-%u not the group head", page_id->file,
        page_id->page);
    size = DEFAULT_PAGE_SIZE(session) * PAGE_GROUP_COUNT;
    src = (char *)malloc(size + OG_MAX_ALIGN_SIZE_4K);
    if (src == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, size + OG_MAX_ALIGN_SIZE_4K, "recover compress group");
        return OG_ERROR;
    }
    org_group = (char *)malloc(size);
    if (org_group == NULL) {
        free(src);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, size, "recover compress group");
        return OG_ERROR;
    }
    read_buf = (char *)cm_aligned_buf(src);
    if (spc_read_datafile(session, df, &handle, offset, read_buf, size) != OG_SUCCESS) {
        spc_close_datafile(df, &handle);
        OG_LOG_RUN_ERR("[CKPT] failed to read datafile %s, file %u, page %u", df->ctrl->name, page_id->file,
            page_id->page);

        if (spc_auto_offline_space(session, space, df)) {
            OG_LOG_RUN_INF("[CKPT] skip recover offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
            free(org_group);
            free(src);
            return OG_SUCCESS;
        }

        free(org_group);
        free(src);
        return OG_ERROR;
    }

    if (ckpt_recover_decompress(session, &handle, page, read_buf, org_group) != OG_SUCCESS) {
        OG_LOG_RUN_INF("[CKPT] datafile %s decompress group failed(file %u, page %u), recover from doublewrite",
            df->ctrl->name, page_id->file, page_id->page);
        /* we need to recover the compress group as a whole */
        for (uint32 i = 0; i < PAGE_GROUP_COUNT; i++) {
            if (ckpt_recover_one(session, &handle, ogx->rcy_items[slot + i].page,
                (page_head_t *)((char *)org_group + i * DEFAULT_PAGE_SIZE(session)), OG_TRUE) != OG_SUCCESS) {
                status = OG_ERROR;
                break;
            }
        }
    }

    free(org_group);
    free(src);
    spc_close_datafile(df, &handle);
    return status;
}

static status_t ckpt_recover_normal(knl_session_t *session, ckpt_context_t *ogx, uint32 slot, page_head_t *org_page)
{
    rcy_sort_item_t *item = &ogx->rcy_items[slot];
    page_head_t *page = item->page;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    space_t *space = SPACE_GET(session, df->space_id);
    int32 handle = -1;
    status_t status;

    if (spc_read_datafile(session, df, &handle, offset, org_page, DEFAULT_PAGE_SIZE(session)) != OG_SUCCESS) {
        spc_close_datafile(df, &handle);
        OG_LOG_RUN_ERR("[CKPT] failed to read datafile %s, file %u, page %u", df->ctrl->name, page_id->file,
            page_id->page);

        if (spc_auto_offline_space(session, space, df)) {
            OG_LOG_RUN_INF("[CKPT] skip recover offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
            return OG_SUCCESS;
        }

        return OG_ERROR;
    }

    status = ckpt_recover_one(session, &handle, page, org_page, OG_FALSE);
    spc_close_datafile(df, &handle);
    return status;
}

static status_t ckpt_recover_page(knl_session_t *session, ckpt_context_t *ogx, uint32 slot, page_head_t *org_page,
    uint32 *skip_cnt)
{
    rcy_sort_item_t *item = &ogx->rcy_items[slot];
    page_head_t *page = item->page;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(session, page_id->file);
    space_t *space = SPACE_GET(session, df->space_id);
    status_t status;

    if (!SPACE_IS_ONLINE(space) || !DATAFILE_IS_ONLINE(df)) {
        OG_LOG_RUN_INF("[CKPT] skip recover offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
        return OG_SUCCESS;
    }

    if (page_compress(session, *page_id)) {
        *skip_cnt = PAGE_GROUP_COUNT;
        status = ckpt_recover_compress_group(session, ogx, slot);
    } else {
        *skip_cnt = 1;
        status = ckpt_recover_normal(session, ogx, slot, org_page);
    }

    return status;
}

static int32 ckpt_rcyorder_comparator(const void *pa, const void *pb)
{
    const rcy_sort_item_t *a = (const rcy_sort_item_t *)pa;
    const rcy_sort_item_t *b = (const rcy_sort_item_t *)pb;

    /* compare fileid */
    if (AS_PAGID(a->page->id).file < AS_PAGID(b->page->id).file) {
        return -1;
    } else if (AS_PAGID(a->page->id).file > AS_PAGID(b->page->id).file) {
        return 1;
    }

    /* compare page */
    if (AS_PAGID(a->page->id).page < AS_PAGID(b->page->id).page) {
        return -1;
    } else if (AS_PAGID(a->page->id).page > AS_PAGID(b->page->id).page) {
        return 1;
    }

    /* equal pageid is impossible */
    return 0;
}

static void ckpt_recover_prepare(knl_session_t *session, ckpt_context_t *ogx)
{
    page_head_t *page = NULL;

    for (uint32 i = 0; i < ogx->group.count; i++) {
        page = (page_head_t *)(ogx->group.buf + i * DEFAULT_PAGE_SIZE(session));
        ogx->rcy_items[i].page = page;
        ogx->rcy_items[i].buf_id = i;
    }
    qsort(ogx->rcy_items, ogx->group.count, sizeof(rcy_sort_item_t), ckpt_rcyorder_comparator);
}

static status_t ckpt_recover_pages(knl_session_t *session, ckpt_context_t *ogx, uint32 node_id)
{
    uint32 i;
    page_head_t *page = NULL;
    char *page_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session) + OG_MAX_ALIGN_SIZE_4K);
    char *head = (char *)cm_aligned_buf(page_buf);
    dtc_node_ctrl_t *node = dtc_get_ctrl(session, node_id);
    uint16 swap_file_head = SPACE_GET(session, node->swap_space)->ctrl->files[0];
    uint32 skip_cnt;

    ckpt_recover_prepare(session, ogx);
    for (i = 0; i < ogx->group.count; i = i + skip_cnt) {
        page = ogx->rcy_items[i].page;
        page_id_t *page_id = AS_PAGID_PTR(page->id);
        skip_cnt = 1;

        if (page_id->file == swap_file_head) {
            OG_LOG_RUN_INF("[CKPT] skip recover swap datafile %s", DATAFILE_GET(session, swap_file_head)->ctrl->name);
            continue;
        }

        if (ckpt_recover_page(session, ogx, i, (page_head_t *)head, &skip_cnt) != OG_SUCCESS) {
            cm_pop(session->stack);
            return OG_ERROR;
        }
    }

    cm_pop(session->stack);
    ogx->group.count = 0;
    ogx->dw_ckpt_start = ogx->dw_ckpt_end;
    node->dw_start = ogx->dw_ckpt_end;

    if (dtc_save_ctrl(session, node_id) != OG_SUCCESS) {
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when checkpoint recover pages");
    }

    return OG_SUCCESS;
}

status_t ckpt_recover_partial_write_node(knl_session_t *session, uint32 node_id)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    dtc_node_ctrl_t *node = dtc_get_ctrl(session, node_id);

    ogx->dw_ckpt_start = node->dw_start;
    ogx->dw_ckpt_end = node->dw_end;

    if (ogx->dw_ckpt_start == ogx->dw_ckpt_end) {
        return OG_SUCCESS;
    }

    if (ckpt_read_doublewrite_pages(session, node_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ckpt_recover_pages(session, ogx, node_id) != OG_SUCCESS) {
        return OG_ERROR;
    }
    OG_LOG_RUN_INF("[CKPT] ckpt recover doublewrite finish for node %u", node_id);
    return OG_SUCCESS;
}

status_t ckpt_recover_partial_write(knl_session_t *session)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    dtc_node_ctrl_t *node = dtc_my_ctrl(session);
    uint32 node_count = session->kernel->db.ctrl.core.node_count;

    if (DB_ATTR_CLUSTER(session) && !rc_is_master()) {
        ogx->dw_ckpt_start = node->dw_start;
        ogx->dw_ckpt_end = node->dw_start;
        OG_LOG_RUN_INF("[CKPT] ckpt doublewrite recover has been done on master node.");
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < node_count; i++) {
        ckpt_recover_partial_write_node(session, i);
    }

    ogx->dw_ckpt_start = node->dw_start;
    ogx->dw_ckpt_end = node->dw_start;

    OG_LOG_RUN_INF("[CKPT] ckpt recover finish, memory usage=%lu", cm_print_memory_usage());
    return OG_SUCCESS;
}

/* Forbidden others to set new task, and then wait the running task to finish */
void ckpt_disable(knl_session_t *session)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    cm_spin_lock(&ogx->disable_lock, NULL);
    ogx->disable_cnt++;
    ogx->ckpt_enabled = OG_FALSE;
    cm_spin_unlock(&ogx->disable_lock);
    while ((ogx->trigger_task != CKPT_MODE_IDLE || ogx->timed_task != CKPT_MODE_IDLE) && !ogx->ckpt_blocked) {
        cm_sleep(10);
    }
}

void ckpt_enable(knl_session_t *session)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    cm_spin_lock(&ogx->disable_lock, NULL);
    if (ogx->disable_cnt > 0) {
        ogx->disable_cnt--;
    }
    if (ogx->disable_cnt == 0) {
        ogx->ckpt_enabled = OG_TRUE;
    }
    cm_spin_unlock(&ogx->disable_lock);
}

void ckpt_disable_update_point(knl_session_t *session)
{
    ckpt_disable(session);
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    cm_spin_lock(&ogx->disable_lock, NULL);
    ogx->disable_update_point_cnt++;
    ogx->ckpt_enable_update_point = OG_FALSE;
    cm_spin_unlock(&ogx->disable_lock);
    ckpt_enable(session);
}

void ckpt_enable_update_point(knl_session_t *session)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    cm_spin_lock(&ogx->disable_lock, NULL);
    if (ogx->disable_update_point_cnt > 0)
    {
        ogx->disable_update_point_cnt--;
    }
    if (ogx->disable_update_point_cnt == 0)
    {
        ogx->ckpt_enable_update_point = OG_TRUE;
    }
    cm_spin_unlock(&ogx->disable_lock);
}

/*
 * disable ckpt and remove page of df to be removed from ckpt queue
 */
void ckpt_remove_df_page(knl_session_t *session, datafile_t *df, bool32 need_disable)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ogx = &kernel->ckpt_ctx;
    uint32 pop_count = 0;

    if (need_disable) {
        ckpt_disable(session);
    }

    /* remove page from queue base on file id */
    cm_spin_lock(&ogx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    buf_ctrl_t *curr = ogx->queue.first;
    buf_ctrl_t *last = ogx->queue.last;
    cm_spin_unlock(&ogx->queue.lock);

    buf_ctrl_t *next = NULL;
    while (ogx->queue.count != 0 && curr != NULL && curr != last->ckpt_next) {
        next = curr->ckpt_next;
        if (curr->page_id.file == df->ctrl->id) {
            ckpt_pop_page(session, ogx, curr);
            curr->is_dirty = 0;
            curr->is_remote_dirty = 0;
            curr->is_edp = 0;
            buf_expire_page(session, curr->page_id);
            pop_count++;
        }
        curr = next;
    }

    if (need_disable) {
        ckpt_enable(session);
    }

    OG_LOG_RUN_INF("[CKPT] remove df page, count=%u, df=%s.", pop_count, df->ctrl->name);
}

static status_t ckpt_clean_try_latch_group(knl_session_t *session, buf_ctrl_t *ctrl, buf_ctrl_t **ctrl_group)
{
    page_id_t page_id;
    uint32 i;
    uint32 j;
    buf_ctrl_t *cur_ctrl = NULL;

    page_id = page_first_group_id(session, ctrl->page_id);
    
    for (i = 0; i < PAGE_GROUP_COUNT; i++, page_id.page++) {
        cur_ctrl = buf_find_by_pageid(session, page_id);
        knl_panic(cur_ctrl != NULL);
        if (!ckpt_try_latch_ctrl(session, cur_ctrl)) {
            for (j = 0; j < i; j++) {
                buf_unlatch(session, ctrl_group[j], OG_FALSE);
            }
            return OG_ERROR;
        }
        ctrl_group[i] = cur_ctrl;
    }

    return OG_SUCCESS;
}

static status_t ckpt_clean_prepare_compress(knl_session_t *session, ckpt_context_t *ogx, buf_ctrl_t *head)
{
    ogx->has_compressed = OG_TRUE;
    buf_ctrl_t *ctrl_group[PAGE_GROUP_COUNT];
    int32 i;
    int32 j;

    if (ogx->group.count + PAGE_GROUP_COUNT > OG_CKPT_GROUP_SIZE(session)) {
        return OG_SUCCESS; // continue the next
    }

    if (ckpt_clean_try_latch_group(session, head, ctrl_group) != OG_SUCCESS) {
        return OG_SUCCESS; // continue the next
    }

    knl_panic(!head->is_marked);
    knl_panic(head->in_ckpt);

    /* Copy all the compression group pages to ckpt group.
     * If a page is dirty (in ckpt queue), we will pop it and update its flags.
     */
    for (i = 0; i < PAGE_GROUP_COUNT; i++) {
        knl_panic_log(IS_SAME_PAGID(ctrl_group[i]->page_id, AS_PAGID(ctrl_group[i]->page->id)),
            "ctrl_group[%d]'s page_id and page's id are not same, panic info: page_id %u-%u type %u, page id %u-%u "
            "type %u", i, ctrl_group[i]->page_id.file, ctrl_group[i]->page_id.page, ctrl_group[i]->page->type,
            AS_PAGID(ctrl_group[i]->page->id).file, AS_PAGID(ctrl_group[i]->page->id).page, ctrl_group[i]->page->type);

        errno_t ret = memcpy_sp(ogx->group.buf + DEFAULT_PAGE_SIZE(session) * ogx->group.count,
            DEFAULT_PAGE_SIZE(session), ctrl_group[i]->page, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);

        if (ctrl_group[i]->is_dirty) {
            knl_panic(ctrl_group[i]->in_ckpt);
            ckpt_pop_page(session, ogx, ctrl_group[i]);
            if (ogx->consistent_lfn < ctrl_group[i]->lastest_lfn) {
                ogx->consistent_lfn = ctrl_group[i]->lastest_lfn;
            }
            ctrl_group[i]->is_marked = 1;
            CM_MFENCE;
            ctrl_group[i]->is_dirty = 0;
        }

        buf_unlatch(session, ctrl_group[i], OG_FALSE);

        ogx->group.items[ogx->group.count].ctrl = ctrl_group[i];
        ogx->group.items[ogx->group.count].buf_id = ogx->group.count;
        ogx->group.items[ogx->group.count].need_punch = OG_FALSE;

        if (ckpt_encrypt(session, ogx) != OG_SUCCESS) {
            for (j = i + 1; j < PAGE_GROUP_COUNT; j++) {
                buf_unlatch(session, ctrl_group[j], OG_FALSE);
            }
            return OG_ERROR;
        }
        if (ckpt_checksum(session, ogx) != OG_SUCCESS) {
            for (j = i + 1; j < PAGE_GROUP_COUNT; j++) {
                buf_unlatch(session, ctrl_group[j], OG_FALSE);
            }
            return OG_ERROR;
        }

        ogx->group.count++;
    }

    return OG_SUCCESS;
}

static status_t ckpt_clean_prepare_normal(knl_session_t *session, ckpt_context_t *ogx, buf_ctrl_t *shift)
{
    if (!ckpt_try_latch_ctrl(session, shift)) {
        return OG_SUCCESS; // continue the next
    }

    if (DB_IS_CLUSTER(session)) {
        if (shift->is_edp) {
            OG_LOG_DEBUG_INF("[CKPT]checkpoint find edp [%u-%u], count(%d)", shift->page_id.file, shift->page_id.page,
                             ogx->edp_group.count);
            knl_panic(DCS_BUF_CTRL_NOT_OWNER(session, shift));
            buf_unlatch(session, shift, OG_FALSE);
            (void)(dtc_add_to_edp_group(session, &ogx->edp_group, OG_CKPT_GROUP_SIZE(session), shift->page_id,
                                        shift->page->lsn));
            return OG_SUCCESS;
        }

        if (shift->in_ckpt == OG_FALSE) {
            buf_unlatch(session, shift, OG_FALSE);
            return OG_SUCCESS;
        }

        knl_panic(DCS_BUF_CTRL_IS_OWNER(session, shift));
        if (shift->is_remote_dirty && !dtc_add_to_edp_group(session, &ogx->remote_edp_clean_group,
            OG_CKPT_GROUP_SIZE(session),
                                                            shift->page_id, shift->page->lsn)) {
            buf_unlatch(session, shift, OG_FALSE);
            return OG_SUCCESS;
        }
    }

    knl_panic(!shift->is_marked);
    knl_panic(shift->in_ckpt);

    knl_panic_log(IS_SAME_PAGID(shift->page_id, AS_PAGID(shift->page->id)),
        "shift's page_id and shift page's id are not same, panic info: page_id %u-%u type %u, "
        "page id %u-%u type %u", shift->page_id.file, shift->page_id.page,
        shift->page->type, AS_PAGID(shift->page->id).file,
        AS_PAGID(shift->page->id).page, shift->page->type);

    /* copy page from buffer to ckpt group */
    errno_t ret = memcpy_sp(ogx->group.buf + DEFAULT_PAGE_SIZE(session) * ogx->group.count,
        DEFAULT_PAGE_SIZE(session), shift->page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    
    ckpt_pop_page(session, ogx, shift);
    
    if (ogx->consistent_lfn < shift->lastest_lfn) {
        ogx->consistent_lfn = shift->lastest_lfn;
    }

    shift->is_marked = 1;
    CM_MFENCE;
    shift->is_dirty = 0;
    shift->is_remote_dirty = 0;
    buf_unlatch(session, shift, OG_FALSE);

    ogx->group.items[ogx->group.count].ctrl = shift;
    ogx->group.items[ogx->group.count].buf_id = ogx->group.count;
    ogx->group.items[ogx->group.count].need_punch = OG_FALSE;

    if (ckpt_encrypt(session, ogx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (ckpt_checksum(session, ogx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    ckpt_put_to_part_group(session, ogx, shift);
    ogx->group.count++;
    return OG_SUCCESS;
}

/*
 * prepare pages to be cleaned
 * 1.search dirty page from write list of buffer set and copy to ckpt group
 * 2.stash dirty pages for releasing after flushing.
 */
static status_t ckpt_clean_prepare_pages(knl_session_t *session, ckpt_context_t *ogx, buf_set_t *set,
    buf_lru_list_t *page_list, ckpt_stat_items_t *stat)
{
    ogx->has_compressed = OG_FALSE;
    buf_ctrl_t *ctrl = NULL;
    buf_ctrl_t *shift = NULL;
    if (ogx->clean_end != NULL) {
        ctrl = ogx->clean_end;
    } else {
        cm_spin_lock(&set->write_list.lock, NULL);
        ctrl = set->write_list.lru_last;
        cm_spin_unlock(&set->write_list.lock);
    }
    init_ckpt_part_group(session);
    ogx->group.count = 0;
    ogx->edp_group.count = 0;
    if (DB_IS_CLUSTER(session)) {
        dcs_ckpt_remote_edp_prepare(session, ogx);
        dcs_ckpt_clean_local_edp(session, ogx, stat);
    }

    if (ogx->group.count >= OG_CKPT_GROUP_SIZE(session)) {
        return OG_SUCCESS;
    }

    while (ctrl != NULL) {
        shift = ctrl;
        ctrl = ctrl->prev;
    
        /* page has been expired */
        if (shift->bucket_id == OG_INVALID_ID32) {
            buf_stash_marked_page(set, page_list, shift);
            continue;
        }
        /* page has alreay add to group by dcs_ckpt_remote_edp_prepare */
        if (DB_IS_CLUSTER(session) && shift->is_marked) {
            continue;
        }

        /* page has already been flushed by checkpoint.
         * We need not hold lock to the ctrl when tesing dirty, since there is no harm
         * if it is set to dirty by others again after we get a not-dirty result.
         */
        if (!shift->is_dirty) {
            buf_stash_marked_page(set, page_list, shift);
            continue;
        }

        /* because page clean doesn't modify batch_end, therefore we skip ctrl which equals batch_end,
         * otherwise checkpoint full will not end */
        if (shift == ogx->batch_end) {
            buf_stash_marked_page(set, page_list, shift);
            continue;
        }
    
        status_t status;
        if (page_compress(session, shift->page_id)) {
            status = ckpt_clean_prepare_compress(session, ogx, shift);
        } else {
            status = ckpt_clean_prepare_normal(session, ogx, shift);
        }
        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }

        buf_stash_marked_page(set, page_list, shift);

        if (ogx->group.count >= OG_CKPT_GROUP_SIZE(session) || ogx->edp_group.count >= OG_CKPT_GROUP_SIZE(session) ||
            ogx->remote_edp_clean_group.count >= OG_CKPT_GROUP_SIZE(session)) {
            ogx->clean_end = ctrl;
            return OG_SUCCESS;
        }
    }

    ogx->clean_end = NULL;
    return OG_SUCCESS;
}

/*
 * clean dirty page on write list of given buffer set.
 * 1.only flush a part of dirty page to release clean page of other buffer set.
 * 2.need to flush one more time because of ckpt group size limitation.
 */
static status_t ckpt_clean_single_set(knl_session_t *session, ckpt_context_t *ckpt_ctx,
                                      buf_set_t *set, ckpt_stat_items_t *stat)
{
    buf_lru_list_t page_list;
    int64 clean_cnt = (int64)(set->write_list.count * CKPT_PAGE_CLEAN_RATIO(session));
    ckpt_ctx->clean_end = NULL;

    for (;;) {
        page_list = g_init_list_t;
        if (ckpt_clean_prepare_pages(session, ckpt_ctx, set, &page_list, stat) != OG_SUCCESS) {
            return OG_ERROR;
        }

        dcs_notify_owner_for_ckpt(session, ckpt_ctx);
        stat->flush_pages += ckpt_ctx->group.count;

        if (ckpt_ctx->group.count == 0) {
            dcs_clean_edp(session, ckpt_ctx);
            buf_reset_cleaned_pages(set, &page_list);
            return OG_SUCCESS;
        }

        if (ckpt_flush_prepare(session, ckpt_ctx) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (ckpt_flush_pages(session) != OG_SUCCESS) {
            CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean page.");
        }

        dcs_clean_edp(session, ckpt_ctx);
        buf_reset_cleaned_pages(set, &page_list);

        clean_cnt -= ckpt_ctx->group.count;
        ckpt_ctx->group.count = 0;
        ckpt_ctx->dw_ckpt_start = ckpt_ctx->dw_ckpt_end;
        dtc_my_ctrl(session)->dw_start = ckpt_ctx->dw_ckpt_end;

        if (dtc_save_ctrl(session, session->kernel->id) != OG_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        }

        /* only clean a part of pages when generate by trigger */
        if (clean_cnt <= 0 || ckpt_ctx->clean_end == NULL) {
            return OG_SUCCESS;
        }
    }
    return OG_SUCCESS;
}

static inline void ckpt_bitmap_set(uint8 *bitmap, uint8 num)
{
    uint8 position;
    position = (uint8)1 << (num % CKPT_BITS_PER_BYTE);

    bitmap[num / CKPT_BITS_PER_BYTE] |= position;
}

static inline void ckpt_bitmap_clear(uint8 *bitmap, uint8 num)
{
    uint8 position;
    position = ~((uint8)1 << (num % CKPT_BITS_PER_BYTE));

    bitmap[num / CKPT_BITS_PER_BYTE] &= position;
}

static inline bool32 ckpt_bitmap_exist(uint8 *bitmap, uint8 num)
{
    uint8 position;
    position = (uint8)1 << (num % CKPT_BITS_PER_BYTE);
    position = bitmap[num / CKPT_BITS_PER_BYTE] & position;

    return 0 != position;
}

static status_t ckpt_clean_prepare_pages_all_set(knl_session_t *session, ckpt_context_t *ogx, buf_lru_list_t *page_list,
    ckpt_clean_ctx_t *page_clean_ctx, ckpt_stat_items_t *stat)
{
    ogx->has_compressed = OG_FALSE;
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    buf_ctrl_t *shift = NULL;
    ogx->group.count = 0;
    ogx->edp_group.count = 0;
    init_ckpt_part_group(session);
    if (DB_IS_CLUSTER(session)) {
        dcs_ckpt_remote_edp_prepare(session, ogx);
        dcs_ckpt_clean_local_edp(session, ogx, stat);
    }

    if (ogx->group.count >= OG_CKPT_GROUP_SIZE(session)) {
        return OG_SUCCESS;
    }

    uint32 index = page_clean_ctx->next_index;
    while (memcmp(page_clean_ctx->bitmap, g_page_clean_finish_flag, PAGE_CLEAN_MAX_BYTES) != 0) {
        index = page_clean_ctx->next_index;
        page_clean_ctx->next_index = (index + 1) % buf_ctx->buf_set_count;
        if (!ckpt_bitmap_exist(page_clean_ctx->bitmap, index)) {
            continue;
        }
        shift = page_clean_ctx->ctrl[index];
        if (shift == NULL) {
            ckpt_bitmap_clear(page_clean_ctx->bitmap, index);
            continue;
        }
        page_clean_ctx->ctrl[index] = shift->prev;
        page_clean_ctx->clean_count[index] -= 1;
        if (page_clean_ctx->clean_count[index] == 0) {
            ckpt_bitmap_clear(page_clean_ctx->bitmap, index);
        }
        /* page has been expired */
        if (shift->bucket_id == OG_INVALID_ID32) {
            buf_stash_marked_page(&buf_ctx->buf_set[index], page_list, shift);
            continue;
        }

        /* page has alreay add to group by dcs_ckpt_remote_edp_prepare */
        if (DB_IS_CLUSTER(session) && shift->is_marked) {
            continue;
        }
        /* page has already been flushed by checkpoint.
         * We need not hold lock to the ctrl when tesing dirty, since there is no harm
         * if it is set to dirty by others again after we get a not-dirty result.
         */
        if (!shift->is_dirty) {
            buf_stash_marked_page(&buf_ctx->buf_set[index], page_list, shift);
            continue;
        }

        /* because page clean doesn't modify batch_end, therefore we skip ctrl which equals batch_end,
         * otherwise checkpoint full will not end */
        if (shift == ogx->batch_end) {
            buf_stash_marked_page(&buf_ctx->buf_set[index], page_list, shift);
            continue;
        }

        status_t status;
        if (page_compress(session, shift->page_id)) {
            status = ckpt_clean_prepare_compress(session, ogx, shift);
        } else {
            status = ckpt_clean_prepare_normal(session, ogx, shift);
        }
        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }

        buf_stash_marked_page(&buf_ctx->buf_set[index], page_list, shift);
        if (ogx->group.count >= OG_CKPT_GROUP_SIZE(session) || ogx->edp_group.count >= OG_CKPT_GROUP_SIZE(session) ||
            ogx->remote_edp_clean_group.count >= OG_CKPT_GROUP_SIZE(session)) {
            return OG_SUCCESS;
        }
    }
    return OG_SUCCESS;
}

static void ckpt_clean_prepare_buf_list(buf_context_t *buf_ctx, ckpt_clean_ctx_t *page_clean_ctx, double clean_ratio)
{
    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        page_clean_ctx->clean_count[i] = buf_ctx->buf_set[i].write_list.count * clean_ratio;
        cm_spin_lock(&buf_ctx->buf_set[i].write_list.lock, NULL);
        page_clean_ctx->ctrl[i] = buf_ctx->buf_set[i].write_list.lru_last;
        cm_spin_unlock(&buf_ctx->buf_set[i].write_list.lock);
        ckpt_bitmap_set(page_clean_ctx->bitmap, i);
    }
}

/*
 * clean dirty page on write list of all buffer set.
 * 1.only flush a part of dirty page to release clean page of buffer set.
 * 2.need to flush one more time because of ckpt group size limitation.
 * 3.when flush once will get page from all off the buffer set
 */
static status_t ckpt_clean_all_set(knl_session_t *session, ckpt_stat_items_t *stat)
{
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;
    ckpt_clean_ctx_t page_clean_ctx = {0};
    ckpt_clean_prepare_buf_list(buf_ctx, &page_clean_ctx, CKPT_PAGE_CLEAN_RATIO(session));
    buf_lru_list_t page_list;
    for (;;) {
        page_list = g_init_list_t;
        if (ckpt_clean_prepare_pages_all_set(session, ckpt_ctx, &page_list, &page_clean_ctx, stat) != OG_SUCCESS) {
            return OG_ERROR;
        }

        dcs_notify_owner_for_ckpt(session, ckpt_ctx);
        stat->flush_pages += ckpt_ctx->group.count;
        if (ckpt_ctx->group.count == 0) {
            dcs_clean_edp(session, ckpt_ctx);
            buf_reset_cleaned_pages_all_bufset(buf_ctx, &page_list);
            return OG_SUCCESS;
        }

        if (ckpt_flush_prepare(session, ckpt_ctx) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (ckpt_flush_pages(session) != OG_SUCCESS) {
            CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean page.");
        }

        dcs_clean_edp(session, ckpt_ctx);
        buf_reset_cleaned_pages_all_bufset(buf_ctx, &page_list);

        ckpt_ctx->group.count = 0;
        ckpt_ctx->dw_ckpt_start = ckpt_ctx->dw_ckpt_end;
        dtc_my_ctrl(session)->dw_start = ckpt_ctx->dw_ckpt_end;

        if (dtc_save_ctrl(session, session->kernel->id) != OG_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        }

        /* only clean a part of pages when generate by trigger */
        if (memcmp(page_clean_ctx.bitmap, g_page_clean_finish_flag, PAGE_CLEAN_MAX_BYTES) == 0) {
            return OG_SUCCESS;
        }
    }
    return OG_SUCCESS;
}

/*
 * clean dirty page on buffer write list of each buffer set
 */
static void ckpt_page_clean(knl_session_t *session, ckpt_stat_items_t *stat)
{
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;
    page_clean_t clean_mode = session->kernel->attr.page_clean_mode;
    if (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master() == OG_FALSE) {
        return;
    }
    uint64 task_begin = KNL_NOW(session);
    stat->ckpt_begin_time = (date_t)task_begin;
    if (clean_mode == PAGE_CLEAN_MODE_ALLSET) {
        ckpt_block_and_wait_enable(&session->kernel->ckpt_ctx);
        uint64 task_wait = KNL_NOW(session);
        stat->wait_us += ckpt_stat_time_diff(task_begin, task_wait);
        if (ckpt_clean_all_set(session, stat) != OG_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean dirty page");
        }
        uint64 task_clean = KNL_NOW(session);
        stat->clean_edp_us += ckpt_stat_time_diff(task_wait, task_clean);
    } else if (clean_mode == PAGE_CLEAN_MODE_SINGLESET) {
        for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
            uint64 task_buf_set_begin = KNL_NOW(session);
            ckpt_block_and_wait_enable(&session->kernel->ckpt_ctx);
            uint64 task_wait = KNL_NOW(session);
            stat->wait_us += ckpt_stat_time_diff(task_buf_set_begin, task_wait);
            if (ckpt_clean_single_set(session, ckpt_ctx, &buf_ctx->buf_set[i], stat) != OG_SUCCESS) {
                KNL_SESSION_CLEAR_THREADID(session);
                CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean dirty page");
            }
            uint64 task_clean = KNL_NOW(session);
            stat->clean_edp_us += ckpt_stat_time_diff(task_wait, task_clean);
        }
    } else {
        CM_ABORT(0, "[CKPT] ABORT INFO: Not support this mode %d", session->kernel->attr.page_clean_mode);
    }
    uint64 task_end = KNL_NOW(session);
    stat->task_us += ckpt_stat_time_diff(task_begin, task_end);
}

void ckpt_put_to_part_group(knl_session_t *session, ckpt_context_t *ogx, buf_ctrl_t *to_flush_ctrl)
{
    if (cm_dbs_is_enable_dbs() == OG_FALSE || cm_dbs_is_enable_batch_flush() == OG_FALSE) {
        return;
    }
    uint32 part_id = 0;
    (void)cm_cal_partid_by_pageid(to_flush_ctrl->page_id.page, DEFAULT_PAGE_SIZE(session), &part_id);
    uint32 index = ogx->ckpt_part_group[part_id].count;
    ogx->ckpt_part_group[part_id].count++;
    ogx->ckpt_part_group[part_id].item_index[index] = ogx->group.count;
}
