/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co., Ltd. All rights reserved.
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
 * knl_remote_buffer.h
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/knl_remote_buffer.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_REMOTE_BUFFER_H__
#define __KNL_REMOTE_BUFFER_H__

#include "cm_types.h"
#include "cm_spinlock.h"
#include "knl_buffer.h"
#include "knl_context.h"
#include "dtc_drc.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void remote_buf_unlatch(knl_session_t *session, buf_ctrl_t *ctrl, bool32 release)
{
    buf_set_t *set = &DRC_GBP_BUF_CTX->buf_set[ctrl->buf_pool_id];
    buf_bucket_t *bucket = BUF_GET_BUCKET(set, ctrl->bucket_id);
    buf_latch_t *latch = &ctrl->latch;

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);

    if (latch->shared_count > 0) {
        latch->shared_count--;
    }

    if (release) {
        if (SECUREC_UNLIKELY(ctrl->ref_num == 0)) {
            /* Idempotent: migrate retry / MES abort may release twice; still drop latch. */
            OG_LOG_DEBUG_WAR("[DCS-GBP][%u-%u] remote_buf_unlatch skip ref_num--, already 0, latch_stat=%u",
                           ctrl->page_id.file, ctrl->page_id.page, (uint32)latch->stat);
        } else {
            ctrl->ref_num--;
        }
    }

    if ((latch->stat == LATCH_STATUS_S || latch->stat == LATCH_STATUS_X) && (latch->shared_count == 0)) {
        latch->stat = LATCH_STATUS_IDLE;
    }

    cm_spin_unlock(&bucket->lock);
}

/* GBP migrate alloc failed: leave LOAD_FAILED so next buf_alloc_ctrl can take over (NEED_LOAD alone deadlocks). */
static inline void remote_buf_release_gbp_alloc_failed(knl_session_t *session, buf_ctrl_t *ctrl)
{
    if (ctrl == NULL) {
        return;
    }
    ctrl->load_status = (uint8)BUF_LOAD_FAILED;
    remote_buf_unlatch(session, ctrl, OG_TRUE);
}

/* GBP migrate alloc succeeded: mark loaded and drop latch held by buf_alloc_ctrl. */
static inline void remote_buf_release_gbp_alloc_success(knl_session_t *session, buf_ctrl_t *ctrl)
{
    if (ctrl == NULL) {
        return;
    }
    ctrl->load_status = (uint8)BUF_IS_LOADED;
    remote_buf_unlatch(session, ctrl, OG_TRUE);
}

#ifdef __cplusplus
}
#endif

#endif
