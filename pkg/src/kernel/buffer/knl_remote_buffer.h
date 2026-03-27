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
        knl_panic_log(ctrl->ref_num > 0, "ctrl's ref_num is invalid, panic info: page %u-%u type %u ref_num %u",
                      ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, ctrl->ref_num);
        ctrl->ref_num--;
    }

    if ((latch->stat == LATCH_STATUS_S || latch->stat == LATCH_STATUS_X) && (latch->shared_count == 0)) {
        latch->stat = LATCH_STATUS_IDLE;
    }

    cm_spin_unlock(&bucket->lock);
}


#ifdef __cplusplus
}
#endif

#endif
