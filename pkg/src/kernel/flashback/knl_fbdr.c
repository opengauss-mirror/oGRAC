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
 * knl_fbdr.c
 *
 *
 * IDENTIFICATION
 * src/kernel/flashback/knl_fbdr.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_flash_module.h"
#include "knl_dc.h"
#include "knl_context.h"
#include "knl_session.h"
#include "knl_page.h"
#include "knl_fbdr.h"

static inline bool32 is_invalid_undo_rid(rowid_t rid)
{
    return (rid.file == INVALID_FILE_ID || (rid.file == 0 && rid.page == 0));
}

status_t fbdr_prepare(fbdr_handler_t *handler, const text_t *user, const text_t *table_name)
{
    knl_session_t *session = handler->session;
    knl_dictionary_t dc;

    if (dc_open(session, (text_t *)user, (text_t *)table_name, &dc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    table_t *table = &((dc_entity_t *)dc.handle)->table;

    if (IS_INVALID_PAGID(table->desc.entry)) {
        handler->cursor->eof = OG_TRUE;
        dc_close(&dc);
        return OG_SUCCESS;
    }

    handler->cursor->eof = OG_FALSE;
    handler->pagid = table->heap.segment->data_first;
    handler->itl_id = 0;
    handler->undo_rid = INVALID_ROWID;
    handler->org_scn = table->desc.org_scn;
    handler->uid = table->desc.uid;
    handler->oid = table->desc.oid;

    if (table->desc.cr_mode == CR_ROW) {
        handler->page_type = PAGE_TYPE_HEAP_DATA;
        handler->undo_type = UNDO_HEAP_DELETE;
    } else {
        handler->page_type = PAGE_TYPE_PCRH_DATA;
        handler->undo_type = UNDO_PCRH_DELETE;
    }

    dc_close(&dc);
    return OG_SUCCESS;
}

static status_t fbdr_locate_undo_pcr(fbdr_handler_t *handler)
{
    knl_session_t *session = handler->session;
    pcr_itl_t itl;
    heap_page_t *page = NULL;
    status_t status = OG_SUCCESS;

    for (;;) {
        // move to the heap end
        if (IS_INVALID_PAGID(handler->pagid)) {
            handler->cursor->eof = OG_TRUE;
            return OG_SUCCESS;
        }

        if (buf_read_page(session, handler->pagid, LATCH_MODE_S, 0) != OG_SUCCESS) {
            return OG_ERROR;
        }

        page = (heap_page_t *)session->curr_page;
        if (page->head.type != handler->page_type ||
            page->org_scn != handler->org_scn || page->uid != handler->uid) {
            buf_leave_page(session, OG_FALSE);
            HEAP_CHECKPAGE_ERROR(handler->cursor);
            status = OG_ERROR;
            break;
        }

        if (handler->itl_id == page->itls) {
            handler->pagid = AS_PAGID(page->next);
            handler->itl_id = 0;
            buf_leave_page(session, OG_FALSE);
            continue;
        }

        itl = *pcrh_get_itl(page, handler->itl_id);
        buf_leave_page(session, OG_FALSE);

        handler->prev_undo_scn = OG_INVALID_ID64;
        handler->undo_rid.page = itl.undo_page.page;
        handler->undo_rid.file = itl.undo_page.file;
        handler->undo_rid.slot = itl.undo_slot;
        handler->itl_id++;  // current undo entry is loaded, handler point to the next ITL id
        break;
    }

    return status;
}

static status_t fbdr_locate_undo_rcr(fbdr_handler_t *handler)
{
    knl_session_t *session = handler->session;
    row_dir_t dir;
    heap_page_t *page = NULL;
    status_t status = OG_SUCCESS;

    for (;;) {
        // move to the heap end
        if (IS_INVALID_PAGID(handler->pagid)) {
            handler->cursor->eof = OG_TRUE;
            return OG_SUCCESS;
        }

        if (buf_read_page(session, handler->pagid, LATCH_MODE_S, 0) != OG_SUCCESS) {
            return OG_ERROR;
        }

        page = (heap_page_t *)session->curr_page;
        if (page->head.type != handler->page_type ||
            page->org_scn != handler->org_scn || page->uid != handler->uid) {
            buf_leave_page(session, OG_FALSE);
            HEAP_CHECKPAGE_ERROR(handler->cursor);
            status = OG_ERROR;
            break;
        }

        if (handler->slot == page->rows) {
            handler->pagid = AS_PAGID(page->next);
            handler->slot = 0;
            buf_leave_page(session, OG_FALSE);
            continue;
        }

        dir = *heap_get_dir(page, handler->slot);
        buf_leave_page(session, OG_FALSE);

        handler->prev_undo_scn = OG_INVALID_ID64;
        handler->undo_rid.page = dir.undo_page.page;
        handler->undo_rid.file = dir.undo_page.file;
        handler->undo_rid.slot = dir.undo_slot;
        handler->slot++;  // current undo entry is loaded, handler point to the next row's slot
        break;
    }
    
    return status;
}

static inline status_t fbdr_locate_undo(fbdr_handler_t *handler)
{
    if (handler->page_type == PAGE_TYPE_HEAP_DATA) {
        return fbdr_locate_undo_rcr(handler);
    }

    return fbdr_locate_undo_pcr(handler);
}

static status_t fbdr_mine_undo(fbdr_handler_t *handler, bool32 *is_found)
{
    knl_session_t *session = handler->session;
    undo_page_t *ud_page = NULL;
    undo_row_t *ud_row = NULL;
    page_id_t pagid;
    page_id_t heap_pagid;
    uint32    slot;
    errno_t ret;

    *is_found = OG_FALSE;

    for (;;) {
        pagid = GET_ROWID_PAGE(handler->undo_rid);

        if (is_invalid_undo_rid(handler->undo_rid)) {
            return OG_SUCCESS;
        }

        slot = (uint32)handler->undo_rid.slot;
        if (buf_read_page(session, pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL) != OG_SUCCESS) {
            return OG_ERROR;
        }

        ud_page = (undo_page_t *)CURR_PAGE(session);
        if (slot >= ud_page->rows) {
            buf_leave_page(session, OG_FALSE);
            OG_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return OG_ERROR;
        }

        ud_row = UNDO_ROW(session, ud_page, slot);
        heap_pagid = GET_ROWID_PAGE(ud_row->rowid);
        if (handler->prev_undo_scn < ud_row->scn || !IS_SAME_PAGID(heap_pagid, handler->pagid)) {
            buf_leave_page(session, OG_FALSE);
            OG_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return OG_ERROR;
        }

        // the undo is older than flashbacking expected
        if (handler->fbdr_scn > ud_row->scn) {
            buf_leave_page(session, OG_FALSE);
            handler->undo_rid = INVALID_ROWID;
            return OG_SUCCESS;
        }

        handler->prev_undo_scn = ud_row->scn;
        handler->undo_rid.file = ud_row->prev_page.file;
        handler->undo_rid.page = ud_row->prev_page.page;
        handler->undo_rid.slot = ud_row->prev_slot;

        if (ud_row->type == handler->undo_type) {
            ret = memcpy_sp(handler->cursor->page_buf, DEFAULT_PAGE_SIZE(session), ud_row->data, ud_row->data_size);
            knl_securec_check(ret);
            *is_found = OG_TRUE;
            buf_leave_page(session, OG_FALSE);
            return OG_SUCCESS;
        }

        buf_leave_page(session, OG_FALSE);
    }
}

status_t fbdr_fetch(fbdr_handler_t *handler)
{
    bool32 is_found = OG_FALSE;

    if (handler->cursor->eof) {
        return OG_SUCCESS;
    }

    for (;;) {
        if (is_invalid_undo_rid(handler->undo_rid)) {
            if (fbdr_locate_undo(handler) != OG_SUCCESS) {
                return OG_ERROR;
            }

            if (handler->cursor->eof) {
                return OG_SUCCESS;
            }
        }

        if (fbdr_mine_undo(handler, &is_found) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (is_found) {
            break;
        }
    }

    return OG_SUCCESS;
}

