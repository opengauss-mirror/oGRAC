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
 * knl_flashback.c
 *
 *
 * IDENTIFICATION
 * src/kernel/flashback/knl_flashback.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_flash_module.h"
#include "knl_flashback.h"
#include "knl_table.h"
#include "knl_database.h"
#include "knl_context.h"
#include "pcr_heap.h"
#include "pcr_heap_scan.h"
#include "dtc_dls.h"

/*
 * PCR flashback action map
 * --------------------------------------------------------------------
 *     flashback version    |        curr version       |  action
 * --------------------------------------------------------------------
 *    same scn with curr    |    same scn with old      |  skip
 *  free/deleted/migration  |  free/deleted/migration/  |  skip
 *  free/deleted/migration  |        normal/link        |  delete curr
 *       normal/link        |  free/deleted/migration/  |  insert old
 */
typedef enum en_fb_action {
    FB_SKIP = 0,
    FB_DELETE_ONLY = 1,
    FB_INSERT_ONLY = 2,
    FB_DELETE_INSERT = 3,
} fb_action_t;

typedef struct st_fb_match_cond {
    knl_cursor_t *cursor;
    knl_scn_t fb_scn;
}fb_match_cond_t;

static status_t fb_check_index_part_state(knl_session_t *session, index_t *index)
{
    if (!IS_PART_INDEX(index)) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < index->part_index->desc.partcnt; i++) {
        index_part_t *index_part = PART_GET_ENTITY(index->part_index, i);
        if (index_part == NULL) {
            continue;
        }
        
        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            if (index_part->desc.is_invalid && (index->desc.primary || index->desc.unique)) {
                OG_THROW_ERROR(ERR_INDEX_PART_UNUSABLE, index_part->desc.name, index->desc.name);
                return OG_ERROR;
        }
            continue;
        }

        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_part_t *sub_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (sub_part == NULL) {
                continue;
            }

            if (sub_part->desc.is_invalid && (index->desc.primary || index->desc.unique)) {
                OG_THROW_ERROR(ERR_INDEX_PART_UNUSABLE, sub_part->desc.name, index->desc.name);
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

static status_t fb_check_lob_part(knl_session_t *session, lob_t *lob, table_t *table, knl_scn_t scn)
{
    table_part_t *table_part = NULL;
    lob_part_t *lob_part = NULL;
    lob_part_t *lob_subpart = NULL;

    if (lob == NULL || table == NULL) {
        return OG_SUCCESS;
    }

    if (!IS_PART_TABLE(table)) {
        return OG_SUCCESS;
    }

    for (uint32 j = 0; j < table->part_table->desc.partcnt; j++) {
        table_part = TABLE_GET_PART(table, j);
        lob_part = LOB_GET_PART(lob, j);
        if (!IS_READY_PART(table_part) || lob_part == NULL) {
            continue;
        }

        if (!IS_PARENT_LOBPART(&lob_part->desc)) {
            if (lob_part->lob_entity.segment == NULL) {
                continue;
            }
            if (scn <= LOB_SEGMENT(session, lob_part->lob_entity.entry, lob_part->lob_entity.segment)->shrink_scn) {
                return OG_ERROR;
            }
            continue;
        }

        for (uint32 k = 0; k < lob_part->desc.subpart_cnt; k++) {
            lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[k]);
            if (lob_subpart == NULL || lob_subpart->lob_entity.segment == NULL) {
                continue;
            }
            if (scn <= LOB_SEGMENT(session, lob_subpart->lob_entity.entry,
                lob_subpart->lob_entity.segment)->shrink_scn) {
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t fb_check_lobs_shrink_scn(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t scn)
{
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        if (!IS_PART_TABLE(table)) {
            if (lob->lob_entity.segment == NULL) {
                continue;
            }
            if (scn <= LOB_SEGMENT(session, lob->lob_entity.entry, lob->lob_entity.segment)->shrink_scn) {
                return OG_ERROR;
            }
            continue;
        }

        /* part table */
        if (fb_check_lob_part(session, lob, table, scn) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

/**
 * prepare flashback table
 * Do necessary check and drop foreign key cons.
 * @param kernel session, origin dictionary, flashback scn
 */
status_t fb_prepare_flashback_table(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t scn)
{
    table_t *table = DC_TABLE(dc);
    index_t *index = NULL;
    index_set_t *index_set = &table->index_set;

    if (scn <= table->desc.chg_scn) {
        OG_THROW_ERROR(ERR_DEF_CHANGED, DC_ENTRY_USER_NAME(dc), table->desc.name);
        return OG_ERROR;
    }

    if (fb_check_lobs_shrink_scn(session, dc, scn) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_DEF_CHANGED, DC_ENTRY_USER_NAME(dc), table->desc.name);
        return OG_ERROR;
    }

    for (uint32 i = 0; i < index_set->total_count; i++) {
        index = index_set->items[i];
        if (index->desc.is_invalid && (index->desc.primary || index->desc.unique)) {
            OG_THROW_ERROR(ERR_INDEX_NOT_STABLE, index->desc.name);
            return OG_ERROR;
        }

        if (fb_check_index_part_state(session, index) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t fb_match_latest_data(void *handle, bool32 *mathched)
{
    fb_match_cond_t *fb_match_cond = (fb_match_cond_t *)handle;

    *mathched = OG_FALSE;

    /* means curr row's commit_scn > flashback scn */
    if (fb_match_cond->cursor->scn > fb_match_cond->fb_scn) {
        *mathched = OG_TRUE;
    }

    return OG_SUCCESS;
}

static status_t fb_delete_latest_data(knl_session_t *session, knl_cursor_t *cursor_delete)
{
    if (knl_fetch(session, cursor_delete) != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (!cursor_delete->eof) {
        if (knl_internal_delete(session, cursor_delete) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (knl_fetch(session, cursor_delete) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t fb_match_old_data(void *handle, bool32 *mathched)
{
    fb_match_cond_t *fb_match_cond = (fb_match_cond_t *)handle;

    *mathched = OG_FALSE;

    /* means curr  row get from undo data */
    if (fb_match_cond->cursor->snapshot.is_valid) {
        *mathched = OG_TRUE;
    }

    return OG_SUCCESS;
}

static status_t fb_insert_old_data(knl_session_t *session, knl_cursor_t *cursor_select, knl_cursor_t *cursor_insert)
{
    if (knl_fetch(session, cursor_select) != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (!cursor_select->eof) {
        if (knl_copy_row(session, cursor_select, cursor_insert) != OG_SUCCESS) {
            return OG_ERROR;
        }

        /* set action to update to catch unique index conflict */
        cursor_insert->action = CURSOR_ACTION_UPDATE;
        if (knl_internal_insert(session, cursor_insert) != OG_SUCCESS) {
            return OG_ERROR;
        }

        cursor_insert->action = CURSOR_ACTION_INSERT;
        if (knl_fetch(session, cursor_select) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t fb_flashback_table_rows(knl_session_t *session, knl_scn_t fb_scn, knl_cursor_t *cursor_delete,
                                        knl_cursor_t *cursor_select, knl_cursor_t *cursor_insert)
{
    void *org_delete_stmt = cursor_delete->stmt;
    void *org_select_stmt = cursor_select->stmt;
    knl_match_cond_t org_match_cond  = session->match_cond;
    fb_match_cond_t latest_data_cond;
    fb_match_cond_t old_data_cond;

    latest_data_cond.cursor = cursor_delete;
    latest_data_cond.fb_scn = fb_scn;
    cursor_delete->stmt  = (void *)&latest_data_cond;
    session->match_cond  = fb_match_latest_data;

    if (fb_delete_latest_data(session, cursor_delete) != OG_SUCCESS) {
        session->match_cond = org_match_cond;
        cursor_delete->stmt = org_delete_stmt;
        cursor_select->stmt = org_select_stmt;
        return OG_ERROR;
    }

    old_data_cond.cursor = cursor_select;
    cursor_select->stmt  = (void *)&old_data_cond;
    session->match_cond  = fb_match_old_data;
    if (fb_insert_old_data(session, cursor_select, cursor_insert) != OG_SUCCESS) {
        session->match_cond = org_match_cond;
        cursor_delete->stmt = org_delete_stmt;
        cursor_select->stmt = org_select_stmt;
        return OG_ERROR;
    }

    session->match_cond = org_match_cond;
    cursor_delete->stmt = org_delete_stmt;
    cursor_select->stmt = org_select_stmt;

    return OG_SUCCESS;
}

static status_t fb_flashback_entity_data(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t fb_scn,
    knl_cursor_t *cursor_delete, knl_cursor_t *cursor_select, knl_cursor_t *cursor_insert)
{
    if (knl_reopen_cursor(session, cursor_select, dc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (knl_reopen_cursor(session, cursor_delete, dc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (knl_reopen_cursor(session, cursor_insert, dc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    knl_set_table_part(cursor_insert, cursor_insert->part_loc);
    if (fb_flashback_table_rows(session, fb_scn, cursor_delete, cursor_select, cursor_insert) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t fb_flashback_part_data(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t fb_scn,
    knl_cursor_t *cursor_delete, knl_cursor_t *cursor_select, knl_cursor_t *cursor_insert)
{
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        cursor_select->part_loc.part_no = i;
        cursor_delete->part_loc.part_no = i;
        cursor_insert->part_loc.part_no = i;
        if (!IS_PARENT_TABPART(&table_part->desc)) {
            cursor_select->part_loc.subpart_no = OG_INVALID_ID32;
            cursor_delete->part_loc.subpart_no = OG_INVALID_ID32;
            cursor_insert->part_loc.subpart_no = OG_INVALID_ID32;
            if (fb_flashback_entity_data(session, dc, fb_scn, cursor_delete, cursor_select,
                cursor_insert) != OG_SUCCESS) {
                return OG_ERROR;
            }

            continue;
        }
        
        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
            if (table_subpart == NULL) {
                continue;
            }

            cursor_select->part_loc.subpart_no = j;
            cursor_delete->part_loc.subpart_no = j;
            cursor_insert->part_loc.subpart_no = j;

            if (fb_flashback_entity_data(session, dc, fb_scn, cursor_delete, cursor_select,
                cursor_insert) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

static status_t fb_flashback_table_data(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t fb_scn,
    knl_cursor_t *cursor_delete, knl_cursor_t *cursor_select, knl_cursor_t *cursor_insert)
{
    table_t *table = DC_TABLE(dc);

    if (IS_PART_TABLE(table)) {
        if (fb_flashback_part_data(session, dc, fb_scn, cursor_delete, cursor_select, cursor_insert) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        if (fb_flashback_table_rows(session, fb_scn, cursor_delete, cursor_select, cursor_insert) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static inline fb_action_t fb_get_action(knl_cursor_t *cursor, heap_page_t *old_page, heap_page_t *curr_page)
{
    pcr_row_dir_t *dir;
    row_head_t *row = NULL;
    bool32 delete_curr = OG_FALSE;
    bool32 insert_old = OG_FALSE;

    dir = pcrh_get_dir(curr_page, (uint16)cursor->rowid.slot);
    if (PCRH_DIR_IS_FREE(dir)) {
        delete_curr = OG_FALSE;
    } else {
        row = PCRH_GET_ROW(curr_page, dir);
        delete_curr = !(row->is_deleted || row->is_migr);
    }

    if (old_page->dirs <= (uint16)cursor->rowid.slot) {
        insert_old = OG_FALSE;
    } else {
        dir = pcrh_get_dir(old_page, (uint16)cursor->rowid.slot);
        if (PCRH_DIR_IS_FREE(dir)) {
            insert_old = OG_FALSE;
        } else {
            row = PCRH_GET_ROW(old_page, dir);
            insert_old = !(row->is_deleted || row->is_migr);
        }
    }

    if (delete_curr) {
        return (insert_old ? FB_DELETE_INSERT : FB_DELETE_ONLY);
    } else {
        return (insert_old ? FB_INSERT_ONLY : FB_SKIP);
    }
}

static status_t fb_scan_cr_page(knl_session_t *session, knl_cursor_t *cursor, char *page_buf, uint8 *fb_mark,
                                fb_action_t *action)
{
    heap_page_t *old_page = NULL;
    heap_page_t *curr_page = NULL;

    *action = FB_SKIP;
    curr_page = (heap_page_t *)cursor->page_buf;
    old_page = (heap_page_t *)page_buf;

    knl_panic_log(old_page->dirs <= curr_page->dirs, "the old_page's dirs is more than curr_page's, panic info: "
                  "page %u-%u type %u table %s old_page's dirs %u curr_page's dirs %u", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name,
                  old_page->dirs, curr_page->dirs);

    for (;;) {
        if (cursor->rowid.slot == INVALID_SLOT) {
            cursor->rowid.slot = 0;
        } else {
            cursor->rowid.slot++;
        }

        if (cursor->rowid.slot == curr_page->dirs) {
            if (IS_SAME_PAGID(cursor->scan_range.r_page, AS_PAGID(curr_page->head.id))) {
                SET_ROWID_PAGE(&cursor->rowid, INVALID_PAGID);
            } else {
                SET_ROWID_PAGE(&cursor->rowid, AS_PAGID(curr_page->next));
            }

            cursor->rowid.slot = INVALID_SLOT;
            return OG_SUCCESS;
        } else if (cursor->rowid.slot > curr_page->dirs) {
            OG_THROW_ERROR(ERR_INVALID_ROWID);
            return OG_ERROR;
        }

        if (!fb_mark[cursor->rowid.slot]) {
            continue;
        }

        *action = fb_get_action(cursor, old_page, curr_page);
        if (*action != FB_SKIP) {
            return OG_SUCCESS;
        }
    }
}

static status_t fb_fetch_cr_page(knl_session_t *session, knl_cursor_t *cursor, char *page_buf, bool8 *fb_mark,
                                 knl_scn_t scn, fb_action_t *action)
{
    errno_t ret;

    if (cursor->rowid.slot == INVALID_SLOT) {
        ret = memset_sp(fb_mark, DEFAULT_PAGE_SIZE(session), 0, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);

        if (pcrh_prefetch_crpage(session, cursor, scn, GET_ROWID_PAGE(cursor->rowid), page_buf, fb_mark) !=
            OG_SUCCESS) {
            return OG_ERROR;
        }

        if (pcrh_prefetch_crpage(session, cursor, cursor->query_scn, GET_ROWID_PAGE(cursor->rowid), cursor->page_buf,
                                  NULL) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (fb_scan_cr_page(session, cursor, page_buf, fb_mark, action) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t fb_insert_old_lob(knl_session_t *session, knl_cursor_t *cursor)
{
    dc_entity_t *entity;
    row_head_t *row = NULL;
    lob_locator_t *src_locator = NULL;
    lob_locator_t *dst_locator = NULL;
    knl_column_t *column = NULL;
    errno_t ret;
    uint16 i;

    row = cursor->row;
    entity = (dc_entity_t *)cursor->dc_entity;

    for (i = 0; i < ROW_COLUMN_COUNT(row); i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column) || CURSOR_COLUMN_SIZE(cursor, i) == OG_NULL_VALUE_LEN) {
            continue;
        }

        src_locator = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, i);
        if (!src_locator->head.is_outline) {
            continue;
        }

        dst_locator = (lob_locator_t *)cm_push(session->stack, OG_LOB_LOCATOR_BUF_SIZE);
        ret = memset_sp(dst_locator, sizeof(lob_locator_t), 0xFF, sizeof(lob_locator_t));
        knl_securec_check(ret);

        if (knl_copy_lob(session, cursor, dst_locator, src_locator, column) != OG_SUCCESS) {
            cm_pop(session->stack);
            return OG_ERROR;
        }

        *src_locator = *dst_locator;
        cm_pop(session->stack);
    }

    return OG_SUCCESS;
}

static inline void fb_reorganize_row(row_head_t *row)
{
    uint16 copy_size;
    uint16 dst_pos;
    uint16 src_pos;
    errno_t ret;

    if (!row->is_migr) {
        return;
    }
    // could not overflow :ROW_BITMAP_EX_SIZE(row) max value is 1024
    dst_pos = cm_row_init_size(row->is_csf, ROW_COLUMN_COUNT(row));
    src_pos = dst_pos + sizeof(rowid_t);
    copy_size = row->size - src_pos;

    if (copy_size > 0) {
        ret = memmove_s((char *)row + dst_pos, copy_size, (char *)row + src_pos, copy_size);
        knl_securec_check(ret);
    }

    row->size -= sizeof(rowid_t);
    row->is_migr = 0;
}

static status_t fb_flashback_pcr_entity(knl_session_t *session, knl_cursor_t *scan_cursor,
                                        knl_cursor_t *fb_cursor, knl_scn_t scn)
{
    char *page_buf = NULL;
    bool8 *fb_mark = NULL;
    fb_action_t action;

    CM_SAVE_STACK(session->stack);
    fb_mark = (bool8 *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    page_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));

    for (;;) {
        if (IS_INVALID_ROWID(scan_cursor->rowid)) {
            break;
        }

        if (fb_fetch_cr_page(session, scan_cursor, page_buf, fb_mark, scn, &action) != OG_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return OG_ERROR;
        }

        ROWID_COPY(fb_cursor->rowid, scan_cursor->rowid);

        if (action == FB_DELETE_ONLY || action == FB_DELETE_INSERT) {
            fb_cursor->action = CURSOR_ACTION_DELETE;
            fb_cursor->query_scn = scan_cursor->query_scn;

            if (pcrh_fetch_by_rid(session, fb_cursor) != OG_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return OG_ERROR;
            }

            if (knl_internal_delete(session, fb_cursor) != OG_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return OG_ERROR;
            }
        }

        if (action == FB_INSERT_ONLY || action == FB_DELETE_INSERT) {
            fb_cursor->action = CURSOR_ACTION_SELECT;
            fb_cursor->query_scn = scn;

            if (pcrh_fetch_by_rid(session, fb_cursor) != OG_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return OG_ERROR;
            }

            if (fb_insert_old_lob(session, fb_cursor) != OG_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return OG_ERROR;
            }

            fb_reorganize_row(fb_cursor->row);

            /** set action to update to catch unique index conflict */
            fb_cursor->action = CURSOR_ACTION_UPDATE;
            if (knl_internal_insert(session, fb_cursor) != OG_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return OG_ERROR;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return OG_SUCCESS;
}

static status_t fb_do_pcr_part_flashback(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *scan_cursor,
    knl_cursor_t *fb_cursor, knl_scn_t scn)
{
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        scan_cursor->part_loc.part_no = i;
        fb_cursor->part_loc.part_no = i;
        scan_cursor->part_loc.subpart_no = OG_INVALID_ID32;
        fb_cursor->part_loc.subpart_no = OG_INVALID_ID32;
        if (!IS_PARENT_TABPART(&table_part->desc)) {
            if (knl_reopen_cursor(session, scan_cursor, dc) != OG_SUCCESS) {
                return OG_ERROR;
            }

            if (knl_reopen_cursor(session, fb_cursor, dc) != OG_SUCCESS) {
                return OG_ERROR;
            }

            knl_set_table_part(scan_cursor, scan_cursor->part_loc);
            knl_set_table_part(fb_cursor, fb_cursor->part_loc);

            if (fb_flashback_pcr_entity(session, scan_cursor, fb_cursor, scn) != OG_SUCCESS) {
                return OG_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
            if (table_subpart == NULL) {
                continue;
            }

            scan_cursor->part_loc.subpart_no = j;
            fb_cursor->part_loc.subpart_no = j;

            if (knl_reopen_cursor(session, scan_cursor, dc) != OG_SUCCESS) {
                return OG_ERROR;
            }

            if (knl_reopen_cursor(session, fb_cursor, dc) != OG_SUCCESS) {
                return OG_ERROR;
            }

            knl_set_table_part(scan_cursor, scan_cursor->part_loc);
            knl_set_table_part(fb_cursor, fb_cursor->part_loc);

            if (fb_flashback_pcr_entity(session, scan_cursor, fb_cursor, scn) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

static status_t fb_do_pcr_flashback(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *scan_cursor,
                                    knl_cursor_t *fb_cursor, knl_scn_t scn)
{
    table_t *table = DC_TABLE(dc);

    if (IS_PART_TABLE(table)) {
        if (fb_do_pcr_part_flashback(session, dc, scan_cursor, fb_cursor, scn) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        if (fb_flashback_pcr_entity(session, scan_cursor, fb_cursor, scn) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t fb_flashback_pcr_table(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t scn)
{
    knl_cursor_t *scan_cursor = NULL;
    knl_cursor_t *fb_cursor = NULL;

    knl_reset_index_conflicts(session);

    CM_SAVE_STACK(session->stack);

    scan_cursor = knl_push_cursor(session);
    scan_cursor->action = CURSOR_ACTION_SELECT;
    scan_cursor->scan_mode = SCAN_MODE_TABLE_FULL;

    if (knl_open_cursor(session, scan_cursor, dc) != OG_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    scan_cursor->isolevel = ISOLATION_READ_COMMITTED;

    knl_inc_session_ssn(session);

    fb_cursor = knl_push_cursor(session);
    fb_cursor->action = CURSOR_ACTION_DELETE;
    fb_cursor->scan_mode = SCAN_MODE_TABLE_FULL;

    if (knl_open_cursor(session, fb_cursor, dc) != OG_SUCCESS) {
        knl_close_cursor(session, scan_cursor);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    fb_cursor->isolevel = ISOLATION_READ_COMMITTED;

    if (fb_do_pcr_flashback(session, dc, scan_cursor, fb_cursor, scn) != OG_SUCCESS) {
        knl_close_cursor(session, scan_cursor);
        knl_close_cursor(session, fb_cursor);
        knl_rollback(session, NULL);
        knl_reset_index_conflicts(session);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    knl_close_cursor(session, scan_cursor);
    knl_close_cursor(session, fb_cursor);

    if (knl_check_index_conflicts(session, 0) != OG_SUCCESS) {
        knl_rollback(session, NULL);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    } else {
        knl_commit(session);
        CM_RESTORE_STACK(session->stack);
        return OG_SUCCESS;
    }
}

/*
 * flashback table interface
 * flashback table to specified scn in following steps:
 * 1.use cursor_delete to delete all latest rows which commit_scn > fb_scn
 * 2.use cursor_select to fetch all old rows which commit_scn <= fb_scn and get from undo data
 * 3.use cursor_insert to insert all old rows into this table again
 * @param kernel session, dictionary, flashback scn
 */
status_t fb_flashback_table(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t scn)
{
    knl_cursor_t *cursor_select = NULL;
    knl_cursor_t *cursor_delete = NULL;
    knl_cursor_t *cursor_insert = NULL;
    table_t *table = DC_TABLE(dc);

    if (fb_prepare_flashback_table(session, dc, scn) != OG_SUCCESS) {
        return OG_ERROR;
    }
   
    if (table->desc.cr_mode == CR_PAGE) {
        return fb_flashback_pcr_table(session, dc, scn);
    }

    CM_SAVE_STACK(session->stack);

    cursor_select = knl_push_cursor(session);
    cursor_select->action = CURSOR_ACTION_SELECT;
    cursor_select->scan_mode = SCAN_MODE_TABLE_FULL;

    cursor_delete = knl_push_cursor(session);
    cursor_delete->action = CURSOR_ACTION_DELETE;
    cursor_delete->scan_mode = SCAN_MODE_TABLE_FULL;

    cursor_insert = knl_push_cursor(session);
    cursor_insert->action = CURSOR_ACTION_INSERT;

    if (knl_open_cursor(session, cursor_select, dc) != OG_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }
    cursor_select->query_scn = scn;
    knl_inc_session_ssn(session);
    
    if (knl_open_cursor(session, cursor_delete, dc) != OG_SUCCESS) {
        knl_close_cursor(session, cursor_select);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }
    cursor_delete->query_scn = DB_CURR_SCN(session);
    knl_inc_session_ssn(session);
    
    if (knl_open_cursor(session, cursor_insert, dc) != OG_SUCCESS) {
        knl_close_cursor(session, cursor_select);
        knl_close_cursor(session, cursor_delete);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }
    cursor_insert->query_scn = DB_CURR_SCN(session);
    cursor_insert->row = (row_head_t *)cm_push(session->stack, OG_MAX_ROW_SIZE);

    if (fb_flashback_table_data(session, dc, scn, cursor_delete, cursor_select, cursor_insert) != OG_SUCCESS) {
        knl_close_cursor(session, cursor_select);
        knl_close_cursor(session, cursor_delete);
        knl_close_cursor(session, cursor_insert);
        knl_rollback(session, NULL);
        knl_reset_index_conflicts(session);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    knl_close_cursor(session, cursor_select);
    knl_close_cursor(session, cursor_delete);
    knl_close_cursor(session, cursor_insert);
    CM_RESTORE_STACK(session->stack);

    if (knl_check_index_conflicts(session, 0) != OG_SUCCESS) {
        knl_rollback(session, NULL);
        return OG_ERROR;
    } else {
        knl_commit(session);
        return OG_SUCCESS;
    }
}

static status_t fb_flashback_check_dc(knl_dictionary_t *dc, knl_flashback_def_t *def)
{
    if (SYNONYM_EXIST(dc)) {
        OG_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return OG_ERROR;
    }

    if (dc->type != DICT_TYPE_TABLE) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "flashback table", "view or tmp table");
        return OG_ERROR;
    }

    if (IS_SYS_DC(dc)) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "flashback table", "system table");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t fb_flashback(knl_session_t *session, knl_flashback_def_t *def)
{
    knl_dictionary_t dc;
    table_t *table = NULL;
    status_t status = OG_SUCCESS;
    dc_user_t *user = NULL;

    if (def->type == FLASHBACK_DROP_TABLE) {
        if (dc_open_user(session, &def->owner, &user) != OG_SUCCESS) {
            return OG_ERROR;
        }

        dls_latch_x(session, &user->user_latch, session->id, NULL);
        status = rb_flashback_drop_table(session, def);
        dls_unlatch(session, &user->user_latch, NULL);
        return status;
    }

    if (dc_open(session, &def->owner, &def->name, &dc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (fb_flashback_check_dc(&dc, def) != OG_SUCCESS) {
        dc_close(&dc);
        return OG_ERROR;
    }

    uint32 timeout = session->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(session, &dc, timeout) != OG_SUCCESS) {
        dc_close(&dc);
        return OG_ERROR;
    }

    table = DC_TABLE(&dc);
    if (db_table_is_referenced(session, table, OG_TRUE)) {
        unlock_tables_directly(session);
        dc_close(&dc);
        OG_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
        return OG_ERROR;
    }

    switch (def->type) {
        case FLASHBACK_TO_SCN:
        case FLASHBACK_TO_TIMESTAMP:
            if (fb_flashback_table(session, &dc, def->scn) != OG_SUCCESS) {
                status = OG_ERROR;
            }
            break;

        case FLASHBACK_TRUNCATE_TABLE:
            if (rb_flashback_truncate_table(session, &dc, def->force) != OG_SUCCESS) {
                knl_rollback(session, NULL);
                dc_invalidate(session, DC_ENTITY(&dc));
                status = OG_ERROR;
            }
            break;

        case FLASHBACK_TABLE_PART:
            if (rb_flashback_truncate_tabpart(session, &dc, &def->ext_name, def->force) != OG_SUCCESS) {
                knl_rollback(session, NULL);
                dc_invalidate(session, DC_ENTITY(&dc));
                status = OG_ERROR;
            }
            break;
        
        case FLASHBACK_TABLE_SUBPART:
            if (!IS_PART_TABLE(table) || !IS_COMPART_TABLE(table->part_table)) {
                unlock_tables_directly(session);
                OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "flashback table subpartition", DC_ENTRY_NAME(&dc));
                dc_close(&dc);
                return OG_ERROR;
            }
            
            if (rb_flashback_truncate_tabsubpart(session, &dc, &def->ext_name, def->force) != OG_SUCCESS) {
                knl_rollback(session, NULL);
                dc_invalidate(session, DC_ENTITY(&dc));
                status = OG_ERROR;
            }
            break;

        default:
            OG_THROW_ERROR(ERR_INVALID_FLASHBACK_TYPE, def->type);
            status = OG_ERROR;
            break;
    }

    unlock_tables_directly(session);
    dc_close(&dc);
    return status;
}

