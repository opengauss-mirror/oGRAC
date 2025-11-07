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
 * ogsql_type_map.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/node/ogsql_type_map.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_type_map.h"
#include "cm_file.h"
#include "srv_instance.h"

static text_t g_type_number = { "NUMBER", 6 };

static inline status_t sql_get_src_type(text_t *src_text, typmode_t *src_type)
{
    text_t prec_text;
    text_t scale_text;
    int32 prec;
    int32 scale;

    if (!cm_text_str_contain_equal_ins(src_text, g_type_number.str, g_type_number.len)) {
        return OG_ERROR;
    }
    src_text->str += g_type_number.len;
    src_text->len -= g_type_number.len;
    cm_trim_text(src_text);

    if (src_text->len <= 2 || src_text->str[0] != '(' || src_text->str[src_text->len - 1] != ')') {
        return OG_ERROR;
    }
    src_text->str += 1;
    src_text->len -= 2;

    cm_split_text(src_text, ',', '\0', &prec_text, &scale_text);
    cm_trim_text(&prec_text);
    cm_trim_text(&scale_text);

    if (cm_text2int(&prec_text, &prec) != OG_SUCCESS ||
        (prec < OG_MIN_NUM_PRECISION || prec > OG_MAX_NUM_PRECISION)) {
        return OG_ERROR;
    }

    if (cm_text2int(&scale_text, &scale) != OG_SUCCESS || (scale < OG_MIN_REAL_SCALE || scale > OG_MAX_REAL_SCALE)) {
        return OG_ERROR;
    }

    src_type->datatype = OG_TYPE_NUMBER;
    src_type->precision = (uint8)prec;
    src_type->scale = (uint8)scale;
    return OG_SUCCESS;
}

static inline status_t sql_get_dst_type(text_t *dst_text, typmode_t *dst_type)
{
    word_t word;
    word.text.value = *dst_text;
    return lex_get_word_typmode(&word, dst_type);
}

static inline status_t sql_get_user(text_t *line, list_t *type_maps, sql_user_typemap_t **user_typemap,
    bool32 *continue_fetch)
{
    text_t user_text;
    sql_user_typemap_t *tmp_typemap = NULL;

    if (line->len <= 2 || line->str[0] != '[' || line->str[line->len - 1] != ']') {
        return OG_SUCCESS;
    }

    user_text.str = line->str + 1;
    user_text.len = line->len - 2;
    cm_trim_text(&user_text);
    if (user_text.len == 0) {
        *continue_fetch = OG_TRUE;
        return OG_SUCCESS;
    }

    /* get an new user */
    if (cm_list_new(type_maps, (void **)&tmp_typemap) == OG_ERROR) {
        return OG_ERROR;
    }

    tmp_typemap->is_like = (user_text.str[user_text.len - 1] == '*');
    tmp_typemap->user.str = tmp_typemap->user_buf;
    tmp_typemap->user.len = tmp_typemap->is_like ? user_text.len - 1 : user_text.len;
    if (tmp_typemap->user.len > 0) {
        tmp_typemap->user.len = MIN(OG_NAME_BUFFER_SIZE, tmp_typemap->user.len);
        MEMS_RETURN_IFERR(
            memcpy_s(tmp_typemap->user.str, OG_NAME_BUFFER_SIZE, user_text.str, tmp_typemap->user.len));
    }
    cm_create_list(&tmp_typemap->type_map_list, sizeof(sql_type_item_t));

    *user_typemap = tmp_typemap;
    *continue_fetch = OG_TRUE;
    return OG_SUCCESS;
}

static inline status_t sql_get_type(text_t *line, sql_user_typemap_t *user_typemap, bool32 *continue_fetch)
{
    sql_type_item_t *type_item = NULL;
    typmode_t src_type;
    typmode_t dst_type;
    text_t src_text;
    text_t dst_text;

    cm_split_text(line, '=', '\0', &src_text, &dst_text);
    cm_trim_text(&src_text);
    cm_trim_text(&dst_text);
    if (src_text.len == 0 || dst_text.len == 0) {
        *continue_fetch = OG_TRUE;
        return OG_SUCCESS;
    }
    MEMS_RETURN_IFERR(memset_s(&src_type, sizeof(typmode_t), 0, sizeof(typmode_t)));
    MEMS_RETURN_IFERR(memset_s(&dst_type, sizeof(typmode_t), 0, sizeof(typmode_t)));
    /* 1.src type must be number(p, s)
       2.dst type can be int, double or bigint
    */
    if (sql_get_src_type(&src_text, &src_type) != OG_SUCCESS || sql_get_dst_type(&dst_text, &dst_type) != OG_SUCCESS) {
        *continue_fetch = OG_TRUE;
        return OG_SUCCESS;
    }
    /* ignore duplicate item */
    OG_RETURN_IFERR(cm_list_new(&user_typemap->type_map_list, (void **)&type_item));
    type_item->src_type = src_type;
    type_item->dst_type = dst_type;
    return OG_SUCCESS;
}

status_t sql_load_type_map(void)
{
    char file_name[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    list_t *type_maps = &g_instance->sql.type_map.type_maps;
    text_t filepath;
    bool32 is_fullpath = OG_FALSE;
    int32 fp;
    char *buffer = NULL;
    uint32 buf_size;
    text_t text;
    text_t line;
    bool32 do_continue = OG_FALSE;
    errno_t rc_memzero;
    sql_user_typemap_t *user_typemap = NULL;
    status_t status = OG_SUCCESS;

    if (!g_instance->sql.type_map.do_typemap) {
        return OG_SUCCESS;
    }

    /* create the user type map list */
    cm_create_list(type_maps, sizeof(sql_user_typemap_t));

    /* read config info */
    filepath.str = g_instance->sql.type_map.file_name;
    filepath.len = (uint32)strlen(g_instance->sql.type_map.file_name);
    is_fullpath = (CM_TEXT_FIRST(&filepath) == '/' || CM_TEXT_FIRST(&filepath) == '\\');
#ifdef WIN32
    is_fullpath = is_fullpath || (cm_get_first_pos(&filepath, ':') != OG_INVALID_ID32);
#endif
    if (is_fullpath) {
        PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s",
            g_instance->sql.type_map.file_name));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
            g_instance->home, g_instance->sql.type_map.file_name));
    }

    if (!cm_file_exist(file_name) || cm_open_file(file_name, O_RDONLY, &fp) != OG_SUCCESS) {
        cm_reset_error();
        return OG_SUCCESS;
    }
    buffer = (char *)malloc(SIZE_K(64));
    if (buffer == NULL) {
        cm_close_file(fp);
        return OG_ERROR;
    }
    rc_memzero = memset_s(buffer, SIZE_K(64), 0, SIZE_K(64));
    if (rc_memzero != EOK) {
        cm_close_file(fp);
        CM_FREE_PTR(buffer);
        return OG_ERROR;
    }
    if (cm_read_file(fp, buffer, SIZE_K(64), (int32 *)&buf_size) != OG_SUCCESS) {
        cm_close_file(fp);
        CM_FREE_PTR(buffer);
        return OG_ERROR;
    }

    text.len = buf_size;
    text.str = buffer;

    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        cm_trim_text(&line);

        /* ignore empty or note line */
        if (line.len == 0 || line.str[0] == '#') {
            continue;
        }

        do_continue = OG_FALSE;

        /* try get user, [username] or [username*] */
        if (sql_get_user(&line, type_maps, &user_typemap, &do_continue) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (user_typemap == NULL || do_continue) {
            continue;
        }

        /* get type map, src_type = dst_type
           1.src type must be number(p,s)
           2.dst type can be int, bigint or double
        */
        if (sql_get_type(&line, user_typemap, &do_continue) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (do_continue) {
            continue;
        }
    }

    cm_close_file(fp);
    CM_FREE_PTR(buffer);
    return status;
}

void sql_try_match_type_map(text_t *curr_user, typmode_t *type)
{
    list_t *type_maps = &g_instance->sql.type_map.type_maps;
    sql_user_typemap_t *user_typemap = NULL;
    sql_type_item_t *type_item = NULL;
    bool32 match_user = OG_FALSE;
    uint32 i;
    uint32 j;

    if (!g_instance->sql.type_map.do_typemap || (curr_user == NULL)) {
        return;
    }

    /* try match user */
    for (i = 0; i < type_maps->count; i++) {
        user_typemap = (sql_user_typemap_t *)cm_list_get(type_maps, i);
        if ((user_typemap->is_like &&
            cm_text_str_contain_equal_ins(curr_user, user_typemap->user.str, user_typemap->user.len)) ||
            cm_compare_text_ins(curr_user, &user_typemap->user) == 0) {
            match_user = OG_TRUE;
            break;
        }
    }

    if (!match_user) {
        return;
    }

    /* try match type item */
    for (j = 0; j < user_typemap->type_map_list.count; j++) {
        type_item = (sql_type_item_t *)cm_list_get(&user_typemap->type_map_list, j);
        if (type_item->src_type.datatype == type->datatype && type_item->src_type.precision == type->precision &&
            type_item->src_type.scale == type->scale) {
            *type = type_item->dst_type;
            return;
        }
    }

    /* number(N) type map of auto match:
       N=[1,2]   -> tinyint
       N=[4,4]   -> smallint
       N=[6,9]   -> integer
       N=[11]    -> number(11), need supports unsigned int !!!
       N=[12,18] -> bigint
    */
    if (type->scale != 0) {
        return;
    }

    if ((type->precision >= 1 && type->precision <= 2) || (type->precision == 4) ||
        (type->precision >= 6 && type->precision <= 9)) {
        type->datatype = OG_TYPE_INTEGER;
        type->size = sizeof(int32);
    } else if (type->precision >= 12 && type->precision <= 18) {
        type->datatype = OG_TYPE_BIGINT;
        type->size = sizeof(int64);
    }
}
