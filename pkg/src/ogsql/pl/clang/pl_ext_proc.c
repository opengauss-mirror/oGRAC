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
 * pl_ext_proc.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/clang/pl_ext_proc.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_ext_proc.h"
#include "pl_executor.h"
#include "mes_packet.h"
#include "srv_instance.h"
#include "func_mgr.h"
#include "base_compiler.h"

/* sql type                            og_type_t            c type
  bool/boolean                         OG_TYPE_BOOLEAN      bool*
  short/smallint                       OG_TYPE_SMALLINT     short*
  ushort/usmallint                     OG_TYPE_USMALLINT    unsigned short*
  int/Integer/binary_integer           OG_TYPE_INTEGER      int*
  binary_uint32/uint/uinteger          OG_TYPE_UINT32       unsigned int*
  bigint/binary_bigint                 OG_TYPE_BIGINT       long long*
  binary_float/float                   OG_TYPE_FLOAT        double*
  binary_double/double/real            OG_TYPE_REAL         double*
  binary                               OG_TYPE_BINARY       cbinary_t*
  varbinary                            OG_TYPE_VARBINARY    cbinary_t*
  raw                                  OG_TYPE_RAW          cbinary_t*
  nvarchar/nvarchar2/varchar2/varchar  OG_TYPE_VARCHAR      ogext_t*
  char/character/bpchar                OG_TYPE_CHAR         ogext_t*
*/
static status_t put_param_value(mes_message_ex_t *pack, variant_t *value)
{
    switch ((og_type_t)value->type) {
        case OG_TYPE_SMALLINT:
        case OG_TYPE_USMALLINT:
        case OG_TYPE_TINYINT:
        case OG_TYPE_UTINYINT:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
            OG_RETURN_IFERR(mes_put_int32(pack, VALUE(uint32, value)));
            break;

        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
            OG_RETURN_IFERR(mes_put_int64(pack, VALUE(int64, value)));
            break;

        case OG_TYPE_FLOAT:
        case OG_TYPE_REAL:
            OG_RETURN_IFERR(mes_put_double(pack, VALUE(double, value)));
            break;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            OG_RETURN_IFERR(mes_put_text(pack, VALUE_PTR(text_t, value)));
            break;

        default:
            OG_SET_ERROR_MISMATCH_EX(value->type);
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t check_output_arg(sql_stmt_t *stmt, expr_node_t *actual_node, plv_decl_t *formal_decl, uint32 param_id,
    expr_node_t *node)
{
    var_udo_t *obj = sql_node_get_obj(node);
    if (formal_decl->drct == PLV_DIR_IN) {
        return OG_SUCCESS;
    }

    if (actual_node->type != EXPR_NODE_V_ADDR || !sql_pair_type_is_plvar(actual_node)) {
        OG_SRC_THROW_ERROR(NODE_LOC(node), ERR_PL_ARG_FMT, param_id, T2S(&obj->name),
            "cannot be used as an assignment target");
        return OG_ERROR;
    }
    var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(actual_node->value.v_address.pairs, 0);
    if (pair->stack->decl->type == PLV_PARAM &&
        stmt->param_info.params[pair->stack->decl->param.param_id].direction == PLV_DIR_IN) {
        OG_SRC_THROW_ERROR(NODE_LOC(node), ERR_PL_ARG_FMT, param_id, T2S(&obj->name),
            "is out parameter and cannot be assigned to in parameter");
        return OG_ERROR;
    }
    if (!var_datatype_matched(formal_decl->variant.type.datatype, NODE_DATATYPE(actual_node))) {
        OG_SRC_THROW_ERROR(NODE_LOC(node), ERR_PL_ARG_FMT, param_id, T2S(&obj->name),
            "formal argument and actual argument type is inconsistent");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t encode_rpc_req(sql_stmt_t *stmt, expr_node_t *node, mes_message_ex_t *pack, ext_assist_t *assist)
{
    function_t *func = assist->func;
    uint32 i;
    uint32 arg_count;
    plv_decl_t *decl = NULL;
    variant_t value;
    og_type_t datatype;
    uint8 *types = NULL;
    uint8 *flags = NULL;

    if (func->desc.pl_type == PL_FUNCTION) {
        i = 1;
        arg_count = func->desc.arg_count - 1;
        assist->is_func = OG_TRUE;
    } else {
        i = 0;
        arg_count = func->desc.arg_count;
        assist->is_func = OG_FALSE;
    }

    uint32 len = ((node->argument == NULL) ? 0 : sql_expr_list_len(node->argument));
    if (len != arg_count || len > FUNC_MAX_ARGS) {
        OG_THROW_ERROR(ERR_ASSERT_ERROR, "the amount of actual arguments and formal arguments are inconsistent");
        return OG_ERROR;
    }

    assist->args_num = arg_count;
    OG_RETURN_IFERR(mes_put_int32(pack, assist->is_func));
    OG_RETURN_IFERR(mes_put_str(pack, assist->library->path));
    OG_RETURN_IFERR(mes_put_text2str(pack, &((pl_line_begin_t *)func->body)->func));
    OG_RETURN_IFERR(mes_put_int64(pack, assist->oid));
    OG_RETURN_IFERR(mes_put_int32(pack, arg_count));

    if (assist->is_func) {
        decl = cm_galist_get(func->desc.params, 0);
        OG_RETURN_IFERR(mes_put_int32(pack, (uint32)decl->variant.type.datatype));
    }

    if (arg_count == 0) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(mes_reserve_space(pack, arg_count, (void **)&types));
    OG_RETURN_IFERR(mes_reserve_space(pack, arg_count, (void **)&flags));

    expr_tree_t *curr_arg = node->argument;
    for (uint32 j = 0; j < len && curr_arg; i++, j++) {
        decl = cm_galist_get(func->desc.params, i);
        OG_RETURN_IFERR(check_output_arg(stmt, curr_arg->root, decl, j, node));
        datatype = decl->variant.type.datatype;
        SET_DATA_TYPE(types[j], datatype);
        SET_DIR_FLAG(flags[j], decl->drct);
        SET_NULL_FLAG(flags[j], OG_TRUE);
        if (decl->drct == PLV_DIR_IN || decl->drct == PLV_DIR_INOUT) {
            if (sql_exec_expr(stmt, curr_arg, &value) != OG_SUCCESS) {
                pl_check_and_set_loc(curr_arg->loc);
                return OG_ERROR;
            }
            SET_NULL_FLAG(flags[j], value.is_null);
            if (value.is_null) {
                curr_arg = curr_arg->next;
                continue;
            }
            OG_RETURN_IFERR(sql_convert_variant(stmt, &value, datatype));
            sql_keep_stack_variant(stmt, &value);
            OG_RETURN_IFERR(put_param_value(pack, &value));
        }

        curr_arg = curr_arg->next;
    }

    return OG_SUCCESS;
}

static status_t get_param_value(sql_stmt_t *stmt, mes_message_ex_t *pack, og_type_t datatype, variant_t *value)
{
    text_t text;
    value->type = datatype;
    value->is_null = OG_FALSE;
    switch (datatype) {
        case OG_TYPE_SMALLINT:
        case OG_TYPE_USMALLINT:
        case OG_TYPE_TINYINT:
        case OG_TYPE_UTINYINT:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
            OG_RETURN_IFERR(mes_get_int32(pack, VALUE_PTR(int32, value)));
            break;

        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
            OG_RETURN_IFERR(mes_get_int64(pack, VALUE_PTR(int64, value)));
            break;

        case OG_TYPE_FLOAT:
        case OG_TYPE_REAL:
            OG_RETURN_IFERR(mes_get_double(pack, VALUE_PTR(double, value)));
            break;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            OG_RETURN_IFERR(mes_get_text(pack, &text));
            OG_RETURN_IFERR(sql_push(stmt, text.len, (void **)&value->v_text.str));
            value->v_text.len = text.len;
            if (text.len > 0) {
                errno_t ret = memcpy_sp(value->v_text.str, text.len, text.str, text.len);
                if (ret != EOK) {
                    OGSQL_POP(stmt);
                    OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
                    return OG_ERROR;
                }
            }
            break;

        default:
            OG_SET_ERROR_MISMATCH_EX(datatype);
            return OG_ERROR;
    }

    return OG_SUCCESS;
}


static status_t proc_rpc_ack(sql_stmt_t *stmt, mes_message_ex_t *pack, expr_node_t *node, ext_assist_t *assist,
    variant_t *result)
{
    function_t *func = assist->func;
    uint32 i = assist->is_func ? 1 : 0;
    uint32 k = 0;
    plv_decl_t *decl = NULL;
    ple_var_t *dst = NULL;
    expr_tree_t *curr_arg = node->argument;
    variant_t value;

    while (k < assist->args_num) {
        decl = cm_galist_get(func->desc.params, i);
        if (decl->drct != PLV_DIR_IN) {
            if (curr_arg->root->type != EXPR_NODE_V_ADDR) {
                OG_SRC_THROW_ERROR(curr_arg->root->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
                return OG_ERROR;
            }
            var_address_pair_t *pair = sql_get_last_addr_pair(curr_arg->root);
            if (pair == NULL || pair->type != UDT_STACK_ADDR) {
                OG_SRC_THROW_ERROR(curr_arg->root->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
                return OG_ERROR;
            }
            dst = ple_get_plvar((pl_executor_t *)stmt->pl_exec, pair->stack->decl->vid);
            OG_RETURN_IFERR(get_param_value(stmt, pack, decl->variant.type.datatype, &value));
            OG_RETURN_IFERR(ple_move_value(stmt, &value, dst));
        }

        curr_arg = curr_arg->next;
        k++;
        i++;
    }

    if (assist->is_func && result != NULL) {
        decl = (plv_decl_t *)cm_galist_get(func->desc.params, 0);
        OG_RETURN_IFERR(get_param_value(stmt, pack, decl->variant.type.datatype, result));
    }
    return OG_SUCCESS;
}

static status_t pl_clear_sym_cache_core(knl_session_t *session, knl_cursor_t *cursor, char *lib_path)
{
    mes_message_ex_t pack;
    char *buf = NULL;
    status_t status;
    int64 oid;
    buf = cm_push(session->stack, MES_MESSAGE_BUFFER_SIZE);
    if (buf == NULL) {
        return OG_ERROR;
    }
    mes_init_set(&pack, buf, MES_MESSAGE_BUFFER_SIZE);
    mes_init_send_head(GET_MSG_HEAD(&pack), MES_CMD_DROP_LIB_REQ, sizeof(mes_message_head_t), MES_MOD_EXTPROC, 0, 1,
        session->id, OG_INVALID_ID16);

    uint32 count = 0;
    uint32 *offset = NULL;

    OG_RETURN_IFERR(mes_reserve_space(&pack, sizeof(uint32), (void **)&offset));

    while (!cursor->eof) {
        oid = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_OBJ_ID_COL);
        OG_RETURN_IFERR(mes_put_int64(&pack, oid));
        count++;
        if (knl_fetch(session, cursor) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    OG_RETURN_IFERR(mes_put_str(&pack, lib_path));
    *offset = count;

    OG_RETURN_IFERR(mes_send_data((const void *)GET_MSG_HEAD(&pack)));

    mes_message_ex_t ack_pack;
    OG_RETURN_IFERR(mes_recv(session->id, &ack_pack.msg, MES_MOD_EXTPROC, OG_FALSE, OG_INVALID_ID32, EXT_WAIT_TIMEOUT));
    mes_init_get(&ack_pack);
    switch (GET_MSG_HEAD(&ack_pack)->cmd) {
        case MES_CMD_DROP_LIB_ACK:
            status = OG_SUCCESS;
            break;

        case MES_CMD_ERROR_MSG:
            mes_handle_error_msg(GET_MSG_BUFF(&ack_pack));
            status = OG_ERROR;
            break;
        default:
            mes_release_message_buf(GET_MSG_BUFF(&ack_pack));
            OG_THROW_ERROR(ERR_MES_ILEGAL_MESSAGE, "invalid MES message type");
            return OG_ERROR;
    }
    mes_release_message_buf(GET_MSG_BUFF(&ack_pack));
    return status;
}

status_t pl_clear_sym_cache(knl_handle_t se, uint32 lib_uid, char *name, char *lib_path)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *session = (knl_session_t *)se;
    status_t status;
    if (!GET_PL_MGR->bootstrap) {
        return OG_SUCCESS;
    }
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, IX_PROC_004_ID);
    knl_init_index_scan(cursor, OG_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, OG_TYPE_INTEGER, (void *)&lib_uid,
        sizeof(uint32), IX_COL_PROC_004_USER_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, OG_TYPE_STRING, (void *)name,
        (uint16)strlen(name), IX_COL_PROC_004_LIB_NAME);
    if (knl_fetch(session, cursor) != OG_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return OG_SUCCESS;
    }

    status = pl_clear_sym_cache_core(session, cursor, lib_path);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t ple_exec_call_clang_func_core(sql_stmt_t *stmt, expr_node_t *node, variant_t *result, ext_assist_t *assist)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_line_begin_t *begin_line = (pl_line_begin_t *)assist->func->body;
    mes_message_ex_t ack_pack;
    mes_message_ex_t pack;
    char *buf = NULL;
    status_t status = OG_SUCCESS;

    CM_SAVE_STACK(knl_session->stack);
    if (sql_push(stmt, MES_MESSAGE_BUFFER_SIZE, (void **)&buf) != OG_SUCCESS) {
        return OG_ERROR;
    }
    mes_init_set(&pack, buf, MES_MESSAGE_BUFFER_SIZE);
    mes_init_send_head(GET_MSG_HEAD(&pack), MES_CMD_RPC_REQ, sizeof(mes_message_head_t), MES_MOD_EXTPROC, 0, 1,
        knl_session->id, OG_INVALID_ID16);

    if (encode_rpc_req(stmt, node, &pack, assist) != OG_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return OG_ERROR;
    }

    if (mes_send_data((const void *)GET_MSG_HEAD(&pack)) != OG_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return OG_ERROR;
    }
    CM_RESTORE_STACK(knl_session->stack);

    if (mes_recv(knl_session->id, &ack_pack.msg, MES_MOD_EXTPROC, OG_FALSE, OG_INVALID_ID32, EXT_WAIT_TIMEOUT) !=
        OG_SUCCESS) {
        cm_reset_error();
        OG_THROW_ERROR(ERR_INVOKE_EXT_FUNC_ERR, T2S(&begin_line->func), "internal exception");
        return OG_ERROR;
    }
    mes_init_get(&ack_pack);
    switch (GET_MSG_HEAD(&ack_pack)->cmd) {
        case MES_CMD_RPC_ACK:
            status = proc_rpc_ack(stmt, &ack_pack, node, assist, result);
            break;
        case MES_CMD_ERROR_MSG:
            mes_handle_error_msg(GET_MSG_BUFF(&ack_pack));
            status = OG_ERROR;
            break;
        default:
            mes_release_message_buf(GET_MSG_BUFF(&ack_pack));
            OG_THROW_ERROR(ERR_MES_ILEGAL_MESSAGE, "invalid MES message type");
            return OG_ERROR;
    }
    mes_release_message_buf(GET_MSG_BUFF(&ack_pack));
    return status;
}