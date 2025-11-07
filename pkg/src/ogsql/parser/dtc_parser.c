#include "dtc_parser.h"
#include "ddl_parser.h"
#include "dtc_database.h"
#include "srv_instance.h"
#include "ddl_database_parser.h"
#include "cm_dbs_intf.h"

/* ********************* SYNTAX DEMO ************************
static create database clustered db_name
controlfile('ctrl1', 'ctrl2', 'ctrl3')
system     tablespace      datafile 'system.dat' size 128M
temporary  tablespace      tempfile 'temp.dat' size 100M
temporary  undo tablespace tempfile 'temp_undo.dat' size 100M
default    tablespace      datafile 'user.dat' size 100M
doublewrite area 'sysdwa.dat'
instance
node 0
undo tablespace datafile 'undo11.dat' size 128M
swap tablespace tempfile 'swap1.dat' size 100M
logfile ('redo11.dat' size 128M, 'redo12.dat' size 128M, 'redo13.dat' size 128M)
node 1
undo tablespace datafile 'undo21.dat' size 128M
swap tablespace tempfile 'swap2.dat' size 100M
logfile ('redo21.dat' size 128M, 'redo22.dat' size 128M, 'redo23.dat' size 128M)
/
*/

static status_t dtc_parse_undo_space(sql_stmt_t *stmt, dtc_node_def_t *node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    char *name;
    errno_t code;

    if (lex_expected_fetch_word(lex, "tablespace") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, OG_NAME_BUFFER_SIZE, (void **)&name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    code = snprintf_s(name, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "UNDO_%02u", node->id);
    PRTS_RETURN_IFERR(code);

    node->undo_space.name.str = name;
    node->undo_space.name.len = (uint32)strlen(name);
    if (node->id == 0) {
        node->undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_NODE0;
    } else {
        node->undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_NODE1;
    }

    if (lex_expected_fetch_word(lex, "datafile") != OG_SUCCESS) {
        return OG_ERROR;
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, &node->undo_space);
}

static status_t dtc_parse_temp_undo_space(sql_stmt_t *stmt, dtc_node_def_t *node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    char *name;
    errno_t code;

    if (lex_expected_fetch_word(lex, "undo") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "tablespace") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, OG_NAME_BUFFER_SIZE, (void **)&name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    code = snprintf_s(name, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "TEMP_UNDO_%u1", node->id);
    PRTS_RETURN_IFERR(code);

    node->temp_undo_space.name.str = name;
    node->temp_undo_space.name.len = (uint32)strlen(name);
    if (node->id == 0) {
        node->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_TEMP | SPACE_TYPE_NODE0;
    } else {
        node->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_TEMP | SPACE_TYPE_NODE1;
    }

    if (lex_expected_fetch_word(lex, "TEMPFILE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, &node->temp_undo_space);
}

static status_t dtc_parse_swap_space(sql_stmt_t *stmt, dtc_node_def_t *node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    char *name;
    errno_t code;

    if (lex_expected_fetch_word(lex, "tablespace") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, OG_NAME_BUFFER_SIZE, (void **)&name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    code = snprintf_s(name, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "SWAP_%02u", node->id);
    PRTS_RETURN_IFERR(code);

    node->swap_space.name.str = name;
    node->swap_space.name.len = (uint32)strlen(name);
    if (node->id == 0) {
        node->swap_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_SWAP | SPACE_TYPE_DEFAULT | SPACE_TYPE_NODE0;
    } else {
        node->swap_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_SWAP | SPACE_TYPE_DEFAULT | SPACE_TYPE_NODE1;
    }

    if (lex_expected_fetch_word(lex, "TEMPFILE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, &node->swap_space);
}

static status_t dtc_parse_node_def(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    dtc_node_def_t *node;
    lex_t *lex = stmt->session->lex;

    if (cm_galist_new(&def->nodes, sizeof(dtc_node_def_t), (pointer_t *)&node) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->id = def->nodes.count - 1;
    cm_galist_init(&node->logfiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&node->undo_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&node->swap_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&node->temp_undo_space.datafiles, stmt->context, sql_alloc_mem);

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    for (;;) {
        switch (word->id) {
            case KEY_WORD_UNDO:
                if (dtc_parse_undo_space(stmt, node, word) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                break;

            case KEY_WORD_LOGFILE:
                if (sql_parse_dbca_logfiles(stmt, &node->logfiles, word) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                break;

            case KEY_WORD_TEMPORARY:
                if (dtc_parse_swap_space(stmt, node, word) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                break;
            case KEY_WORD_NO_LOGGING:
                if (dtc_parse_temp_undo_space(stmt, node, word) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                break;
            default:
                return OG_SUCCESS;
        }
    }

    return OG_SUCCESS;
}

static status_t dtc_parse_nodes(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    uint32 node_id;
    uint32 id;
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "node")) {
        return OG_ERROR;
    }

    node_id = 0;

    for (;;) {
        if (lex_expected_fetch_uint32(lex, &id) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (id != node_id) {
            OG_SRC_THROW_ERROR_EX(lex->loc, ERR_INVALID_DATABASE_DEF, "instance number error, '%u' expected", node_id);
            return OG_ERROR;
        }

        if (dtc_parse_node_def(stmt, def, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (word->id != KEY_WORD_NODE) {
            break;
        }

        node_id++;
    }

    return OG_SUCCESS;
}

status_t dtc_parse_instance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (def->nodes.count > 0) {
        OG_SRC_THROW_ERROR(lex->loc, ERR_SQL_SYNTAX_ERROR, "INSTANCE is already defined");
        return OG_ERROR;
    }

    return dtc_parse_nodes(stmt, def, word);
}

status_t dtc_parse_maxinstance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    return lex_expected_fetch_uint32(lex, &def->max_instance);
}

static status_t dtc_verify_node(sql_stmt_t *stmt, knl_database_def_t *def, uint32 id)
{
    dtc_node_def_t *node;
    node = (dtc_node_def_t *)cm_galist_get(&def->nodes, id);
    if (node->undo_space.name.len == 0 || node->undo_space.datafiles.count == 0) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "UNDO tablespace of instances %d is not specific", id + 1);
        return OG_ERROR;
    }

    if (node->swap_space.name.len == 0 || node->swap_space.datafiles.count == 0) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for swap tablespace");
        return OG_ERROR;
    }

    if (node->temp_undo_space.name.len == 0 || node->temp_undo_space.datafiles.count == 0) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "TEMP_UNDO tablespace of instances %d is not specific", id + 1);
        return OG_ERROR;
    }

    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
        if (node->logfiles.count == 1) {
            return OG_SUCCESS;
        }
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of redo log files is invalid, should be 1 for DBstor.");
        return OG_ERROR;
    }

    if (node->logfiles.count < OG_MIN_LOG_FILES || node->logfiles.count > OG_MAX_LOG_FILES) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of redo log files is invalid, should be in [3, 256]");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t dtc_verify_instances(sql_stmt_t *stmt, knl_database_def_t *def)
{
    uint32 i;

    if (def->nodes.count < 1 || def->nodes.count > OG_MAX_INSTANCES) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of instances is invalid");
        return OG_ERROR;
    }

    for (i = 0; i < def->nodes.count; i++) {
        if (dtc_verify_node(stmt, def, i) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t dtc_verify_database_def(sql_stmt_t *stmt, knl_database_def_t *def)
{
    galist_t *list = NULL;
    knl_device_def_t *dev = NULL;

    list = &def->ctrlfiles;
    if (list->count < 2 || list->count > OG_MAX_CTRL_FILES) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of control files is invalid");
        return OG_ERROR;
    }

    if (dtc_verify_instances(stmt, def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    list = &def->system_space.datafiles;
    if (list->count == 0) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for system tablespace");
        return OG_ERROR;
    }

    dev = cm_galist_get(list, 0);
    if (dev->size < SYSTEM_FILE_MIN_SIZE) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "first system file size less than %d(MB)",
            SYSTEM_FILE_MIN_SIZE / SIZE_M(1));
        return OG_ERROR;
    }

    list = &def->temp_space.datafiles;
    if (list->count == 0) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for temporary tablespace");
        return OG_ERROR;
    }

    list = &def->temp_undo_space.datafiles;
    if (list->count == 0) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for temporary undo tablespace");
        return OG_ERROR;
    }

    if (strlen(def->sys_password) != 0 && cm_compare_str_ins(def->sys_password, SYS_USER_NAME) != 0) {
        OG_RETURN_IFERR(cm_verify_password_str(SYS_USER_NAME, def->sys_password, OG_PASSWD_MIN_LEN));
    }

    if (g_instance->kernel.db.status != DB_STATUS_NOMOUNT) {
        OG_THROW_ERROR(ERR_DATABASE_ALREADY_MOUNT, "database already mounted");
        return OG_ERROR;
    }

    list = &def->sysaux_space.datafiles;
    if (list->count != 1) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "sysaux must have only one datafile");
        return OG_ERROR;
    }
    dev = cm_galist_get(list, 0);
    uint32 min_size = OG_MIN_SYSAUX_DATAFILE_SIZE +
        (def->nodes.count - 1) * DOUBLE_WRITE_PAGES * SIZE_K(8); /* default page size is SIZE_K(8) */
    if (dev->size < min_size) {
        OG_THROW_ERROR_EX(ERR_INVALID_DATABASE_DEF, "first datafile size less than %d(MB), node count(%d)",
            min_size / SIZE_M(1), def->nodes.count);
        return OG_ERROR;
    }

    if (def->max_instance > OG_MAX_INSTANCES) {
        OG_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "MAXINSTANCES larger than 64");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t dtc_parse_create_database(sql_stmt_t *stmt)
{
    return OG_ERROR;
}
