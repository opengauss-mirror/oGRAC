/*
 * Called before any actual parsing is done
 */
 
core_yyscan_t c_scanner_init(const sql_text_t *sql,
             core_yy_extra_type *yyext,
             const ScanKeywordList *keywordlist,
             const uint16 *keyword_tokens,
             sql_stmt_t *stmt)
{
    size_t        slen = sql->len;
    const char *str = sql->str;
    yyscan_t    scanner;

    if (ct_yylex_init(&scanner, stmt) != 0) {
        return NULL;
    }

    c_core_yyset_extra(yyext, scanner);

    yyext->keywordlist = keywordlist;
    yyext->keyword_tokens = keyword_tokens;
    yyext->in_slash_proc_body = false;
    yyext->paren_depth = 0;
    // yyext->query_string_locationlist = NIL;
    yyext->is_createstmt = false;
    yyext->dolqstart = NULL;
    yyext->is_hint_str = false;
    // yyext->parameter_list = NIL;
    yyext->include_ora_comment = false;
    yyext->func_param_begin = 0;
    yyext->func_param_end = 0;
    yyext->return_pos_end = 0;

    /*
     * Make a scan buffer with special termination needed by flex.
     */
    size_t scanbuf_size = slen + SCANBUF_EXTRA_SIZE;
    yyext->scanbuf_malloced = false;
    if (scanbuf_size > stmt->context->ctrl.memory->pool->page_size) {
        yyext->scanbuf = (char *)malloc(scanbuf_size);
        if (yyext->scanbuf == NULL) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)scanbuf_size, "scanner buffer");
            return NULL;
        }
        yyext->scanbuf_malloced = true;
    } else {
        if (sql_alloc_mem(stmt->context, (uint32)scanbuf_size, (void **)&yyext->scanbuf) != OG_SUCCESS) {
            return NULL;
        }
    }
    yyext->scanbuflen = slen;
    yyext->stmt = stmt;
    yyext->pending_prev_cte = NULL;
    if (sql_create_array(stmt->context, &yyext->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS) != OG_SUCCESS) {
        if (yyext->scanbuf_malloced) {
            free(yyext->scanbuf);
            yyext->scanbuf = NULL;
            yyext->scanbuf_malloced = false;
        }
        return NULL;
    }
    errno_t ret = memcpy_s(yyext->scanbuf, slen + 1, str, slen);
    knl_securec_check(ret);
    yyext->scanbuf[slen] = yyext->scanbuf[slen + 1] = YY_END_OF_BUFFER_CHAR;
    if (stmt->parser_text_valid) {
        stmt->parser_text.str = yyext->scanbuf;
        stmt->parser_text.len = (uint32)slen;
        stmt->parser_text.loc = sql->loc;
        stmt->parser_text.implicit = sql->implicit;
    }
    yy_scan_buffer(yyext->scanbuf, slen + SCANBUF_EXTRA_SIZE, scanner);

    /* initialize literal buffer to a reasonable but expansible size */
    yyext->literalalloc = LITERAL_SIZE;
    yyext->literalbuf = (char *)c_core_yyalloc(yyext->literalalloc, scanner);
    if (yyext->literalbuf == NULL) {
        if (yyext->scanbuf_malloced) {
            free(yyext->scanbuf);
            yyext->scanbuf = NULL;
            yyext->scanbuf_malloced = false;
        }
        return NULL;
    }
    yyext->literallen = 0;
    yyext->warnOnTruncateIdent = true;

    /* plpgsql keyword params */
    yyext->isPlpgsqlKeyWord = false;
    // yyext->plKeywordValue = NULL;
    yyext->is_delimiter_name = false;
    yyext->is_last_colon = false;
    yyext->is_proc_end = false;
    yyext->multi_line_sql = strchr(str, '\n') != NULL;

    return scanner;
}

/*
 * Called after parsing is done to clean up after scanner_init()
 */
void c_scanner_finish(core_yyscan_t yyscanner)
{
    scanner_finish(yyscanner);
}

void* core_yyalloc(yy_size_t bytes, core_yyscan_t yyscanner);

void* c_core_yyalloc(yy_size_t bytes, core_yyscan_t yyscanner)
{
    return core_yyalloc(bytes, yyscanner);
}

void* core_yyrealloc(void *ptr, yy_size_t bytes, core_yyscan_t yyscanner);

void* c_core_yyrealloc(void *ptr, yy_size_t bytes, core_yyscan_t yyscanner)
{
    return core_yyrealloc(ptr, bytes, yyscanner);
}

void core_yyfree(void *ptr, core_yyscan_t yyscanner);

void c_core_yyfree(void *ptr, core_yyscan_t yyscanner)
{
    core_yyfree(ptr, yyscanner);
}

#define core_yyset_extra c_core_yyset_extra
