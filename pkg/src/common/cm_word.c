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
 * cm_word.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_word.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif
static key_word_t g_key_words[] = {
    { (uint32)KEY_WORD_ABNORMAL, OG_FALSE, { (char *)"abnormal" } },
    { (uint32)KEY_WORD_ABORT, OG_TRUE, { (char *)"abort" } },
    { (uint32)KEY_WORD_ACCOUNT, OG_TRUE, { (char *)"account" } },
    { (uint32)KEY_WORD_ACTIVATE, OG_TRUE, { (char *)"activate" } },
    { (uint32)KEY_WORD_ACTIVE, OG_TRUE, { (char *)"active" } },
    { (uint32)KEY_WORD_ADD, OG_FALSE, { (char *)"add" } },
    { (uint32)KEY_WORD_AFTER, OG_TRUE, { (char *)"after" } },
    { (uint32)KEY_WORD_ALL, OG_FALSE, { (char *)"all" } },
    { (uint32)KEY_WORD_ALTER, OG_FALSE, { (char *)"alter" } },
    { (uint32)KEY_WORD_ANALYZE, OG_TRUE, { (char *)"analyze" } },
    { (uint32)KEY_WORD_AND, OG_FALSE, { (char *)"and" } },
    { (uint32)KEY_WORD_ANY, OG_FALSE, { (char *)"any" } },
    { (uint32)KEY_WORD_APPENDONLY, OG_TRUE, { (char *)"appendonly" } },
    { (uint32)KEY_WORD_ARCHIVE, OG_TRUE, { (char *)"archive" } },
    { (uint32)KEY_WORD_ARCHIVELOG, OG_TRUE, { (char *)"archivelog" } },
    { (uint32)KEY_WORD_ARCHIVE_SET, OG_FALSE, { (char *)"archive_set" } },
    { (uint32)KEY_WORD_AS, OG_FALSE, { (char *)"as" } },
    { (uint32)KEY_WORD_ASC, OG_FALSE, { (char *)"asc" } },
    { (uint32)KEY_WORD_ASYNC, OG_TRUE, { (char *)"async" } },
    { (uint32)KEY_WORD_AUDIT, OG_FALSE, { (char *)"audit" } },
    { (uint32)KEY_WORD_AUTOALLOCATE, OG_TRUE, { (char *)"autoallocate" } },
    { (uint32)KEY_WORD_AUTOEXTEND, OG_TRUE, { (char *)"autoextend" } },
    { (uint32)KEY_WORD_AUTOMATIC, OG_TRUE, { (char *)"automatic" } },
    { (uint32)KEY_WORD_AUTON_TRANS, OG_TRUE, { (char *)"autonomous_transaction" } },
    { (uint32)KEY_WORD_AUTOOFFLINE, OG_TRUE, { (char *)"autooffline" } },
    { (uint32)KEY_WORD_AUTOPURGE, OG_TRUE, { (char *)"autopurge" } },
    { (uint32)KEY_WORD_AUTO_INCREMENT, OG_TRUE, { (char *)"auto_increment" } },
    { (uint32)KEY_WORD_AVAILABILITY, OG_TRUE, { (char *)"availability" } },
    { (uint32)KEY_WORD_BACKUP, OG_TRUE, { (char *)"backup" } },
    { (uint32)KEY_WORD_BACKUPSET, OG_TRUE, { (char *)"backupset" } },
    { (uint32)KEY_WORD_BEFORE, OG_TRUE, { (char *)"before" } },
    { (uint32)KEY_WORD_BEGIN, OG_TRUE, { (char *)"begin" } },
    { (uint32)KEY_WORD_BETWEEN, OG_FALSE, { (char *)"between" } },
    { (uint32)KEY_WORD_BODY, OG_TRUE, { (char *)"body" } },
    { (uint32)KEY_WORD_BOTH, OG_TRUE, { (char *)"both" } }, /* for TRIM expression only */
    { (uint32)KEY_WORD_BUFFER, OG_TRUE, { (char *)"buffer" } },
    { (uint32)KEY_WORD_BUILD, OG_TRUE, { (char *)"build" } },
    { (uint32)KEY_WORD_BULK, OG_TRUE, { (char *)"bulk" } },
    { (uint32)KEY_WORD_BY, OG_FALSE, { (char *)"by" } },
    { (uint32)KEY_WORD_CACHE, OG_TRUE, { (char *)"cache" } },
    { (uint32)KEY_WORD_CALL, OG_TRUE, { (char *)"call" } },
    { (uint32)KEY_WORD_CANCEL, OG_TRUE, { (char *)"cancel" } },
    { (uint32)KEY_WORD_CASCADE, OG_TRUE, { (char *)"cascade" } },
    { (uint32)KEY_WORD_CASCADED, OG_TRUE, { (char *)"cascaded" } },
    { (uint32)KEY_WORD_CASE, OG_FALSE, { (char *)"case" } },
    { (uint32)KEY_WORD_CAST, OG_TRUE, { (char *)"cast" } },
    { (uint32)KEY_WORD_CATALOG, OG_TRUE, { (char *)"catalog" } },
    { (uint32)KEY_WORD_CHARACTER, OG_TRUE, { (char *)"character" } },
    { (uint32)KEY_WORD_CHARSET, OG_TRUE, { (char *)"charset" } },
    { (uint32)KEY_WORD_CHECK, OG_FALSE, { (char *)"check" } },
    { (uint32)KEY_WORD_CHECKPOINT, OG_TRUE, { (char *)"checkpoint" } },
    { (uint32)KEY_WORD_CLOSE, OG_TRUE, { (char *)"close" } },
    { (uint32)KEY_WORD_CLUSTER, OG_TRUE, { (char *)"cluster" } },
    { (uint32)KEY_WORD_CLUSTERED, OG_TRUE, { (char *)"clustered" } },
    { (uint32)KEY_WORD_COALESCE, OG_TRUE, { (char *)"coalesce" } },
    { (uint32)KEY_WORD_COLLATE, OG_TRUE, { (char *)"collate" } },
    { (uint32)KEY_WORD_COLUMN, OG_FALSE, { (char *)"column" } },
    { (uint32)KEY_WORD_COLUMNS, OG_TRUE, { (char *)"columns" } },
    { (uint32)KEY_WORD_COLUMN_VALUE, OG_TRUE, { (char *)"column_value" } },
    { (uint32)KEY_WORD_COMMENT, OG_TRUE, { (char *)"comment" } },
    { (uint32)KEY_WORD_COMMIT, OG_TRUE, { (char *)"commit" } },
    { (uint32)KEY_WORD_COMPRESS, OG_FALSE, { (char *)"compress" } },
    { (uint32)KEY_WORD_CONFIG, OG_TRUE, { (char *)"config" } },
    { (uint32)KEY_WORD_CONNECT, OG_FALSE, { (char *)"connect" } },
    { (uint32)KEY_WORD_CONSISTENCY, OG_TRUE, { (char *)"consistency" } },
    { (uint32)KEY_WORD_CONSTRAINT, OG_FALSE, { (char *)"constraint" } },
    { (uint32)KEY_WORD_CONTENT, OG_TRUE, { (char *)"content" } },
    { (uint32)KEY_WORD_CONTINUE, OG_TRUE, { (char *)"continue" } },
    { (uint32)KEY_WORD_CONTROLFILE, OG_TRUE, { (char *)"controlfile" } },
    { (uint32)KEY_WORD_CONVERT, OG_TRUE, { (char *)"convert" } },
    { (uint32)KEY_WORD_COPY, OG_TRUE, { (char *)"copy" } },
    { (uint32)KEY_WORD_CREATE, OG_FALSE, { (char *)"create" } },
    { (uint32)KEY_WORD_CRMODE, OG_FALSE, { (char *)"crmode" } },
    { (uint32)KEY_WORD_CROSS, OG_TRUE, { (char *)"cross" } },
    { (uint32)KEY_WORD_CTRLFILE, OG_TRUE, { (char *)"ctrlfile" } },
    { (uint32)KEY_WORD_CUMULATIVE, OG_FALSE, { (char *)"cumulative" } },
    { (uint32)KEY_WORD_CURRENT, OG_FALSE, { (char *)"current" } },
    { (uint32)KEY_WORD_CURRVAL, OG_TRUE, { (char *)"currval" } },
    { (uint32)KEY_WORD_CURSOR, OG_TRUE, { (char *)"cursor" } },
    { (uint32)KEY_WORD_CYCLE, OG_TRUE, { (char *)"cycle" } },
    { (uint32)KEY_WORD_DATA, OG_TRUE, { (char *)"data" } },
    { (uint32)KEY_WORD_DATABASE, OG_TRUE, { (char *)"database" } },
    { (uint32)KEY_WORD_DATAFILE, OG_TRUE, { (char *)"datafile" } },
    { (uint32)KEY_WORD_DB, OG_FALSE, { (char *)"db" } },
    { (uint32)KEY_WORD_DEBUG, OG_TRUE, { (char *)"debug" } },
    { (uint32)KEY_WORD_DECLARE, OG_TRUE, { (char *)"declare" } },
    { (uint32)KEY_WORD_DEFERRABLE, OG_TRUE, { (char *)"deferrable" } },
    { (uint32)KEY_WORD_DELETE, OG_FALSE, { (char *)"delete" } },
    { (uint32)KEY_WORD_DESC, OG_FALSE, { (char *)"desc" } },
    { (uint32)KEY_WORD_DICTIONARY, OG_TRUE, { (char *)"dictionary" } },
    { (uint32)KEY_WORD_DIRECTORY, OG_TRUE, { (char *)"directory" } },
    { (uint32)KEY_WORD_DISABLE, OG_TRUE, { (char *)"disable" } },
    { (uint32)KEY_WORD_DISCARD, OG_TRUE, { (char *)"discard" } },
    { (uint32)KEY_WORD_DISCONNECT, OG_TRUE, { (char *)"disconnect" } },
    { (uint32)KEY_WORD_DISTINCT, OG_FALSE, { (char *)"distinct" } },
    { (uint32)KEY_WORD_DISTRIBUTE, OG_TRUE, { (char *)"distribute" } },
    { (uint32)KEY_WORD_DO, OG_TRUE, { (char *)"do" } },
    { (uint32)KEY_WORD_DOUBLEWRITE, OG_TRUE, { (char *)"doublewrite" } },
    { (uint32)KEY_WORD_DROP, OG_FALSE, { (char *)"drop" } },
    { (uint32)KEY_WORD_DUMP, OG_TRUE, { (char *)"dump" } },
    { (uint32)KEY_WORD_DUPLICATE, OG_TRUE, { (char *)"duplicate" } },
    { (uint32)KEY_WORD_ELSE, OG_FALSE, { (char *)"else" } },
    { (uint32)KEY_WORD_ELSIF, OG_TRUE, { (char *)"elsif" } },
    { (uint32)KEY_WORD_ENABLE, OG_TRUE, { (char *)"enable" } },
    { (uint32)KEY_WORD_ENABLE_LOGIC_REPLICATION, OG_TRUE, { (char *)"enable_logic_replication" } },
    { (uint32)KEY_WORD_ENCRYPTION, OG_TRUE, { (char *)"encryption" } },
    { (uint32)KEY_WORD_END, OG_TRUE, { (char *)"end" } },
    { (uint32)KEY_WORD_ERROR, OG_TRUE, { (char *)"error" } },
    { (uint32)KEY_WORD_ESCAPE, OG_TRUE, { (char *)"escape" } },
    { (uint32)KEY_WORD_EXCEPT, OG_FALSE, { (char *)"except" } },
    { (uint32)KEY_WORD_EXCEPTION, OG_TRUE, { (char *)"exception" } },
    { (uint32)KEY_WORD_EXCLUDE, OG_TRUE, { (char *)"exclude" } },
    { (uint32)KEY_WORD_EXEC, OG_TRUE, { (char *)"exec" } },
    { (uint32)KEY_WORD_EXECUTE, OG_TRUE, { (char *)"execute" } },
    { (uint32)KEY_WORD_EXISTS, OG_FALSE, { (char *)"exists" } },
    { (uint32)KEY_WORD_EXIT, OG_TRUE, { (char *)"exit" } },
    { (uint32)KEY_WORD_EXPLAIN, OG_TRUE, { (char *)"explain" } },
    { (uint32)KEY_WORD_EXTENT, OG_TRUE, { (char *)"extent" } },
    { (uint32)KEY_WORD_FAILOVER, OG_TRUE, { (char *)"failover" } },
    { (uint32)KEY_WORD_FETCH, OG_TRUE, { (char *)"fetch" } },
    { (uint32)KEY_WORD_FILE, OG_TRUE, { (char *)"file" } },
    { (uint32)KEY_WORD_FILETYPE, OG_TRUE, { (char *)"filetype" } },
    { (uint32)KEY_WORD_FINAL, OG_TRUE, { (char *)"final" } },
    { (uint32)KEY_WORD_FINISH, OG_TRUE, { (char *)"finish" } },
    { (uint32)KEY_WORD_FLASHBACK, OG_TRUE, { (char *)"flashback" } },
    { (uint32)KEY_WORD_FLUSH, OG_TRUE, { (char *)"flush" } },
    { (uint32)KEY_WORD_FOLLOWING, OG_TRUE, { (char *)"following" } },
    { (uint32)KEY_WORD_FOR, OG_FALSE, { (char *)"for" } },
    { (uint32)KEY_WORD_FORALL, OG_FALSE, { (char *)"forall" } },
    { (uint32)KEY_WORD_FORCE, OG_TRUE, { (char *)"force" } },
    { (uint32)KEY_WORD_FOREIGN, OG_TRUE, { (char *)"foreign" } },
    { (uint32)KEY_WORD_FORMAT, OG_TRUE, { (char *)"format" } },
    { (uint32)KEY_WORD_FROM, OG_FALSE, { (char *)"from" } },
    { (uint32)KEY_WORD_FULL, OG_TRUE, { (char *)"full" } },
    { (uint32)KEY_WORD_FUNCTION, OG_TRUE, { (char *)"function" } },
    { (uint32)KEY_WORD_GLOBAL, OG_TRUE, { (char *)"global" } },
    { (uint32)KEY_WORD_GOTO, OG_TRUE, { (char *)"goto" } },
    { (uint32)KEY_WORD_GRANT, OG_TRUE, { (char *)"grant" } },
    { (uint32)KEY_WORD_GROUP, OG_FALSE, { (char *)"group" } },
    { (uint32)KEY_WORD_GROUPID, OG_TRUE, { (char *)"groupid" } },
    { (uint32)KEY_WORD_HASH, OG_TRUE, { (char *)"hash" } },
    { (uint32)KEY_WORD_HAVING, OG_FALSE, { (char *)"having" } },
    { (uint32)KEY_WORD_IDENTIFIED, OG_FALSE, { (char *)"identified" } },
    { (uint32)KEY_WORD_IF, OG_TRUE, { (char *)"if" } },
    { (uint32)KEY_WORD_IGNORE, OG_TRUE, { (char *)"ignore" } },
    { (uint32)KEY_WORD_IN, OG_FALSE, { (char *)"in" } },
    { (uint32)KEY_WORD_INCLUDE, OG_TRUE, { (char *)"include" } },
    { (uint32)KEY_WORD_INCLUDING, OG_TRUE, { (char *)"including" } },
    { (uint32)KEY_WORD_INCREMENT, OG_FALSE, { (char *)"increment" } },
    { (uint32)KEY_WORD_INCREMENTAL, OG_TRUE, { (char *)"incremental" } },
    { (uint32)KEY_WORD_INDEX, OG_FALSE, { (char *)"index" } },
    { (uint32)KEY_WORD_INDEXCLUSTER, OG_FALSE, { (char *)"indexcluster" } },
    { (uint32)KEY_WORD_INDEX_ASC, OG_TRUE, { (char *)"index_asc" } },
    { (uint32)KEY_WORD_INDEX_DESC, OG_TRUE, { (char *)"index_desc" } },
    { (uint32)KEY_WORD_INIT, OG_TRUE, { (char *)"init" } },
    { (uint32)KEY_WORD_INITIAL, OG_TRUE, { (char *)"initial" } },
    { (uint32)KEY_WORD_INITIALLY, OG_TRUE, { (char *)"initially" } },
    { (uint32)KEY_WORD_INITRANS, OG_TRUE, { (char *)"initrans" } },
    { (uint32)KEY_WORD_INNER, OG_TRUE, { (char *)"inner" } },
    { (uint32)KEY_WORD_INSERT, OG_FALSE, { (char *)"insert" } },
    { (uint32)KEY_WORD_INSTANCE, OG_TRUE, { (char *)"instance" } },
    { (uint32)KEY_WORD_INSTANTIABLE, OG_TRUE, { (char *)"instantiable" } },
    { (uint32)KEY_WORD_INSTEAD, OG_TRUE, { (char *)"instead" } },
    { (uint32)KEY_WORD_INTERSECT, OG_FALSE, { (char *)"intersect" } },
    { (uint32)KEY_WORD_INTO, OG_FALSE, { (char *)"into" } },
    { (uint32)KEY_WORD_INVALIDATE, OG_TRUE, { (char *)"invalidate" } },
    { (uint32)KEY_WORD_IS, OG_FALSE, { (char *)"is" } },
    { (uint32)KEY_WORD_IS_NOT, OG_TRUE, { (char *)"isnot" } },
    { (uint32)KEY_WORD_JOIN, OG_TRUE, { (char *)"join" } },
    { (uint32)KEY_WORD_JSON, OG_TRUE, { (char *)"json" } },
    { (uint32)KEY_WORD_JSONB_TABLE, OG_TRUE, { (char *)"jsonb_table" } },
    { (uint32)KEY_WORD_JSON_TABLE, OG_TRUE, { (char *)"json_table" } },
    { (uint32)KEY_WORD_KEEP, OG_TRUE, { (char *)"keep" } },
    { (uint32)KEY_WORD_KEY, OG_TRUE, { (char *)"key" } },
    { (uint32)KEY_WORD_KILL, OG_TRUE, { (char *)"kill" } },
    { (uint32)KEY_WORD_LANGUAGE, OG_TRUE, { (char *)"language" } },
    { (uint32)KEY_WORD_LEADING, OG_TRUE, { (char *)"leading" } }, /* for TRIM expression only */
    { (uint32)KEY_WORD_LEFT, OG_TRUE, { (char *)"left" } },
    { (uint32)KEY_WORD_LESS, OG_TRUE, { (char *)"less" } },
    { (uint32)KEY_WORD_LEVEL, OG_FALSE, { (char *)"level" } },
    { (uint32)KEY_WORD_LIBRARY, OG_FALSE, { (char *)"library" } },
    { (uint32)KEY_WORD_LIKE, OG_FALSE, { (char *)"like" } },
    { (uint32)KEY_WORD_LIMIT, OG_TRUE, { (char *)"limit" } },
    { (uint32)KEY_WORD_LIST, OG_TRUE, { (char *)"list" } },
    { (uint32)KEY_WORD_LNNVL, OG_TRUE, { (char *)"lnnvl" } },
    { (uint32)KEY_WORD_LOAD, OG_TRUE, { (char *)"load" } },
    { (uint32)KEY_WORD_LOB, OG_TRUE, { (char *)"lob" } },
    { (uint32)KEY_WORD_LOCAL, OG_TRUE, { (char *)"local" } },
    { (uint32)KEY_WORD_LOCK, OG_FALSE, { (char *)"lock" } },
    { (uint32)KEY_WORD_LOCK_WAIT, OG_TRUE, { (char *)"lock_wait" } },
    { (uint32)KEY_WORD_LOG, OG_TRUE, { (char *)"log" } },
    { (uint32)KEY_WORD_LOGFILE, OG_TRUE, { (char *)"logfile" } },
    { (uint32)KEY_WORD_LOGGING, OG_TRUE, { (char *)"logging" } },
    { (uint32)KEY_WORD_LOGICAL, OG_TRUE, { (char *)"logical" } },
    { (uint32)KEY_WORD_LOOP, OG_TRUE, { (char *)"loop" } },
    { (uint32)KEY_WORD_MANAGED, OG_TRUE, { (char *)"managed" } },
    { (uint32)KEY_WORD_MAXIMIZE, OG_TRUE, { (char *)"maximize" } },
    { (uint32)KEY_WORD_MAXINSTANCES, OG_TRUE, { (char *)"maxinstances" } },
    { (uint32)KEY_WORD_MAXSIZE, OG_TRUE, { (char *)"maxsize" } },
    { (uint32)KEY_WORD_MAXTRANS, OG_TRUE, { (char *)"maxtrans" } },
    { (uint32)KEY_WORD_MAXVALUE, OG_TRUE, { (char *)"maxvalue" } },
    { (uint32)KEY_WORD_MEMBER, OG_TRUE, { (char *)"member" } },
    { (uint32)KEY_WORD_MEMORY, OG_TRUE, { (char *)"memory" } },
    { (uint32)KEY_WORD_MERGE, OG_TRUE, { (char *)"merge" } },
    { (uint32)KEY_WORD_MINUS, OG_FALSE, { (char *)"minus" } },
    { (uint32)KEY_WORD_MINVALUE, OG_TRUE, { (char *)"minvalue" } },
    { (uint32)KEY_WORD_MODE, OG_TRUE, { (char *)"mode" } },
    { (uint32)KEY_WORD_MODIFY, OG_FALSE, { (char *)"modify" } },
    { (uint32)KEY_WORD_MONITOR, OG_TRUE, { (char *)"monitor" } },
    { (uint32)KEY_WORD_MOUNT, OG_TRUE, { (char *)"mount" } },
    { (uint32)KEY_WORD_MOVE, OG_TRUE, { (char *)"move" } },
    { (uint32)KEY_WORD_NEXT, OG_TRUE, { (char *)"next" } },
    { (uint32)KEY_WORD_NEXTVAL, OG_TRUE, { (char *)"nextval" } },
    { (uint32)KEY_WORD_NOARCHIVELOG, OG_TRUE, { (char *)"noarchivelog" } },
    { (uint32)KEY_WORD_NO_CACHE, OG_TRUE, { (char *)"nocache" } },
    { (uint32)KEY_WORD_NO_COMPRESS, OG_FALSE, { (char *)"nocompress" } },
    { (uint32)KEY_WORD_NO_CYCLE, OG_TRUE, { (char *)"nocycle" } },
    { (uint32)KEY_WORD_NODE, OG_TRUE, { (char *)"node" } },
    { (uint32)KEY_WORD_NO_LOGGING, OG_TRUE, { (char *)"nologging" } },
    { (uint32)KEY_WORD_NO_MAXVALUE, OG_TRUE, { (char *)"nomaxvalue" } },
    { (uint32)KEY_WORD_NO_MINVALUE, OG_TRUE, { (char *)"nominvalue" } },
    { (uint32)KEY_WORD_NO_ORDER, OG_TRUE, { (char *)"noorder" } },
    { (uint32)KEY_WORD_NO_RELY, OG_TRUE, { (char *)"norely" } },
    { (uint32)KEY_WORD_NOT, OG_FALSE, { (char *)"not" } },
    { (uint32)KEY_WORD_NO_VALIDATE, OG_TRUE, { (char *)"novalidate" } },
    { (uint32)KEY_WORD_NOWAIT, OG_FALSE, { (char *)"nowait" } },
    { (uint32)KEY_WORD_NULL, OG_FALSE, { (char *)"null" } },
    { (uint32)KEY_WORD_NULLS, OG_TRUE, { (char *)"nulls" } },
    { (uint32)KEY_WORD_OF, OG_FALSE, { (char *)"of" } },
    { (uint32)KEY_WORD_OFF, OG_TRUE, { (char *)"off" } },
    { (uint32)KEY_WORD_OFFLINE, OG_FALSE, { (char *)"offline" } },
    { (uint32)KEY_WORD_OFFSET, OG_TRUE, { (char *)"offset" } },
    { (uint32)KEY_WORD_OGRAC, OG_TRUE, { (char *)"ograc" } },
    { (uint32)KEY_WORD_ON, OG_FALSE, { (char *)"on" } },
    { (uint32)KEY_WORD_ONLINE, OG_FALSE, { (char *)"online" } },
    { (uint32)KEY_WORD_ONLY, OG_TRUE, { (char *)"only" } },
    { (uint32)KEY_WORD_OPEN, OG_TRUE, { (char *)"open" } },
    { (uint32)KEY_WORD_OR, OG_FALSE, { (char *)"or" } },
    { (uint32)KEY_WORD_ORDER, OG_FALSE, { (char *)"order" } },
    { (uint32)KEY_WORD_ORGANIZATION, OG_TRUE, { (char *)"organization" } },
    { (uint32)KEY_WORD_OUTER, OG_TRUE, { (char *)"outer" } },
    { (uint32)KEY_WORD_PACKAGE, OG_TRUE, { (char *)"package" } },
    { (uint32)KEY_WORD_PARALLEL, OG_TRUE, { (char *)"parallel" } },
    { (uint32)KEY_WORD_PARALLELISM, OG_TRUE, { (char *)"parallelism" } },
    { (uint32)KEY_WORD_PARAM, OG_TRUE, { (char *)"parameter" } },
    { (uint32)KEY_WORD_PARTITION, OG_TRUE, { (char *)"partition" } },
    { (uint32)KEY_WORD_PASSWORD, OG_TRUE, { (char *)"password" } },
    { (uint32)KEY_WORD_PATH, OG_TRUE, { (char *)"path" } },
    { (uint32)KEY_WORD_PCTFREE, OG_TRUE, { (char *)"pctfree" } },
    { (uint32)KEY_WORD_PERFORMANCE, OG_TRUE, { (char *)"performance" } },
    { (uint32)KEY_WORD_PHYSICAL, OG_TRUE, { (char *)"physical" } },
    { (uint32)KEY_WORD_PIVOT, OG_TRUE, { (char *)"pivot" } },
    { (uint32)KEY_WORD_PLAN, OG_TRUE, { (char *)"plan" } },
    { (uint32)KEY_WORD_PRAGMA, OG_TRUE, { (char *)"pragma" } },
    { (uint32)KEY_WORD_PRECEDING, OG_TRUE, { (char *)"preceding" } },
    { (uint32)KEY_WORD_PREPARE, OG_TRUE, { (char *)"prepare" } },
    { (uint32)KEY_WORD_PREPARED, OG_TRUE, { (char *)"prepared" } },
    { (uint32)KEY_WORD_PRESERVE, OG_TRUE, { (char *)"preserve" } },
    { (uint32)KEY_WORD_PRIMARY, OG_TRUE, { (char *)"primary" } },
    { (uint32)KEY_WORD_PRIOR, OG_TRUE, { (char *)"prior" } },
    { (uint32)KEY_WORD_PRIVILEGES, OG_FALSE, { (char *)"privileges" } },
    { (uint32)KEY_WORD_PROCEDURE, OG_TRUE, { (char *)"procedure" } },
    { (uint32)KEY_WORD_PROFILE, OG_TRUE, { (char *)"profile" } },
    { (uint32)KEY_WORD_PROTECTION, OG_TRUE, { (char *)"protection" } },
    { (uint32)KEY_WORD_PUBLIC, OG_FALSE, { (char *)"public" } },
    { (uint32)KEY_WORD_PUNCH, OG_TRUE, { (char *)"punch" } },
    { (uint32)KEY_WORD_PURGE, OG_TRUE, { (char *)"purge" } },
    { (uint32)KEY_WORD_QUERY, OG_TRUE, { (char *)"query" } },
    { (uint32)KEY_WORD_RAISE, OG_TRUE, { (char *)"raise" } },
    { (uint32)KEY_WORD_RANGE, OG_TRUE, { (char *)"range" } },
    { (uint32)KEY_WORD_READ, OG_TRUE, { (char *)"read" } },
    { (uint32)KEY_WORD_READ_ONLY, OG_TRUE, { (char *)"readonly" } },
    { (uint32)KEY_WORD_READ_WRITE, OG_TRUE, { (char *)"readwrite" } },
    { (uint32)KEY_WORD_REBUILD, OG_TRUE, { (char *)"rebuild" } },
    { (uint32)KEY_WORD_RECOVER, OG_TRUE, { (char *)"recover" } },
    { (uint32)KEY_WORD_RECYCLE, OG_TRUE, { (char *)"recycle" } },
    { (uint32)KEY_WORD_RECYCLEBIN, OG_TRUE, { (char *)"recyclebin" } },
    { (uint32)KEY_WORD_REDO, OG_TRUE, { (char *)"redo" } },
    { (uint32)KEY_WORD_REFERENCES, OG_TRUE, { (char *)"references" } },
    { (uint32)KEY_WORD_REFRESH, OG_TRUE, { (char *)"refresh" } },
    { (uint32)KEY_WORD_REGEXP, OG_TRUE, { (char *)"regexp" } },
    { (uint32)KEY_WORD_REGEXP_LIKE, OG_TRUE, { (char *)"regexp_like" } },
    { (uint32)KEY_WORD_REGISTER, OG_TRUE, { (char *)"register" } },
    { (uint32)KEY_WORD_RELEASE, OG_TRUE, { (char *)"release" } },
    { (uint32)KEY_WORD_RELOAD, OG_TRUE, { (char *)"reload" } },
    { (uint32)KEY_WORD_RELY, OG_TRUE, { (char *)"rely" } },
    { (uint32)KEY_WORD_RENAME, OG_FALSE, { (char *)"rename" } },
    { (uint32)KEY_WORD_REPAIR, OG_FALSE, { (char *)"repair" } },
    { (uint32)KEY_WORD_REPAIR_COPYCTRL, OG_FALSE, { (char *)"repair_copyctrl" } },
    { (uint32)KEY_WORD_REPAIR_PAGE, OG_FALSE, { (char *)"repair_page" } },
    { (uint32)KEY_WORD_REPLACE, OG_TRUE, { (char *)"replace" } },
    { (uint32)KEY_WORD_REPLICATION, OG_TRUE, { (char *)"replication" } },
    { (uint32)KEY_WORD_RESET, OG_TRUE, { (char *)"reset" } },
    { (uint32)KEY_WORD_RESIZE, OG_TRUE, { (char *)"resize" } },
    { (uint32)KEY_WORD_RESTORE, OG_TRUE, { (char *)"restore" } },
    { (uint32)KEY_WORD_RESTRICT, OG_TRUE, { (char *)"restrict" } },
    { (uint32)KEY_WORD_RETURN, OG_TRUE, { (char *)"return" } },
    { (uint32)KEY_WORD_RETURNING, OG_TRUE, { (char *)"returning" } },
    { (uint32)KEY_WORD_REUSE, OG_TRUE, { (char *)"reuse" } },
    { (uint32)KEY_WORD_REVERSE, OG_TRUE, { (char *)"reverse" } },
    { (uint32)KEY_WORD_REVOKE, OG_TRUE, { (char *)"revoke" } },
    { (uint32)KEY_WORD_RIGHT, OG_TRUE, { (char *)"right" } },
    { (uint32)KEY_WORD_ROLE, OG_TRUE, { (char *)"role" } },
    { (uint32)KEY_WORD_ROLLBACK, OG_TRUE, { (char *)"rollback" } },
    { (uint32)KEY_WORD_ROUTE, OG_TRUE, { (char *)"route" } },
    { (uint32)KEY_WORD_ROWS, OG_FALSE, { (char *)"rows" } },
    { (uint32)KEY_WORD_SAVEPOINT, OG_TRUE, { (char *)"savepoint" } },
    { (uint32)KEY_WORD_SCN, OG_TRUE, { (char *)"scn" } },
    { (uint32)KEY_WORD_SECONDARY, OG_TRUE, { (char *)"secondary" } },
    { (uint32)KEY_WORD_SECTION, OG_TRUE, { (char *)"section" } },
    { (uint32)KEY_WORD_SELECT, OG_FALSE, { (char *)"select" } },
    { (uint32)KEY_WORD_SEPARATOR, OG_TRUE, { (char *)"separator" } },
    { (uint32)KEY_WORD_SEQUENCE, OG_TRUE, { (char *)"sequence" } },
    { (uint32)KEY_WORD_SERIALIZABLE, OG_TRUE, { (char *)"serializable" } },
    { (uint32)KEY_WORD_SERVER, OG_TRUE, { (char *)"server" } },
    { (uint32)KEY_WORD_SESSION, OG_FALSE, { (char *)"session" } },
    { (uint32)KEY_WORD_SET, OG_FALSE, { (char *)"set" } },
    { (uint32)KEY_WORD_SHARE, OG_TRUE, { (char *)"share" } },
    { (uint32)KEY_WORD_SHOW, OG_TRUE, { (char *)"show" } },
    { (uint32)KEY_WORD_SHRINK, OG_TRUE, { (char *)"shrink" } },
    { (uint32)KEY_WORD_SHUTDOWN, OG_TRUE, { (char *)"shutdown" } },
#ifdef DB_DEBUG_VERSION
    { (uint32)KEY_WORD_SIGNAL, OG_TRUE, { (char *)"signal" } },
#endif
    { (uint32)KEY_WORD_SIZE, OG_TRUE, { (char *)"size" } },
    { (uint32)KEY_WORD_SKIP, OG_TRUE, { (char *)"skip" } },
    { (uint32)KEY_WORD_SKIP_ADD_DROP_TABLE, OG_TRUE, { (char *)"skip_add_drop_table" } },
    { (uint32)KEY_WORD_SKIP_COMMENTS, OG_TRUE, { (char *)"skip_comment" } },
    { (uint32)KEY_WORD_SKIP_TRIGGERS, OG_TRUE, { (char *)"skip_triggers" } },
    { (uint32)KEY_WORD_SKIP_QUOTE_NAMES, OG_TRUE, { (char *)"skip_quote_names" } },
    { (uint32)KEY_WORD_SPACE, OG_TRUE, { (char *)"space" } },
    { (uint32)KEY_WORD_SPLIT, OG_TRUE, { (char *)"split" } },
    { (uint32)KEY_WORD_SPLIT_FACTOR, OG_TRUE, { (char *)"split_factor" } },
    { (uint32)KEY_WORD_SQL_MAP, OG_FALSE, { (char *)"sql_map" } },
    { (uint32)KEY_WORD_STANDARD, OG_TRUE, { (char *)"standard" } },
    { (uint32)KEY_WORD_STANDBY, OG_TRUE, { (char *)"standby" } },
    { (uint32)KEY_WORD_START, OG_FALSE, { (char *)"start" } },
    { (uint32)KEY_WORD_STARTUP, OG_TRUE, { (char *)"startup" } },
    { (uint32)KEY_WORD_STOP, OG_TRUE, { (char *)"stop" } },
    { (uint32)KEY_WORD_STORAGE, OG_TRUE, { (char *)"storage" } },
    { (uint32)KEY_WORD_SUBPARTITION, OG_TRUE, { (char *)"subpartition" } },
    { (uint32)KEY_WORD_SWAP, OG_TRUE, { (char *)"swap" } },
    { (uint32)KEY_WORD_SWITCH, OG_TRUE, { (char *)"switch" } },
    { (uint32)KEY_WORD_SWITCHOVER, OG_TRUE, { (char *)"switchover" } },
#ifdef DB_DEBUG_VERSION
    { (uint32)KEY_WORD_SYNCPOINT, OG_TRUE, { (char *)"syncpoint" } },
#endif
    { (uint32)KEY_WORD_SYNONYM, OG_FALSE, { (char *)"synonym" } },
    { (uint32)KEY_WORD_SYSAUX, OG_TRUE, { (char *)"sysaux" } },
    { (uint32)KEY_WORD_SYSTEM, OG_TRUE, { (char *)"system" } },
    { (uint32)KEY_WORD_TABLE, OG_FALSE, { (char *)"table" } },
    { (uint32)KEY_WORD_TABLES, OG_TRUE, { (char *)"tables" } },
    { (uint32)KEY_WORD_TABLESPACE, OG_TRUE, { (char *)"tablespace" } },
    { (uint32)KEY_WORD_TAG, OG_TRUE, { (char *)"tag" } },
    { (uint32)KEY_WORD_TEMP, OG_TRUE, { (char *)"temp" } },
    { (uint32)KEY_WORD_TEMPFILE, OG_TRUE, { (char *)"tempfile" } },
    { (uint32)KEY_WORD_TEMPORARY, OG_TRUE, { (char *)"temporary" } },
    { (uint32)KEY_WORD_TENANT, OG_TRUE, { (char *)"tenant" } },
    { (uint32)KEY_WORD_THAN, OG_TRUE, { (char *)"than" } },
    { (uint32)KEY_WORD_THEN, OG_FALSE, { (char *)"then" } },
    { (uint32)KEY_WORD_THREAD, OG_TRUE, { (char *)"thread" } },
    { (uint32)KEY_WORD_TIMEOUT, OG_TRUE, { (char *)"timeout" } },
    { (uint32)KEY_WORD_TIMEZONE, OG_TRUE, { (char *)"time_zone" } },
    { (uint32)KEY_WORD_TO, OG_FALSE, { (char *)"to" } },
    { (uint32)KEY_WORD_TRAILING, OG_TRUE, { (char *)"trailing" } }, /* for TRIM expression only */
    { (uint32)KEY_WORD_TRANSACTION, OG_TRUE, { (char *)"transaction" } },
    { (uint32)KEY_WORD_TRIGGER, OG_FALSE, { (char *)"trigger" } },
    { (uint32)KEY_WORD_TRUNCATE, OG_TRUE, { (char *)"truncate" } },
    { (uint32)KEY_WORD_TYPE, OG_TRUE, { (char *)"type" } },
    { (uint32)KEY_WORD_UNDO, OG_TRUE, { (char *)"undo" } },
    { (uint32)KEY_WORD_UNIFORM, OG_TRUE, { (char *)"uniform" } },
    { (uint32)KEY_WORD_UNION, OG_FALSE, { (char *)"union" } },
    { (uint32)KEY_WORD_UNIQUE, OG_TRUE, { (char *)"unique" } },
    { (uint32)KEY_WORD_UNLIMITED, OG_TRUE, { (char *)"unlimited" } },
    { (uint32)KEY_WORD_UNLOCK, OG_TRUE, { (char *)"unlock" } },
    { (uint32)KEY_WORD_UNPIVOT, OG_TRUE, { (char *)"unpivot" } },
    { (uint32)KEY_WORD_UNTIL, OG_TRUE, { (char *)"until" } },
    { (uint32)KEY_WORD_UNUSABLE, OG_TRUE, { (char *)"unusable" } },
    { (uint32)KEY_WORD_UPDATE, OG_FALSE, { (char *)"update" } },
    { (uint32)KEY_WORD_USER, OG_FALSE, { (char *)"user" } },
    { (uint32)KEY_WORD_USERS, OG_TRUE, { (char *)"users" } },
    { (uint32)KEY_WORD_USING, OG_TRUE, { (char *)"using" } },
    { (uint32)KEY_WORD_VALIDATE, OG_TRUE, { (char *)"validate" } },
    { (uint32)KEY_WORD_VALUES, OG_FALSE, { (char *)"values" } },
    { (uint32)KEY_WORD_VIEW, OG_FALSE, { (char *)"view" } },
    { (uint32)KEY_WORD_WAIT, OG_TRUE, { (char *)"wait" } },
    { (uint32)KEY_WORD_WHEN, OG_TRUE, { (char *)"when" } },
    { (uint32)KEY_WORD_WHERE, OG_FALSE, { (char *)"where" } },
    { (uint32)KEY_WORD_WHILE, OG_FALSE, { (char *)"while" } },
    { (uint32)KEY_WORD_WITH, OG_FALSE, { (char *)"with" } },
};

#ifdef WIN32
static_assert(sizeof(g_key_words) / sizeof(key_word_t) == KEY_WORD_DUMB_END - KEY_WORD_0_UNKNOWN - 1,
              "Array g_key_words defined error");
#endif

/* datatype key words */
static datatype_word_t g_datatype_words[] = {
    { { (char *)"bigint" }, DTYP_BIGINT, OG_TRUE, OG_TRUE },
    { { (char *)"binary" }, DTYP_BINARY, OG_TRUE, OG_FALSE },
    { { (char *)"binary_bigint" }, DTYP_BINARY_BIGINT, OG_TRUE, OG_TRUE },
    { { (char *)"binary_double" }, DTYP_BINARY_DOUBLE, OG_TRUE, OG_FALSE },
    { { (char *)"binary_float" }, DTYP_BINARY_FLOAT, OG_TRUE, OG_FALSE },
    { { (char *)"binary_integer" }, DTYP_BINARY_INTEGER, OG_TRUE, OG_TRUE },
    { { (char *)"binary_uint32" }, DTYP_UINTEGER, OG_TRUE, OG_FALSE },
    { { (char *)"blob" }, DTYP_BLOB, OG_TRUE, OG_FALSE },
    { { (char *)"bool" }, DTYP_BOOLEAN, OG_TRUE, OG_FALSE },
    { { (char *)"boolean" }, DTYP_BOOLEAN, OG_TRUE, OG_FALSE },
    { { (char *)"bpchar" }, DTYP_CHAR, OG_TRUE, OG_FALSE },
    { { (char *)"bytea" }, DTYP_BLOB, OG_TRUE, OG_FALSE },
    { { (char *)"char" }, DTYP_CHAR, OG_FALSE, OG_FALSE },
    { { (char *)"character" }, DTYP_CHAR, OG_TRUE, OG_FALSE },
    { { (char *)"clob" }, DTYP_CLOB, OG_TRUE, OG_FALSE },
    { { (char *)"date" }, DTYP_DATE, OG_FALSE, OG_FALSE },
    { { (char *)"datetime" }, DTYP_DATE, OG_TRUE, OG_FALSE },
    { { (char *)"decimal" }, DTYP_DECIMAL, OG_FALSE, OG_FALSE },
    { { (char *)"double" }, DTYP_DOUBLE, OG_TRUE, OG_FALSE },
    { { (char *)"float" }, DTYP_FLOAT, OG_TRUE, OG_FALSE },
    { { (char *)"image" }, DTYP_IMAGE, OG_TRUE, OG_FALSE },
    { { (char *)"int" }, DTYP_INTEGER, OG_TRUE, OG_TRUE },
    { { (char *)"integer" }, DTYP_INTEGER, OG_FALSE, OG_TRUE },
    { { (char *)"interval" }, DTYP_INTERVAL, OG_TRUE, OG_FALSE },
    { { (char *)"jsonb" }, DTYP_JSONB, OG_TRUE, OG_FALSE },
    { { (char *)"long" }, DTYP_CLOB, OG_TRUE, OG_FALSE },
    { { (char *)"longblob" }, DTYP_IMAGE, OG_TRUE, OG_FALSE },
    { { (char *)"longtext" }, DTYP_CLOB, OG_TRUE, OG_FALSE },
    { { (char *)"mediumblob" }, DTYP_IMAGE, OG_TRUE, OG_FALSE },
    { { (char *)"nchar" }, DTYP_NCHAR, OG_TRUE, OG_FALSE },
    { { (char *)"number" }, DTYP_NUMBER, OG_FALSE, OG_FALSE },
    { { (char *)"number2" }, DTYP_NUMBER2, OG_TRUE, OG_FALSE },
    { { (char *)"numeric" }, DTYP_DECIMAL, OG_TRUE, OG_FALSE },
    { { (char *)"nvarchar" }, DTYP_NVARCHAR, OG_TRUE, OG_FALSE },
    { { (char *)"nvarchar2" }, DTYP_NVARCHAR, OG_TRUE, OG_FALSE },
    { { (char *)"raw" }, DTYP_RAW, OG_FALSE, OG_FALSE },
    { { (char *)"real" }, DTYP_DOUBLE, OG_TRUE, OG_FALSE },
    { { (char *)"serial" }, DTYP_SERIAL, OG_TRUE, OG_FALSE },
    { { (char *)"short" }, DTYP_SMALLINT, OG_TRUE, OG_TRUE },
    { { (char *)"smallint" }, DTYP_SMALLINT, OG_TRUE, OG_TRUE },
    { { (char *)"text" }, DTYP_CLOB, OG_TRUE, OG_FALSE },
    { { (char *)"timestamp" }, DTYP_TIMESTAMP, OG_TRUE, OG_FALSE },
    { { (char *)"tinyint" }, DTYP_TINYINT, OG_TRUE, OG_TRUE },
    { { (char *)"ubigint" }, DTYP_UBIGINT, OG_TRUE, OG_FALSE },
    { { (char *)"uint" }, DTYP_UINTEGER, OG_TRUE, OG_FALSE },
    { { (char *)"uinteger" }, DTYP_UINTEGER, OG_TRUE, OG_FALSE },
    { { (char *)"ushort" }, DTYP_USMALLINT, OG_TRUE, OG_FALSE },
    { { (char *)"usmallint" }, DTYP_USMALLINT, OG_TRUE, OG_FALSE },
    { { (char *)"utinyint" }, DTYP_UTINYINT, OG_TRUE, OG_FALSE },
    { { (char *)"varbinary" }, DTYP_VARBINARY, OG_TRUE, OG_FALSE },
    { { (char *)"varchar" }, DTYP_VARCHAR, OG_FALSE, OG_FALSE },
    { { (char *)"varchar2" }, DTYP_VARCHAR, OG_FALSE, OG_FALSE },
};

/* reserved keywords
 * **Note:** the reserved keywords must be arrange in alphabetically
 * ascending order for speeding the search process. */
static key_word_t g_reserved_words[] = {
    { (uint32)RES_WORD_COLUMN_VALUE,       OG_TRUE,  { (char *)"column_value" } },
    { (uint32)RES_WORD_CONNECT_BY_ISCYCLE, OG_TRUE,  { (char *)"connect_by_iscycle" } },
    { (uint32)RES_WORD_CONNECT_BY_ISLEAF,  OG_TRUE,  { (char *)"connect_by_isleaf" } },
    { (uint32)RES_WORD_CURDATE,            OG_TRUE,  { (char *)"curdate" } },
    { (uint32)RES_WORD_CURDATE,            OG_TRUE,  { (char *)"current_date" } },
    { (uint32)RES_WORD_CURTIMESTAMP,       OG_TRUE,  { (char *)"current_timestamp" } },
    { (uint32)RES_WORD_DATABASETZ,         OG_TRUE,  { (char *)"dbtimezone" } },
    { (uint32)RES_WORD_DEFAULT,            OG_FALSE, { (char *)"default" } },
    { (uint32)RES_WORD_DELETING,           OG_TRUE,  { (char *)"deleting" } },
    { (uint32)RES_WORD_FALSE,              OG_FALSE, { (char *)"false" } },
    { (uint32)RES_WORD_INSERTING,          OG_TRUE,  { (char *)"inserting" } },
    { (uint32)RES_WORD_LEVEL,              OG_FALSE, { (char *)"level" } },
    { (uint32)RES_WORD_LOCALTIMESTAMP,     OG_TRUE,  { (char *)"localtimestamp" } },
    { (uint32)RES_WORD_SYSTIMESTAMP,       OG_TRUE,  { (char *)"now" } },
    { (uint32)RES_WORD_NULL,               OG_FALSE, { (char *)"null" } },
    { (uint32)RES_WORD_ROWID,              OG_FALSE, { (char *)"rowid" } },
    { (uint32)RES_WORD_ROWNODEID,          OG_FALSE, { (char *)"rownodeid" } },
    { (uint32)RES_WORD_ROWNUM,             OG_FALSE, { (char *)"rownum" } },
    { (uint32)RES_WORD_ROWSCN,             OG_FALSE, { (char *)"rowscn" } },
    { (uint32)RES_WORD_SESSIONTZ,          OG_TRUE,  { (char *)"sessiontimezone" } },
    { (uint32)RES_WORD_SYSDATE,            OG_FALSE, { (char *)"sysdate" } },
    { (uint32)RES_WORD_SYSTIMESTAMP,       OG_TRUE,  { (char *)"systimestamp" } },
    { (uint32)RES_WORD_TRUE,               OG_FALSE, { (char *)"true" } },
    { (uint32)RES_WORD_UPDATING,           OG_TRUE,  { (char *)"updating" } },
    { (uint32)RES_WORD_USER,               OG_FALSE, { (char *)"user" } },
    { (uint32)RES_WORD_UTCTIMESTAMP,       OG_TRUE,  { (char *)"utc_timestamp" } },
};

static key_word_t g_datetime_unit_words[] = {
    { (uint32)IU_DAY,         OG_TRUE, { "DAY", 3 } },
    { (uint32)IU_HOUR,        OG_TRUE, { "HOUR", 4 } },
    { (uint32)IU_MICROSECOND, OG_TRUE, { "MICROSECOND", 11 } },
    { (uint32)IU_MINUTE,      OG_TRUE, { "MINUTE", 6 } },
    { (uint32)IU_MONTH,       OG_TRUE, { "MONTH", 5 } },
    { (uint32)IU_QUARTER,     OG_TRUE, { "QUARTER", 7 } },
    { (uint32)IU_SECOND,      OG_TRUE, { "SECOND", 6 } },
    { (uint32)IU_DAY,         OG_TRUE, { "SQL_TSI_DAY", 11 } },
    { (uint32)IU_MICROSECOND, OG_TRUE, { "SQL_TSI_FRAC_SECOND", 19 } },
    { (uint32)IU_HOUR,        OG_TRUE, { "SQL_TSI_HOUR", 12 } },
    { (uint32)IU_MINUTE,      OG_TRUE, { "SQL_TSI_MINUTE", 14 } },
    { (uint32)IU_MONTH,       OG_TRUE, { "SQL_TSI_MONTH", 13 } },
    { (uint32)IU_QUARTER,     OG_TRUE, { "SQL_TSI_QUARTER", 15 } },
    { (uint32)IU_SECOND,      OG_TRUE, { "SQL_TSI_SECOND", 14 } },
    { (uint32)IU_WEEK,        OG_TRUE, { "SQL_TSI_WEEK", 12 } },
    { (uint32)IU_YEAR,        OG_TRUE, { "SQL_TSI_YEAR", 12 } },
    { (uint32)IU_WEEK,        OG_TRUE, { "WEEK", 4 } },
    { (uint32)IU_YEAR,        OG_TRUE, { "YEAR", 4 } },
};

static key_word_t g_hint_key_words[] = {
    { (uint32)ID_HINT_CB_MTRL,          OG_FALSE, { (char *)"cb_mtrl", 7 } },
    { (uint32)ID_HINT_DB_VERSION,       OG_FALSE, { (char *)"db_version", 10 } },
    { (uint32)ID_HINT_FULL,             OG_FALSE, { (char *)"full", 4 } },
    { (uint32)ID_HINT_HASH_AJ,          OG_FALSE, { (char *)"hash_aj", 7 } },
    { (uint32)ID_HINT_HASH_BUCKET_SIZE, OG_FALSE, { (char *)"hash_bucket_size", 16 } },
    { (uint32)ID_HINT_HASH_SJ,          OG_FALSE, { (char *)"hash_sj", 7 } },
    { (uint32)ID_HINT_HASH_TABLE,       OG_FALSE, { (char *)"hash_table", 10 } },
    { (uint32)ID_HINT_INDEX,            OG_FALSE, { (char *)"index", 5 } },
    { (uint32)ID_HINT_INDEX_ASC,        OG_FALSE, { (char *)"index_asc", 9 } },
    { (uint32)ID_HINT_INDEX_DESC,       OG_FALSE, { (char *)"index_desc", 10 } },
    { (uint32)ID_HINT_INDEX_FFS,        OG_FALSE, { (char *)"index_ffs", 9 } },
    { (uint32)ID_HINT_INDEX_SS,         OG_FALSE, { (char *)"index_ss", 8 } },
    { (uint32)ID_HINT_INLINE,           OG_FALSE, { (char *)"inline", 6 } },
    { (uint32)ID_HINT_LEADING,          OG_FALSE, { (char *)"leading", 7 } },
    { (uint32)ID_HINT_MATERIALIZE,      OG_FALSE, { (char *)"materialize", 11 } },
    { (uint32)ID_HINT_NL_BATCH,         OG_FALSE, { (char *)"nl_batch", 8 } },
    { (uint32)ID_HINT_NL_FULL_MTRL,     OG_FALSE, { (char *)"nl_full_mtrl", 12 } },
    { (uint32)ID_HINT_NL_FULL_OPT,      OG_FALSE, { (char *)"nl_full_opt", 11 } },
    { (uint32)ID_HINT_NO_CB_MTRL,       OG_FALSE, { (char *)"no_cb_mtrl", 10 } },
    { (uint32)ID_HINT_NO_HASH_TABLE,    OG_FALSE, { (char *)"no_hash_table", 13 } },
    { (uint32)ID_HINT_NO_INDEX,         OG_FALSE, { (char *)"no_index", 8 } },
    { (uint32)ID_HINT_NO_INDEX_FFS,     OG_FALSE, { (char *)"no_index_ffs", 12 } },
    { (uint32)ID_HINT_NO_INDEX_SS,      OG_FALSE, { (char *)"no_index_ss", 11 } },
    { (uint32)ID_HINT_NO_OR_EXPAND,     OG_FALSE, { (char *)"no_or_expand", 12 } },
    { (uint32)ID_HINT_NO_PUSH_PRED,     OG_FALSE, { (char *)"no_push_pred", 12 } },
    { (uint32)ID_HINT_NO_UNNEST,        OG_FALSE, { (char *)"no_unnest", 9 } },
    { (uint32)ID_HINT_OPTIM_MODE,       OG_FALSE, { (char *)"optimizer_mode", 14 } },
    { (uint32)ID_HINT_OPT_ESTIMATE,     OG_FALSE, { (char *)"opt_estimate", 12 } },
    { (uint32)ID_HINT_OPT_PARAM,        OG_FALSE, { (char *)"opt_param", 9 } },
    { (uint32)ID_HINT_ORDERED,          OG_FALSE, { (char *)"ordered", 7 } },
    { (uint32)ID_HINT_OR_EXPAND,        OG_FALSE, { (char *)"or_expand", 9 } },
    { (uint32)ID_HINT_FEATURES_ENABLE,  OG_FALSE, { (char *)"outline_features_enable", 23 } },
    { (uint32)ID_HINT_PARALLEL,         OG_FALSE, { (char *)"parallel", 8 } },
    { (uint32)ID_HINT_RULE,             OG_FALSE, { (char *)"rule", 4 } },
    { (uint32)ID_HINT_SEMI_TO_INNER,    OG_FALSE, { (char *)"semi_to_inner", 13 } },
#ifdef OG_RAC_ING
    { (uint32)ID_HINT_SHD_READ_MASTER,  OG_FALSE, { (char *)"shd_read_master", 15 } },
    { (uint32)ID_HINT_SQL_WHITELIST,    OG_FALSE, { (char *)"sql_whitelist", 13 } },
#endif
    { (uint32)ID_HINT_THROW_DUPLICATE,  OG_FALSE, { (char *)"throw_duplicate", 15 } },
    { (uint32)ID_HINT_UNNEST,           OG_FALSE, { (char *)"unnest", 6 } },
    { (uint32)ID_HINT_USE_CONCAT,       OG_FALSE, { (char *)"use_concat", 10 } },
    { (uint32)ID_HINT_USE_HASH,         OG_FALSE, { (char *)"use_hash", 8 } },
    { (uint32)ID_HINT_USE_MERGE,        OG_FALSE, { (char *)"use_merge", 9 } },
    { (uint32)ID_HINT_USE_NL,           OG_FALSE, { (char *)"use_nl", 6 } },
};

const key_word_t g_method_key_words[] = {
    {(uint32)METHOD_COUNT,  OG_TRUE, { (char *)"COUNT",  5 } },
    {(uint32)METHOD_DELETE, OG_TRUE, { (char *)"DELETE", 6 } },
    {(uint32)METHOD_EXISTS, OG_TRUE, { (char *)"EXISTS", 6 } },
    {(uint32)METHOD_EXTEND, OG_TRUE, { (char *)"EXTEND", 6 } },
    {(uint32)METHOD_FIRST,  OG_TRUE, { (char *)"FIRST",  5 } },
    {(uint32)METHOD_LAST,   OG_TRUE, { (char *)"LAST",   4 } },
    {(uint32)METHOD_LIMIT,  OG_TRUE, { (char *)"LIMIT",  5 } },
    {(uint32)METHOD_NEXT,   OG_TRUE, { (char *)"NEXT",   4 } },
    {(uint32)METHOD_PRIOR,  OG_TRUE, { (char *)"PRIOR",  5 } },
    {(uint32)METHOD_TRIM,   OG_TRUE, { (char *)"TRIM",   4 } }
};

const key_word_t g_pl_attr_words[] = {
    { (uint32)PL_ATTR_WORD_FOUND,     OG_TRUE, { (char *)"FOUND",    5 } },
    { (uint32)PL_ATTR_WORD_ISOPEN,    OG_TRUE, { (char *)"ISOPEN",   6 } },
    { (uint32)PL_ATTR_WORD_NOTFOUND,  OG_TRUE, { (char *)"NOTFOUND", 8 } },
    { (uint32)PL_ATTR_WORD_ROWCOUNT,  OG_TRUE, { (char *)"ROWCOUNT", 8 } },
    { (uint32)PL_ATTR_WORD_ROWTYPE,   OG_TRUE, { (char *)"ROWTYPE",  7 } },
    { (uint32)PL_ATTR_WORD_TYPE,      OG_TRUE, { (char *)"TYPE",     4 } },
};

#define RESERVED_WORDS_COUNT (sizeof(g_reserved_words) / sizeof(key_word_t))
#define KEY_WORDS_COUNT      (sizeof(g_key_words) / sizeof(key_word_t))
#define DATATYPE_WORDS_COUNT (ELEMENT_COUNT(g_datatype_words))
#define HINT_KEY_WORDS_COUNT (sizeof(g_hint_key_words) / sizeof(key_word_t))

bool32 lex_match_subset(key_word_t *word_set, int32 count, word_t *word)
{
    int32 begin_pos;
    int32 end_pos;
    int32 mid_pos;
    int32 cmp_result;
    key_word_t *cmp_word = NULL;

    begin_pos = 0;
    end_pos = count - 1;

    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        cmp_word = &word_set[mid_pos];

        cmp_result = cm_compare_text_ins((text_t *)&word->text, &cmp_word->text);
        if (cmp_result == 0) {
            word->namable = (uint32)cmp_word->namable;
            word->id = (uint32)cmp_word->id;
            return OG_TRUE;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    return OG_FALSE;
}

bool32 lex_match_datetime_unit(word_t *word)
{
    return lex_match_subset(g_datetime_unit_words, ELEMENT_COUNT(g_datetime_unit_words), word);
}

const datatype_word_t *lex_match_datatype_words(const datatype_word_t *word_set, int32 count, word_t *word)
{
    int32 begin_pos;
    int32 end_pos;
    int32 mid_pos;
    int32 cmp_result;
    const datatype_word_t *cmp_word = NULL;

    begin_pos = 0;
    end_pos = count - 1;

    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        cmp_word = &word_set[mid_pos];

        cmp_result = cm_compare_text_ins((text_t *)&word->text, &cmp_word->text);
        if (cmp_result == 0) {
            return cmp_word;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    return NULL;
}

bool32 lex_check_datatype(struct st_lex *lex, word_t *typword)
{
    return lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, typword) != NULL;
}

static inline status_t lex_match_if_unsigned_type(struct st_lex *lex, word_t *word, uint32 unsigned_type)
{
    uint32 signed_flag;
    if (lex_try_fetch_1of2(lex, "SIGNED", "UNSIGNED", &signed_flag) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (signed_flag == 1) {
        word->id = unsigned_type;
    }
    return OG_SUCCESS;
}

static inline status_t lex_match_datatype(struct st_lex *lex, word_t *word)
{
    bool32 result = OG_FALSE;
    /* special handling PG's datatype:
     * + character varying
     * + double precision */
    switch (word->id) {
        case DTYP_CHAR:
            if (lex_try_fetch(lex, "varying", &result) != OG_SUCCESS) {
                return OG_ERROR;
            }
            if (result) {  // if `varying` is found, then the datatype is `VARCHAR`
                word->id = DTYP_VARCHAR;
            }
            break;
        case DTYP_DOUBLE:
            return lex_try_fetch(lex, "precision", &result);

        case DTYP_TINYINT:
            return lex_match_if_unsigned_type(lex, word, DTYP_UTINYINT);

        case DTYP_SMALLINT:
            return lex_match_if_unsigned_type(lex, word, DTYP_USMALLINT);

        case DTYP_BIGINT:
            return lex_match_if_unsigned_type(lex, word, DTYP_UBIGINT);

        case DTYP_INTEGER:
            return lex_match_if_unsigned_type(lex, word, DTYP_UINTEGER);

        case DTYP_BINARY_INTEGER:
            return lex_match_if_unsigned_type(lex, word, DTYP_BINARY_UINTEGER);

        case DTYP_BINARY_BIGINT:
            return lex_match_if_unsigned_type(lex, word, DTYP_BINARY_UBIGINT);

        default:
            // DO NOTHING
            break;
    }
    return OG_SUCCESS;
}

status_t lex_try_match_datatype(struct st_lex *lex, word_t *word, bool32 *matched)
{
    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);

    if (dt_word == NULL) {
        if (SECUREC_UNLIKELY(lex->key_word_count != 0)) {  // match external key words only
            if (!lex_match_subset((key_word_t *)lex->key_words, (int32)lex->key_word_count, word)) {
                *matched = OG_FALSE;
                return OG_SUCCESS;
            }
        } else {
            *matched = OG_FALSE;
            return OG_SUCCESS;
        }
    } else {
        word->id = (uint32)dt_word->id;
    }

    word->type = WORD_TYPE_DATATYPE;
    if (lex_match_datatype(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    *matched = OG_TRUE;
    return OG_SUCCESS;
}

status_t lex_match_keyword(struct st_lex *lex, word_t *word)
{
    lex->ext_flags = 0;
    if (SECUREC_UNLIKELY(lex->key_word_count != 0)) {  // match external key words only
        if (lex_match_subset((key_word_t *)lex->key_words, (int32)lex->key_word_count, word)) {
            word->type = WORD_TYPE_KEYWORD;
            lex->ext_flags = LEX_SINGLE_WORD | LEX_WITH_OWNER;
            return OG_SUCCESS;
        }
    }

    if (lex_match_subset((key_word_t *)g_reserved_words, RESERVED_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_RESERVED;
        return OG_SUCCESS;
    }

    if (lex_match_subset((key_word_t *)g_key_words, KEY_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_KEYWORD;
        if (word->id == KEY_WORD_PRIOR) {
            word->type = WORD_TYPE_OPERATOR;
            word->id = OPER_TYPE_PRIOR;
        }
        return OG_SUCCESS;
    }

    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);
    if (dt_word != NULL) {
        word->type = WORD_TYPE_DATATYPE;
        word->id = (uint32)dt_word->id;
        word->namable = dt_word->namable;
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

status_t lex_match_hint_keyword(struct st_lex *lex, word_t *word)
{
    if (lex_match_subset((key_word_t *)g_hint_key_words, HINT_KEY_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_HINT_KEYWORD;
    }

    return OG_SUCCESS;
}

void lex_init_keywords(void)
{
    uint32 i;

    for (i = 0; i < KEY_WORDS_COUNT; i++) {
        g_key_words[i].text.len = (uint32)strlen(g_key_words[i].text.str);
    }

    for (i = 0; i < RESERVED_WORDS_COUNT; i++) {
        g_reserved_words[i].text.len = (uint32)strlen(g_reserved_words[i].text.str);
    }

    for (i = 0; i < DATATYPE_WORDS_COUNT; i++) {
        g_datatype_words[i].text.len = (uint32)strlen(g_datatype_words[i].text.str);
    }

    for (i = 0; i < HINT_KEY_WORDS_COUNT; i++) {
        g_hint_key_words[i].text.len = (uint32)strlen(g_hint_key_words[i].text.str);
    }
}

status_t lex_get_word_typmode(word_t *word, typmode_t *typmod)
{
    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);
    if (dt_word == NULL) {
        return OG_ERROR;
    }

    switch (dt_word->id) {
        case DTYP_UINTEGER:
        case DTYP_BINARY_UINTEGER:
            typmod->datatype = OG_TYPE_UINT32;
            typmod->size = sizeof(uint32);
            break;
        case DTYP_SMALLINT:
        case DTYP_USMALLINT:
        case DTYP_TINYINT:
        case DTYP_UTINYINT:
        case DTYP_INTEGER:
        case DTYP_BINARY_INTEGER:
            typmod->datatype = OG_TYPE_INTEGER;
            typmod->size = sizeof(int32);
            break;

        case DTYP_BIGINT:
        case DTYP_SERIAL:
        case DTYP_BINARY_BIGINT:
            typmod->datatype = OG_TYPE_BIGINT;
            typmod->size = sizeof(int64);
            break;

        case DTYP_DOUBLE:
        case DTYP_BINARY_DOUBLE:
        case DTYP_FLOAT:
        case DTYP_BINARY_FLOAT:
            typmod->datatype = OG_TYPE_REAL;
            typmod->size = sizeof(double);
            typmod->precision = OG_UNSPECIFIED_REAL_PREC;
            typmod->scale = OG_UNSPECIFIED_REAL_SCALE;
            break;

        default:
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

bool32 lex_match_coll_method_name(sql_text_t *method_name, uint8 *method_id)
{
    if (method_name == NULL) {
        *method_id = METHOD_END;
        return OG_FALSE;
    }

    word_t word;
    word.text = *method_name;
    if (lex_match_subset((key_word_t *)g_method_key_words, METHOD_KEY_WORDS_COUNT, &word)) {
        *method_id = (uint8)word.id;
        return OG_TRUE;
    } else {
        *method_id = METHOD_END;
        return OG_FALSE;
    }
}


#ifdef __cplusplus
}
#endif
