alter system set SLOWSQL_LOG_MODE=ON;
alter system set SQL_STAGE_THRESHOLD=5;
alter system set SLOWSQL_STATS_ENABLE=TRUE;
show parameter SLOWSQL_LOG_MODE;
show parameter SQL_STAGE_THRESHOLD;
show parameter SLOWSQL_STATS_ENABLE;