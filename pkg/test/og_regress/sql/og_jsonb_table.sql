-- The code of JSONB_TABLE is almost depended on JSON_TABLE.
-- The main process is not changed, so when someone find a bug in JSONB_TABLE, it maybe occurs in JSON_TABLE very possiblely.
SELECT * FROM JSON_TABLE('{"a":100, "b":200}', '$' COLUMNS (a  PATH '$.a' , b PATH '$.b', c EXISTS PATH '$.a'));
SELECT * FROM JSON_TABLE('{"a":100, "b":200, "c":[true, false]}', '$' COLUMNS (a  PATH '$.a' , b PATH '$.b', c PATH '$.c[*]'));
SELECT * FROM JSON_TABLE('{"list":[{"a":100, "b":200}, {"a":300, "b":400}]}', '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) order by a;
SELECT * FROM JSON_TABLE('{"list":[{"a":100, "b":200}, {"a":300, "b":400}, {"a":500, "b":600}]}', '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) order by a;
SELECT * FROM JSON_TABLE('[1, {"start":{"list":[{"a":100, "b":200}, {"a":300, "b":400}, {"a":500, "b":600}]}}]', '$[1].start.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) order by a;

drop table if exists jsonb_tbl_test;
create table jsonb_tbl_test (a jsonb, b int);
insert into jsonb_tbl_test values('{"a":100, "b":200}', 1);
insert into jsonb_tbl_test values('{"a":100, "b":200, "c":[true, false]}', 2);
insert into jsonb_tbl_test values('{"list":[{"a":100, "b":200}, {"a":300, "b":400}]}', 3);
insert into jsonb_tbl_test values('{"list":[{"a":100, "b":200}, {"a":300, "b":400}, {"a":500, "b":600}]}', 4);
insert into jsonb_tbl_test values('[1, {"start":{"list":[{"a":100, "b":200}, {"a":300, "b":400}, {"a":500, "b":600}]}}]', 5);
commit;
SELECT jbt.a, jbt.b, jbt.c FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$' COLUMNS (a  PATH '$.a' , b PATH '$.b', c EXISTS PATH '$.a')) jbt on t.b = 1;
SELECT jbt.a, jbt.b, jbt.c FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$' COLUMNS (a  PATH '$.a' , b PATH '$.b', c PATH '$.c[*]')) jbt on t.b = 2;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$.list' error on error COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on t.b = 3 order by jbt.a;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on t.b = 3 order by jbt.a;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on t.b = 4 order by jbt.a;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on (t.b = 3 or t.b = 4) order by jbt.a;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$[1].start.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on t.b = 5 order by jbt.a;
drop table if exists jsonb_tbl_test;

drop table if exists test_jsonb_table;
create table test_jsonb_table (f1 varchar(100), f2 jsonb);
insert into test_jsonb_table values(1, '[{"Phone" : [{"type" : "a", "number" : "909-555-7307"}, {"type" : "b", "number" : "415-555-1234"}]}, {"Phone" : [{"type" : "c", "number" : "909-555-7307"}, {"type" : "d", "number" : "415-555-1234"}]}]');
insert into test_jsonb_table values(2, '[{"Phone" : [{"type" : "e", "number" : "909-555-7307"}, {"type" : "f", "number" : "415-555-1234"}]}, {"Phone" : [{"type" : "g", "number" : "909-555-7307"}, {"type" : "h", "number" : "415-555-1234"}]}]');
insert into test_jsonb_table values(3, '[{"Phone" : [{"type" : "3", "number" : "909-555-7307"}, {"type" : "b", "number" : "415-555-1234"}]}, {"Phone" : [{"type" : "3", "number" : "909-555-7307"}, {"type" : "d", "number" : "415-555-1234"}]}]');
insert into test_jsonb_table values(4, '[{"Phone" : [{"type" : "4", "number" : "909-555-7307"}, {"type" : "4", "number" : "415-555-1234"}]}, {"Phone" : [{"type" : "g", "number" : "909-555-7307"}, {"type" : "h", "number" : "415-555-1234"}]}]');
commit;
select a.f1,b.* from test_jsonb_table a, jsonb_table(a.f2,'$[*].Phone[*]' error on error COLUMNS (type VARChAR2(100) PATH '$.type' )) b where a.f1(+) = b.type;
select a.f1,b.* from test_jsonb_table a, jsonb_table(a.f2,'$[*].Phone[*]' error on error COLUMNS (type VARChAR2(100) PATH '$.type' )) b;
drop table if exists test_jsonb_table;

-- JSON builtin columns (path / format json path / exists path) in json_table must resolve.
select * from json_table('[{"a":"a1","b":{"bb":"ds"},"c":"c3"},{"a":"a2","b":{"bb":"ds"},"c":"c6"}]', '$[*]' error on error columns (f1 varchar2(100) path '$.a', f2 varchar2(100) format json path '$.b', f3 varchar2(100) exists path '$.c', f4 for ordinality)) order by 1;

-- issue #362: a json_table that depends on a column of its join partner must not be planned as
-- the build(inner) side of a hash/merge join. grow the table so the plan flips to hash join.
drop table if exists t_jt362;
create table t_jt362(id int, c_int int, c_date datetime, c_json varchar(8000) check(c_json is json));
insert into t_jt362 values(1, 1, to_date('2009-10-11','YYYY-MM-DD'), '{"s1":"lili","n":"3","s2":{"k3":{"k4":[{"k5":"d1"},{"k6":{"k7":[{"k8":"d2"},{"k10":{"k11":{"k12":[{"k13":"d4"},{"k17":"d7"},2000,3000,{"k19":"d9"}]}}},20000,{"k20":"2009-10-11 00:00:00"}]}}]}}}');
insert into t_jt362 values(2, 2, to_date('2009-10-12','YYYY-MM-DD'), '{"s1":"lili","n":"3","s2":{"k3":{"k4":[{"k5":"d1"},{"k6":{"k7":[{"k8":"d2"},{"k10":{"k11":{"k12":[{"k13":"d4"},{"k17":"d7"},2000,3000,{"k19":"d9"}]}}},20000,{"k20":"2009-10-11 00:00:00"}]}}]}}}');
insert into t_jt362 values(3, 3, to_date('2009-10-13','YYYY-MM-DD'), '{"s1":"lili","n":"3","s2":{"k3":{"k4":[{"k5":"d1"},{"k6":{"k7":[{"k8":"d2"},{"k10":{"k11":{"k12":[{"k13":"d4"},{"k17":"d7"},2000,3000,{"k19":"d9"}]}}},20000,{"k20":"2009-10-11 00:00:00"}]}}]}}}');
insert into t_jt362 values(4, 4, to_date('2009-10-14','YYYY-MM-DD'), '{"s1":"lili","n":"3","s2":{"k3":{"k4":[{"k5":"d1"},{"k6":{"k7":[{"k8":"d2"},{"k10":{"k11":{"k12":[{"k13":"d4"},{"k17":"d7"},2000,3000,{"k19":"d9"}]}}},20000,{"k20":"2009-10-11 00:00:00"}]}}]}}}');
insert into t_jt362 values(5, 5, to_date('2009-10-15','YYYY-MM-DD'), '{"s1":"lili","n":"3","s2":{"k3":{"k4":[{"k5":"d1"},{"k6":{"k7":[{"k8":"d2"},{"k10":{"k11":{"k12":[{"k13":"d4"},{"k17":"d7"},2000,3000,{"k19":"d9"}]}}},20000,{"k20":"2009-10-11 00:00:00"}]}}]}}}');
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
insert into t_jt362 select * from t_jt362;
commit;
analyze table t_jt362 compute statistics;
select count(*) as cnt_date from t_jt362 t2,
  json_table(t2.c_json, '$' error on error columns(c14 varchar2(20) path '$.s2.k3.k4.k6.k7.k20')) t3
  where t2.c_date = t3.c14;
select count(*) as cnt_int from t_jt362 t2,
  json_table(t2.c_json, '$' error on error columns(c14 varchar2(20) path '$.n')) t3
  where t2.c_int = t3.c14;
select count(*) as cnt_control from t_jt362 t2,
  json_table('[{"a":3}]', '$[*]' columns(a varchar2(20) path '$.a')) t3
  where t2.c_int = t3.a;
drop table if exists t_jt362;
