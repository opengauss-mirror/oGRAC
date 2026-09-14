-- Test for IN2EXISTS optimization
DROP TABLE IF EXISTS IN2EXISTS_T1;
DROP TABLE IF EXISTS IN2EXISTS_T2;
CREATE TABLE IN2EXISTS_T1 (
    nullable INT NOT NULL,
    not_nullable INT
);

CREATE TABLE IN2EXISTS_T2 (
    nullable INT NOT NULL,
    not_nullable INT
);

EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE nullable IN (SELECT nullable FROM IN2EXISTS_T2 WHERE nullable > 1);
EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE not_nullable IN (SELECT not_nullable FROM IN2EXISTS_T2 where not_nullable > 1);
EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE nullable NOT IN (SELECT nullable FROM IN2EXISTS_T2 WHERE nullable > 1);
EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE not_nullable NOT IN (SELECT not_nullable FROM IN2EXISTS_T2 WHERE not_nullable > 1);

EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE nullable*10 + 1  IN (SELECT nullable FROM IN2EXISTS_T2 WHERE nullable > 1);
EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE nullable*10 + 1  NOT IN (SELECT nullable FROM IN2EXISTS_T2 WHERE nullable > 1);


EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE (nullable, not_nullable) IN (SELECT nullable, not_nullable FROM IN2EXISTS_T2 WHERE nullable > 1);
EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE (nullable, not_nullable) NOT IN (SELECT nullable, not_nullable FROM IN2EXISTS_T2 WHERE nullable > 1);

EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE IN2EXISTS_T1.ROWID IN (SELECT IN2EXISTS_T1.ROWID FROM IN2EXISTS_T2 WHERE nullable > 1);
EXPLAIN SELECT * FROM IN2EXISTS_T1 WHERE IN2EXISTS_T1.ROWID IN (SELECT IN2EXISTS_T2.ROWID FROM IN2EXISTS_T2 WHERE nullable > 1);

DROP TABLE IN2EXISTS_T1;
DROP TABLE IN2EXISTS_T2;

-- Test for EXISTS optimization
DROP TABLE IF EXISTS EXISTS_OPT_T1;
DROP TABLE IF EXISTS EXISTS_OPT_T2;
CREATE TABLE EXISTS_OPT_T1 (
    nullable INT NOT NULL,
    not_nullable INT
);

CREATE TABLE EXISTS_OPT_T2 (
    nullable INT NOT NULL,
    not_nullable INT
);

EXPLAIN SELECT * FROM EXISTS_OPT_T1 WHERE EXISTS (SELECT * from EXISTS_OPT_T2);

EXPLAIN SELECT * FROM EXISTS_OPT_T1 WHERE EXISTS (SELECT AVG(nullable) from EXISTS_OPT_T2);

EXPLAIN SELECT * FROM EXISTS_OPT_T1 WHERE EXISTS (SELECT DISTINCT nullable from EXISTS_OPT_T2 GROUP BY nullable ORDER BY nullable);

EXPLAIN SELECT * FROM EXISTS_OPT_T1 WHERE EXISTS (SELECT 1 from EXISTS_OPT_T2 START WITH EXISTS_OPT_T1.nullable = EXISTS_OPT_T2.nullable CONNECT BY PRIOR EXISTS_OPT_T2*10 = EXISTS_OPT_T2.not_nullable);

EXPLAIN SELECT * FROM EXISTS_OPT_T1 WHERE EXISTS (SELECT nullable, ROW_NUMBER() OVER (ORDER BY not_nullable DESC) AS col1 from EXISTS_OPT_T2);


-- test not in (select null) constraints
drop table if exists not_in_null_t1;
drop table if exists not_in_null_t2;

create table not_in_null_t1(c1 int, c2 int not null, constraint pk_not_in_null_t1 primary key(c1));
create table not_in_null_t2(c1 int, c2 int not null, c3 varchar(10) check(c3 is json), constraint pk_not_in_null_t2 primary key(c1));

insert into not_in_null_t1 values(1,1);
insert into not_in_null_t1 values(2,2);
insert into not_in_null_t1 values(3,4);
insert into not_in_null_t2 values(3,1,null);
insert into not_in_null_t2 values(4,2,null);
insert into not_in_null_t2 values(5,3,null);
commit;

explain plan for 
select * from not_in_null_t2 t1 left join not_in_null_t1 t2 on t1.c2=t2.c2 where t1.c1 not in (select null from not_in_null_t2 t3);
select * from not_in_null_t2 t1 left join not_in_null_t1 t2 on t1.c2=t2.c2 where t1.c1 not in (select null from not_in_null_t2 t3);

explain plan for 
select * from not_in_null_t1 t1 
where t1.c1 not in (
    select t3.c1 from not_in_null_t1 t2 left join not_in_null_t2 t3 on t2.c2 = t3.c2
);
select * from not_in_null_t1 t1 
where t1.c1 not in (
    select t3.c1 from not_in_null_t1 t2 left join not_in_null_t2 t3 on t2.c2 = t3.c2
);

explain plan for 
select * from not_in_null_t1 t1 
where t1.c1 not in (
    select nullif(t2.c1, 1) from not_in_null_t1 t2 left join not_in_null_t2 t3 on t2.c2 = t3.c2
);
select * from not_in_null_t1 t1 
where t1.c1 not in (
    select nullif(t2.c1, 1) from not_in_null_t1 t2 left join not_in_null_t2 t3 on t2.c2 = t3.c2
);

explain plan for 
select * from not_in_null_t1 t1 
where t1.c1 not in (
    select sleep(1) from not_in_null_t1 t2 left join not_in_null_t2 t3 on t2.c2 = t3.c2
);
select * from not_in_null_t1 t1 
where t1.c1 not in (
    select sleep(1) from not_in_null_t1 t2 left join not_in_null_t2 t3 on t2.c2 = t3.c2
);

-- set autotrace on;
SELECT * 
FROM not_in_null_t1 t1 
WHERE t1.c1 NOT IN (
    SELECT t2.c3 
    FROM not_in_null_t2 t2
);

SELECT * 
FROM not_in_null_t1 t1 
WHERE t1.c1 NOT IN (
    SELECT (CASE WHEN t2.c1 < 1000 THEN 1 ELSE NULL END) 
    FROM not_in_null_t2 t2
);

SELECT * 
FROM not_in_null_t1 t1 
WHERE t1.c1 NOT IN (
    SELECT SUM(null) OVER (PARTITION BY 1) 
    FROM not_in_null_t2 t2
);
-- set autotrace off;


drop table if exists not_in_null_t1;
drop table if exists not_in_null_t2;

-- Nested quantified membership on an unindexed table.
DROP TABLE IF EXISTS urn;
CREATE TABLE urn (n NUMBER);
BEGIN FOR p IN 1..1000 LOOP INSERT INTO urn VALUES (p); END LOOP; END;
/
COMMIT;
SELECT COUNT(*) FROM urn
WHERE n <> ALL (SELECT n FROM urn WHERE n IN (SELECT n FROM urn));
DROP TABLE urn;
