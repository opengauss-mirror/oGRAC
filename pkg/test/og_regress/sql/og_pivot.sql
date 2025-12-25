drop table if exists tab_pivot;
create table tab_pivot(c_id int, c_pay number(12,3));

insert into tab_pivot values(19, .137458);
insert into tab_pivot values(1, null);
insert into tab_pivot values(8, .137458);
insert into tab_pivot values(8, .137458);
insert into tab_pivot values(24, .137458);
insert into tab_pivot values(44, .137458);
commit;

SELECT * FROM tab_pivot
PIVOT(COUNT(DISTINCT c_pay) as AGGR_0 FOR (c_id) IN ((8) AS PEXPR_0));

CREATE TABLE T1(TID VARCHAR(100 BYTE) NOT NULL,TNAME VARCHAR(256 BYTE),"PROCESSDEFKEY" VARCHAR(256 BYTE),ENDTIME DATE,EXECSEQUENCENUM NUMBER,OUTPUT CHAR(1 BYTE),FORMURL VARCHAR(512 BYTE));

INSERT INTO T1 VALUES('105#','tiantiankaixin','TD_211','2020-07-14 02:02:22',2,'1','/flag');

SELECT *
FROM T1
PIVOT (
  MAX(CAST('2020-02-24 12:18:22' AS TIMESTAMP WITH TIME ZONE)) AS A0,
  LISTAGG(DISTINCT CAST(NULL AS TIMESTAMP))
    WITHIN GROUP(ORDER BY T1.ENDTIME DESC NULLS FIRST) AS A1
  FOR (EXECSEQUENCENUM, OUTPUT)
  IN ((5, '0') AS PEXPR_0)
);