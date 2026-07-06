drop table if exists zsharding_tbl;
create table zsharding_tbl(
c_id int, c_int int, c_integer integer, c_bool int, c_boolean int, c_bigint integer,
c_real real, c_double real,
c_decimal decimal(38), c_number number(38), c_numeric numeric(38),
c_char char(50) default null, c_varchar varchar(20), c_varchar2 varchar2(4000),
c_date date, c_datetime date
)
PARTITION BY RANGE (c_integer)
(
partition P_20180121 values less than (0),
partition P_20190122 values less than (50000),
partition P_20200123 values less than (100000),
partition P_max values less than (maxvalue)
);
INSERT INTO zsharding_tbl VALUES ( 20, 0, 10, 1, 0, -1088618496, 500000, 1000, 9, 5, 8, 'a', 'def', '2003-02-28', TO_DATE('2002-03-18', 'YYYY-MM-DD'), TO_DATE('2003-11-25', 'YYYY-MM-DD') );
INSERT INTO zsharding_tbl VALUES ( 21, 30000, 20000, 0, 1, 30000, 294453248, 0, 2, -110231552, 9, 'ghi', '2004-05-24', 'kbvumx', TO_DATE('2010-08-08', 'YYYY-MM-DD'), TO_DATE('1995-08-08', 'YYYY-MM-DD') );
INSERT INTO zsharding_tbl VALUES ( 22, 12, 20000, 1, 1, 0, 1, 10, 3000, 13, 0, 'ekb', 'eekbvumxm', 'd', TO_DATE('1995-08-08', 'YYYY-MM-DD'), TO_DATE('2009-11-25', 'YYYY-MM-DD') );
INSERT INTO zsharding_tbl VALUES ( 23, -1294729216, -1349124096, 1, 1, 1421737984, 10, 20000, 2, 3000, 3000, 'b', '%b%', '2004-06-20 20:20:31', TO_DATE('1880-08-08', 'YYYY-MM-DD'), TO_DATE('2009-11-08', 'YYYY-MM-DD') );
INSERT INTO zsharding_tbl VALUES ( 24, -1485242368, -480182272, 1, 0, 3000, 1000, 0, 12, 11, 1000, '2005-09-02', 'q', '2001-08-18 14:31:12', TO_DATE('2002-05-09', 'YYYY-MM-DD'), TO_DATE('2005-08-06', 'YYYY-MM-DD'));
INSERT INTO zsharding_tbl VALUES ( 25, 1000, 0, 1, 0, 4, 20000, 3000, -1371799552, -1394540544, 3, 'def', 'abc', '%b%', TO_DATE('2009-02-10', 'YYYY-MM-DD'), TO_DATE('2001-05-14', 'YYYY-MM-DD'));
INSERT INTO zsharding_tbl VALUES ( 26, 1, 10, 1, 0, 1971322880, 11, 30000, 0, 1088159744, 9, 'abc', '_a_%', 'abe', TO_DATE('2002-12-07', 'YYYY-MM-DD'), TO_DATE('2000-07-02', 'YYYY-MM-DD'));
INSERT INTO zsharding_tbl VALUES ( 27, 1199702016, 10, 0, 1, 500000, -1063911424, 12, 0, 11, 5, 'abcdef', 'a', 'c', TO_DATE('2009-04-08', 'YYYY-MM-DD'), TO_DATE('2010-08-08', 'YYYY-MM-DD'));
INSERT INTO zsharding_tbl VALUES ( 28, 5, 30000, 1, 1, 14, 500000, 5, 292421632, 5, 13, 'c', 'mab', 'b', TO_DATE('2006-02-08', 'YYYY-MM-DD'), TO_DATE('2000-08-08', 'YYYY-MM-DD'));
INSERT INTO zsharding_tbl VALUES ( 29, 1000, 500000, 1, 0, 1221525504, 20000, 2077491200, 13, 12, 40000, '', '2003-07-06 21:08:14', '2004-05-15', TO_DATE('2000-04-20', 'YYYY-MM-DD'), TO_DATE('2008-01-02', 'YYYY-MM-DD'));
INSERT INTO zsharding_tbl VALUES ( 30, 1000, 500000, 1, 0, 1221525504, 20000, 2077491200, 13, 12, 40000, 'abcdefgaaaaaaaaa', '2003-07-06 21:08:14', '2004-05-15', TO_DATE('2000-04-20', 'YYYY-MM-DD'), TO_DATE('2008-01-02', 'YYYY-MM-DD'));
INSERT INTO zsharding_tbl VALUES ( 31, 1000, 500000, 1, 0, 1221525504, 20000, 2077491200, 13, 12, 40000, null, '2003-07-06 21:08:14', '2004-05-15', TO_DATE('2000-04-20', 'YYYY-MM-DD'), TO_DATE('2008-01-02', 'YYYY-MM-DD'));
select t1.c_integer,t1.c_real,t2.c_integer c1 ,t2.c_real c2 from zsharding_tbl t1 full join zsharding_tbl t2 on t1.c_integer=t2.c_real order by 1,2,3,4;
drop table if exists zsharding_tbl;
