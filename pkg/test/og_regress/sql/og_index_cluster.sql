--test create index_cluster
drop table if exists TB_TABLE_01;
drop table if exists TB_PARTITION_HASH_01;

CREATE TABLE TB_TABLE_01
       (EMPNO NUMBER NOT NULL,
        ENAME VARCHAR(64 BYTE),
        JOB VARCHAR(10 BYTE),
        MGR NUMBER(20),
        HIREDATE DATE,
        SAL NUMBER(10, 2),
        COMM VARCHAR(256 BYTE),
        DEPTNO NUMBER);

declare
v_empno number;
v_mgr   number;
v_deptno number;
begin
for i in 1..1000 loop
v_empno := i;
v_mgr := 2*i;
v_deptno :=i;
INSERT INTO TB_TABLE_01 VALUES (v_empno, 'SMITH',  'CLERK',     v_mgr,TO_DATE('17-DEC-1980', 'DD-MON-YYYY'),  800, NULL, v_deptno);
INSERT INTO TB_TABLE_01 VALUES (v_empno, 'ALLEN',  'SALESMAN',  v_mgr,TO_DATE('20-FEB-1981', 'DD-MON-YYYY'), 1600,  300, v_deptno);
INSERT INTO TB_TABLE_01 VALUES (v_empno, 'WARD',   'SALESMAN',  v_mgr,TO_DATE('22-FEB-1981', 'DD-MON-YYYY'), 1250,  500, v_deptno);
INSERT INTO TB_TABLE_01 VALUES (v_empno, 'JONES',  'MANAGER',   v_mgr,TO_DATE('2-APR-1981', 'DD-MON-YYYY'),  2975, NULL, v_deptno);
INSERT INTO TB_TABLE_01 VALUES (v_empno, 'MARTIN', 'SALESMAN',  v_mgr,TO_DATE('28-SEP-1981', 'DD-MON-YYYY'), 1250, 1400, v_deptno);
INSERT INTO TB_TABLE_01 VALUES (v_empno, 'BLAKE',  'MANAGER',   v_mgr,TO_DATE('1-MAY-1981', 'DD-MON-YYYY'),  2850, NULL, v_deptno);
INSERT INTO TB_TABLE_01 VALUES (v_empno, 'CLARK',  'MANAGER',   v_mgr,TO_DATE('9-JUN-1981', 'DD-MON-YYYY'),  2450, NULL, v_deptno);
INSERT INTO TB_TABLE_01 VALUES (v_empno, 'SCOTT',  'ANALYST',   v_mgr,TO_DATE('09-DEC-1982', 'DD-MON-YYYY'), 3000, NULL, v_deptno);
INSERT INTO TB_TABLE_01 VALUES (v_empno, 'KING',   'PRESIDENT', null,TO_DATE('17-NOV-1981', 'DD-MON-YYYY'), 5000, NULL, v_deptno);
INSERT INTO TB_TABLE_01 VALUES (7934,    'MILLER', 'CLERK',     7782,TO_DATE('23-JAN-1982', 'DD-MON-YYYY'), 1300, NULL, v_deptno);
end loop;
commit;
end;
/

CREATE TABLE TB_PARTITION_HASH_01
(EMPNO NUMBER NOT NULL,
        ENAME VARCHAR(64 BYTE),
        JOB VARCHAR(10 BYTE),
        MGR NUMBER(20),
        HIREDATE DATE,
        SAL NUMBER(10, 2),
        COMM VARCHAR(256 BYTE),
        DEPTNO NUMBER)
PARTITION BY hash(EMPNO)
(partition part_01,
 partition part_02,
 partition part_03);
insert into TB_PARTITION_HASH_01 select * from TB_TABLE_01;
commit;

create indexcluster (
INDEX idx_clus_04 on TB_PARTITION_HASH_01(EMPNO ASC,MGR DESC) parallel 48,
INDEX idx_clus_05 on TB_PARTITION_HASH_01(EMPNO ASC,SAL DESC) parallel 48,
INDEX idx_clus_06 on TB_PARTITION_HASH_01(JOB ASC,ENAME DESC) parallel 48,
INDEX idx_clus_07 on TB_PARTITION_HASH_01(ENAME ASC,MGR DESC) parallel 48,
INDEX idx_clus_08 on TB_PARTITION_HASH_01(MGR ASC,HIREDATE DESC) parallel 48,
INDEX idx_clus_09 on TB_PARTITION_HASH_01(HIREDATE ASC,SAL DESC) parallel 48,
INDEX idx_clus_10 on TB_PARTITION_HASH_01(SAL ASC,COMM DESC) parallel 48,
INDEX idx_clus_11 on TB_PARTITION_HASH_01(HIREDATE ASC,SAL,DEPTNO DESC) parallel 48);
