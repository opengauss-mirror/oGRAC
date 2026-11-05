DROP TABLE IF EXISTS autotrace_test;
CREATE TABLE autotrace_test(c1 int);
INSERT INTO autotrace_test VALUES(1);
COMMIT;

SET AUTOTRACE ON;
select * from autotrace_test;
SET AUTOTRACE TRACEONLY;
select * from autotrace_test;
SET AUTOTRACE OFF;
select * from autotrace_test;

DROP TABLE IF EXISTS autotrace_test;

DROP VIEW IF EXISTS autotrace_view;
DROP TABLE IF EXISTS autotrace_view_input PURGE;
CREATE TABLE autotrace_view_input(k INT, a INT[]);
BEGIN
    FOR i IN 1..10000 LOOP
        INSERT INTO autotrace_view_input(k) VALUES(1);
    END LOOP;
END;
/
COMMIT;
ANALYZE TABLE autotrace_view_input COMPUTE STATISTICS;
CREATE VIEW autotrace_view AS SELECT * FROM autotrace_view_input;
SET AUTOTRACE TRACEONLY;
SELECT * FROM autotrace_view l JOIN autotrace_view r ON l.k=r.k+1 LIMIT 50;
SET AUTOTRACE OFF;
DROP VIEW autotrace_view;
DROP TABLE autotrace_view_input PURGE;
