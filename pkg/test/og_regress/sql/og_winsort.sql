DROP TABLE IF EXISTS winsort_sum_t1;
CREATE TABLE winsort_sum_t1 (a int, b int);
INSERT INTO winsort_sum_t1 VALUES(1, 2);
INSERT INTO winsort_sum_t1 VALUES(1, 1);
INSERT INTO winsort_sum_t1 VALUES(1, 3);
INSERT INTO winsort_sum_t1 VALUES(1, 2);
INSERT INTO winsort_sum_t1 VALUES(2, 2);
INSERT INTO winsort_sum_t1 VALUES(2, 1);
INSERT INTO winsort_sum_t1 VALUES(2, 1);
SELECT a, SUM(b) OVER(PARTITION BY a) FROM winsort_sum_t1;
SELECT b, SUM(a) OVER(PARTITION BY b) FROM winsort_sum_t1;
SELECT a, SUM(DISTINCT b) OVER(PARTITION BY a) FROM winsort_sum_t1;
SELECT b, SUM(DISTINCT a) OVER(PARTITION BY b) FROM winsort_sum_t1;
DROP TABLE IF EXISTS winsort_sum_t1;

DROP TABLE IF EXISTS winsort_distinct_t1;
CREATE TABLE winsort_distinct_t1 (p INT, v INT);
INSERT INTO winsort_distinct_t1 VALUES
    (1, 5), (1, 5), (1, NULL),
    (2, 1), (2, 1), (2, 3), (2, NULL),
    (3, NULL), (3, NULL);

SELECT DISTINCT p,
    COUNT(DISTINCT v) OVER (PARTITION BY p) AS cnt_key,
    SUM(DISTINCT v) OVER (PARTITION BY p) AS sum_key,
    AVG(DISTINCT v) OVER (PARTITION BY p) AS avg_key
FROM winsort_distinct_t1
ORDER BY p;

SELECT p, v,
    COUNT(v) OVER (PARTITION BY p ORDER BY v) AS cnt_key,
    SUM(v) OVER (PARTITION BY p ORDER BY v) AS sum_key,
    AVG(v) OVER (PARTITION BY p ORDER BY v) AS avg_key
FROM (SELECT DISTINCT p, v FROM winsort_distinct_t1 WHERE v IS NOT NULL) d
ORDER BY p, v;

DROP TABLE winsort_distinct_t1;
