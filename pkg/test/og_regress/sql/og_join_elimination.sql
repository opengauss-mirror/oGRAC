DROP TABLE IF EXISTS t1;
CREATE TABLE t1 (id INT PRIMARY KEY, name VARCHAR(100), age INT);
DROP TABLE IF EXISTS t2;
CREATE TABLE t2 (id INT PRIMARY KEY, t1_id INT, value VARCHAR(100), CONSTRAINT fk_t2_t1 FOREIGN KEY (t1_id) REFERENCES t1(id));
DROP TABLE IF EXISTS t3;
CREATE TABLE t3 (id INT PRIMARY KEY, t2_id INT, data VARCHAR(100));
INSERT INTO t1 VALUES (1, 'Alice', 25), (2, 'Bob', 30), (3, 'Charlie', 35);
INSERT INTO t2 VALUES (1, 1, 'A'), (2, 2, 'B'), (3, 3, 'C');
INSERT INTO t3 VALUES (1, 1, 'X'), (2, 2, 'Y'), (3, 3, 'Z');
CREATE UNIQUE INDEX idx_t2_t1_id ON t2(t1_id);

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NOT NULL;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NOT NULL;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.value = 'A';
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.value = 'A';

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id LEFT JOIN t3 ON t2.id = t3.t2_id WHERE t2.id IS NOT NULL AND t3.id IS NOT NULL;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id LEFT JOIN t3 ON t2.id = t3.t2_id WHERE t2.id IS NOT NULL AND t3.id IS NOT NULL;

EXPLAIN SELECT t1.*, t2.value FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;
SELECT t1.*, t2.value FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;

EXPLAIN SELECT t1.*, t2.value, t2.id FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;
SELECT t1.*, t2.value, t2.id FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;

EXPLAIN SELECT t1.* FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.value IS NOT NULL;
SELECT t1.* FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.value IS NOT NULL;

EXPLAIN SELECT DISTINCT t1.* FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;
SELECT DISTINCT t1.* FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;

EXPLAIN SELECT t1.id, MAX(t2.value) FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id GROUP BY t1.id;
SELECT t1.id, MAX(t2.value) FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id GROUP BY t1.id;

EXPLAIN SELECT t1.id, COUNT(t2.id) FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id GROUP BY t1.id;
SELECT t1.id, COUNT(t2.id) FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id GROUP BY t1.id;

EXPLAIN SELECT * FROM t1 FULL JOIN t2 ON t1.id = t2.t1_id WHERE t1.id IS NOT NULL;
SELECT * FROM t1 FULL JOIN t2 ON t1.id = t2.t1_id WHERE t1.id IS NOT NULL;

EXPLAIN SELECT * FROM t1 FULL JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NOT NULL;
SELECT * FROM t1 FULL JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NOT NULL;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NOT NULL OR t1.age > 30;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NOT NULL OR t1.age > 30;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NOT NULL AND t2.value = 'A';
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NOT NULL AND t2.value = 'A';

EXPLAIN SELECT * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 LEFT JOIN t3 ON t2.id = t3.t2_id WHERE t2.t1_id = t1.id AND t3.id IS NOT NULL);
SELECT * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 LEFT JOIN t3 ON t2.id = t3.t2_id WHERE t2.t1_id = t1.id AND t3.id IS NOT NULL);

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NULL;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IS NULL;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id > 0;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id > 0;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id + t1.age > 50;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id + t1.age > 50;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IN (1, 2, 3);
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id IN (1, 2, 3);

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id BETWEEN 1 AND 10;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.id BETWEEN 1 AND 10;

EXPLAIN SELECT t1.id, CASE WHEN t2.id IS NOT NULL THEN t2.value ELSE 'NULL' END FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;
SELECT t1.id, CASE WHEN t2.id IS NOT NULL THEN t2.value ELSE 'NULL' END FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id ORDER BY t2.value;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id ORDER BY t2.value;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id LIMIT 10;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id LIMIT 10;

EXPLAIN SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id FOR UPDATE;
SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id FOR UPDATE;

DROP TABLE IF EXISTS je_win_avg_left;
DROP TABLE IF EXISTS je_win_avg_right;

CREATE TABLE je_win_avg_left (k INT);
CREATE TABLE je_win_avg_right (k INT);

INSERT INTO je_win_avg_left
SELECT CASE WHEN a.n <= 50 THEN 1 ELSE (a.n - 51) * 200 + b.n END
FROM (SELECT LEVEL n FROM sys_dummy CONNECT BY LEVEL <= 100) a,
     (SELECT LEVEL n FROM sys_dummy CONNECT BY LEVEL <= 200) b;

INSERT INTO je_win_avg_right
SELECT (a.n - 1) * 200 + b.n + 1000
FROM (SELECT LEVEL n FROM sys_dummy CONNECT BY LEVEL <= 100) a,
     (SELECT LEVEL n FROM sys_dummy CONNECT BY LEVEL <= 200) b;

ANALYZE TABLE je_win_avg_left COMPUTE STATISTICS;
ANALYZE TABLE je_win_avg_right COMPUTE STATISTICS;

EXPLAIN
SELECT DISTINCT
    AVG(DISTINCT l.k) OVER () AS avg_key,
    SUM(DISTINCT l.k) OVER () AS sum_key,
    COUNT(DISTINCT l.k) OVER () AS cnt_key
FROM je_win_avg_left l
LEFT JOIN je_win_avg_right r
  ON l.k = r.k OR r.k > 5;

SELECT DISTINCT
    AVG(DISTINCT l.k) OVER () AS avg_key,
    SUM(DISTINCT l.k) OVER () AS sum_key,
    COUNT(DISTINCT l.k) OVER () AS cnt_key
FROM je_win_avg_left l
LEFT JOIN je_win_avg_right r
  ON l.k = r.k OR r.k > 5;

DROP TABLE je_win_avg_left;
DROP TABLE je_win_avg_right;
