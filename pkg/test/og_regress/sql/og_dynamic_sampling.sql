DROP TABLE IF EXISTS test_dy_1;
DROP TABLE IF EXISTS test_dy;
CREATE TABLE test_dy_1 (f1 int, f2 integer, f3 bigint);

CREATE OR REPLACE PROCEDURE insert_test_dy_1_data
AS
    v_i INT := 1;
BEGIN
    WHILE v_i <= 100 LOOP
        INSERT INTO test_dy_1 VALUES(
            MOD(v_i, 20),
            MOD(v_i, 30),
            MOD(v_i, 40)
        );
        IF MOD(v_i, 25) = 0 THEN
            COMMIT;
        END IF;
        v_i := v_i + 1;
    END LOOP;
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK;
        RAISE;
END;
/

CALL insert_test_dy_1_data();
SELECT COUNT(*) AS total_rows FROM test_dy_1;
CREATE TABLE test_dy AS SELECT * FROM test_dy_1 WHERE 1=0;
INSERT INTO test_dy SELECT * FROM test_dy_1 ORDER BY f1;
COMMIT;
CREATE INDEX idx_test_dy_1 ON test_dy (f1);
CREATE INDEX idx_test_dy_2 ON test_dy (f2);
CREATE INDEX idx_test_dy_3 ON test_dy (f1, f2);
DELETE FROM test_dy;
INSERT INTO test_dy SELECT * FROM test_dy_1 ORDER BY f1;
COMMIT;
SELECT table_name, column_name, sample_size, histogram FROM MY_TAB_COL_STATISTICS WHERE table_name = 'TEST_DY' ORDER BY column_name DESC;
CALL dbe_stats.collect_table_stats(schema=>user, name=>'test_dy', sample_ratio => 100, method_opt=>'for all indexed columns');
SELECT table_name, column_name, num_distinct, low_value, high_value, density, num_nulls, sample_size, histogram FROM MY_TAB_COL_STATISTICS WHERE table_name = 'TEST_DY'ORDER BY column_name DESC;

DROP PROCEDURE IF EXISTS insert_test_dy_1_data;
DROP TABLE IF EXISTS test_dy_1;
DROP TABLE IF EXISTS test_dy;

DROP TABLE IF EXISTS DATA_DS_TEST;
CREATE TABLE DATA_DS_TEST (id INT PRIMARY KEY, int_f0 INT NOT NULL, int_f1 INT, varchar_f2 VARCHAR(50), create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
INSERT INTO DATA_DS_TEST (id, int_f0, int_f1, varchar_f2) VALUES (1,180,800,'val_180');
COMMIT;
INSERT INTO DATA_DS_TEST (id, int_f0, int_f1, varchar_f2)
SELECT id + 1, 380, 1500, 'val_380' FROM DATA_DS_TEST;
INSERT INTO DATA_DS_TEST (id, int_f0, int_f1, varchar_f2)
SELECT id + 2, 380, 1500, 'val_380' FROM DATA_DS_TEST;
INSERT INTO DATA_DS_TEST (id, int_f0, int_f1, varchar_f2)
SELECT id + 4, 380, 1500, 'val_380' FROM DATA_DS_TEST;
INSERT INTO DATA_DS_TEST (id, int_f0, int_f1, varchar_f2)
SELECT id + 8, 380, 1500, 'val_380' FROM DATA_DS_TEST;
INSERT INTO DATA_DS_TEST (id, int_f0, int_f1, varchar_f2)
SELECT id + 16, 380, 1500, 'val_380' FROM DATA_DS_TEST;
INSERT INTO DATA_DS_TEST (id, int_f0, int_f1, varchar_f2)
SELECT id + 32, 250, 1100, 'val_250' FROM DATA_DS_TEST;
INSERT INTO DATA_DS_TEST (id, int_f0, int_f1, varchar_f2)
SELECT id + 64, 180, 800, 'val_180' FROM DATA_DS_TEST;
COMMIT;

SELECT COUNT(*) FROM DATA_DS_TEST;
SELECT int_f0, COUNT(*) AS row_count FROM DATA_DS_TEST GROUP BY int_f0;
ALTER SYSTEM SET _opt_cbo_stat_sampling_level = 0;
CALL dbe_stats.delete_table_stats(schema=>user, name=>'DATA_DS_TEST');
EXPLAIN SELECT * FROM DATA_DS_TEST t0, DATA_DS_TEST t1 WHERE t0.int_f0 < 200 AND t0.id = t1.id LIMIT 1;
select table_name, num_rows, blocks, empty_blocks, avg_row_len, sample_size FROM my_tables  WHERE table_name = 'DATA_DS_TEST';
ALTER SYSTEM SET _opt_cbo_stat_sampling_level = 1;
CALL dbe_stats.delete_table_stats(schema=>user, name=>'DATA_DS_TEST');
EXPLAIN SELECT * FROM DATA_DS_TEST t0, DATA_DS_TEST t1 WHERE t0.int_f0 < 200 AND t0.id = t1.id LIMIT 1;
select table_name, sample_size, CASE WHEN abs(sample_size/num_rows - 10/(CASE WHEN blocks > 10 THEN blocks ELSE 10 END)) < 0.1 THEN true ELSE false END FROM my_tables  WHERE table_name = 'DATA_DS_TEST';

ALTER SYSTEM SET _opt_cbo_stat_sampling_level = 10;
ALTER SYSTEM SET _opt_cbo_stat_sampling_level = -1;
ALTER SYSTEM SET _opt_cbo_stat_sampling_level = 5.5;

ANALYZE TABLE DATA_DS_TEST COMPUTE STATISTICS;

DROP TABLE IF EXISTS DATA_DS_TEST;
CREATE TABLE DATA_DS_TEST(id INT);
SELECT COUNT(*) FROM DATA_DS_TEST WHERE id > 0;
DROP TABLE DATA_DS_TEST;
