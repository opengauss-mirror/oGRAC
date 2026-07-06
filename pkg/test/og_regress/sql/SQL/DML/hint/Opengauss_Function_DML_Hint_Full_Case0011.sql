drop TABLE if exists t_dml0011;
CREATE TABLE t_dml0011 (
    emp_id SERIAL PRIMARY KEY,
    emp_name VARCHAR(100),
    department_id INT,
    salary NUMERIC
);

INSERT INTO t_dml0011 (emp_name, department_id, salary) VALUES
('Alice', 1, 50000),
('Bob', 2, 60000),
('Charlie', 1, 55000),
('David', 3, 70000);
SELECT /*+ FULL(t_dml0011) */ emp_id, emp_name, salary FROM t_dml0011 WHERE department_id = 1;
EXPLAIN SELECT /*+ FULL(t_dml0011) */ emp_id, emp_name, salary FROM t_dml0011 WHERE department_id = 1;
drop TABLE if exists t_dml0011;
