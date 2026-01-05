-- @owner: Nerifish
-- @date: 2026/1/31
-- @testpoint: explain执行条件中对between,like,in,is null,=true/false测试,数据较少走频率直方图,要求rows列的值与select结果完全一致
DROP TABLE IF EXISTS employees;

CREATE TABLE employees (
id INT PRIMARY KEY,
name VARCHAR(50),
age INT,
salary DECIMAL(10,2),
department VARCHAR(30),
is_active BOOLEAN,
manager_id INT,
bonus DECIMAL(8,2)
);

-- 插入测试数据
INSERT INTO employees VALUES (1, '张三', 25, 50000.00, '技术部', true, NULL, 5000.00),
(2, '李四', 30, 60000.00, '技术部', true, 1, 6000.00),
(3, '王五', 28, 55000.00, '销售部', true, NULL, 4500.00),
(4, '赵六', 35, 75000.00, '销售部', false, 3, NULL),
(5, '钱七', 22, 45000.00, '人事部', true, NULL, 3000.00),
(6, '孙八', 40, 80000.00, '技术部', true, 1, 10000.00),
(7, '周九', 26, 48000.00, '财务部', true, NULL, 4000.00),
(8, '吴十', 33, 68000.00, '销售部', true, 3, 7000.00),
(9, '郑十一', 29, 58000.00, '技术部', false, 1, 5500.00),
(10, '王芳', 31, 62000.00, '人事部', true, 5, 6500.00),
(101, '张%特殊', 26, 48000.00, '技术部', true, 1, 3500.00),
(102, '李_测试', 32, 65000.00, '销售部', true, 3, 5800.00),
(103, '孙九', 33, 65000.00, '特殊部门', false, 3, 5800.00),
(105, '钱\反斜杠', 24, 43000.00, '财务部', true, 7, 2800.00);
ANALYZE TABLE employees compute statistics;

 
-----测试in操作符适配-----
-- 用例1: IN 操作符
EXPLAIN SELECT count(*) FROM employees WHERE department IN ('技术部', '销售部', '人事部');
SELECT count(*) FROM employees WHERE department IN ('技术部', '销售部', '人事部');

-- 用例2: NOT IN 操作符
EXPLAIN SELECT count(*) FROM employees WHERE department NOT IN ('财务部', '测试部');
SELECT count(*) FROM employees WHERE department NOT IN ('财务部', '测试部');

-- 用例3: IN 与数值
EXPLAIN SELECT count(*) FROM employees WHERE age IN (25, 30, 35, 40);
SELECT count(*) FROM employees WHERE age IN (25, 30, 35, 40);

-----测试between and操作符适配-----
-- 用例4: BETWEEN 操作符
EXPLAIN SELECT count(*) FROM employees WHERE salary BETWEEN 50000 AND 70000;
SELECT count(*) FROM employees WHERE salary BETWEEN 50000 AND 70000;

-- 用例5: NOT BETWEEN 操作符
EXPLAIN SELECT count(*) FROM employees WHERE salary NOT BETWEEN 60000 AND 80000;
SELECT count(*) FROM employees WHERE salary NOT BETWEEN 60000 AND 80000;

-----true/false操作符适配-----
-- 用例6: = true 测试
EXPLAIN SELECT count(*) FROM employees WHERE is_active = true;
SELECT count(*) FROM employees WHERE is_active = true;

-- 用例7: = false 测试
EXPLAIN SELECT count(*) FROM employees WHERE is_active = false;
SELECT count(*) FROM employees WHERE is_active = false;

-----ISNULL操作符适配-----
-- 用例8: IS NULL 测试
EXPLAIN SELECT count(*) FROM employees WHERE manager_id IS NULL;
SELECT count(*) FROM employees WHERE manager_id IS NULL;

-- 用例9: IS NOT NULL 测试
EXPLAIN SELECT count(*) FROM employees WHERE manager_id IS NOT NULL;
SELECT count(*) FROM employees WHERE manager_id IS NOT NULL;

-- 用例10: 多列 IS NULL
EXPLAIN SELECT count(*) FROM employees WHERE bonus IS NULL OR manager_id IS NULL;
SELECT count(*) FROM employees WHERE bonus IS NULL OR manager_id IS NULL;

-----LIKE操作符适配-----
-- 用例11: LIKE 前缀匹配
EXPLAIN SELECT count(*) FROM employees WHERE name LIKE '王%';
SELECT count(*) FROM employees WHERE name LIKE '王%';

-- 用例12: LIKE 中间匹配
EXPLAIN SELECT count(*) FROM employees WHERE name LIKE '%测试%';
SELECT count(*) FROM employees WHERE name LIKE '%测试%';

-- 用例13: NOT LIKE 测试
EXPLAIN SELECT count(*) FROM employees WHERE name NOT LIKE '张%';
SELECT count(*) FROM employees WHERE name NOT LIKE '张%';

-- 用例14: LIKE 单字符匹配
EXPLAIN SELECT count(*) FROM employees WHERE name LIKE '孙_';
SELECT count(*) FROM employees WHERE name LIKE '孙_';

-- 用例15：LIKE 带ESCAPE－匹配包含_的姓名
EXPLAIN SELECT count(*) FROM employees WHERE name LIKE '%\_%' ESCAPE '\';
SELECT count(*) FROM employees WHERE name LIKE '%\_%' ESCAPE '\';

--  用例16：LIKE 带ESCAPE－匹配以%开头的姓名
EXPLAIN SELECT count(*) FROM employees WHERE name NOT LIKE '\%%' ESCAPE '\';
SELECT count(*) FROM employees WHERE name NOT LIKE '\%%' ESCAPE '\';

-- 用例17：LIKE 带ESCAPE－匹配包含_的姓名，并且无通配符
EXPLAIN SELECT count(*) FROM employees WHERE name NOT LIKE '李\_测试' ESCAPE '\';
SELECT count(*) FROM employees WHERE name NOT LIKE '李\_测试' ESCAPE '\';

--用例18：NOT LIKE 带ESCAPE－排除包含特殊字符的姓名
EXPLAIN SELECT count(*) FROM employees WHERE name NOT LIKE '%\%%' ESCAPE '\';
SELECT count(*) FROM employees WHERE name NOT LIKE '%\%%' ESCAPE '\';

--清理环境
DROP TABLE IF EXISTS employees;