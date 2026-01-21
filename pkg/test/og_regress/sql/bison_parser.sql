alter system set use_bison_parser = true;

drop table if exists bison_t1;
create table bison_t1 (a int, b char(10));
insert into bison_t1 values (1,'abc');
insert into bison_t1 values (1,'abc'), (2, 'abc');
insert into sys.bison_t1 values (1,'abc'), (2, 'abc');
insert sys.bison_t1 values (1,'abc'), (2, 'abc');
insert into bison_t1(a,b) values (1,'abc'), (2, 'abc');
insert into bison_t1(sys.bison_t1.a, bison_t1.b) values (1,'abc'), (2, 'abc');
insert into bison_t1 tbison_t1(sys.bison_t1.a, tbison_t1.b) values (1,'abc'), (2, 'abc');
insert into bison_t1 as values(sys.bison_t1.a, bison_t1.b) values (1,'abc'), (2, 'abc');
insert into bison_t1 values(sys.bison_t1.a, bison_t1.b) values (1,'abc'), (2, 'abc'); --error
insert into bison_t1(sys.bison_t1.a, bison_t2.b) values (1,'abc'), (2, 'abc'); --error

drop table bison_t2;
create table bison_t2 (a int primary key, b int);
insert into bison_t2 values (1,1);
insert ignore into bison_t2 values (1,1);
insert into bison_t2 values (1,1); --error

insert /*+parallel(10)*/ into bison_t2 values (1,1);
insert /*+parallel(10)*/ into bison_t2(a, b) values (1,1);
insert /*+opt_param(abc=true)*/ into bison_t2 values (1,1);
insert /*+db_version(=abc)*/ into bison_t2 values (1,1);
insert /*+db_version(==abc)*/ into bison_t2 values (1,1);

drop table bison_t1;
drop table bison_t2;
create table bison_t1 (a int);
create table bison_t2 (a int);
insert into bison_t2 values (1), (2);
insert all into bison_t1 values (1) into bison_t1 values (2) select a from bison_t2;
insert all into bison_t1 values (1) into bison_t1 values (2) select 1;
insert all into bison_t1 (a) values (1) into bison_t1 (a) values (2) select 1;
insert all into bison_t1 (a) values (1) into bison_t1 values (2) select 1; --error

insert into bison_t1 select a from bison_t2;
insert into bison_t1(a) select a from bison_t2;

drop table bison_t1;
create table bison_t1 (a int primary key, b int);
insert into bison_t1 values (1,1);
insert into bison_t1 values (1,2) on duplicate key update b = 2;

drop table bison_t1;
create table bison_t1 (a int primary key, b int, c int);
insert into bison_t1 values (1,1,1);
insert into bison_t1 values (1,2,3) on duplicate key update (a, b) = (select 1,2), c = 4;
insert into bison_t1 values (1,2,3) on duplicate key update (a, b) = (1,2), c = 4; --error

insert into bison_t1 values (1, 1, 1) returning a; --error
insert into bison_t1 values (1, 1) returning a; --error

declare
	tmp int;
begin
	insert into bison_t1 values (1,2,3) on duplicate key update (a, b) = (select 1,2), c = 4 returning c into tmp;
	dbe_output.print_line(tmp);
end;
/

drop table bison_t1;
create table bison_t1 (a int, b int);
insert into bison_t1 values (1, 1);
insert into bison_t1 values (2, 2);
delete bison_t1;
delete from bison_t1;

insert into bison_t1 values (1, 1);
insert into bison_t1 values (2, 2);
delete from bison_t1 where a;
delete from bison_t1 where (a);
delete from bison_t1 where (a = 2);

delete from bison_t1 where not a;
delete from bison_t1 where not (a = 2);

delete from bison_t1 where a = 1 and b = 2;

insert into bison_t1 values (0, 0), (1, 2);
delete from bison_t1 where a = 0 or b = 2;

insert into bison_t1 values (1,1), (2,2), (3,3);
delete from bison_t1 where a = 2;
delete from bison_t1 where a > 1;
delete from bison_t1 where a < 2;

delete from bison_t1 where a = (select 1);

insert into bison_t1 values (1,1), (2,2), (3,3);
delete from bison_t1 where a >= 2;
delete from bison_t1 where a <= 2;
delete from bison_t1 where a <> 2;

insert into bison_t1 values (1,1), (2,2), (3,3);
delete from bison_t1 where a = any (2,3);
delete from bison_t1 where a = any (select 1);
delete from bison_t1 where a = any ((select 1), (select 3));
delete from bison_t1 where a = any (select 1,2); --error

delete from bison_t1 where a > any (2, 5);
delete from bison_t1 where a > all (2, 5);
delete from bison_t1 where a < any ((select 1), (select 3));
delete from bison_t1 where a <= any ((select 1), (select 3));

delete from bison_t1 where a in (2, 3);
delete from bison_t1 where a in (select 1);
delete from bison_t1 where a in ((select 1), (select 2));

delete from bison_t1 where a not in (2, 3);
delete from bison_t1 where a not in ((select 1), (select 2));
delete from bison_t1 where (a, b) not in (select 1,1);

delete from bison_t1 where (a, b) in (select 1,1);
delete from bison_t1 where (a,b) in (((select 2), 2));
delete from bison_t1 where (a,b) in (((select 2), 2),(3, (select 3)));
delete from bison_t1 where (a, b) in ((2,3));
delete from bison_t1 where (a,b) in (((select 2), (select 3)), (1,1));

delete from bison_t1 where (a, b) in ((2), (3)); --error
delete from bison_t1 where (a, b) in (2,3); --error
delete from bison_t1 where (a, b) in (select 2); --error
delete from bison_t1 where (a,b) in (((select 1), 2), ((select 2))); --error

insert into bison_t1 values (null, 2);
delete from bison_t1 where a is null;
delete from bison_t1 where (select 1) is null;
delete from bison_t1 where a is not null;

delete from bison_t1 where a is not json;
delete from bison_t1 where a is json;

drop table bison_t1;
create table bison_t1 (a varchar(10));
insert into bison_t1 values ('abcdef');
insert into bison_t1 values ('abcdef%');
delete from bison_t1 where a like 'abc%';
delete from bison_t1 where a not like 'abc%';

delete from bison_t1 where (select 'abc') like 'abc%';

delete from bison_t1 where a like '%\%' escape '\';
delete from bison_t1 where a not like '%\%' escape '\';

delete from bison_t1 where a regexp 'abc';
delete from bison_t1 where a not regexp 'abc';

delete from bison_t1 where a between 'ab' and 'ac';
delete from bison_t1 where a not between 'ab' and 'ac';

alter system set _OPTIM_SUBQUERY_REWRITE=false;
delete from bison_t1 where exists (select 'ab');
delete from bison_t1 where not exists (select 'ab');

delete from bison_t1 where regexp_like (a, 'ab');
delete from bison_t1 where regexp_like (a);  --error
delete from bison_t1 where regexp_like (a, 'ab', 'ab', 'ab');  --error

drop table bison_t1;
create table bison_t1 (a int, b int);
insert into bison_t1 values (1, 1);
insert into bison_t1 values (2, 2);

drop table bison_t2;
create table bison_t2 (c int, d int);
insert into bison_t2 values (1, 1);
insert into bison_t2 values (2, 2);

delete from bison_t1 where a = 1;
delete from bison_t1 using bison_t1, bison_t2 where a = 1;	
delete from bison_t1, bison_t2 using bison_t1, bison_t2 where a = 2;

delete from bison_t1 using bison_t1, bison_t2;

delete from bison_t1 using bison_t2 partition(p1), bison_t1 where a = 1;

delete from bison_t1, bison_t2 using bison_t1 join bison_t2 where a = c;

delete from bison_t1, bison_t2 using bison_t1 inner join bison_t2 where a = c;

delete from bison_t1, bison_t2 using bison_t1 join bison_t2 on a = c;

delete from bison_t1, bison_t2; -- error

delete bison_t1 from bison_t1, bison_t2 where a = 1;
delete bison_t1, bison_t2 from bison_t1, bison_t2 where a = 2;

delete bison_t1, bison_t2; -- error

select 1 from table(abc(1,2));  --does not exist
select 1 from table(cast(1 as int)); -- verify error

select name from json_table('{"name":"Messi", "age": 10}' format json, '$' default '1' on error COLUMNS(name (RETURNING varchar2) PATH '$.name', age varchar2 PATH '$.age')); --error

select name from json_table('{"name":"Messi", "age": 10}' format json, '$' default '1' on error COLUMNS(name for ordinality, age varchar2 PATH '$.age'));

select name from json_table('{"name":"Messi", "age": 10}' format json, '$' default '1' on error COLUMNS(name for ordinality, age varchar2('10abc') PATH '$.age')); --error

select name from json_table('{"name":"Messi", "age": 10}' format json, '$' default '1' on error COLUMNS(name varchar2 exists PATH '$.name' TRUE ON ERROR, age varchar2 exists PATH '$.age' TRUE ON ERROR));

select name from json_table('{"name":"Messi", "age": 10}' format json, '$' default '1' on error COLUMNS(name varchar2 PATH '$.name' TRUE ON ERROR, age varchar2 PATH '$.age' TRUE ON ERROR));  -- error

select name from json_table('{"name":"Messi", "age": 10}' format json, '$' default '1' on error COLUMNS(name for ordinality, age varchar2(10) PATH '$.age')) jian;

select name from json_table('{"name":"Messi"}' format json, '$' default '1' on error COLUMNS(name for ordinality));

select name from json_table('{"name":"Messi"}' format json, '$' default '1' on error COLUMNS(name varchar2(10) PATH '$.age'));

select name from json_table('{"name":"Messi", "age": 10}' format json, '$' default '1' on error COLUMNS(name varchar2 exists PATH '$.name' TRUE ON ERROR, age varchar2 exists PATH '$.age' TRUE ON ERROR));



create table clob_bison_t1 (a clob);
insert into clob_bison_t1 values ('{"name":"Messi", "age": 10}');
select * from clob_bison_t1, json_table (clob_bison_t1.a, '$' default '1' on error COLUMNS(name varchar2 PATH '$.name', age varchar2 PATH '$.age'));

drop table bison_t1;
create table bison_t1 (a int, b int);
insert into bison_t1 values (1,1), (2,2);
delete from bison_t1 limit 1 offset 1;

delete from bison_t1 order by a desc limit 1 offset 1;
delete from bison_t1 order by a desc limit 1 offset 1 returning a;

delete from bison_t1 order by a desc offset 1 limit 1;

delete from bison_t1 order siblings by a desc limit 1 offset 1; --error
delete from bison_t1, bison_t2 using bison_t1, bison_t2 limit 1 offset 1;  --error
delete from bison_t1, bison_t2 using bison_t1, bison_t2 order by a;  --error

drop table bison_t1;
create table bison_t1 (a int, b int);
insert into bison_t1 values (1,1), (2,2);
update bison_t1 set a = 1 where b = 2;
update bison_t1 set a = 3, b = 3 where a = 1;

drop table bison_t2;
create table bison_t2 (c int, d int);
insert into bison_t2 values (1,1), (2,2);
update bison_t1, bison_t2 set a = 3, b = 3 where a = 1;

select a from bison_t1;
select abs
(a) from bison_t1;
select 1;

select a as "abc" from bison_t1;
select a as abc from bison_t1;
select a "abc" from bison_t1;
select a abc from bison_t1;

select "A" from bison_t1;
select "a" from bison_t1;
select a from bison_t1;

select a "abc", b def from bison_t1;

select * from bison_t1, bison_t2;

-- 创建销售数据表
CREATE TABLE sales_data (
    product_id VARCHAR2(10),
    month VARCHAR2(20),
    sales_amount NUMBER(10,2),
    region VARCHAR2(20)
);

-- 插入示例数据
INSERT INTO sales_data VALUES ('P001', 'January', 1000, 'North');
INSERT INTO sales_data VALUES ('P001', 'February', 1500, 'North');
INSERT INTO sales_data VALUES ('P001', 'March', 1200, 'North');
INSERT INTO sales_data VALUES ('P001', 'January', 800, 'South');
INSERT INTO sales_data VALUES ('P001', 'February', 900, 'South');
INSERT INTO sales_data VALUES ('P001', 'March', 1100, 'South');
INSERT INTO sales_data VALUES ('P002', 'January', 2000, 'North');
INSERT INTO sales_data VALUES ('P002', 'February', 1800, 'North');
INSERT INTO sales_data VALUES ('P002', 'March', 2200, 'North');
INSERT INTO sales_data VALUES ('P002', 'January', 1200, 'South');
INSERT INTO sales_data VALUES ('P002', 'February', 1400, 'South');
INSERT INTO sales_data VALUES ('P002', 'March', 1600, 'South');

COMMIT;

-- 简单的按月汇总
SELECT *
FROM (
    SELECT product_id, month, sales_amount
    FROM sales_data
)
PIVOT (
    SUM(sales_amount)
    FOR month IN ('January' AS Jan, 'February' AS Feb, 'March' AS Mar)
)
ORDER BY product_id;


SELECT *
FROM (
    SELECT product_id, month, sales_amount
    FROM sales_data
)
PIVOT (
    SUM(sales_amount)
    FOR month IN ('January' AS Jan, 'February' AS Feb, 'March' AS Mar)
)
PIVOT (
    SUM(jan)
    FOR product_id IN ('P001' AS p1, 'P002' AS p2)
);

SELECT *
FROM (
    SELECT product_id, month, sales_amount
    FROM sales_data
)
PIVOT (
    sales_amount
    FOR month IN ('January' AS Jan, 'February' AS Feb, 'March' AS Mar)
)
ORDER BY product_id; -- verify error

SELECT *
FROM (
    SELECT product_id, month, sales_amount
    FROM sales_data
)
PIVOT (
    SUM(sales_amount)
    FOR month IN ('January', 'February', 'March')
)
ORDER BY product_id;

SELECT *
FROM (
    SELECT product_id, month, sales_amount
    FROM sales_data
)
PIVOT (
    SUM(sales_amount)
    FOR (product_id, month) IN (('P001', 'January'), ('P001', 'February'), ('P001', 'March'), ('P002', 'January'), ('P002', 'February'), ('P002', 'March'))
);

drop table sales_data;
CREATE TABLE sales_data (
    region VARCHAR2(20),
    quarter VARCHAR2(10),
    product_a NUMBER,
    product_b NUMBER,
    product_c NUMBER
);

INSERT INTO sales_data VALUES ('North', 'Q1', 1000, 1500, 1200);
INSERT INTO sales_data VALUES ('North', 'Q2', 1100, 1600, 1300);
INSERT INTO sales_data VALUES ('South', 'Q1', 900, 1400, 1100);
INSERT INTO sales_data VALUES ('South', 'Q2', 950, 1450, 1150);
COMMIT;

SELECT region, quarter, product_type, sales_amount
FROM sales_data
UNPIVOT (
    sales_amount          -- 新列：存放原来多列的值
    FOR product_type      -- 新列：存放原来列名的描述
    IN (                  -- 指定要转换的列
        product_a AS 'A', -- 可以给原列名起别名
        product_b AS 'B',
        product_c AS 'C'
    )
);

-- 包含NULL值的数据
INSERT INTO sales_data VALUES ('West', 'Q1', NULL, 1800, 1400);

-- 使用INCLUDE NULLS（默认是EXCLUDE NULLS）
SELECT region, quarter, product_type, sales_amount
FROM sales_data
UNPIVOT INCLUDE NULLS (
    sales_amount
    FOR product_type
    IN (
        product_a AS 'A',
        product_b AS 'B',
        product_c AS 'C'
    )
);

SELECT region, quarter, product_type, sales_amount
FROM sales_data
UNPIVOT EXCLUDE NULLS (
    sales_amount
    FOR product_type
    IN (
        product_a AS 'A',
        product_b AS 'B',
        product_c AS 'C'
    )
);

CREATE TABLE employee_metrics (
    emp_id NUMBER,
    emp_name VARCHAR2(50),
    q1_sales NUMBER,
    q1_target NUMBER,
    q2_sales NUMBER,
    q2_target NUMBER
);

INSERT INTO employee_metrics VALUES (1, '张三', 50000, 45000, 55000, 50000);
INSERT INTO employee_metrics VALUES (2, '李四', 48000, 50000, 52000, 48000);
COMMIT;

SELECT emp_id, emp_name, quarter, sales, target
FROM employee_metrics
UNPIVOT (
    (sales, target)           -- 同时处理多列值对
    FOR quarter
    IN (
        (q1_sales, q1_target) AS 'Q1',
        (q2_sales, q2_target) AS 'Q2'
    )
);

-- 创建员工表
CREATE TABLE employees (
    employee_id NUMBER,
    employee_name VARCHAR2(50),
    manager_id NUMBER
);

-- 插入测试数据
INSERT INTO employees VALUES (1, 'CEO', NULL);
INSERT INTO employees VALUES (2, '技术副总裁', 1);
INSERT INTO employees VALUES (3, '销售副总裁', 1);
INSERT INTO employees VALUES (4, '开发经理', 2);
INSERT INTO employees VALUES (5, '测试经理', 2);
INSERT INTO employees VALUES (6, '销售经理', 3);
INSERT INTO employees VALUES (7, '高级开发工程师', 4);
INSERT INTO employees VALUES (8, '初级开发工程师', 4);
INSERT INTO employees VALUES (9, '测试工程师', 5);
INSERT INTO employees VALUES (10, '销售代表', 6);
COMMIT;

SELECT 
    employee_id,
    employee_name,
    manager_id
FROM employees
START WITH manager_id IS NULL
CONNECT BY PRIOR employee_id = manager_id;

SELECT 
    employee_id,
    employee_name,
    manager_id
FROM employees
START WITH manager_id IS NULL
CONNECT BY PRIOR employee_id = manager_id order siblings by employee_id;

-- 原生会报错,order by前加个括号就可以执行；raw_parser加不加都可以执行，结果一致
SELECT 
    employee_id,
    employee_name,
    manager_id
FROM employees
START WITH manager_id IS NULL
CONNECT BY PRIOR employee_id = manager_id order siblings by employee_id order by manager_id;

-- error
(SELECT 
    employee_id,
    employee_name,
    manager_id
FROM employees
START WITH manager_id IS NULL
CONNECT BY PRIOR employee_id = manager_id) order siblings by employee_id;

select * from bison_t1 order siblings by a; -- error

SELECT 
    employee_id,
    employee_name,
    manager_id
FROM employees
CONNECT BY PRIOR employee_id = manager_id
START WITH manager_id IS NULL;

SELECT 
    employee_id,
    employee_name,
    manager_id
FROM employees
CONNECT BY PRIOR employee_id = manager_id;

-- 目前会报错，level需要映射为EXPR_NODE_RESERVED
SELECT 
    employee_id,
    employee_name,
    manager_id,
    level as hierarchy_level
FROM employees
START WITH manager_id IS NULL
CONNECT BY PRIOR employee_id = manager_id;

-- 创建示例表
drop table sales_data;
CREATE TABLE sales_data (
    sale_id NUMBER,
    region VARCHAR2(20),
    product_category VARCHAR2(20),
    salesperson VARCHAR2(30),
    sale_amount NUMBER(10,2),
    sale_date DATE
);

-- 插入示例数据
INSERT INTO sales_data VALUES (1, 'North', 'Electronics', 'John', 1500, DATE '2024-01-15');
INSERT INTO sales_data VALUES (2, 'North', 'Furniture', 'John', 2500, DATE '2024-01-20');
INSERT INTO sales_data VALUES (3, 'South', 'Electronics', 'Sarah', 1800, DATE '2024-01-10');
INSERT INTO sales_data VALUES (4, 'South', 'Furniture', 'Sarah', 2200, DATE '2024-01-25');
INSERT INTO sales_data VALUES (5, 'North', 'Electronics', 'Mike', 1200, DATE '2024-02-05');
INSERT INTO sales_data VALUES (6, 'South', 'Furniture', 'Mike', 1900, DATE '2024-02-10');
INSERT INTO sales_data VALUES (7, 'North', 'Electronics', 'John', 1700, DATE '2024-02-15');
INSERT INTO sales_data VALUES (8, 'South', 'Electronics', 'Sarah', 2100, DATE '2024-02-20');

COMMIT;

SELECT 
    region,
    product_category,
    SUM(sale_amount) AS total_sales
FROM sales_data
GROUP BY GROUPING SETS ( 
    (region, product_category));

SELECT 
    region,
    product_category,
    SUM(sale_amount) AS total_sales
FROM sales_data
GROUP BY ( 
    region, product_category);

SELECT 
    region,
    product_category,
    SUM(sale_amount) AS total_sales
FROM sales_data
GROUP BY GROUPING SETS ( grouping sets
    (region, product_category));


SELECT 
    region,
    product_category,
    salesperson,
    SUM(sale_amount) AS total_sales,
    COUNT(*) AS transaction_count
FROM sales_data
GROUP BY GROUPING SETS (
    (region, product_category, salesperson),
    (region, product_category),             
    (region, salesperson),                  
    (product_category, salesperson),        
    (region),                               
    (product_category),                     
    (salesperson),                           
    ()
);

SELECT 
    region,
    product_category,
    salesperson,
    SUM(sale_amount) AS total_sales,
    GROUPING_ID(region, product_category, salesperson) AS grp_id
FROM sales_data
GROUP BY GROUPING SETS (
    ROLLUP(region, product_category, salesperson)
);

SELECT 
    region,
    product_category,
    salesperson,
    SUM(sale_amount) AS total_sales,
    GROUPING_ID(region, product_category, salesperson) AS grp_id
FROM sales_data
GROUP BY CUBE (region, product_category, salesperson);

SELECT salesperson, SUM(sale_amount) AS total_sales
FROM sales_data
GROUP BY salesperson
HAVING SUM(sale_amount) > 5000;

SELECT region, 
       SUM(sale_amount) AS total_sales,
       AVG(sale_amount) AS avg_sale
FROM sales_data
GROUP BY region
HAVING SUM(sale_amount) > 3000 
   AND AVG(sale_amount) < 2000;

SELECT region, product_category, COUNT(*) AS order_count
FROM sales_data
WHERE sale_date >= '2024-01-01'
GROUP BY region, product_category
HAVING COUNT(*) >= 2;

SELECT salesperson, COUNT(DISTINCT product_category) AS category_count
FROM sales_data
GROUP BY salesperson
HAVING COUNT(DISTINCT product_category) >= 2;

SELECT region, product_category, SUM(sale_amount) AS total
FROM sales_data
GROUP BY GROUPING SETS ((region), (product_category), ())
HAVING SUM(sale_amount) > 4000;

drop table if exists bison_t1;
create table bison_t1 (a int);
insert into bison_t1 values (2), (1), (3), (5);
insert into bison_t1 values (null);
commit;

select * from bison_t1 order by a;
select * from bison_t1 order by a asc;
select * from bison_t1 order by a desc;
select * from bison_t1 order by a nulls first;
select * from bison_t1 order by a nulls last;

select * from bison_t1 order by a desc limit 2 offset 1;
select * from bison_t1 order by a desc offset 2 limit 1;

select a from bison_t1 union select c from bison_t2;
select a from bison_t1 union all select c from bison_t2;
select a from bison_t1 intersect select c from bison_t2;
select a from bison_t1 intersect all select c from bison_t2;
select a from bison_t1 intersect distinct select c from bison_t2;
select a from bison_t1 except select c from bison_t2;
select a from bison_t1 except all select c from bison_t2;
select a from bison_t1 except distinct select c from bison_t2;
select a from bison_t1 minus select c from bison_t2;

select a from bison_t1 order by a union select c from bison_t2; -- error
(select a from bison_t1 order by a) union select c from bison_t2;
(select a from bison_t1 order by a) union (select c from bison_t2 order by c);
select a from bison_t1 union select c from bison_t2 order by a;

select a from bison_t1 limit 1 union select c from bison_t2; -- error
(select a from bison_t1 limit 1) union select c from bison_t2;

select * from bison_t1 for update;
select * from bison_t1 for update of a;
select * from bison_t1 for update of a nowait;
select * from bison_t1 for update of a wait 10;
select * from bison_t1 for update of a skip locked;
select a from bison_t1 union select c from bison_t2 order by a for update;
select a from bison_t1 for update union select c from bison_t2 order by a;


select SQL_CALC_FOUND_ROWS * from bison_t1 limit 2;
select found_rows();

select SQL_CALC_FOUND_ROWS c from bison_t2 union select a from bison_t1;
(select SQL_CALC_FOUND_ROWS c from bison_t2) union (select a from bison_t1);

select a from bison_t1 union select SQL_CALC_FOUND_ROWS c from bison_t2 limit 1;
(select a from bison_t1) union (select SQL_CALC_FOUND_ROWS c from bison_t2);

with tmp as (select c from bison_t2) select * from tmp;
(select a from bison_t1) union (with tmp as (select c from bison_t2) select * from tmp);

with tmp as (select a from bison_t1) select * from (with tmp as (select c from bison_t2) select * from tmp);

-- 子查询
select * from (select a from bison_t1);
select * from bison_t1 where a in (select c from bison_t2);

select * from (with tmp as (select c from bison_t2) select * from tmp), tmp;

with tmp as (with tmp1 as (select * from bison_t1) select * from tmp1) select * from tmp;

with tmp as (with tmp1 as (select * from bison_t1) select * from tmp1) select * from tmp order by a;

with tmp as (with tmp1 as (select * from bison_t1) select * from tmp1) select * from tmp limit 2;

-- 目标表：现有员工信息
drop table if exists employees;
CREATE TABLE employees (
    emp_id NUMBER PRIMARY KEY,
    name VARCHAR2(20),
    salary NUMBER,
    last_update DATE
);
INSERT INTO employees VALUES (1, '张三', 5000, SYSDATE-30);
INSERT INTO employees VALUES (2, '李四', 6000, SYSDATE-30);

-- 来源表：本次要同步的更新数据
drop table if exists salary_updates;
CREATE TABLE salary_updates (
    emp_id NUMBER PRIMARY KEY,
    new_salary NUMBER,
    update_date DATE
);
INSERT INTO salary_updates VALUES (1, 5500, SYSDATE); -- 张三加薪
INSERT INTO salary_updates VALUES (3, 7000, SYSDATE); -- 新员工王五

MERGE INTO employees e
USING salary_updates s
ON (e.emp_id = s.emp_id)
WHEN MATCHED THEN
    UPDATE SET 
        e.salary = s.new_salary,
        e.last_update = s.update_date
    WHERE s.new_salary > e.salary
WHEN NOT MATCHED THEN INSERT (e.emp_id, e.name, e.salary, e.last_update)
    VALUES (s.emp_id, '新员工', s.new_salary, s.update_date);

MERGE INTO employees e
USING salary_updates s
ON (e.emp_id = s.emp_id)
WHEN NOT MATCHED THEN INSERT (e.emp_id, e.name, e.salary, e.last_update)
    VALUES (s.emp_id, '新员工', s.new_salary, s.update_date);

MERGE INTO employees e
USING salary_updates s
ON (e.emp_id = s.emp_id)
WHEN MATCHED THEN
    UPDATE SET 
        e.salary = s.new_salary,
        e.last_update = s.update_date
    WHERE s.new_salary > e.salary;

MERGE INTO employees e
USING salary_updates s
ON (e.emp_id = s.emp_id)
WHEN NOT MATCHED THEN INSERT (e.emp_id, e.name, e.salary, e.last_update)
    VALUES (s.emp_id, '新员工', s.new_salary, s.update_date)
WHEN MATCHED THEN
    UPDATE SET 
        e.salary = s.new_salary,
        e.last_update = s.update_date
    WHERE s.new_salary > e.salary;

drop table bison_t1;
create table bison_t1 (a int, b int);
replace into bison_t1 (a, b) values (1,1), (2,2);
replace into bison_t1 (a, b) select 1,2;
replace into bison_t1 values (1,1), (2,2);
replace into bison_t1 select 1,2;
replace into bison_t1 set a = 5, b = 5;

drop table bison_t1;
drop table if exists bison_t1;

create temporary table #temp_bison_t1 (a int);
drop table #temp_bison_t1;
drop temporary table #temp_bison_t1;

drop table if exists bison_t1;
create table bison_t1 (a int);
drop view if exists v1;
create view v1 as select * from bison_t1;
drop table bison_t1;
drop table bison_t1 cascade;
drop table bison_t1 cascade constraints;

drop table if exists bison_t1;
create table bison_t1 (a int);
drop table bison_t1 purge;

drop table if exists bison_t1;
create table bison_t1 (a int);
drop table sys.bison_t1;

drop table if exists bison_t1;
create table bison_t1 (a int, b int);
create index bison_t1_idx on bison_t1 (a);
drop index sys.bison_t1_idx on bison_t1;
drop index if exists sys.bison_t1_idx on bison_t1;
create index bison_t1_idx on bison_t1 (a);
drop index sys.bison_t1_idx;
drop index if exists sys.bison_t1_idx;

create sequence bison_t1;
drop sequence if exists bison_t1;

drop tablespace bison_t1;
drop tablespace bison_t1 including contents cascade;
drop tablespace bison_t1 including contents and datafiles cascade;
drop tablespace bison_t1 including contents keep datafiles;

drop user if exists xbin;
drop user if exists xbin cascade;

drop public synonym public.syn1;
drop public synonym sys.syn1 force;
drop synonym public.syn1;
drop public synonym "PUBLIC".syn1;
drop synonym sys.syn1 force;

drop role xbin;

drop profile default cascade;
drop profile xxx cascade;

drop directory xxx;

drop function fun1;
drop function if exists fun1;
drop function if exists sys.fun1;
drop function if exists fun1(int); --error

drop procedure if exists pro1;
drop procedure if exists sys.pro1;

drop trigger if exists tri1;

drop package if exists pkg1;
drop package body if exists pkg1;

drop type if exists typ1 force;
drop type body if exists typ1 force;

drop library lib1;


create table bison_t1 (a int, b int);
insert into bison_t1 values (1,1);
truncate table bison_t1;
truncate table bison_t1 purge;
truncate table bison_t1 purge drop storage;
truncate table bison_t1 purge drop storage drop storage;
truncate table bison_t1 purge reuse storage;
truncate table bison_t1 purge reuse storage drop storage;

flashback table bison_t1 to scn '10';
flashback table bison_t1 to scn 10;
flashback table bison_t1 to TIMESTAMP to_timestamp('2025-12-15 10:00:00');

flashback table bison_t1 to before drop rename to tbison_t2;
flashback table bison_t1 to before drop;
flashback table bison_t1 to before truncate force;
flashback table bison_t1 to before truncate;

flashback table bison_t1 partition p1 to before truncate;

flashback table bison_t1 partition p1 to scn '10'; --error
flashback table bison_t1 partition p1 to before drop rename to tbison_t2; --error

comment on table bison_t1 is 'test comment table';
comment on column bison_t1.a is 'test comment column';
comment on table bison_t1 is 'xx''a';

comment on column bison_t1.a is '';
comment on column bison_t1.a is NULL; --error

drop table bison_t1;
create table bison_t1 (a int, b int);
create index bison_t1_idx on bison_t1(a);

analyze table bison_t1 compute statistics;
analyze table bison_t1 compute statistics for report;
analyze table bison_t1 compute statistics for report sample 60;

analyze index bison_t1_idx compute statistics;
analyze index bison_t1_idx estimate statistics 10;
analyze index bison_t1_idx compute statistics for report; --error

create database clustered db1 user SYS IDENTIFIED by 'Huawei@123' instance node 0 nologging undo tablespace tempfile 'a' size 10M undo tablespace datafile 'b' size 10M temporary TABLESPACE TEMPFILE 'c' size 10M logfile ('logfile1' size 10M blocksize 512, 'logfile2' size 10M blocksize 512, 'logfile3' size 10M blocksize 512) controlfile ('d', 'e') character set uft8 archivelog;

create database clustered db1 user SYS IDENTIFIED by 'Huawei@123' instance node 0 nologging undo tablespace tempfile 'a' size 10M undo tablespace datafile 'b' size 10M, 'bb' size 10M reuse autoextend off temporary TABLESPACE TEMPFILE 'c' size 10M logfile ('logfile1' size 10M blocksize 512, 'logfile2' size 10M blocksize 512, 'logfile3' size 10M blocksize 512) controlfile ('d', 'e') character set uft8 archivelog;

create database clustered db1 user SYS IDENTIFIED by 'Huawei@123' instance node 0 nologging undo tablespace tempfile 'a' size 10M undo tablespace datafile 'b' size 10M, 'bb' size 10M reuse autoextend on next 5M maxsize 100M temporary TABLESPACE TEMPFILE 'c' size 10M logfile ('logfile1' size 10M blocksize 512, 'logfile2' size 10M blocksize 512, 'logfile3' size 10M blocksize 512) controlfile ('d', 'e') character set uft8 archivelog;

create database clustered db1 user SYS IDENTIFIED by 'Huawei@123' nologging undo tablespace tempfile 'a' size 10M system tablespace datafile 'st' size 128.6M sysaux tablespace datafile 'ast' size 128M default tablespace datafile 'ast' size 1M instance node 0 nologging undo tablespace tempfile 'a' size 10M undo tablespace datafile 'b' size 10M temporary TABLESPACE TEMPFILE 'c' size 10M logfile ('logfile1' size 10M blocksize 512, 'logfile2' size 10M blocksize 512, 'logfile3' size 10M blocksize 512) controlfile ('d', 'e') character set uft8 archivelog MAXINSTANCES 5;

create database clustered db1 user SYS IDENTIFIED by 'Huawei@123' instance node 0 nologging undo tablespace tempfile 'a' size 10M undo tablespace datafile 'b' size 10M temporary TABLESPACE TEMPFILE 'c' size 10M logfile ('logfile1' size 10M blocksize 512, 'logfile2' size 10M blocksize 512, 'logfile3' size 10M blocksize 512) node 0 nologging undo tablespace tempfile 'aa' size 10M undo tablespace datafile 'bb' size 10M temporary TABLESPACE TEMPFILE 'cc' size 10M logfile ('logfile11' size 10M blocksize 512, 'logfile21' size 10M blocksize 512, 'logfile31' size 10M blocksize 512) controlfile ('d', 'e') character set uft8 noarchivelog;

create database db1 user xbin IDENTIFIED by 'Huawei@123'; --error


alter system set use_bison_parser = false;
