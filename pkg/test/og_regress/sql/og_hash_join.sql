DROP TABLE IF EXISTS small_customers;
DROP TABLE IF EXISTS small_orders;
CREATE TABLE small_customers (customer_id INT PRIMARY KEY, customer_name VARCHAR(50), city VARCHAR(50));
INSERT INTO small_customers VALUES (1,'Alice','New York'),(2,'Bob','London'),(3,'Charlie','New York'),(4,'David','Paris'),(5,'Eve','Berlin');
CREATE TABLE small_orders (order_id INT PRIMARY KEY, customer_id INT, order_date DATE, amount DECIMAL(10,2), city VARCHAR(50));
INSERT INTO small_orders VALUES (101,1,'2024-01-15',100.00,'New York'),(102,1,'2024-01-20',200.00,'London'),(103,2,'2024-01-25',150.00,'London'),(104,3,'2024-01-30',300.00,'New York'),(105,3,'2024-02-01',250.00,'Tokyo'),(106,3,'2024-02-05',400.00,'New York'),(107,5,'2024-02-10',500.00,'Berlin'),(108,5,'2024-02-15',350.00,'Berlin');
analyze table  small_customers  compute STATISTICS;
analyze table  small_orders  compute STATISTICS;
alter system set ENABLE_NESTLOOP_JOIN=false;
alter system set ENABLE_HASH_JOIN=true;

SELECT c.customer_id, c.customer_name, o.order_id, o.amount FROM small_customers c INNER JOIN small_orders o ON c.customer_id = o.customer_id AND c.city = o.city;
SELECT c.customer_id, c.customer_name, o.order_id, o.amount FROM small_customers c LEFT JOIN small_orders o ON c.customer_id = o.customer_id AND c.city = o.city AND o.amount > 200;
SELECT c.customer_id, c.customer_name FROM small_customers c WHERE EXISTS (SELECT 1 FROM small_orders o WHERE o.customer_id = c.customer_id AND o.city = c.city AND o.order_date > '2024-01-31');
SELECT c.customer_id, c.customer_name FROM small_customers c WHERE NOT EXISTS (SELECT 1 FROM small_orders o WHERE o.customer_id = c.customer_id AND o.city = c.city);
SELECT customer_id, customer_name FROM small_customers c WHERE customer_id IN (SELECT customer_id FROM small_orders WHERE city = 'New York' AND amount > 150);
SELECT customer_id, customer_name FROM small_customers c WHERE customer_id NOT IN (SELECT customer_id FROM small_orders WHERE city = c.city);
SELECT c.customer_id, c.customer_name, o1.order_id as order1, o2.order_id as order2 FROM small_customers c JOIN small_orders o1 ON c.customer_id = o1.customer_id JOIN small_orders o2 ON c.customer_id = o2.customer_id AND o1.order_id < o2.order_id AND o1.city = o2.city;
SELECT c.customer_id, c.customer_name FROM small_customers c JOIN small_orders o ON c.customer_id = o.customer_id WHERE c.city = 'New York' AND o.amount > 200 GROUP BY c.customer_id, c.customer_name HAVING COUNT(o.order_id) >= 2;
SELECT c.customer_name, o.order_id, o.amount FROM small_customers c RIGHT JOIN small_orders o ON c.customer_id = o.customer_id;
SELECT c.customer_name, o.order_id, o.amount FROM small_customers c RIGHT JOIN small_orders o ON c.customer_id = o.customer_id AND c.city = o.city;
SELECT c.customer_name, o.order_id, o.amount FROM small_orders o RIGHT JOIN small_customers c ON c.customer_id = o.customer_id;
SELECT c.customer_id, c.customer_name, o.order_id, o.amount FROM small_customers c RIGHT JOIN small_orders o ON c.customer_id = o.customer_id WHERE c.customer_id IS NULL;
SELECT c.customer_id, c.customer_name, o.order_id, o.amount FROM small_customers c RIGHT JOIN small_orders o ON c.customer_id = o.customer_id WHERE o.amount > 300;
SELECT c.city as customer_city, o.city as order_city, COUNT(o.order_id) FROM small_customers c RIGHT JOIN small_orders o ON c.customer_id = o.customer_id GROUP BY c.city, o.city;

SELECT c.customer_name, o.order_id FROM small_customers c FULL OUTER JOIN small_orders o ON c.customer_id = o.customer_id;
SELECT COUNT(*) FROM small_customers CROSS JOIN small_orders;
SELECT c.customer_id, c.customer_name, o.order_id, o.amount, RANK() OVER (PARTITION BY c.customer_id ORDER BY o.amount DESC) FROM small_customers c LEFT JOIN small_orders o ON c.customer_id = o.customer_id;
WITH high_value_orders AS (SELECT * FROM small_orders WHERE amount > 250) SELECT c.customer_name, h.order_id FROM small_customers c JOIN high_value_orders h ON c.customer_id = h.customer_id;

alter system set ENABLE_NESTLOOP_JOIN=true;