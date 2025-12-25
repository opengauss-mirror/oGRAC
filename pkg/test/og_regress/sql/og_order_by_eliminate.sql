--test order array element error
create table t_order_array_1(id number(5,5), c_int int[]);
select id, c_int from t_order_array_1 union all select id, c_int from t_order_array_1 order by id desc, c_int[2] + c_int[3] desc limit 1; -- error
select id, c_int from t_order_array_1 union all select id, c_int from t_order_array_1 order by id desc, c_int[2], c_int[3] desc limit 1; -- error
select id, c_int[1] from t_order_array_1 union all select id, c_int[1] from t_order_array_1 order by id desc, c_int[1] desc limit 1; -- success
select id, c_int[2] from t_order_array_1 union all select id, c_int[2] from t_order_array_1 order by id desc, c_int[3] desc limit 1; -- error
drop table if exists t_order_array_1;