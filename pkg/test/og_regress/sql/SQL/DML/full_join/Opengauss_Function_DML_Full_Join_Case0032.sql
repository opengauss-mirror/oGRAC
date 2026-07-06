drop table if exists t_fulljoin_0032;
create table t_fulljoin_0032
(customer_id integer,
 cust_first_name  varchar(20) not null,
 cust_last_name   varchar(20) not null,
 credit_limit integer
);

insert into t_fulljoin_0032 values (1, 'li', 'adjani', 100);
insert into t_fulljoin_0032 values (2, 'li', 'alexander', 2000);
insert into t_fulljoin_0032 values (3, 'li', 'altman', 5000);

select * from t_fulljoin_0032 t1 full join t_fulljoin_0032 t2 on
case t2.credit_limit
when 100 then 'low'
when 5000 then 'high'
when 2000 then 'medium'
end between 'high' and 'high'
join t_fulljoin_0032 t3 on
case t3.credit_limit
when 100 then 'low'
when 5000 then 'high'
when 2000 then 'medium'
end between 'high' and 'high' order by 1, 2, 3, 4;

drop table if exists t_fulljoin_0032;
