drop table if exists t_fulljoin_0031;
create table t_fulljoin_0031
(customer_id integer,
 cust_first_name  varchar(20) not null,
 cust_last_name   varchar(20) not null,
 credit_limit integer
);

insert into t_fulljoin_0031 values (1, 'li', 'adjani', 100);
insert into t_fulljoin_0031 values (2, 'li', 'alexander', 2000);
insert into t_fulljoin_0031 values (3, 'li', 'altman', 5000);

select * from t_fulljoin_0031 t1 full join t_fulljoin_0031 t2 on
case t1.credit_limit
when 100 then upper('low')
when 5000 then upper('high')
when 2000 then upper('medium')
end <'low' order by 1,2,3,4;

drop table if exists t_fulljoin_0031;
