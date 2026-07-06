drop table if exists products17;
CREATE TABLE products17 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products17 values(01,'grains',5.5);
select * from products17;
insert into  products17 values(02,'grains',5.5) on DUPLICATE key update name='grains', price=5.5;
select * from products17;
insert into  products17 values(02,'grains',5.5) on DUPLICATE key update name='grains', price=5.5;
select * from  products17;
drop table products17;
