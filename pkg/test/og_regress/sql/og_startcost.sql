create table t_startcost(id serial primary key, b int, c int,d char(1));
create index idx_b on t_startcost(b);
create index idx_b_c on t_startcost(b,c);

BEGIN
    INSERT INTO t_startcost (b, c, d) VALUES (1, 10, 'A');
   
    FOR i IN 2..1000 LOOP
        INSERT INTO t_startcost (b, c, d) VALUES (
            MOD(i, 100),                    
            i * 10,                        
            CASE MOD(i, 4)
                WHEN 0 THEN 'A'
                WHEN 1 THEN 'B'
                WHEN 2 THEN 'C'
                WHEN 3 THEN 'D'
            END
        );
    END LOOP;
END;
/

analyze table t_startcost compute statistics;

explain select * from t_startcost;
explain select * from t_startcost where id = 100;

explain select * from t_startcost as a1 join t_startcost as a2 on (a1.b=a2.b);

explain select * from t_startcost limit 100;
explain select * from t_startcost limit 10 offset 800;

explain select b from t_startcost group by b;
explain select b, count(*) from t_startcost group by b; 
explain select b, d, count(*) from t_startcost group by b, d;

drop table if exists t_startcost;