drop FUNCTION if EXISTS func_add_sql011;
CREATE FUNCTION func_add_sql011(num1 integer) RETURN integer
AS
BEGIN
RETURN num1;
END;
/
select func_add_sql011(30) from sys_dummy;
drop FUNCTION func_add_sql011;
