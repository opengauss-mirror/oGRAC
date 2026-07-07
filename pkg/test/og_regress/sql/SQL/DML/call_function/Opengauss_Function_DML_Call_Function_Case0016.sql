drop FUNCTION if EXISTS func_add_sql017;
CREATE FUNCTION func_add_sql017(num1 integer, num2 char) RETURN char
AS
BEGIN
RETURN num2;
END;
/
select func_add_sql017(999,'hello') from sys_dummy;
drop FUNCTION func_add_sql017;
