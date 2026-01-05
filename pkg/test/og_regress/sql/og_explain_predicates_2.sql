-- @owner: Nerifish
-- @date: 2026/1/31
-- @testpoint: explain执行条件中对varchar类型的between,like,in,is null测试,要求rows列的值与select尽可能相近
DROP TABLE IF EXISTS test_explain_data;

-- 创建测试表，使用varchar类型
CREATE TABLE test_explain_data (
    id INT PRIMARY KEY,
    varchar_col VARCHAR(100)  -- 使用varchar类型，最大长度100
);

-- 插入10000条随机数据
BEGIN
    DECLARE
        str_len INT;
        rand_str VARCHAR(100);
        rand_char CHAR(1);
        insert_pos INT;
    BEGIN
        -- 插入前100条特定数据，包含各种边界情况和特殊字符
        INSERT INTO test_explain_data VALUES 
        (1, 'abc'),
        (2, 'def'),
        (3, 'ghi'),
        (4, 'jkl'),
        (5, 'mno'),
        (6, 'pqr'),
        (7, 'stu'),
        (8, 'vwx'),
        (9, 'yz'),
        (10, ''),
        (11, 'a'),
        (12, 'z'),
        (13, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),  -- 40个a
        (14, 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'),  -- 40个z
        (15, 'abcdefghijklmnopqrstuvwxyzabcdefghijklmn'),  -- 40个字母
        (16, 'test'),
        (17, 'null_test'),
        (18, 'like_test'),
        (19, 'between_test'),
        (20, 'in_test'),
        (21, 'abc123'),
        (22, 'special%char'),
        (23, 'char_with_space'),
        (24, 'char_with_underscore'),
        (25, 'char-with-hyphen'),
        (26, 'char_with_numbers123'),
        (27, 'char_with_CAPS'),
        (28, 'char_with_特殊字符'),
        (29, 'char_with_mixed123abc'),
        (30, 'char_with_punctuation!'),
        (31, NULL),  -- 插入NULL值
        (32, NULL),  -- 插入NULL值
        (33, ''),
        (34, ' '),  -- 单个空格
        (35, '  '),  -- 两个空格
        (36, '        '),  -- 8个空格
        (37, '                                        '),  -- 40个空格
        (38, 'a b c d e'),
        (39, 'abc def ghi'),
        (40, 'test_data_123'),
        (41, 'very_long_string_that_is_close_to_max_length_but_not_quite_there_yet_1234567890'),
        (42, 'edge_case_1'),
        (43, 'edge_case_2'),
        (44, 'edge_case_3'),
        (45, '边界值测试'),
        (46, 'a' || CHR(9) || 'b'),  -- 包含制表符
        (47, 'a' || CHR(10) || 'b'),  -- 包含换行符
        (48, 'a' || CHR(13) || 'b'),  -- 包含回车符
        (49, 'unicode_测试'),
        (50, 'emoji_😀');
        
        -- 从51开始插入随机数据，直到10000
        FOR i IN 51..10000 LOOP
            -- 决定字符串长度：0到80之间随机，varchar(100)但保留一些空间
            str_len := MOD(i, 80);
            
            -- 初始化字符串
            rand_str := '';
            
            -- 根据长度生成随机小写字母字符串
            FOR j IN 1..str_len LOOP
                -- 使用MOD(i*j, 26)生成0-25的随机数，加上97得到小写字母的ASCII码
                rand_char := CHR(97 + MOD(i * j, 26));
                rand_str := rand_str || rand_char;
            END LOOP;
            
            -- 5%的概率插入NULL
            IF MOD(i, 20) = 0 THEN
                rand_str := NULL;
            END IF;
            
            -- 3%的概率插入空字符串
            IF MOD(i, 33) = 0 THEN
                rand_str := '';
            END IF;
            
            -- 2%的概率插入包含特殊字符的字符串
            IF MOD(i, 50) = 0 THEN
                -- 在随机位置插入特殊字符
                insert_pos := CASE 
                    WHEN str_len = 0 THEN 1 
                    ELSE MOD(i, str_len) + 1 
                END;
                rand_str := SUBSTRING(rand_str FROM 1 FOR insert_pos - 1) || 
                           CASE MOD(i, 8)
                               WHEN 0 THEN '%'
                               WHEN 1 THEN '_'
                               WHEN 2 THEN ' '
                               WHEN 3 THEN '-'
                               WHEN 4 THEN '!'
                               WHEN 5 THEN '@'
                               WHEN 6 THEN '#'
                               ELSE '$'
                           END ||
                           SUBSTRING(rand_str FROM insert_pos);
            END IF;
            
            -- 10%的概率插入包含数字的字符串
            IF MOD(i, 10) = 0 THEN
                rand_str := rand_str || MOD(i, 1000);
            END IF;
            
            -- 插入数据
            INSERT INTO test_explain_data VALUES (i, rand_str);
            
        END LOOP;
        
    END;
END;
/

-- 收集统计信息
ANALYZE TABLE test_explain_data compute statistics;

-----测试BETWEEN操作符适配-----
-- 用例1: BETWEEN 基础测试 - 小写字母范围
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col BETWEEN 'a' AND 'f';
SELECT count(*) FROM test_explain_data WHERE varchar_col BETWEEN 'a' AND 'f';

-- 用例2: BETWEEN 边界测试 - 从空字符串开始
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col BETWEEN '' AND 'c';
SELECT count(*) FROM test_explain_data WHERE varchar_col BETWEEN '' AND 'c';

-- 用例3: BETWEEN 边界测试 - 到特定字符串
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col BETWEEN 'x' AND 'zzzzzz';
SELECT count(*) FROM test_explain_data WHERE varchar_col BETWEEN 'x' AND 'zzzzzz';

-- 用例4: NOT BETWEEN 测试
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col NOT BETWEEN 'm' AND 't';
SELECT count(*) FROM test_explain_data WHERE varchar_col NOT BETWEEN 'm' AND 't';

-- 用例5: BETWEEN 长字符串范围
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col BETWEEN 'aaaaaaaaaa' AND 'mmmmmmmmmm';
SELECT count(*) FROM test_explain_data WHERE varchar_col BETWEEN 'aaaaaaaaaa' AND 'mmmmmmmmmm';

-----测试IS NULL操作符适配-----
-- 用例6: IS NULL 基础测试
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col IS NULL;
SELECT count(*) FROM test_explain_data WHERE varchar_col IS NULL;

-- 用例7: IS NOT NULL 测试
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col IS NOT NULL;
SELECT count(*) FROM test_explain_data WHERE varchar_col IS NOT NULL;

-----测试LIKE操作符适配-----
-- 用例8: LIKE 前缀匹配 - 以a开头
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE 'a%';
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE 'a%';

-- 用例9: LIKE 中间匹配 - 包含test
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '%test%';
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '%test%';

-- 用例10: LIKE 后缀匹配 - 以z结尾
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '%z';
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '%z';

-- 用例11: NOT LIKE 测试
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col NOT LIKE 'a%';
SELECT count(*) FROM test_explain_data WHERE varchar_col NOT LIKE 'a%';

-- 用例12: LIKE 单字符匹配
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '_';
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '_';

-- 用例13: LIKE 多字符匹配
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '____';  -- 正好4个字符
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '____';  -- 正好4个字符

-- 用例14: LIKE 带通配符的混合模式
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE 'a%z';
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE 'a%z';

-- 用例15: LIKE 匹配下划线（使用ESCAPE）
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '%\_%' ESCAPE '\';
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '%\_%' ESCAPE '\';

-- 用例16: LIKE 匹配百分号（使用ESCAPE）
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '%\%%' ESCAPE '\';
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '%\%%' ESCAPE '\';

-- 用例17: LIKE 匹配空格
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '% %';
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '% %';

-- 用例18: LIKE 复杂模式
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '_e%t';
SELECT count(*) FROM test_explain_data WHERE varchar_col LIKE '_e%t';

-----测试IN操作符适配-----
-- 用例19: IN 基础测试 - 单个字符
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col IN ('a', 'b', 'c', 'd', 'e');
SELECT count(*) FROM test_explain_data WHERE varchar_col IN ('a', 'b', 'c', 'd', 'e');

-- 用例20: IN 测试 - 多个字符串
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col IN ('abc', 'def', 'ghi', 'test');
SELECT count(*) FROM test_explain_data WHERE varchar_col IN ('abc', 'def', 'ghi', 'test');

-- 用例21: IN 测试 - 包含空字符串
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col IN ('', 'abc', 'def');
SELECT count(*) FROM test_explain_data WHERE varchar_col IN ('', 'abc', 'def');

-- 用例22: NOT IN 测试
EXPLAIN SELECT count(*) FROM test_explain_data WHERE varchar_col NOT IN ('abc', 'def', 'ghi');
SELECT count(*) FROM test_explain_data WHERE varchar_col NOT IN ('abc', 'def', 'ghi');

-- 清理环境
DROP TABLE IF EXISTS test_explain_data;