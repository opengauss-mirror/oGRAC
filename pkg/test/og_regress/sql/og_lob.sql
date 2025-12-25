DROP TABLE IF EXISTS lob_test;
CREATE TABLE lob_test (
    id            INT PRIMARY KEY,
    col_blob      BLOB,
    col_bytea     BYTEA,
    col_clob      CLOB,
    col_text      TEXT,
    col_longtext  LONGTEXT,
    col_long      LONG
);

INSERT INTO lob_test (
    id, col_blob, col_bytea, col_clob, col_text, col_longtext, col_long
) VALUES (
    1,
    HEXTORAW('626C6F625F64617461'),
    HEXTORAW('62797465615F64617461'),
    'small_clob_data',
    'small_text_data',
    'small_longtext_data',
    'small_long_data'
);

DECLARE
    big_str TEXT := RPAD('A', 1000000, 'A');
BEGIN
    INSERT INTO lob_test (
        id, col_blob, col_bytea, col_clob, col_text, col_longtext, col_long
    ) VALUES (
        2,
        big_str, big_str, big_str, big_str, big_str, big_str
    );
END;
/

SELECT
    id,
    col_blob,
    col_bytea,
    col_clob,
    col_text,
    col_longtext,
    col_long
FROM lob_test;

SELECT
    id,
    SUBSTR(col_clob || '_CLOB', 1, 30) AS clob_result,
    SUBSTR(col_text || '_TEXT', 1, 30) AS text_result,
    SUBSTR(col_longtext || '_LONGTXT', 1, 30) AS longtext_result,
    SUBSTR(col_long || '_LONG', 1, 30) AS long_result
FROM lob_test;