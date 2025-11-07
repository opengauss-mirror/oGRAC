/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * gspe.c
 *
 *
 * IDENTIFICATION
 * src/utils/gspe/gspe.c
 *
 * -------------------------------------------------------------------------
 */
#include "pe_module.h"
#include "cm_base.h"
#include "cm_defs.h"
#include "cm_encrypt.h"
#include "cm_utils.h"
#include "cm_file.h"
#include "cm_log.h"
#include "cm_date.h"
#include "cm_timer.h"
#include "cm_pbl.h"
#include "cm_system.h"
#ifdef WIN32
#include <conio.h>
#else
#include <termios.h>
#endif


static int32 g_optind = 1;

const char *g_env_home = "OGDB_HOME";
char *g_ogdb_home = NULL;

#define PE_LOG_FILE_PERMISSIONS  600
#define PE_LOG_PATH_PERMISSIONS  700
#define PE_LOG_FILE_PERMISSIONS_640  640
#define PE_LOG_PATH_PERMISSIONS_750  750
#define PE_LOG_MAX_SIZE          10240
#define PE_LOG_BACKUP_FILE_COUNT 10

typedef enum en_pe_cmd_type {
    E_PE_OPT_ENC_SCRAM_SHA256,
    E_PE_OPT_ENC_AES_256,
    E_PE_OPT_ENC_KDF2,
    E_PE_OPT_VERSION,
    E_PE_OPT_HELP,
    E_PE_OPT_GEN_KEY,
    E_PE_OPT_GEN_WORK_KEY,
    E_PE_OPT_GEN_KEY_FILE,
    E_PE_OPT_ENC_AES_256_REPL,
    E_PE_OPT_BUTT
} og_pe_cmd_type;

typedef struct st_pe_opt {
    const char* name;        // parameter name : begin with '-'
    uint32 extend_param_cnt; // follow parameter count
} og_pe_opt_t;

#define CHECKPARAM(min, max, arg)           \
    do {                                    \
        if ((arg) < (min) || (arg) > (max)) \
            return E_PE_OPT_BUTT;           \
    } while (0)
#define PE_ENCRYPTION_PBKDF2       "PBKDF2"
#define PE_ENCRYPTION_AES256_CBC   "AES256"
#define PE_ENCRYPTION_SCRAM_SHA256 "SCRAM_SHA256"

#define PE_ENC_PBKDF2_ARGC_MIN 3
#define PE_ENC_SCRAM_ARGC_MIN 5

#define PE_ENC_KMC_ARGC_MAX 17

#define PE_ARGS_MAX 17

#define OG_CMD_BUFFER_SIZE 1024
#define OG_HOST_BUFFER_SIZE 256

static int32 get_encryption(const char *arg)
{
    if (arg == NULL) {
        return E_PE_OPT_BUTT;
    }
    text_t text;
    cm_str2text((char*)arg, &text);

    if (cm_text_str_equal_ins(&text, PE_ENCRYPTION_PBKDF2)) {
        return E_PE_OPT_ENC_KDF2;
    }
    if (cm_text_str_less_equal_ins(&text, PE_ENCRYPTION_AES256_CBC, 3)) {
        return E_PE_OPT_ENC_AES_256;
    }
    if (cm_text_str_less_equal_ins(&text, PE_ENCRYPTION_SCRAM_SHA256, 5)) {
        return E_PE_OPT_ENC_SCRAM_SHA256;
    }

    return E_PE_OPT_BUTT;
}

static og_pe_opt_t g_expect_opts[] = {
    { "h", 0 },
    { "v", 0 },
    { "r", 0 },
    { "d", 1 },
    { "e", 1 },
    { "k", 1 },
    { "f", 1 },
    { "o", 1 },
    { "i", 1 },
    { "g", 0 },
    { "b", 1 },
    { "u", 1 }
};

#define OG_PE_EXPEOG_CNT (sizeof(g_expect_opts) / sizeof(og_pe_opt_t))

static int32 pe_parse_opt(int32 argc, char **argv, const og_pe_opt_t *expect_opts, uint32 expect_cnt, char **extend_opt)
{
    int32 begin_idx = g_optind;
    *extend_opt = NULL;

    OG_RETVALUE_IFTRUE(begin_idx >= argc, -1);
    OG_RETVALUE_IFTRUE((argv[begin_idx][0] != '-' || argv[begin_idx][1] == '\0'), -1);

    for (uint32 i = 0; i < expect_cnt; i++) {
        if (cm_strcmpi(expect_opts[i].name, &argv[begin_idx][1]) == 0) {
            OG_RETVALUE_IFTRUE(((int32)expect_opts[i].extend_param_cnt + begin_idx >= argc), -1);
            begin_idx++;
            if (expect_opts[i].extend_param_cnt > 0) {
                *extend_opt = argv[begin_idx];
            }
            g_optind += (1 + expect_opts[i].extend_param_cnt);
            return (int32)argv[begin_idx - 1][1];
        }
    }

    return '?';
}
static og_pe_cmd_type get_option(int32 argc, char **argv, const char **key, const char **work_key, const char **dir)
{
    int32 opt = -1;
    CHECKPARAM(2, PE_ARGS_MAX, argc);
    og_pe_cmd_type cmd = E_PE_OPT_BUTT;
    char* extend_opt = NULL;

    while ((opt = pe_parse_opt(argc, argv, g_expect_opts, OG_PE_EXPEOG_CNT, &extend_opt)) != -1) {
        switch (opt) {
            case 'e':
            case 'E':
                cmd = get_encryption(extend_opt);
                if (cmd == E_PE_OPT_ENC_AES_256) {
                    CHECKPARAM(7, 7, argc);
                } else if (cmd == E_PE_OPT_ENC_KDF2) {
                    CHECKPARAM(3, 7, argc);
                } else if (cmd == E_PE_OPT_ENC_SCRAM_SHA256) {
                    CHECKPARAM(3, 9, argc);
                } else {
                    CHECKPARAM(3, 3, argc);
                }
                break;
            case 'v':
            case 'V':
                CHECKPARAM(2, 2, argc);
                return E_PE_OPT_VERSION;
            case 'h':
            case 'H':
                CHECKPARAM(2, 4, argc);
                return E_PE_OPT_HELP;
            case 'g':
            case 'G':
                if (argc == 2) {
                    return E_PE_OPT_GEN_KEY;
                }
                CHECKPARAM(4, 4, argc);
                cmd = E_PE_OPT_GEN_KEY;
                break;
            case 'o':
            case 'O':
                CHECKPARAM(4, 4, argc);
                *key = extend_opt;
                if (cmd == E_PE_OPT_GEN_KEY) {
                    cmd = E_PE_OPT_GEN_KEY_FILE;
                }
                break;
            case 'f':
            case 'F':
                CHECKPARAM(4, PE_ENC_KMC_ARGC_MAX, argc);
                *key = extend_opt;
                if (cmd == E_PE_OPT_GEN_KEY) {
                    cmd = E_PE_OPT_GEN_WORK_KEY;
                }
                break;
            case 'k':
            case 'K':
                CHECKPARAM(5, PE_ENC_KMC_ARGC_MAX, argc);
                *work_key = extend_opt;

                break;
            case 'i':
            case 'I':
                CHECKPARAM(5, 9, argc);
                *key = extend_opt;
                break;
            case 'b':
            case 'B':
                if (cmd == E_PE_OPT_ENC_KDF2) {
                    CHECKPARAM(7, 7, argc);
                } else if (cmd == E_PE_OPT_ENC_SCRAM_SHA256) {
                    CHECKPARAM(7, 9, argc);
                } else {
                    return E_PE_OPT_BUTT;
                }
                *dir = extend_opt;
                break;
            case 'u':
            case 'U':
                if (cmd == E_PE_OPT_ENC_KDF2) {
                    CHECKPARAM(7, 7, argc);
                } else if (cmd == E_PE_OPT_ENC_SCRAM_SHA256) {
                    CHECKPARAM(7, 9, argc);
                } else {
                    return E_PE_OPT_BUTT;
                }
                *work_key = extend_opt;
                break;
            case 'r':
            case 'R':
                CHECKPARAM(4, 4, argc);
                cmd = E_PE_OPT_ENC_AES_256_REPL;
                break;
            case 'd':
            case 'D':
                CHECKPARAM(4, 4, argc);
                *dir = extend_opt;
                break;
            default:
                return E_PE_OPT_BUTT;
        }
    }
    return cmd;
}

static void pe_usage(void)
{
    printf("Usage: ctencrypt [OPTION]\n"
           "   Or: ctencrypt {-h|-H}\n"
           "   Or: ctencrypt {-v|-V}\n"
           "   Or: ctencrypt {-e|-E} PBKDF2 [{-u|U} user {-b|B} file]\n"
           "   Or: ctencrypt {-e|-E} SCRAM[_SHA256] [-i iter_count] [{-u|U} user {-b|B} file]\n"
           "   Or: ctencrypt {-e|-E} AES[256] {-f|-F} factor_key {-k|-K} work_key\n"
           "   Or: ctencrypt {-g|-G} [{-f factor_key | -o key_file}]\n"
           "   Or: ctencrypt {-r|-R} {-d|-D data_dir}\n"
           "Option:\n"
           "\t -h/-H                 Show the help information.\n"
           "\t -v/-V                 Show version information.\n"
           "\t -e/-E                 When encrypt password, allows user to specify encryption algorithm.\n"
           "\t                       Use PBKDF2/SCRAM_SHA256 to encrypt user password.\n"
           "\t                       Use AES256 to encrypt SSL private key password.\n"
           "\t -u/-U                 Specify the user,The -U/u parameter is used with the -B/b parameter at the same time.\n"
           "\t -b/-B                 Specify the password black list file used in PBKDF2/SCRAM_SHA256 encryption.\n"
           "\t -k/-K                 When encrypt using AES256, allows user to specify encrypt key.\n"
           "\t -g/-G                 Generate key, factor key or work key(based on factor key) randomly.\n"
           "\t -f/-F                 When encrypt using AES256 or generate work key, allows user to specify factor key.\n"
           "\t -o/O                  When generate factor key file, allows user to specify output file name.\n"
           "\t -i                    When encrypt using SCRAM_SHA256, allows user to specify iteration count.\n"
           "\t -r/-R                 Use AES256 to encrypt user password for replication, stores the keys and cipher into data_dir/dbs.\n"
           "\t -d/-D                 Specify the data dir to store keys and cipher for replication.\n");
}

#ifdef WIN32
const char *ogencrypt_getDBVersion()
{
    return "NONE";
}
#else
extern const char *ogencrypt_getDBVersion(void);
#endif

static void pe_print_version(void)
{
    printf("%s\n", ogencrypt_getDBVersion());
}

static int32 pe_get_one_char()
{
#ifdef WIN32
    return _getch();

#else
    uint32 count;
    int32 char_ascii;
    struct termios oldt;
    struct termios newt;
    (void)tcgetattr(STDIN_FILENO, &oldt);

    count = sizeof(newt);
    if (count != 0) {
        MEMS_RETURN_IFERR(memcpy_s(&newt, count, &oldt, count));
    }
    newt.c_lflag &= ~(ECHO | ICANON | ECHOE | ECHOK | ECHONL | ICRNL);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    char_ascii = getchar();

    /* Restore the old setting of terminal */
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return char_ascii;
#endif
}

static void receive_password_tip(bool32 isfirst)
{
    if (isfirst) {
        (void)printf("Please enter password to encrypt: \n");
    } else {
        (void)printf("Please input password again: \n");
    }
}

static status_t receive_password_from_terminal(char *buff, int32 buff_size, bool32 isfirst)
{
    int32 pos = 0;
    char char_ascii;
    int32 key = 0;
    bool32 len_exceed = OG_FALSE;

    CM_POINTER(buff);

    receive_password_tip(isfirst);

    do {
        key = pe_get_one_char();
        if (key < 0) {
            (void)printf("invalid char which may be EOF found");
            return OG_ERROR;
        }

        char_ascii = (char)key;

#ifdef WIN32
        if (char_ascii == KEY_BS) {
#else
        if (char_ascii == KEY_BS || char_ascii == KEY_BS_LNX) {
#endif
            if (pos > 0) {
                buff[pos] = '\0';
                pos--;

                /*
                * Recv a key of backspace, print a '\b' backing a char
                and printing
                * a space replacing the char displayed to screen
                with the space.
                */
                (void)printf("\b");
                (void)printf(" ");
                (void)printf("\b");
            } else {
                continue;
            }
        } else if (char_ascii == KEY_LF || char_ascii == KEY_CR) {
            break;
        } else {
            /*
            * Only recv the limited length of pswd characters, on beyond,
            * contine to get a next char entered by user.
            */
            if (pos >= buff_size - 1) {
                len_exceed = OG_TRUE;
                continue;
            }

            /* Faking a mask star * */
            (void)printf("*");
            buff[pos] = char_ascii;
            pos++;
        }
    } while (OG_TRUE);

    buff[pos < buff_size - 1 ? pos : buff_size - 1] = '\0';
    (void)printf("\n");

    if (len_exceed == OG_TRUE) {
        (void)printf("invalid password, maximum length is %u\n", buff_size - 1);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t verify_password_str(const char *text, const char *rptext, bool32 repl_passwd)
{
    uint32 len;
    uint32 rlen;
    char *name = "sys";
    CM_POINTER2(text, rptext);

    // Verify input twice pswd
    len = (uint32)strlen(text);
    rlen = (uint32)strlen(rptext);
    if (len != rlen || strcmp(text, rptext) != 0) {
        printf("Input twice passwords are inconsistent.\n");
        return OG_ERROR;
    }
    
    uint32 pwd_len = repl_passwd ? OG_REPL_PASSWD_MIN_LEN : OG_PASSWD_MIN_LEN;

    return cm_verify_password_str(name, text, pwd_len);
}

static status_t pe_catch_input_text(char *plain, uint32 plain_size, bool32 repl_passwd)
{
    char first[OG_PASSWD_MAX_LEN + 1] = { 0 };
    char second[OG_PASSWD_MAX_LEN + 1] = { 0 };
    status_t ret;
    errno_t errcode;

    do {
        ret = receive_password_from_terminal(first, sizeof(first), OG_TRUE);
        OG_BREAK_IF_ERROR(ret);

        ret = receive_password_from_terminal(second, sizeof(second), OG_FALSE);
        OG_BREAK_IF_ERROR(ret);

        ret = verify_password_str(first, second, repl_passwd);
        if (ret != OG_SUCCESS) {
            printf("1.password can't be more than 64 characters\n"
                "2:password %s can't be less than %d characters\n"
                "3.password should contain at least "
                "three type the following characters:\n"
                "A. at least one lowercase letter\n"
                "B. at least one uppercase letter\n"
                "C. at least one digit\n"
                "D. at least one special character: `~!@#$%%^&*()-_=+\\|[{}]:\'\",<.>/? and space\n",
                repl_passwd ? "authentication between primary and standby " : "",
                repl_passwd ? OG_REPL_PASSWD_MIN_LEN : OG_PASSWD_MIN_LEN);
            break;
        }

        errcode = memcpy_s(plain, plain_size, first, OG_PASSWD_MAX_LEN + 1);
        if (errcode != EOK) {
            ret = OG_ERROR;
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            break;
        }
    } while (0);

    MEMS_RETURN_IFERR(memset_s(first, OG_PASSWD_MAX_LEN + 1, 0, OG_PASSWD_MAX_LEN + 1));
    MEMS_RETURN_IFERR(memset_s(second, OG_PASSWD_MAX_LEN + 1, 0, OG_PASSWD_MAX_LEN + 1));

    return ret;
}
#define KEY_ADD_INFO_LEN_MAX 4
static status_t pe_generate_aes256_cbc(const char *fkey, const char *wkey, char *plain, uint32 max_plain_size)
{
    text_t text;
    char factor_key[OG_MAX_FACTOR_KEY_STR_LEN + KEY_ADD_INFO_LEN_MAX];
    char local_key[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + KEY_ADD_INFO_LEN_MAX];
    char cipher[OG_PASSWORD_BUFFER_SIZE] = { 0 };
    uint32 cipher_len = OG_PASSWORD_BUFFER_SIZE - 1;

    cm_str2text((char *)fkey, &text);
    cm_trim_text(&text);
    if (text.len != OG_MAX_FACTOR_KEY_STR_LEN) {
        printf("Factor key '%s' is invalid.\n", fkey);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_text2str(&text, factor_key, sizeof(factor_key)));

    cm_str2text((char *)wkey, &text);
    cm_trim_text(&text);
    if (text.len != OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE) {
        printf("Work key '%s' is invalid.\n", wkey);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_text2str(&text, local_key, sizeof(local_key)));

    if (pe_catch_input_text(plain, max_plain_size, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_encrypt_passwd(OG_TRUE, plain, (uint32)strlen(plain),
        cipher, &cipher_len, local_key, factor_key) != OG_SUCCESS) {
        printf("Fail to encrypt password.\n");
        return OG_ERROR;
    }

    printf("Cipher: \t%s\n", cipher);
    return OG_SUCCESS;
}

static status_t pe_generate_repl_key_cipher(const char *dir, char *plain, uint32 max_plain_size)
{
    char fkey[OG_AES256KEYSIZE] = { 0 };
    char wkey[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1] = { 0 };
    char cipher[OG_PASSWORD_BUFFER_SIZE] = { 0 };

    if (!cm_dir_exist(dir)) {
        printf("directory %s does not exist.\n", dir);
        return OG_ERROR;
    }

    /* Generate factor key and worker key */
    if (cm_generate_repl_key(fkey, sizeof(fkey), wkey, sizeof(wkey)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* Fetch plain passwd */
    if (pe_catch_input_text(plain, max_plain_size, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* Generate cipher */
    if (cm_generate_repl_cipher(plain, fkey, wkey, cipher, sizeof(cipher)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* Store keys and cipher */
    if (cm_pwd_store_keys(dir, cipher, fkey, wkey) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}
#ifndef WIN32
static status_t pe_check_file(const char *user, const char *pwd_file)
{
    char realfile[OG_UNIX_PATH_MAX] = { 0 };
    if ((pwd_file == NULL) || (user == NULL)) {
        pe_usage();
        return OG_ERROR;
    }
    if (realpath_file(pwd_file, realfile, OG_UNIX_PATH_MAX) != OG_SUCCESS) {
        printf("An error occurs in password blacklist file.\n");
        return OG_ERROR;
    }
    if (cm_check_exist_special_char(realfile, (uint32)strlen(realfile))) {
        printf("An error occurs in password blacklist file.\n");
        return OG_ERROR;
    }
    if (cm_access_file((const char *)realfile, R_OK) != OG_SUCCESS) {
        printf("password blacklist file can't access.\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t pe_check_pwd_in_file(const char *user, char *pwd, uint32 pwd_size, char *filename)
{
    black_context_t black_ctx;
    char log_pwd[OG_PWD_BUFFER_SIZE] = {0};
    OG_INIT_SPIN_LOCK(black_ctx.lock);
    cm_create_list(&black_ctx.user_pwd_black_list, sizeof(pbl_entry_t));
    if (cm_load_pbl(&black_ctx, filename, OG_MAX_PBL_FILE_SIZE) != OG_SUCCESS) {
        printf("An error occurs in password blacklist file.\n");
        return OG_ERROR;
    }
    if (cm_check_pwd_black_list(&black_ctx, user, pwd, log_pwd)) {
        printf("The password violates the pbl rule\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}
static status_t pe_check_pwd(const char *user, char *pwd, uint32 pwd_size, const char *pwd_file)
{
    char filename[OG_UNIX_PATH_MAX] = { 0 };
    if (CM_IS_EMPTY_STR(pwd_file) || CM_IS_EMPTY_STR(user)) {
        return OG_SUCCESS;
    }

    if (realpath_file(pwd_file, filename, OG_UNIX_PATH_MAX) != OG_SUCCESS) {
        printf("An error occurs in password blacklist file.\n");
        return OG_ERROR;
    }

    if (pe_check_pwd_in_file(user, pwd, pwd_size, filename) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cm_verify_password_str(user, pwd, OG_PASSWD_MIN_LEN) != OG_SUCCESS) {
        printf("The password cannot be the same as the user or the reverse of the user.\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}
static status_t pe_check_encrypt_args(og_pe_cmd_type cmd, int32 argc, const char *user, const char *pwd_file)
{
    if ((cmd == E_PE_OPT_ENC_KDF2 && argc > PE_ENC_PBKDF2_ARGC_MIN) ||
        (cmd == E_PE_OPT_ENC_SCRAM_SHA256 && argc > PE_ENC_SCRAM_ARGC_MIN)) {
        if (pe_check_file(user, pwd_file) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}
#endif

static status_t pe_generate_kdf2(const char *user, const char *pwd_file, char *plain, uint32 max_plain_size)
{
    uchar cipher[OG_PASSWORD_BUFFER_SIZE] = { 0 };
    uint32 cipher_len = OG_PASSWORD_BUFFER_SIZE - 1;

    if (pe_catch_input_text(plain, max_plain_size, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }
#ifndef WIN32
    if (pe_check_pwd(user, plain, max_plain_size, pwd_file)) {
        return OG_ERROR;
    }
#endif
    if (cm_generate_kdf2(plain, (uint32)strlen(plain), cipher, &cipher_len) != OG_SUCCESS) {
        printf("Fail to encrypt password.\n");
        return OG_ERROR;
    }

    printf("Cipher: \t%s\n", cipher);
    return OG_SUCCESS;
}

static status_t pe_generate_scram_sha256(const char *key, const char *user, const char *pwd_file, char *plain, uint32
    max_plain_size)
{
    uint32 iter_count;
    uchar cipher[OG_PASSWORD_BUFFER_SIZE] = { 0 };
    uint32 cipher_len = OG_PASSWORD_BUFFER_SIZE - 1;

    if (!CM_IS_EMPTY_STR(key)) {
        if (cm_str2int(key, (int32 *)&iter_count) != OG_SUCCESS) {
            printf("Invalid iteration %s\n", key);
            return OG_ERROR;
        }
        if (iter_count > OG_KDF2MAXITERATION || iter_count < OG_KDF2MINITERATION) {
            printf("Iteration must between %u and %u\n", OG_KDF2MINITERATION, OG_KDF2MAXITERATION);
            return OG_ERROR;
        }
    } else {
        iter_count = OG_KDF2DEFITERATION;
    }

    if (pe_catch_input_text(plain, max_plain_size, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }
#ifndef WIN32
    if (pe_check_pwd(user, plain, max_plain_size, pwd_file) != OG_SUCCESS) {
        return OG_ERROR;
    }
#endif
    if (cm_generate_scram_sha256(plain, (uint32)strlen(plain), iter_count, cipher, &cipher_len) != OG_SUCCESS) {
        printf("Fail to encrypt password.\n");
        return OG_ERROR;
    }

    printf("Cipher: \t%s\n", cipher);
    return OG_SUCCESS;
}

static status_t pe_generate_random_key(void)
{
    uchar key[OG_AESBLOCKSIZE] = { 0 };
    char rand_key[OG_AES256KEYSIZE] = { 0 };
    char work_key[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1];
    uint32 cipher_len = OG_AES256KEYSIZE;
    OG_RETURN_IFERR(cm_rand(key, OG_AESBLOCKSIZE));
    OG_RETURN_IFERR(cm_base64_encode(key, OG_AESBLOCKSIZE, rand_key, &cipher_len));

    printf("Key: \t\t%s\n", rand_key);

    if (cm_generate_work_key(rand_key, work_key, sizeof(work_key)) != OG_SUCCESS) {
        printf("Failed to generate work key\n");
        return OG_ERROR;
    }
    printf("WorkKey: \t%s\n", work_key);

    return OG_SUCCESS;
}

static status_t pe_generate_random_work_key(const char *factor_key)
{
    char work_key[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + KEY_ADD_INFO_LEN_MAX];
    uint32 fkey_len = cm_base64_encode_len(OG_AESBLOCKSIZE) - 1;

    if (CM_IS_EMPTY_STR(factor_key)) {
        printf("Factor key is illegal\n");
        return OG_ERROR;
    }

    if (strlen(factor_key) != fkey_len) {
        printf("Invalid factor key, key length is %u, expect %u\n", (uint32)strlen(factor_key), fkey_len);
        return OG_ERROR;
    }

    if (cm_generate_work_key(factor_key, work_key, sizeof(work_key)) != OG_SUCCESS) {
        printf("Failed to generate work key\n");
        return OG_ERROR;
    }

    printf("Key: \t\t%s\nWorkKey: \t%s\n", factor_key, work_key);
    return OG_SUCCESS;
}

static status_t pe_generate_random_keyfile(const char *keyfile)
{
    status_t ret;
    int32 handle;
    char filepath[OG_FILE_NAME_BUFFER_SIZE];
    uchar file_buf[OG_AESBLOCKSIZE + OG_HMAC256MAXSIZE + KEY_ADD_INFO_LEN_MAX];
    char rand_key[OG_MAX_LOCAL_KEY_STR_LEN + KEY_ADD_INFO_LEN_MAX] = { 0 };
    char work_key[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1];
    char file_dir[OG_MAX_PATH_LEN] = { 0 };
    char *p = NULL;
    uint32 cipher_len;
    uint32 file_size;
    errno_t errcode;

    if (CM_IS_EMPTY_STR(keyfile)) {
        printf("Output keyfile name is required\n");
        return OG_ERROR;
    }

    // file exists
    if (cm_file_exist(keyfile)) {
        printf("keyfile '%s' already exists\n", keyfile);
        return OG_ERROR;
    }

    // dir not exist
    errcode = strncpy_s(file_dir, sizeof(file_dir), keyfile, strlen(keyfile));
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OG_ERROR;
    }
    p = strrchr(file_dir, '/');
    if (p != NULL) {
        *p = '\0';
        if (!cm_dir_exist(file_dir) || 0 != access(file_dir, W_OK | R_OK)) {
            printf("directory '%s' does not exist, or no permission to access\n", file_dir);
            return OG_ERROR;
        }
    }

#ifdef WIN32
    if (!_fullpath(filepath, keyfile, sizeof(filepath) - 1)) {
        printf("Output keyfile '%s' is illegal\n", keyfile);
        return OG_ERROR;
    }
#else
    char resolved_path[PATH_MAX];
    if (!realpath(keyfile, resolved_path)) {
        if (errno != ENOENT) {
            printf("Output keyfile '%s' is illegal\n", keyfile);
            return OG_ERROR;
        }
    }
    if (strlen(resolved_path) >= OG_FILE_NAME_BUFFER_SIZE) {
        printf("Output keyfile name is too long\n");
        return OG_ERROR;
    }
    errcode = strncpy_s(filepath, OG_FILE_NAME_BUFFER_SIZE, resolved_path, strlen(resolved_path));
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return OG_ERROR;
    }
#endif  // WIN32

    // generate random key
    ret = cm_rand(file_buf, OG_AESBLOCKSIZE);
    OG_RETURN_IFERR(ret);
    file_size = OG_AESBLOCKSIZE;

    // encrypt hmac
    cipher_len = sizeof(file_buf) - file_size;
    OG_RETURN_IFERR(cm_encrypt_HMAC(file_buf, OG_AESBLOCKSIZE, file_buf, OG_AESBLOCKSIZE,
                                      (uchar *)(file_buf + OG_AESBLOCKSIZE), &cipher_len));
    file_size += cipher_len;

    // write keyfile
    if (cm_open_file_ex(filepath, O_SYNC | O_CREAT | O_RDWR | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR, &handle)) {
        printf("Open file failed\n");
        return OG_ERROR;
    }
    ret = cm_write_file(handle, file_buf, file_size);
    cm_close_file(handle);
    OG_RETURN_IFERR(ret);

    cipher_len = sizeof(rand_key) - 1;
    ret = cm_base64_encode(file_buf, OG_AESBLOCKSIZE, rand_key, &cipher_len);
    OG_RETURN_IFERR(ret);

    OG_RETURN_IFERR(cm_generate_work_key(rand_key, work_key, sizeof(work_key)));

    printf("Key: \t\t%s\n", rand_key);
    printf("WorkKey: \t%s\n", work_key);
    printf("Keyfile: \t%s\n", filepath);

    return OG_SUCCESS;
}

static status_t pe_execute_command(og_pe_cmd_type option, const char *key, const char *work_key, const char *dir)
{
    status_t stat = OG_SUCCESS;
    SENSI_INFO char plain[OG_PASSWD_MAX_LEN + 1] = { 0 };

    switch (option) {
        case E_PE_OPT_ENC_SCRAM_SHA256:
            stat = pe_generate_scram_sha256(key, work_key, dir, plain, OG_PASSWD_MAX_LEN + 1);
            break;
        case E_PE_OPT_ENC_KDF2:
            stat = pe_generate_kdf2(work_key, dir, plain, OG_PASSWD_MAX_LEN + 1);
            break;
        case E_PE_OPT_ENC_AES_256:
            stat = pe_generate_aes256_cbc(key, work_key, plain, OG_PASSWD_MAX_LEN + 1);
            break;
        case E_PE_OPT_VERSION:
            pe_print_version();
            break;
        case E_PE_OPT_GEN_KEY:
            stat = pe_generate_random_key();
            break;
        case E_PE_OPT_GEN_WORK_KEY:
            stat = pe_generate_random_work_key(key);
            break;
        case E_PE_OPT_GEN_KEY_FILE:
            stat = pe_generate_random_keyfile(key);
            break;
        case E_PE_OPT_ENC_AES_256_REPL:
            stat = pe_generate_repl_key_cipher(dir, plain, OG_PASSWD_MAX_LEN + 1);
            break;
        case E_PE_OPT_BUTT:
            stat = OG_ERROR;
        case E_PE_OPT_HELP:
        default:
            pe_usage();
            break;
    }

    MEMS_RETURN_IFERR(memset_s(plain, OG_PASSWD_MAX_LEN + 1, 0, OG_PASSWD_MAX_LEN + 1));
    return stat;
}

static bool32 srv_check_ctencrypt_root(void)
{
#ifndef WIN32
    if (geteuid() == 0) {
        printf("\"root\" execution of the ogencrypt tool is not permitted.\n");
        return OG_TRUE;
    }

    if (getuid() != geteuid()) {
        printf("ogencrypt: real and effective user IDs must match\n");
        return OG_TRUE;
    }
#endif
    return OG_FALSE;
}
#ifndef WIN32
static void pe_exec_cmd(const char *cmd, uint32 cmd_len, char *res, uint32 res_len)
{
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return;
    }
    char *unused __attribute__((unused));
    unused = fgets(res, res_len, fp);
    (void)pclose(fp);
    return;
}
static void pe_get_user_ip(char *host, uint32 hostlen, char *user, uint32 userlen)
{
    char cmd[OG_CMD_BUFFER_SIZE] = "who am i| awk '{print $1, $NF}'";
    char res[OG_CMD_BUFFER_SIZE] = { 0 };
    text_t res_text;
    text_t user_text;
    errno_t errcode;
    pe_exec_cmd(cmd, OG_CMD_BUFFER_SIZE, res, OG_CMD_BUFFER_SIZE);
    res_text.str = res;
    res_text.len = (uint32)strlen(res);
    if (res_text.len == 0) {
        return;
    }
    if (!cm_fetch_text(&res_text, ' ', 0, &user_text)) {
        return;
    }
    res_text.len--; // remove \n
    cm_remove_brackets(&res_text); // remove bracket
    errcode = strncpy_s(user, userlen, user_text.str, user_text.len);
    if (errcode != EOK) {
        return;
    }
    errcode = strncpy_s(host, hostlen, res_text.str, res_text.len);
    if (errcode != EOK) {
        return;
    }
}
#endif

static status_t pe_oper_log_begin(char *log_buf, uint32 log_buf_len)
{
    int ret;
    char date[OG_MAX_TIME_STRLEN];
    char host[OG_HOST_BUFFER_SIZE + 1] = "NULL";
    char user[OG_NAME_BUFFER_SIZE] = "NULL";
#ifdef WIN32
    char *username = cm_sys_user_name();
    errno_t errcode = strncpy_s(user, OG_NAME_BUFFER_SIZE, username, strlen(username));
    if (errcode != EOK) {
        return OG_ERROR;
    }
    if (cm_get_host_ip(host, OG_HOST_BUFFER_SIZE + 1) == OG_ERROR) {
        return OG_ERROR;
    }
#else
    char *rv = ttyname(0);
    if (rv != NULL) {
        pe_get_user_ip(host, OG_HOST_BUFFER_SIZE + 1, user, OG_NAME_BUFFER_SIZE);
    }
#endif
    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, OG_MAX_TIME_STRLEN);
    ret = snprintf_s(log_buf, log_buf_len, log_buf_len - 1,
        "[TIME:%s] [USER:%s] [HOST IP:%s] [ogencrypt] [LOG] ogencrypt ", date, user, host);
    if (ret == -1) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

#define MAX_PE_ARG 17
static status_t pe_oper_log(int32 argc, char **argv, status_t stat)
{
    char log_buf[PE_LOG_MAX_SIZE];
    uint32 offset;
    uint32 arg_len;
    uint32 log_buf_len = PE_LOG_MAX_SIZE;
    int32 i;
    int32 ret;
    errno_t errcode;
    OG_RETURN_IFERR(pe_oper_log_begin(log_buf, log_buf_len));
    offset = (uint32)strlen(log_buf);
    for (i = 1; i < argc; i++) {
        // add space after each argc
        errcode = memcpy_s(log_buf + offset, log_buf_len - offset, " ", 1);
        if (errcode != EOK) {
            return OG_ERROR;
        }
        offset += 1;

        // check arg is option or key
        if (argv[i][0] == '-') {
            arg_len = (uint32)strlen(argv[i]);
            ret = snprintf_s(log_buf + offset, log_buf_len - offset, arg_len, "%s", argv[i]);
            if (ret == -1) {
                return OG_ERROR;
            }
            offset += arg_len;
        } else {
            // replace key to *
            ret = snprintf_s(log_buf + offset, log_buf_len - offset, log_buf_len - offset - 1, "*");
            if (ret == -1) {
                return OG_ERROR;
            }
            offset += 1;
        }
    }
    if (stat == OG_SUCCESS) {
        ret = snprintf_s(log_buf + offset, log_buf_len - offset, log_buf_len - offset - 1, " SUCCESS");
        if (ret == -1) {
            return OG_ERROR;
        }
    } else {
        ret = snprintf_s(log_buf + offset, log_buf_len - offset, log_buf_len - offset - 1, " FAILED");
        if (ret == -1) {
            return OG_ERROR;
        }
    }
    offset = (uint32)strlen(log_buf);
    cm_write_pe_oper_log(log_buf, offset);
    return OG_SUCCESS;
}

static status_t pe_init_log_parameter(log_param_t *log_param)
{
    uint32 val_len;

    val_len = (uint32)strlen(g_ogdb_home);
    if (val_len >= OG_MAX_LOG_HOME_LEN) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "OGDB_HOME", (int64)OG_MAX_LOG_HOME_LEN - 1);
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(log_param->log_home, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_LOG_HOME_LEN,
        "%s", g_ogdb_home));

    if (!cm_dir_exist(log_param->log_home) || 0 != access(log_param->log_home, W_OK | R_OK)) {
        OG_THROW_ERROR(ERR_INVALID_DIR, log_param->log_home);
        return OG_ERROR;
    }

    log_param->log_backup_file_count = PE_LOG_BACKUP_FILE_COUNT;
    log_param->audit_backup_file_count = PE_LOG_BACKUP_FILE_COUNT;

    log_param->max_log_file_size = PE_LOG_MAX_SIZE;
    log_param->max_audit_file_size = PE_LOG_MAX_SIZE;

    cm_log_set_file_permissions(PE_LOG_FILE_PERMISSIONS_640);

    cm_log_set_path_permissions(PE_LOG_PATH_PERMISSIONS_750);

    return OG_SUCCESS;
}

static status_t pe_get_ogdb_home(void)
{
    g_ogdb_home = getenv(g_env_home);
    if (g_ogdb_home == NULL) {
        return OG_ERROR;
    }

    return cm_dir_exist(g_ogdb_home) ? OG_SUCCESS : OG_ERROR;
}

static status_t pe_init_loggers(void)
{
    char file_name[OG_FILE_NAME_BUFFER_SIZE];
    log_param_t *log_param = cm_log_param_instance();

    log_param->log_level = 0;

    if (OG_SUCCESS != pe_get_ogdb_home()) {
        return OG_ERROR;
    }

    if (cm_start_timer(g_timer()) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (OG_SUCCESS != pe_init_log_parameter(log_param)) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(file_name,
        OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/log/oper/ogencrypt.olog", log_param->log_home));

    cm_log_init(LOG_CTENCRYPT_OPER, (const char *)file_name);

    return OG_SUCCESS;
}

EXTER_ATTACK int32 main(int32 argc, char **argv)
{
    status_t ret;
    if (srv_check_ctencrypt_root()) {
        fflush(stdout);
        return OG_ERROR;
    }
    if (pe_init_loggers() != OG_SUCCESS) {  // log init failed,print warning, don't record ogencrypt oper log
        printf("Warning: ogencrypt operate log will not record, due to log init failed.\n");
    }
    if (argc > MAX_PE_ARG) {
        printf("The command contains too many args.\n");
        pe_usage();
        return OG_ERROR;
    }
    const char *key = NULL;
    const char *work_key = NULL;
    const char *dir = NULL;
    og_pe_cmd_type cmd = get_option(argc, argv, &key, &work_key, &dir);
#ifndef WIN32
    OG_RETURN_IFERR(pe_check_encrypt_args(cmd, argc, work_key, dir));
#endif
    ret = pe_execute_command(cmd, key, work_key, dir);
    return (int32)pe_oper_log(argc, argv, ret);
}
