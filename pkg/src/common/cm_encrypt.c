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
 * cm_encrypt.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_encrypt.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_encrypt.h"
#include "cm_log.h"
#include "cm_file.h"
#include "x509.h"
#include "hmac.h"
#include "rand.h"
#include "cm_entropy.h"
#ifdef WIN32
#include <wincrypt.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* returns base64 encoded string length, include null term */
uint32 cm_base64_encode_len(uint32 length)
{
    uint32 ret;
    uint32 len = length;

    switch (len % 3) {
        case 1:
            len += 2;
            break;
        case 2:
            len += 1;
            break;
        default:
            break;
    }

    ret = (len / 3) * 4 + 1;

    return ret;
}

uint32 cm_base64_decode_len(const char *src)
{
    uint32 ret = 0;
    size_t length;

    if (src == NULL) {
        return ret;
    }
    length = (uint32)strlen(src);
    if (length == 0) {
        return ret;
    }

    ret = (uint32)((length / 4) * 3 + 1);
    if (length > 2) {
        if (*(src + length - 1) == '=') {
            ret--;
        }
        if (*(src + length - 2) == '=') {
            ret--;
        }
    }

    return ret;
}

static char cm_base2char(uchar c)
{
    char ret_char;
    uchar n = c;
    n &= 0x3F;
    if (n < 26) {
        ret_char = (char)(n + 'A');
    } else if (n < 52) {
        ret_char = (char)((n - 26) + 'a');
    } else if (n < 62) {
        ret_char = (char)((n - 52) + '0');
    } else if (n == 62) {
        ret_char = '+';
    } else {
        ret_char = '/';
    }

    return ret_char;
}

static uchar cm_char2base(char ch)
{
    uchar ret;

    if ((ch >= 'A') && (ch <= 'Z')) {
        ret = (uchar)(ch - 'A');
    } else if ((ch >= 'a') && (ch <= 'z')) {
        ret = (uchar)((ch - 'a') + 26);
    } else if ((ch >= '0') && (ch <= '9')) {
        ret = (uchar)((ch - '0') + 52);
    } else if (ch == '+') {
        ret = 62;
    } else if (ch == '/') {
        ret = 63;
    } else {
        ret = 64;
    }

    return ret;
}

static status_t cm_base64_encode_inside(char *dest, uint32 *buf_len, uchar *src, uint32 src_len)
{
    uint32 ret;
    uint32 i = 0;
    uchar c_temp = '\0';

    ret = cm_base64_encode_len(src_len);
    if (ret > *buf_len) {
        OG_LOG_DEBUG_ERR("String buffer for base64 encoding is too short, buffer: %u, required: %u", *buf_len, ret);
        return OG_ERROR;
    }

    do {
        for (i = 0; i < src_len; i++) {
            switch (i % 3) {
                case 0:
                    *dest++ = cm_base2char((uchar)(*src) >> 2);
                    c_temp = ((((uchar)(*src++)) << 4) & 0x3F);
                    break;
                case 1:
                    *dest++ = cm_base2char(c_temp | ((uchar)(*src) >> 4));
                    c_temp = ((((uchar)(*src++)) << 2) & 0x3F);
                    break;
                case 2:
                    *dest++ = cm_base2char(c_temp | ((uchar)(*src) >> 6));
                    *dest++ = cm_base2char((uchar)*src++);
                    break;
                default:
                    break;
            }
        }
        if (src_len % 3 != 0) {
            *dest++ = cm_base2char(c_temp);

            if (src_len % 3 == 1) {
                *dest++ = '=';
            }
            *dest++ = '=';
        }
        *dest = '\0';  //  aDest is an ASCIIZ string
    } while (0);

    *buf_len = ret - 1;
    return OG_SUCCESS;
}

static uint32 cm_base64_decode_inside(uchar *dest, uint32 buf_len, const char *src, uint32 src_len)
{
    uint32 ret;
    uint32 i = 0;
    uchar temp_src = '\0';
    uchar char_temp = '\0';

    ret = cm_base64_decode_len(src);
    if (ret == 0) {
        return ret;
    }

    do {
        OG_BREAK_IF_TRUE((dest == NULL) || (ret > buf_len));

        for (i = 0; i < src_len; ++i) {
            OG_BREAK_IF_TRUE(*src == '=');

            do {
                temp_src = ((*src) ? (cm_char2base((char)(*src++))) : (uchar)(65));
            } while (temp_src == 64);

            OG_BREAK_IF_TRUE(temp_src == 65);

            switch (i % 4) {
                case 0:
                    char_temp = (uchar)(temp_src << 2);
                    break;
                case 1:
                    *dest++ = (char)(char_temp | (temp_src >> 4));
                    char_temp = (uchar)(temp_src << 4);
                    break;
                case 2:
                    *dest++ = (char)(char_temp | (temp_src >> 2));
                    char_temp = (uchar)(temp_src << 6);
                    break;
                case 3:
                    *dest++ = (char)(char_temp | temp_src);
                    break;
                default:
                    break;
            }
        }
        *dest = '\0';
    } while (0);

    return (ret - 1);
}

status_t cm_base64_encode(uchar *src, uint32 src_len, char *cipher, uint32 *cipher_len)
{
    if ((src == NULL) || (src_len == 0) || (cipher == NULL) || (*cipher_len == 0)) {
        return OG_ERROR;
    }

    return cm_base64_encode_inside(cipher, cipher_len, src, src_len);
}

uint32 cm_base64_decode(const char *src, uint32 src_len, uchar *dest_data, uint32 buff_len)
{
    uint32 dest_len;

    if (src == NULL || dest_data == NULL || buff_len == 0) {
        return 0;
    }

    dest_len = cm_base64_decode_len(src);
    if (dest_len == 0 || buff_len < dest_len) {
        return 0;
    }

    return cm_base64_decode_inside(dest_data, dest_len, src, src_len);
}

/*
 @brief Initialize the encrypt ctrl using given algorithm and key
 @param [in,out] ctrl   encrypt ctrl, if ctrl is initialized it will be reinit
 @param [in] alg_type   algorithm type, should be one of E_ALG_AES_256_CBC,E_ALG_HMAC_SHA256,E_ALG_RSA_2048
 @param [in] key        key buffer
 @param [in] key_len    key buffer length
 @notes If alg_type is E_ALG_RSA_2048, if key=NULL && key_len=0, a new RSA key will be generated,
        if key!=null && key_len=0, the key must be a valid RSA key, if key!=null && key_len>0, the key
        must be a X509 public key which was created from a RSA key.
*/
static status_t cm_encyrpt_init(cm_encrypt_ctrl *ctrl, cipher_alg_type alg_type, uchar *key, uint32 key_len)
{
    if (ctrl->is_init == OG_TRUE) {
        MEMS_RETURN_IFERR(memset_sp(ctrl->key, OG_AES256KEYSIZE, 0, OG_AES256KEYSIZE));
        ctrl->key_len = 0;
        ctrl->alg_type = E_ALG_BUTT;
        ctrl->is_init = OG_FALSE;
        ctrl->evp_cipher = NULL;
    }
    switch (alg_type) {
        case E_ALG_AES_256_CBC:
        case E_ALG_HMAC_SHA256:
            if ((key == NULL) || (key_len == 0) || (key_len > OG_AES256KEYSIZE)) {
                return OG_ERROR;
            } else {
                MEMS_RETURN_IFERR(memcpy_sp(ctrl->key, (size_t)OG_AES256KEYSIZE, key, (size_t)key_len));
                ctrl->evp_cipher = (alg_type == E_ALG_AES_256_CBC) ? (pointer_t)EVP_aes_256_cbc() : NULL;
                ctrl->key_len = (int)key_len;
            }
            break;
        default:
            return OG_ERROR;
    }

    ctrl->alg_type = alg_type;
    ctrl->is_init = OG_TRUE;
    return OG_SUCCESS;
}

status_t cm_rand(uchar *buf, uint32 len)
{
    if (buf == NULL || len == 0) {
        return OG_ERROR;
    }

    if (RAND_priv_bytes(buf, (int)len) != 1) {
        OG_THROW_ERROR(ERR_RANDOM_GENERATE);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_encrypt_HMAC(uchar *key, uint32 key_len, uchar *plain, uint32 plain_len, uchar *cipher, uint32 *cipher_len)
{
    if ((key == NULL) || (key_len == 0)) {
        return OG_ERROR;
    }

    if (*cipher_len < OG_HMAC256MAXSIZE) {
        return OG_ERROR;
    }

    if (HMAC(EVP_sha256(), key, (int)key_len, plain, (size_t)plain_len, cipher, cipher_len) == NULL) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_encrypt_KDF2(uchar *plain, uint32 plain_len, uchar *salt, uint32 salt_len, uint32 iter_count,
                         uchar *str_KDF2, uint32 str_len)
{
    if ((plain == NULL) || (salt == NULL) || (salt_len == 0) || (iter_count == 0) || (str_KDF2 == NULL)) {
        OG_LOG_DEBUG_ERR("The parameters of the function cm_encrypt_KDF2 are incorrect");
        return OG_ERROR;
    }

    if (!PKCS5_PBKDF2_HMAC((const char *)plain, /* pwd used as base key for derivation of the key */
                           (int)plain_len,      /* Length of the pwd */
                           salt,                /* salt */
                           (int)salt_len,       /* salt length */
                           (int)iter_count,     /* Number of iterations */
                           EVP_sha256(),        /* the message digest */
                           (int)str_len,        /* Length of derived key */
                           str_KDF2)) {         /* derived key */
        OG_LOG_DEBUG_ERR("encrypt KDF2 failed");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

#define CM_SHA1_ERRMSG_FORMAT "sha1 hash generation failed. returns: %u, cause: %s"

static status_t cm_generate_sha(cipher_alg_type alg, uchar *plain, uint32 plain_len, uchar *cipher, uint32 *cipher_len)
{
    const EVP_MD *type = NULL;

    if (alg == E_ALG_SHA1) {
        type = EVP_sha1();
    } else if (alg == E_ALG_SHA256) {
        type = EVP_sha256();
    } else {
        OG_LOG_DEBUG_ERR(CM_SHA1_ERRMSG_FORMAT, 0, "algorithm not supported");
        return OG_ERROR;
    }

    if (!EVP_Digest(plain, (size_t)plain_len, cipher, cipher_len, type, NULL)) {
        OG_LOG_DEBUG_ERR(CM_SHA1_ERRMSG_FORMAT, 0, "generate sha failed");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_generate_sha1(char *plain, uint32 plain_len, uchar *cipher, uint32 *cipher_len)
{
    return cm_generate_sha(E_ALG_SHA1, (uchar *)plain, plain_len, cipher, cipher_len);
}

status_t cm_generate_sha256(uchar *plain, uint32 plain_len, uchar *cipher, uint32 *cipher_len)
{
    return cm_generate_sha(E_ALG_SHA256, plain, plain_len, cipher, cipher_len);
}

status_t cm_generate_kdf2(char *plain, uint32 plain_len, uchar *cipher, uint32 *cipher_len)
{
    uchar salt[OG_KDF2SALTSIZE + 1] = { 0 };
    uint32 salt_len = OG_KDF2SALTSIZE;
    uint32 kdf2_key_len = OG_KDF2KEYSIZE;
    uchar str_kdf2[OG_KDF2SALTSIZE + OG_KDF2KEYSIZE] = { 0 };
    uint32 kdf2_len = OG_KDF2SALTSIZE + OG_KDF2KEYSIZE;
    uint32 count;

    if (cm_rand((uchar *)salt, salt_len) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // salt + pwd
    count = OG_KDF2SALTSIZE;
    MEMS_RETURN_IFERR(memcpy_sp(str_kdf2, (size_t)(OG_KDF2SALTSIZE + OG_KDF2KEYSIZE), salt, (size_t)count));

    if (cm_encrypt_KDF2((uchar *)plain, plain_len, salt, salt_len, OG_KDF2DEFITERATION, str_kdf2 + OG_KDF2SALTSIZE,
                        kdf2_key_len) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("fail to encrypt");
        return OG_ERROR;
    }

    if (cm_base64_encode(str_kdf2, kdf2_len, (char *)cipher, cipher_len) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("fail to encode cipher text with base64 format");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t cm_encrypt_SCRAM(char *plain, uint32 plain_len, scram_data_t *scram_data)
{
    uchar salted_pwd[OG_KDF2KEYSIZE] = { 0 };
    uchar client_key[OG_HMAC256MAXSIZE] = { 0 };
    uint32 key_len;
    uint32 scram_len;

    // salted pwd
    uint32 iteration = CM_GET_ITERATION(scram_data);
    if (cm_encrypt_KDF2((uchar *)plain, plain_len, scram_data->salt, OG_KDF2SALTSIZE, iteration, salted_pwd,
                        OG_KDF2KEYSIZE) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("fail to encrypt PBKDF2");
        return OG_ERROR;
    }
    // client key
    key_len = sizeof(client_key);
    if (cm_encrypt_HMAC(salted_pwd, OG_KDF2KEYSIZE, (uchar *)OG_CLIENT_KEY, (uint32)strlen(OG_CLIENT_KEY), client_key,
                        &key_len) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("fail to encrypt HMAC_SHA256");
        return OG_ERROR;
    }
    // stored key
    scram_len = OG_HMAC256MAXSIZE;
    if (cm_generate_sha256(client_key, key_len, scram_data->stored_key, &scram_len) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("failed to generate sha256");
        return OG_ERROR;
    }
    // server key
    scram_len = OG_HMAC256MAXSIZE;
    if (cm_encrypt_HMAC(salted_pwd, OG_KDF2KEYSIZE, (uchar *)OG_SERVER_KEY, (uint32)strlen(OG_SERVER_KEY),
                        scram_data->server_key, &scram_len) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("fail to encrypt HMAC_SHA256");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/*
 @brief Generate encrypt cipher using SCRAM_SHA256
 @param [in]     plain       plain text
 @param [in]     plain_len   plain text length
 @param [in]     iter_count  iteration count
 @param [out]    chiper      output cipher buffer
 @param [in,out] cipher_len  [in]cipher buffer max length, [out]cipher buffer actual length
 @retval OG_SUCCESS if success, otherwise failure
*/
status_t cm_generate_scram_sha256(char *plain, uint32 plain_len, uint32 iter_count, uchar *cipher, uint32 *cipher_len)
{
    /*
      SCRAM_SHA256 cipher format:
        rand(4)|alg_id(1)|iter_count(3)|salt(16)|stored_key(32)|server_key(32)
    */
    scram_data_t scram_data;

    // rand(4)
    OG_RETURN_IFERR(cm_rand(scram_data.padding, 4));
    // alg_id(1)
    scram_data.alg_id = (uint8)E_ALG_SCRAM_SHA256;
    // iteration_count(3)
    CM_SET_ITERATION(&scram_data, iter_count);
    // salt(16)
    OG_RETURN_IFERR(cm_rand(scram_data.salt, OG_KDF2SALTSIZE));

    // encrypt scram_sha256
    if (cm_encrypt_SCRAM(plain, plain_len, &scram_data) != OG_SUCCESS) {
        return OG_ERROR;
    }
    // base64 encode
    if (cm_base64_encode((uchar *)&scram_data, sizeof(scram_data_t), (char *)cipher, cipher_len) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("fail to encode cipher text with Base64 format");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t cm_kdf2_to_scram_sha256(uchar *pbkdf2_cipher, uint32 pbkdf2_len, uchar *scram_cipher, uint32 *scram_len)
{
    uchar *salted_pwd = NULL;
    scram_data_t *scram_data = NULL;
    uchar client_key[OG_HMAC256MAXSIZE];
    uint32 key_len;
    uint32 salted_pwd_len;
    uint32 scram_key_len;

    if ((*scram_len < sizeof(scram_data_t)) || (pbkdf2_len != OG_KDF2KEYSIZE + OG_KDF2SALTSIZE)) {
        return OG_ERROR;
    }
    scram_data = (scram_data_t *)scram_cipher;

    // rand + alg_id + iter_count
    OG_RETURN_IFERR(cm_rand(scram_data->padding, 4));
    scram_data->alg_id = (uint8)E_ALG_SCRAM_SHA256;
    CM_SET_ITERATION(scram_data, (uint32)OG_KDF2DEFITERATION);
    // salt(16)
    MEMS_RETURN_IFERR(memcpy_sp(scram_data->salt, OG_KDF2SALTSIZE, pbkdf2_cipher, OG_KDF2SALTSIZE));

    salted_pwd = pbkdf2_cipher + OG_KDF2SALTSIZE;
    salted_pwd_len = pbkdf2_len - OG_KDF2SALTSIZE;

    // client_key
    key_len = sizeof(client_key);
    if (cm_encrypt_HMAC(salted_pwd, salted_pwd_len, (uchar *)OG_CLIENT_KEY, (uint32)strlen(OG_CLIENT_KEY), client_key,
                        &key_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    // stored_key
    scram_key_len = OG_HMAC256MAXSIZE;
    if (cm_generate_sha256(client_key, key_len, scram_data->stored_key, &scram_key_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    // server key
    scram_key_len = OG_HMAC256MAXSIZE;
    if (cm_encrypt_HMAC(salted_pwd, salted_pwd_len, (uchar *)OG_SERVER_KEY, (uint32)strlen(OG_SERVER_KEY),
                        scram_data->server_key, &scram_key_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    *scram_len = sizeof(scram_data_t);
    return OG_SUCCESS;
}

static status_t cm_verify_scram_sha256(uchar *c_cipher, uint32 c_cipher_len, uchar *s_cipher, uint32 s_cipher_len)
{
    scram_data_t *s_scram = NULL;
    uchar client_sign[OG_HMAC256MAXSIZE];
    uchar client_key[OG_HMAC256MAXSIZE];
    uchar c_stored_key[OG_HMAC256MAXSIZE];
    uchar *client_proof = NULL;
    uint32 key_len;
    uint32 store_key_len;

    // c_nonce + s_nonce + client_proof
    if (c_cipher_len != OG_MAX_CHALLENGE_LEN * 2 + OG_HMAC256MAXSIZE) {
        return OG_ERROR;
    }

    // rand|alg_id|iter|salt|stored_key|server_key
    if (s_cipher_len != OG_SCRAM256MAXSIZE) {
        return OG_ERROR;
    }
    s_scram = (scram_data_t *)s_cipher;

    // client_signature
    key_len = sizeof(client_sign);
    if (cm_encrypt_HMAC(s_scram->stored_key, OG_HMAC256MAXSIZE, c_cipher, OG_MAX_CHALLENGE_LEN * 2, client_sign,
                        &key_len) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return OG_ERROR;
    }
    // client_key
    client_proof = (c_cipher + OG_MAX_CHALLENGE_LEN * 2);
    for (uint32 i = 0; i < OG_HMAC256MAXSIZE; ++i) {
        client_key[i] = client_proof[i] ^ client_sign[i];
    }
    // stored_key
    store_key_len = sizeof(c_stored_key);
    if (cm_generate_sha256(client_key, OG_HMAC256MAXSIZE, c_stored_key, &store_key_len) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return OG_ERROR;
    }
    // compare calculated stored_key with saved stored_key
    if (memcmp(c_stored_key, s_scram->stored_key, OG_HMAC256MAXSIZE) != 0) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t cm_verify_kdf2(uchar *c_cipher, uint32 c_cipher_len, uchar *s_cipher, uint32 s_cipher_len)
{
    uchar scram_cipher[OG_SCRAM256MAXSIZE];
    uint32 scram_cipher_len = sizeof(scram_cipher);

    // pbkdf2 to scram_sha256
    if (cm_kdf2_to_scram_sha256(s_cipher, s_cipher_len, scram_cipher, &scram_cipher_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return cm_verify_scram_sha256(c_cipher, c_cipher_len, scram_cipher, scram_cipher_len);
}

static status_t cm_check_kdf2(char *plain_password, uint32 plain_len, uchar *kdf2_cipher, uint32 kdf2_cipher_len)
{
    uint32 kdf2_key_size = OG_KDF2KEYSIZE;
    uint32 cli_kdf_len = OG_KDF2SALTSIZE + OG_KDF2KEYSIZE;
    uchar cli_kdf[OG_KDF2SALTSIZE + OG_KDF2KEYSIZE] = { 0 };

    if (plain_len == 0 || kdf2_cipher_len != OG_KDF2SALTSIZE + OG_KDF2KEYSIZE) {
        OG_LOG_DEBUG_ERR(
            "The length of the username or password is 0, or the length of the cipher text saved is incorrect!");
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memcpy_sp(cli_kdf, cli_kdf_len, kdf2_cipher, OG_KDF2SALTSIZE));

    if (cm_encrypt_KDF2((uchar *)plain_password, plain_len, kdf2_cipher, OG_KDF2SALTSIZE, OG_KDF2DEFITERATION,
                        cli_kdf + OG_KDF2SALTSIZE, kdf2_key_size) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return OG_ERROR;
    }

    if (memcmp(kdf2_cipher, cli_kdf, (size_t)cli_kdf_len) != 0) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t cm_check_scram_sha256(char *plain_password, uint32 plain_len, uchar *scram_cipher,
                                      uint32 scram_cipher_len)
{
    scram_data_t cli_scram;
    uint32 cli_stuff_len = OG_KDF2SALTSIZE + OG_SCRAM256HEADSIZE;

    if (plain_len == 0 || scram_cipher_len != sizeof(cli_scram)) {
        OG_LOG_DEBUG_ERR(
            "The length of the username or password is 0, or the length of the cipher text saved is incorrect!");
        return OG_ERROR;
    }

    // alg_id + iter + salt
    MEMS_RETURN_IFERR(memcpy_sp((void *)&cli_scram, sizeof(cli_scram), (void *)scram_cipher, (size_t)cli_stuff_len));

    // encrypt scram_sha256
    if (cm_encrypt_SCRAM(plain_password, plain_len, &cli_scram) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (memcmp((void *)&cli_scram, (void *)scram_cipher, sizeof(cli_scram)) != 0) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t cm_get_init_vector(char *buff, uint32 buff_size)
{
    char init_vector[16] = { (char)0xBC, (char)0x70, (char)0x86, (char)0x92, (char)0x32, (char)0x25,
                             (char)0xF7, (char)0x6,  (char)0x27, (char)0xF6, (char)0xA8, (char)0x35,
                             (char)0xC,  (char)0xEF, (char)0xA3, (char)0x57 };
    init_vector[0] = (char)init_vector[15] | (char)init_vector[11];
    init_vector[1] = (char)init_vector[11] - (char)init_vector[13];
    init_vector[2] = (char)init_vector[14] | (char)init_vector[13];
    init_vector[3] = (char)init_vector[15] | (char)init_vector[10];
    init_vector[4] = (char)init_vector[14] & (char)init_vector[5];
    init_vector[5] = (char)init_vector[4] + (char)init_vector[14];
    init_vector[6] = (char)init_vector[9] - (char)init_vector[11];
    init_vector[7] = (char)init_vector[15] - (char)init_vector[10];
    init_vector[8] = (char)init_vector[15] | (char)init_vector[0];
    init_vector[9] = (char)init_vector[4] & (char)init_vector[13];
    init_vector[10] = (char)init_vector[13] | (char)init_vector[12];
    init_vector[11] = (char)init_vector[5] + (char)init_vector[2];
    init_vector[12] = (char)init_vector[10] | (char)init_vector[13];
    init_vector[13] = (char)init_vector[7] & (char)init_vector[4];
    init_vector[14] = (char)init_vector[8] | (char)init_vector[0];
    init_vector[15] = (char)init_vector[4] | (char)init_vector[13];

    MEMS_RETURN_IFERR(memcpy_sp(buff, (size_t)buff_size, init_vector, sizeof(init_vector)));
    return OG_SUCCESS;
}

static status_t cm_get_key(char *buff, uint32 buff_size)
{
    char init_vector[16] = { (char)0x5E, (char)0x58, (char)0x11, (char)0xEC, (char)0xAF, (char)0xF6,
                             (char)0x7A, (char)0x10, (char)0xC4, (char)0xA4, (char)0xE3, (char)0x52,
                             (char)0x92, (char)0x7B, (char)0x6D, (char)0x68 };
    init_vector[0] = (char)init_vector[0] ^ (char)init_vector[15];
    init_vector[1] = (char)init_vector[9] | (char)init_vector[11];
    init_vector[2] = (char)init_vector[2] << (char)init_vector[7];
    init_vector[3] = (char)init_vector[9] ^ (char)init_vector[13];
    init_vector[4] = (char)init_vector[15] | (char)init_vector[3];
    init_vector[5] = (char)init_vector[6] << (char)init_vector[2];
    init_vector[6] = (char)init_vector[14] << (char)init_vector[6];
    init_vector[7] = (char)init_vector[14] | (char)init_vector[4];
    init_vector[8] = (char)init_vector[3] + (char)init_vector[15];
    init_vector[9] = (char)init_vector[7] ^ (char)init_vector[1];
    init_vector[10] = (char)init_vector[11] & (char)init_vector[12];
    init_vector[11] = (char)init_vector[15] + (char)init_vector[7];
    init_vector[12] = (char)init_vector[2] - (char)init_vector[6];
    init_vector[13] = (char)init_vector[3] + (char)init_vector[7];
    init_vector[14] = (char)init_vector[10] + (char)init_vector[5];
    init_vector[15] = (char)init_vector[5] & (char)init_vector[2];

    MEMS_RETURN_IFERR(memcpy_sp(buff, (size_t)buff_size, init_vector, sizeof(init_vector)));
    return OG_SUCCESS;
}

static status_t cm_get_PDB_init_key_once(char *init_key, uint32 init_key_size, const char *local_key)
{
    uint32 i;
    char salt[OG_AESBLOCKSIZE];
    char hard_key[OG_AESBLOCKSIZE];
    char rand_key[OG_AESBLOCKSIZE + 4] = { 0 };

    // localkeyLen 24
    if (local_key == NULL || strlen(local_key) != OG_MAX_LOCAL_KEY_STR_LEN) {
        return OG_ERROR;
    }
    // decode Base64 encoded key, length is 16
    if (cm_base64_decode(local_key, (uint32)strlen(local_key), (uchar *)rand_key, (uint32)sizeof(rand_key)) == 0) {
        return OG_ERROR;
    }

    // get hardcode key, length is 16
    OG_RETURN_IFERR(cm_get_key(hard_key, OG_AESBLOCKSIZE));
    // get hardcode salt, length is 16
    OG_RETURN_IFERR(cm_get_init_vector(salt, OG_AESBLOCKSIZE));

    // process key components
    for (i = 0; i < OG_AESBLOCKSIZE; ++i) {
        rand_key[i] ^= hard_key[i];
    }

    /*
      For the key dervied from java is different from c, use hmac_hash256 instead
    */
    const EVP_MD *md = EVP_sha256();
    if (HMAC(md, (uchar *)salt, OG_HMAC256SALTSIZE, (uchar *)rand_key, OG_AESBLOCKSIZE, (uchar *)init_key,
             &init_key_size) == NULL) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t cm_get_init_key(const char *key, uint32 key_len, char *init_key, uint32 init_key_len)
{
    // Key factor binary
    char plain[OG_AESBLOCKSIZE + 1] = { 0 };
    char salt[OG_KDF2SALTSIZE_DOUBLE + 1] = { 0 };

    OG_RETURN_IFERR(cm_get_init_vector(salt, OG_KDF2SALTSIZE_DOUBLE));
    if (cm_base64_decode((char *)key, key_len, (uchar *)plain, OG_AESBLOCKSIZE + 1) == 0) {
        return OG_ERROR;
    }

    // Use the initial vector as the salt value,the key factor is plaintext to encrypt the data,get the initial key.
    if (OG_SUCCESS != cm_encrypt_KDF2((uchar *)plain, OG_AESBLOCKSIZE, (uchar *)salt, OG_KDF2SALTSIZE_DOUBLE,
                                      OG_KDF2MINITERATION, (uchar *)init_key, init_key_len)) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline uint32 get_aes256_encrypt_len(uint32 plain_len)
{
    return (uint32)((plain_len / OG_AESBLOCKSIZE + 1) * OG_AESBLOCKSIZE + OG_AESBLOCKSIZE);
}

static status_t cm_encrypt(cm_encrypt_ctrl *ctrl, uchar *plain, uint32 plain_len, char *cipher, uint32 *cipher_len)
{
    if ((plain == NULL) || (plain_len == 0) || (ctrl->is_init != OG_TRUE) || (ctrl->evp_cipher == NULL)) {
        return OG_ERROR;
    }

    if (get_aes256_encrypt_len(plain_len) > OG_ENCRYPTION_SIZE) {
        return OG_ERROR;
    }

    uchar buff[OG_ENCRYPTION_SIZE];
    OG_RETURN_IFERR(cm_rand(buff, OG_AESBLOCKSIZE));

    uint32 buff_len = OG_ENCRYPTION_SIZE - OG_AESBLOCKSIZE;

    EVP_CIPHER_CTX *ogx = EVP_CIPHER_CTX_new();
    if (ogx == NULL) {
        return OG_ERROR;
    }

    /* should check the key & IV length first ? */
    if (!EVP_CipherInit_ex(ogx, (EVP_CIPHER *)ctrl->evp_cipher, NULL, ctrl->key, buff, 1)) {
        EVP_CIPHER_CTX_free(ogx);
        return OG_ERROR;
    }

    if (!EVP_CipherUpdate(ogx, buff + OG_AESBLOCKSIZE, (int *)&buff_len, plain, (int)plain_len)) {
        EVP_CIPHER_CTX_free(ogx);
        return OG_ERROR;
    }

    int tmp_len;
    if (!EVP_CipherFinal_ex(ogx, buff + buff_len + OG_AESBLOCKSIZE, &tmp_len)) {
        EVP_CIPHER_CTX_free(ogx);
        return OG_ERROR;
    }

    EVP_CIPHER_CTX_free(ogx);
    buff_len += (uint32)tmp_len;

    if (OG_SUCCESS != cm_base64_encode(buff, (uint32)(OG_AESBLOCKSIZE + buff_len), cipher, cipher_len)) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t cm_decrypt(cm_encrypt_ctrl *ctrl, uchar *cipher, uint32 cipher_len, uchar *plain, uint32 *plain_len)
{
    if ((cipher == NULL) || (cipher_len == 0) || (plain == NULL) || (ctrl->is_init != OG_TRUE) ||
        ctrl->evp_cipher == NULL) {
        return OG_ERROR;
    }

    if (*plain_len > 0 && *plain_len < cipher_len - OG_AESBLOCKSIZE) {
        return OG_ERROR;
    }

    EVP_CIPHER_CTX *ogx = EVP_CIPHER_CTX_new();
    if (ogx == NULL) {
        return OG_ERROR;
    }

    /* should check the key & IV length first ? */
    if (!EVP_CipherInit_ex(ogx, (EVP_CIPHER *)ctrl->evp_cipher, NULL, ctrl->key, cipher, 0)) {
        EVP_CIPHER_CTX_free(ogx);
        return OG_ERROR;
    }

    if (!EVP_CipherUpdate(ogx, plain, (int *)plain_len, cipher + OG_AESBLOCKSIZE,
                          (int)(cipher_len - OG_AESBLOCKSIZE))) {
        EVP_CIPHER_CTX_free(ogx);
        return OG_ERROR;
    }

    int tmp_len;
    if (!EVP_CipherFinal_ex(ogx, plain + *plain_len, &tmp_len)) {
        EVP_CIPHER_CTX_free(ogx);
        return OG_ERROR;
    }

    EVP_CIPHER_CTX_free(ogx);
    *plain_len += (uint32)tmp_len;
    return OG_SUCCESS;
}

static status_t cm_decrypt_work_key(const char *src_work_key, uint32 src_work_key_len, const char *key, uint32 key_len,
                             char *work_key_clear, uint32 *work_key_clear_len)
{
    uint32 work_key_rtn_len = *work_key_clear_len;

    uchar work_key[OG_PASSWD_MAX_LEN + OG_AESBLOCKSIZE * 2 + 4] = { 0 };

    // decode work key
    uint32 work_key_len = (uint32)cm_base64_decode((char *)src_work_key, src_work_key_len, work_key, sizeof(work_key));
    if (work_key_len == 0) {
        return OG_ERROR;
    }

    char init_key[OG_AES256KEYSIZE + 1] = { 0 };

    // get init key and init aes256 cbc
    OG_RETURN_IFERR(cm_get_init_key(key, key_len, init_key, OG_AES256KEYSIZE));

    cm_encrypt_ctrl ctrl;

    MEMS_RETURN_IFERR(memset_sp(&ctrl, sizeof(cm_encrypt_ctrl), 0, sizeof(cm_encrypt_ctrl)));

    if (OG_SUCCESS != cm_encyrpt_init(&ctrl, E_ALG_AES_256_CBC, (uchar *)init_key, OG_AES256KEYSIZE)) {
        return OG_ERROR;
    }

    // decrypt work key
    if (OG_SUCCESS != cm_decrypt(&ctrl, work_key, work_key_len, (uchar *)work_key_clear, &work_key_rtn_len)) {
        return OG_ERROR;
    }

    if (work_key_rtn_len != OG_AES256KEYSIZE) {
        return OG_ERROR;
    }
    *work_key_clear_len = work_key_rtn_len;

    return OG_SUCCESS;
}

static status_t cm_get_PDB_init_key_double(char *init_key, const char *local_key, const char *factor_key)
{
    if (local_key == NULL || factor_key == NULL) {
        return OG_ERROR;
    }

    // work key �ĳ��Ȼ���decryptWorkKeyʱ���µõ���
    uint32 work_key_clear_len = 0;
    size_t local_key_len = strlen(local_key);
    size_t factor_key_len = strlen(factor_key);
    // localkeyLen:88 FactorkeyLen:24
    if (local_key_len != OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE || factor_key_len != OG_MAX_FACTOR_KEY_STR_LEN) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_decrypt_work_key(local_key, (uint32)local_key_len, factor_key, (uint32)factor_key_len, init_key,
                                        &work_key_clear_len));

    return OG_SUCCESS;
}

static status_t cm_get_PDB_init_key(bool32 is_double_enc, char *pdb_init_key, uint32 pdb_init_key_size, const char *local_key,
                             const char *factor_key)
{
    if (pdb_init_key == NULL) {
        return OG_ERROR;
    }
    if (is_double_enc) {
        return cm_get_PDB_init_key_double(pdb_init_key, local_key, factor_key);
    } else {
        return cm_get_PDB_init_key_once(pdb_init_key, pdb_init_key_size, local_key);
    }
}

status_t cm_decrypt_passwd(bool32 is_double_enc, const char *cipher_str, uint32 cipher_len, char *plain_str_buf,
                           uint32 *plain_str_len, const char *local_key, const char *factor_key_str)
{
    cm_encrypt_ctrl ctrl;
    char init_key[OG_MAX_WORK_KEY_CLEAR_LEN + 1] = { 0 };
    uint32 init_key_len = OG_AES256KEYSIZE;
    uint32 plain_len = *plain_str_len;
    uchar passwd[OG_ENCRYPTION_SIZE * 4] = { 0 };
    uint32 passwd_len;

    // 1.get 32 byte init key
    if (OG_SUCCESS !=
        cm_get_PDB_init_key(is_double_enc, init_key, OG_MAX_WORK_KEY_CLEAR_LEN, local_key, factor_key_str)) {
        return OG_ERROR;
    }

    // 2.init Cipher
    MEMS_RETURN_IFERR(memset_sp(&ctrl, sizeof(cm_encrypt_ctrl), 0, sizeof(cm_encrypt_ctrl)));

    if (OG_SUCCESS != cm_encyrpt_init(&ctrl, E_ALG_AES_256_CBC, (uchar *)init_key, init_key_len)) {
        return OG_ERROR;
    }

    // 3.decode Base64 encoded cipher pwd
    passwd_len = cm_base64_decode(cipher_str, cipher_len, passwd, sizeof(passwd));
    if (passwd_len == 0) {
        return OG_ERROR;
    }

    // 4.decrypt cipher pwd
    if (OG_SUCCESS != cm_decrypt(&ctrl, passwd, passwd_len, (uchar *)plain_str_buf, &plain_len)) {
        MEMS_RETURN_IFERR(memset_sp(passwd, sizeof(passwd), 0, sizeof(passwd)));
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memset_sp(passwd, sizeof(passwd), 0, sizeof(passwd)));
    *plain_str_len = plain_len;

    return OG_SUCCESS;
}

status_t cm_encrypt_passwd(bool32 is_double_enc, char *plain_str_buf, uint32 plain_str_len, char *cipher_str,
                           uint32 *cipher_len, const char *local_key_str, const char *factor_key_str)
{
    cm_encrypt_ctrl ctrl;
    char init_key[OG_MAX_WORK_KEY_CLEAR_LEN + 1] = { 0 };
    uint32 init_key_len = OG_AES256KEYSIZE;

    if (OG_SUCCESS !=
        cm_get_PDB_init_key(is_double_enc, init_key, OG_MAX_WORK_KEY_CLEAR_LEN, local_key_str, factor_key_str)) {
        return OG_ERROR;
    }

    // 1.init Cipher
    MEMS_RETURN_IFERR(memset_sp(&ctrl, sizeof(cm_encrypt_ctrl), 0, sizeof(cm_encrypt_ctrl)));

    if (OG_SUCCESS != cm_encyrpt_init(&ctrl, E_ALG_AES_256_CBC, (uchar *)init_key, init_key_len)) {
        return OG_ERROR;
    }

    // 2.encrypt cipher pwd
    if (OG_SUCCESS != cm_encrypt(&ctrl, (uchar *)plain_str_buf, plain_str_len, cipher_str, cipher_len)) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_verify_password(text_t *c_cipher, const text_t *s_cipher)
{
    uchar cipher_key[OG_ENCRYPTION_SIZE];
    uint32 cipher_len;

    cipher_len = cm_base64_decode(s_cipher->str, s_cipher->len, cipher_key, OG_ENCRYPTION_SIZE);
    if (cipher_len == 0) {
        OG_THROW_ERROR(ERR_DECODE_ERROR);
        return OG_ERROR;
    }

    if (cipher_len == OG_SCRAM256MAXSIZE) {
        return cm_verify_scram_sha256((uchar *)c_cipher->str, c_cipher->len, cipher_key, cipher_len);
    } else if (cipher_len == OG_KDF2SALTSIZE + OG_KDF2KEYSIZE) {
        return cm_verify_kdf2((uchar *)c_cipher->str, c_cipher->len, cipher_key, cipher_len);
    } else {
        return OG_ERROR;
    }
}

status_t cm_check_password(text_t *plain_password, text_t *cipher_password)
{
    uchar cipher_key[OG_ENCRYPTION_SIZE];
    uint32 cipher_len;

    cipher_len = cm_base64_decode(cipher_password->str, cipher_password->len, cipher_key, OG_ENCRYPTION_SIZE);
    if (cipher_len == 0) {
        OG_THROW_ERROR(ERR_DECODE_ERROR);
        return OG_ERROR;
    }

    if (cipher_len == OG_SCRAM256MAXSIZE) {
        return cm_check_scram_sha256(plain_password->str, plain_password->len, cipher_key, cipher_len);
    } else if (cipher_len == OG_KDF2SALTSIZE + OG_KDF2KEYSIZE) {
        return cm_check_kdf2(plain_password->str, plain_password->len, cipher_key, cipher_len);
    } else {
        return OG_ERROR;
    }
}

static status_t cm_encrypt_work_key(const char *wkey, uint32 wkey_len, const char *fkey, uint32 fkey_len,
                                    char *wkey_cipher, uint32 wkey_cipher_len)
{
    char init_key[OG_AES256KEYSIZE + 4] = { 0 };
    cm_encrypt_ctrl ctrl;

    MEMS_RETURN_IFERR(memset_sp(&ctrl, sizeof(cm_encrypt_ctrl), 0, sizeof(cm_encrypt_ctrl)));

    OG_RETURN_IFERR(cm_get_init_key((char *)fkey, fkey_len, init_key, sizeof(init_key)));

    if (cm_encyrpt_init(&ctrl, E_ALG_AES_256_CBC, (uchar *)init_key, OG_AES256KEYSIZE) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Failed to init encrypt algorithm");
        return OG_ERROR;
    }
    if (cm_encrypt(&ctrl, (uchar *)wkey, wkey_len, wkey_cipher, &wkey_cipher_len) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Failed to encrypt work key");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cm_generate_work_key(const char *fkey, char *wkey, uint32 wkey_len)
{
    char key_buf[OG_AES256KEYSIZE + 4];
    uint32 keybuf_len = OG_AES256KEYSIZE;
    uint32 rand_len = OG_AES256KEYSIZE / 2;

    // init vector + random
    OG_RETURN_IFERR(cm_get_key(key_buf, sizeof(key_buf)));

    // generate 128bit work key
    OG_RETURN_IFERR(cm_rand((uchar *)(key_buf + rand_len), rand_len));

    // encrypt work key
    if (cm_encrypt_work_key(key_buf, keybuf_len, fkey, (uint32)strlen(fkey), wkey, wkey_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cm_convert_kdf2_scram_sha256(const char *kdf2_str, char *scram_str, uint32 scram_buf_len)
{
    uchar scram_data[OG_SCRAM256MAXSIZE];
    uchar kdf2_data[OG_KDF2SALTSIZE + OG_KDF2KEYSIZE + 4];
    uint32 kdf2_len = OG_KDF2SALTSIZE + OG_KDF2KEYSIZE;
    uint32 scram_len = OG_SCRAM256MAXSIZE;

    if (cm_base64_decode(kdf2_str, (uint32)strlen(kdf2_str), kdf2_data, sizeof(kdf2_data)) == 0) {
        return OG_ERROR;
    }
    if (cm_kdf2_to_scram_sha256(kdf2_data, kdf2_len, scram_data, &scram_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cm_base64_encode(scram_data, scram_len, scram_str, &scram_buf_len) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

bool32 cm_is_password_valid(const char *sys_pwd)
{
    if (CM_IS_EMPTY_STR(sys_pwd)) {
        return OG_FALSE;
    }

    size_t len = strlen(sys_pwd);
    uint32 scram_len;
    uchar scram_buf[OG_SCRAM256MAXSIZE + 4];

    scram_len = cm_base64_decode(sys_pwd, (uint32)len, scram_buf, sizeof(scram_buf));
    if (scram_len != sizeof(scram_data_t)) {
        return OG_FALSE;
    }

    scram_data_t *scram_data = (scram_data_t *)scram_buf;
    uint32 iteration = CM_GET_ITERATION(scram_data);
    if (iteration < OG_KDF2MINITERATION || iteration > OG_KDF2MAXITERATION) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

status_t cm_generate_repl_key(char *fkey, uint32 flen, char *wkey, uint32 wlen)
{
    uchar key[OG_AESBLOCKSIZE] = { 0 };

    if (cm_rand(key, OG_AESBLOCKSIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_base64_encode(key, OG_AESBLOCKSIZE, fkey, &flen) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_generate_work_key(fkey, wkey, wlen) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_generate_repl_cipher(const char *plain, const char *fkey, const char *wkey, char *cipher, uint32 clen)
{
    text_t text;
    char factor_key[OG_MAX_FACTOR_KEY_STR_LEN + 1];
    char local_key[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1];

    cm_str2text((char *)fkey, &text);
    cm_trim_text(&text);
    if (text.len != OG_MAX_FACTOR_KEY_STR_LEN) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_text2str(&text, factor_key, sizeof(factor_key)));

    cm_str2text((char *)wkey, &text);
    cm_trim_text(&text);
    if (text.len != OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_text2str(&text, local_key, sizeof(local_key)));

    if (cm_encrypt_passwd(OG_TRUE, (char *)plain, (uint32)strlen(plain), cipher, &clen, local_key, factor_key) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t cm_pwd_write_file(const char *path, const char *name, const char *buf)
{
    status_t ret;
    char file_name[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    char repl_dir[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 handle = OG_INVALID_HANDLE;

    PRTS_RETURN_IFERR(snprintf_s(repl_dir, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/", path));
    PRTS_RETURN_IFERR(
        snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s", path, name));

    if (!cm_dir_exist(repl_dir)) {
        if (cm_create_dir(repl_dir) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("failed to create dir %s", repl_dir);
            return OG_ERROR;
        }
    }

    if (access(file_name, R_OK | F_OK) == 0) {
        (void)chmod(file_name, S_IRUSR | S_IWUSR);
        OG_RETURN_IFERR(cm_remove_file(file_name));
    }

    OG_RETURN_IFERR(
        cm_open_file_ex(file_name, O_SYNC | O_CREAT | O_RDWR | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR, &handle));

    ret = cm_write_file(handle, (void *)buf, (uint32)strlen(buf));
    cm_close_file(handle);

    return ret;
}

status_t cm_pwd_read_file(const char *path, const char *name, char *buf, uint32 len)
{
    status_t ret;
    int32 handle = OG_INVALID_HANDLE;
    int32 read_size;
    char file_name[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    int print_cnt;

    print_cnt = snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s", path, name);
    if (SECUREC_UNLIKELY(print_cnt == -1)) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, print_cnt);
        return OG_ERROR;
    }
    if (print_cnt < 0) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (print_cnt));
        return OG_ERROR;
    }

    if (access(file_name, R_OK | F_OK) != 0) {
        OG_LOG_RUN_ERR("file %s does not exist", file_name);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_open_file_ex(file_name, O_RDONLY | O_BINARY, S_IRUSR, &handle));

    ret = cm_read_file(handle, (void *)buf, len, &read_size);
    cm_close_file(handle);

    buf[read_size] = '\0';
    return ret;
}

status_t cm_pwd_fetch_plain(const char *path, char *buf, uint32 buf_len)
{
    uint32 len = buf_len;
    char cipher[OG_MAX_CIPHER_LEN + 1] = { 0 };
    char fkey[OG_MAX_FACTOR_KEY_STR_LEN + 1] = { 0 };
    char wkey[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1] = { 0 };

    OG_RETURN_IFERR(cm_pwd_read_file(path, OG_FKEY_REPL, fkey, sizeof(fkey)));
    OG_RETURN_IFERR(cm_pwd_read_file(path, OG_WKEY_REPL, wkey, sizeof(wkey)));
    OG_RETURN_IFERR(cm_pwd_read_file(path, OG_CIPHER_REPL, cipher, sizeof(cipher)));

    /* decrypt pswd using local key */
    OG_RETURN_IFERR(cm_decrypt_passwd(OG_TRUE, cipher, (uint32)strlen(cipher), buf, &len, wkey, fkey));
    buf[len] = '\0';

    return OG_SUCCESS;
}

status_t cm_pwd_store_keys(const char *path, const char *cipher, const char *fkey, const char *wkey)
{
    OG_RETURN_IFERR(cm_pwd_write_file(path, OG_FKEY_REPL, fkey));
    OG_RETURN_IFERR(cm_pwd_write_file(path, OG_WKEY_REPL, wkey));
    OG_RETURN_IFERR(cm_pwd_write_file(path, OG_CIPHER_REPL, cipher));

    return OG_SUCCESS;
}

status_t cm_encrypt_data_by_gcm(EVP_CIPHER_CTX *ogx, char *out_buf, const char *in_buf, int32 in_bufsize)
{
    int32 outlen = 0;
    int32 result;

    result = EVP_EncryptUpdate(ogx, (unsigned char *)out_buf, &outlen, (const unsigned char *)in_buf, in_bufsize);
    if (result == 0) {
        OG_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_decrypt_data_by_gcm(EVP_CIPHER_CTX *ogx, char *out_buf, const char *in_buf, int32 in_bufsize)
{
    int32 outlen = 0;
    int32 result;

    result = EVP_DecryptUpdate(ogx, (unsigned char *)out_buf, &outlen, (const unsigned char *)in_buf, in_bufsize);
    if (result == 0) {
        OG_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_encrypt_end_by_gcm(EVP_CIPHER_CTX *ogx, char *out_buf)
{
    int32 out_len;
    int32 res;
    res = EVP_EncryptFinal_ex(ogx, (unsigned char *)out_buf, &out_len);
    if (res == 0) {
        OG_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return OG_ERROR;
    }

    res = EVP_CIPHER_CTX_ctrl(ogx, EVP_CTRL_AEAD_GET_TAG, EVP_GCM_TLS_TAG_LEN, out_buf);
    if (res == 0) {
        OG_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_dencrypt_end_by_gcm(EVP_CIPHER_CTX *ogx, char *out_buf)
{
    int32 out_len;
    int32 res;

    res = EVP_CIPHER_CTX_ctrl(ogx, EVP_CTRL_AEAD_SET_TAG, EVP_GCM_TLS_TAG_LEN, (void *)out_buf);
    if (res == 0) {
        OG_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return OG_ERROR;
    }

    res = EVP_DecryptFinal_ex(ogx, (unsigned char *)out_buf, &out_len);
    if (res == 0) {
        OG_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
