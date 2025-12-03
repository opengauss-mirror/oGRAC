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
 * cm_kmc.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_kmc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef _KMC_ITF
#define _KMC_ITF

#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif


#define OG_KMC_MAX_CIPHER_SIZE (uint32)256

typedef enum st_encrypt_version {
    NO_ENCRYPT          = 0,
} encrypt_version_t;

typedef struct st_page_cipher_ctrl {
    uint16 cipher_expanded_size;
    uint16 offset;
    uint16 plain_cks;
    uint8 encrypt_version;
    uint8 reserved;
} cipher_ctrl_t;

#ifdef __cplusplus
}
#endif

#endif
