/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#define VERSION_DESCRIP oGRAC
#define DRIVER_VERSION_DESCRIP oGRAC
#define OGSQL_VERSION_DESCRIP
#define PACK_PREFIX oGRAC
#define PROJECT_NAME oGRACDB
#define PROJECT_VERSION 1.0.0

#define DD_OG_LIB_VERSION
#define DD_OG_DRIVER_VERSION static char* str_OG_DRIVER_VERSION="oGRAC Debug "
#define DD_OG_OGSQL_VERSION static char* str_OG_OGSQL_VERSION="oGRAC Debug "
#define DD_GETDBVERSION oGRACd_get_dbversion
#define DD_GETENCRYVERSION ogencrypt_getDBVersion
#define DD_OG_LIB_VER_APINAME ogconn_get_dbversion
#define DD_GETOGSQLVERSION ogsql_get_dbversion
