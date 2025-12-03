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
 * cms_comm.c
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_comm.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_defs.h"
#include "cms_comm.h"
#include "cm_ip.h"
#include "cs_packet.h"
#include "cs_tcp.h"
#include "cms_client.h"
#include "cs_uds.h"
#include "securec.h"
bool32 g_cluster_no_cms = OG_FALSE;
status_t cms_check_addr_dev_stat(struct sockaddr_in* addr)
{
    struct ifaddrs* ifaddr;
    int32 family;

    if (getifaddrs(&ifaddr) == -1) {
        return OG_ERROR;
    }

    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET &&
            memcmp(&addr->sin_addr, &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr, sizeof(struct in_addr)) == 0) {
            if (ifa->ifa_flags & IFF_UP) {
                freeifaddrs(ifaddr);
                return OG_SUCCESS;
            } else {
                freeifaddrs(ifaddr);
                return OG_ERROR;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return OG_ERROR;
}
