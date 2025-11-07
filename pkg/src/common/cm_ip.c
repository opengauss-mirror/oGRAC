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
 * cm_ip.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_ip.c
 *
 * -------------------------------------------------------------------------
 */
#ifndef WIN32
#include <netdb.h>
#include <net/if.h>
#else
#include <ws2tcpip.h>
#endif
#include "cm_ip.h"

static inline int32 cm_get_ip_version(const char *ip_str)
{
    const char *temp_ip = ip_str;

    // support IPV6 local-link
    if (strchr(temp_ip, '%') != NULL) {
        return AF_INET6;
    }

    // cidr or ip string
#define IP_CHARS "0123456789ABCDEFabcdef.:;*/"
    if (strspn(temp_ip, IP_CHARS) != strlen(temp_ip)) {
        return -1;
    }

    while (*temp_ip != '\0') {
        if (*temp_ip == '.') {
            return AF_INET;
        }

        if (*temp_ip == ':') {
            return AF_INET6;
        }

        ++temp_ip;
    }

    return AF_INET;
}

static inline char *ipv6_local_link(const char *host, char *ip, uint32 ip_len)
{
    errno_t errcode;
    size_t host_len;

    int i = 0;

    while (host[i] && host[i] != '%') {
        i++;
    }

    if (host[i] == '\0') {
        return NULL;
    } else {  // handle local link
        host_len = (uint32)strlen(host);
        errcode = strncpy_s(ip, (size_t)ip_len, host, (size_t)host_len);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }

        ip[i] = '\0';
        return ip + i + 1;
    }
}

static status_t cm_ipport_to_sockaddr_ipv6(const char *host, int port, sock_addr_t *sock_addr)
{
    struct sockaddr_in6 *in6 = NULL;
#ifndef WIN32
    char ip[CM_MAX_IP_LEN];
    char *scope = NULL;
#endif

    sock_addr->salen = sizeof(struct sockaddr_in6);
    in6 = SOCKADDR_IN6(sock_addr);

    MEMS_RETURN_IFERR(memset_sp(in6, sizeof(struct sockaddr_in6), 0, sizeof(struct sockaddr_in6)));

    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(port);

#ifndef WIN32
    scope = ipv6_local_link(host, ip, CM_MAX_IP_LEN);
    if (scope != NULL) {
        in6->sin6_scope_id = if_nametoindex(scope);
        if (in6->sin6_scope_id == 0) {
            OG_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "invalid local link \"%s\"", scope);
            return OG_ERROR;
        }

        host = ip;
    }
    // The inet_pton() function shall return 1 if the conversion succeeds
    if (inet_pton(AF_INET6, host, &in6->sin6_addr) != 1) {
#else
    // If no error occurs, the InetPton function returns a value of 1.
    if (InetPton(AF_INET6, host, &in6->sin6_addr) != 1) {
#endif
        OG_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "%s", host);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_ipport_to_sockaddr(const char *host, int port, sock_addr_t *sock_addr)
{
    int sa_family = cm_get_ip_version(host);
    switch (sa_family) {
        case AF_INET: {
            struct sockaddr_in *in4 = NULL;

            sock_addr->salen = sizeof(struct sockaddr_in);
            in4 = SOCKADDR_IN4(sock_addr);

            MEMS_RETURN_IFERR(memset_sp(in4, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in)));

            in4->sin_family = AF_INET;
            in4->sin_port = htons(port);
#ifndef WIN32
            in4->sin_addr.s_addr = inet_addr(host);
            // Upon successful completion, inet_addr() shall return the Internet address.
            // Otherwise, it shall return (in_addr_t)(-1).
            if (in4->sin_addr.s_addr == (in_addr_t)(-1) || (inet_pton(AF_INET, host, &in4->sin_addr.s_addr) != 1)) {
#else
            // If no error occurs, the InetPton function returns a value of 1.
            if (InetPton(AF_INET, host, &in4->sin_addr.s_addr) != 1) {
#endif
                OG_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "%s", host);
                return OG_ERROR;
            }
            return OG_SUCCESS;
        }
        case AF_INET6:
            return cm_ipport_to_sockaddr_ipv6(host, port, sock_addr);

        default: {
            char ip[CM_MAX_IP_LEN] = {0};
            OG_RETURN_IFERR(cm_domain_to_ip(host, ip));
            return cm_ipport_to_sockaddr(ip, port, sock_addr);
        }
    }
}

status_t cm_ip_to_sockaddr(const char *host, sock_addr_t *sock_addr)
{
#define INVALID_PORT 0
    return cm_ipport_to_sockaddr(host, INVALID_PORT, sock_addr);
}

static inline status_t cm_get_cidrmask(const char *cidr_str, int *mask)
{
    if (!cm_check_ip_valid(cidr_str)) {
        char ip[CM_MAX_IP_LEN] = {0};
        OG_RETURN_IFERR(cm_domain_to_ip(cidr_str, ip));
        int family = cm_get_ip_version(ip);
        *mask = (family == AF_INET) ? 32 : 128;
        return OG_SUCCESS;
    }
    int family = cm_get_ip_version(cidr_str);
    if (family != AF_INET && family != AF_INET6) {
        OG_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "invalid address \"%s\"", cidr_str);
        return OG_ERROR;
    }

    char *cidr_slash = strchr(cidr_str, '/');
    if (cidr_slash != NULL) {
        if (cm_str2int(cidr_slash + 1, mask) != OG_SUCCESS || *mask < 0 || (family == AF_INET && *mask > 32) ||
            (family == AF_INET6 && *mask > 128)) {
            OG_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "invalid CIDR mask in address \"%s\"", cidr_str);
            return OG_ERROR;
        }
        *cidr_slash = '\0';
    } else {
        *mask = (family == AF_INET) ? 32 : 128;
    }

    return OG_SUCCESS;
}

status_t cm_parse_lsnr_addr(const char *ipaddrs, uint32 len, uint32 *ip_cnt, char out[][CM_MAX_IP_LEN])
{
    char address_temp[CM_MAX_IP_LEN] = {0};
    char ip_temp[CM_MAX_IP_LEN] = {0};
    uint32 start = 0;
    uint32 end = 0;
    uint32 ip_len = 0;
    *ip_cnt = 0;
    for (uint32 i = 0; i <= len; i++) {
        if (i == len || ipaddrs[i] == ',') {
            end = i;
            ip_len = end - start;
            if (ip_len >= CM_MAX_IP_LEN) {
                return OG_ERROR;
            }

            if (ip_len > 0) {
                MEMS_RETURN_IFERR(memcpy_s(address_temp, CM_MAX_IP_LEN, ipaddrs + start, ip_len));
            }
            address_temp[end - start] = '\0';
            if (cm_check_ip_valid(address_temp)) {
                MEMS_RETURN_IFERR(memcpy_s(ip_temp, CM_MAX_IP_LEN, address_temp, ip_len + 1));
            } else {
                OG_RETURN_IFERR(cm_domain_to_ip(address_temp, ip_temp));
            }
            MEMS_RETURN_IFERR(strncpy_s(out[*ip_cnt], CM_MAX_IP_LEN, ip_temp, strlen(ip_temp)));
            start = end + 1;
            (*ip_cnt)++;
            if ((*ip_cnt) > CM_INST_MAX_IP_NUM) {
                return OG_ERROR;
            }
        }
    }
    return (((*ip_cnt) > 0) ? OG_SUCCESS : OG_ERROR);
}

status_t cm_verify_lsnr_addr(const char *ipaddrs, uint32 len, uint32 *ip_cnt)
{
    char one_addr[OG_HOST_NAME_BUFFER_SIZE + 1];
    uint32 addr_begin = 0;
    uint32 addr_end = 0;

    if (ip_cnt != NULL) {
        *ip_cnt = 0;
    }

    for (uint32 i = 0; i <= len; i++) {
        if (i == len || ipaddrs[i] == ',' || ipaddrs[i] == ';') {
            addr_end = i;
            if (addr_end - addr_begin > OG_HOST_NAME_BUFFER_SIZE) {
                return OG_ERROR;
            }

            if (addr_end - addr_begin > 0) {
                MEMS_RETURN_IFERR(memcpy_s(one_addr, sizeof(one_addr), ipaddrs + addr_begin, addr_end - addr_begin));
            }
            one_addr[addr_end - addr_begin] = '\0';
            /* 适配域名
            if (!cm_check_ip_valid(one_addr)) {
                return OG_ERROR;
            }
            */
            addr_begin = addr_end + 1;

            if (ip_cnt != NULL) {
                (*ip_cnt)++;
            }
        }
    }
    return OG_SUCCESS;
}

status_t cm_split_host_ip(char host[][CM_MAX_IP_LEN], const char *value)
{
    int32 pos = 0;
    uint32 host_count = 0;
    text_t txt;
    char str_tmp[CM_MAX_IP_LEN * OG_MAX_LSNR_HOST_COUNT] = { 0 };
    char *str_pos = NULL;
    int32 len = (uint32)strlen(value);
    MEMS_RETURN_IFERR(strncpy_s(str_tmp, CM_MAX_IP_LEN * OG_MAX_LSNR_HOST_COUNT, value, len));

    str_pos = str_tmp;
    for (pos = 0; len > 0; --len) {
        if (str_pos[pos] != ',') {
            ++pos;
            continue;
        }
        str_pos[pos++] = '\0';
        txt.str = str_pos;
        txt.len = pos - 1;
        cm_trim_text(&txt);
        if (txt.len != 0) {
            MEMS_RETURN_IFERR(strncpy_s(host[host_count], CM_MAX_IP_LEN, txt.str, txt.len));
            if (++host_count > OG_MAX_LSNR_HOST_COUNT) {
                OG_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)OG_MAX_LSNR_HOST_COUNT);
                return OG_ERROR;
            }
        }
        str_pos[pos - 1] = ',';
        str_pos += pos;
        pos = 0;
    }

    if (pos > 0) {
        txt.str = str_pos;
        txt.len = pos;
        cm_trim_text(&txt);
        if (txt.len != 0) {
            MEMS_RETURN_IFERR(strncpy_s(host[host_count], CM_MAX_IP_LEN, txt.str, txt.len));

            if (++host_count > OG_MAX_LSNR_HOST_COUNT) {
                OG_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)OG_MAX_LSNR_HOST_COUNT);
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}
// value格式：node0_ip1,node0_ip2;node1_ip1,node1_ip2 或者 node0_ip1;node1_ip1 或者 node0_ip1
status_t cm_split_node_ip(char host[][OG_MAX_INST_IP_LEN], const char *value)
{
    int32 pos = 0;
    uint32 node_count = 0;
    text_t txt;
    char str_tmp[OG_MAX_INST_IP_LEN] = { 0 };
    char *str_pos = NULL;
    int32 len = (uint32)strnlen(value, OG_MAX_INST_IP_LEN - 1);
    MEMS_RETURN_IFERR(strncpy_s(str_tmp, OG_MAX_INST_IP_LEN, value, len));

    str_pos = str_tmp;
    for (pos = 0; len > 0; --len) {
        if (str_pos[pos] != ';') {
            ++pos;
            continue;
        }
        str_pos[pos++] = '\0';
        txt.str = str_pos;
        txt.len = pos - 1;
        cm_trim_text(&txt);
        if (txt.len != 0) {
            MEMS_RETURN_IFERR(strncpy_s(host[node_count], OG_MAX_INST_IP_LEN, txt.str, txt.len));
            if (++node_count > OG_MAX_INSTANCES) {
                OG_THROW_ERROR(ERR_TOO_MANY_CONNECTIONS, (uint32)OG_MAX_INSTANCES);
                return OG_ERROR;
            }
        }
        str_pos[pos - 1] = ',';
        str_pos += pos;
        pos = 0;
    }

    if (pos > 0) {
        txt.str = str_pos;
        txt.len = pos;
        cm_trim_text(&txt);
        if (txt.len != 0) {
            MEMS_RETURN_IFERR(strncpy_s(host[node_count], OG_MAX_INST_IP_LEN, txt.str, txt.len));
            if (++node_count > OG_MAX_INSTANCES) {
                OG_THROW_ERROR(ERR_TOO_MANY_CONNECTIONS, (uint32)OG_MAX_INSTANCES);
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

status_t cm_split_host_port(uint16 ports[], const char *port_addr)
{
    int32 len = (uint32)strlen(port_addr);
    uint32 port_len = 0;
    uint32 port_count = 0;
    char *port = (char *)port_addr;
    char *pos = NULL;

    for (pos = (char *)port_addr; len > 0; len--) {
        if (*pos != ',') {
            port_len++;
            pos++;
            continue;
        }

        *pos = '\0';
        if (cm_str2uint16(port, &ports[port_count]) != OG_SUCCESS) {
            cm_reset_error();
            OG_THROW_ERROR(ERR_INVALID_PARAMETER, "port");
            return OG_ERROR;
        }

        if (ports[port_count] < OG_MIN_PORT) {
            OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "port", (int64)OG_MIN_PORT);
            return OG_ERROR;
        }

        *pos = ',';
        port += (port_len + 1);
        port_count++;
        port_len = 0;
        pos = port;
    }

    if (port_len > 0) {
        if (cm_str2uint16(port, &ports[port_count]) != OG_SUCCESS) {
            cm_reset_error();
            OG_THROW_ERROR(ERR_INVALID_PARAMETER, "port");
            return OG_ERROR;
        }

        if (ports[port_count] < OG_MIN_PORT) {
            OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "port", (int64)OG_MIN_PORT);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static struct sockaddr_storage *cm_netmask_to_addr(struct sockaddr_storage *ss_mask, int mask_input, int family)
{
    errno_t errcode;
    int mask = mask_input;

    CM_ASSERT(family == AF_INET || family == AF_INET6);
    if (family == AF_INET) {
        struct sockaddr_in mask4;
        long maskl;

        errcode = memset_sp(&mask4, sizeof(mask4), 0, sizeof(mask4));
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }

        /* avoid "x << 32", which is not portable */
        if (mask > 0) {
            maskl = (0xffffffffUL << (uint32)(32 - mask)) & 0xffffffffUL;
        } else {
            maskl = 0;
        }
        mask4.sin_addr.s_addr = htonl(maskl);
        errcode = memcpy_sp(ss_mask, sizeof(struct sockaddr_storage), &mask4, sizeof(mask4));
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    } else {
        struct sockaddr_in6 mask6;
        int i;

        errcode = memset_sp(&mask6, sizeof(mask6), 0, sizeof(mask6));
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
        for (i = 0; i < 16; i++) {
            if (mask <= 0) {
                mask6.sin6_addr.s6_addr[i] = 0;
            } else if (mask >= 8) {
                mask6.sin6_addr.s6_addr[i] = 0xff;
            } else {
                mask6.sin6_addr.s6_addr[i] = (0xff << (uint32)(8 - mask)) & 0xff;
            }
            mask -= 8;
        }
        errcode = memcpy_sp(ss_mask, sizeof(struct sockaddr_storage), &mask6, sizeof(mask6));
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    }

    return ss_mask;
}

// ipstr_in_cidr - is ip_str within the cidr specified by cidr ?
inline status_t cm_ip_in_cidr(const char *ip_str, cidr_t *cidr, bool32 *result)
{
    sock_addr_t sock_addr;
    struct sockaddr_storage ss_mask;
    int family = (int)((struct sockaddr *)&cidr->addr)->sa_family;

    OG_RETURN_IFERR(cm_ip_to_sockaddr(ip_str, &sock_addr));
    if (family != (int)SOCKADDR_FAMILY(&sock_addr)) {
        *result = OG_FALSE;

        return OG_SUCCESS;
    }

    switch (family) {
        case AF_INET: {
            struct sockaddr_in *ipv4 = SOCKADDR_IN4(&sock_addr);
            struct sockaddr_in *net4 = (struct sockaddr_in *)&cidr->addr;
            struct sockaddr_in *msk4 = (struct sockaddr_in *)cm_netmask_to_addr(&ss_mask, cidr->mask, family);

            *result = ((ipv4->sin_addr.s_addr ^ net4->sin_addr.s_addr) & msk4->sin_addr.s_addr) == 0;
            return OG_SUCCESS;
        }
        case AF_INET6: {
            struct sockaddr_in6 *ipv6 = SOCKADDR_IN6(&sock_addr);
            struct sockaddr_in6 *net6 = (struct sockaddr_in6 *)&cidr->addr;
            struct sockaddr_in6 *msk6 = (struct sockaddr_in6 *)cm_netmask_to_addr(&ss_mask, cidr->mask, family);

            for (int i = 0; i < 16; i++) {
                if (((ipv6->sin6_addr.s6_addr[i] ^ net6->sin6_addr.s6_addr[i]) & msk6->sin6_addr.s6_addr[i]) != 0) {
                    *result = OG_FALSE;
                    return OG_SUCCESS;
                }
            }
            *result = OG_TRUE;
            return OG_SUCCESS;
        }
        default:
            return OG_ERROR;
    }
}

// is cidr1 equals to cidr2 ?
inline status_t cm_cidr_equals_cidr(cidr_t *cidr1, cidr_t *cidr2, bool32 *result)
{
    int family1 = (int)((struct sockaddr *)&cidr1->addr)->sa_family;
    int family2 = (int)((struct sockaddr *)&cidr2->addr)->sa_family;

    if (family1 != family2 || cidr1->mask != cidr2->mask) {
        *result = OG_FALSE;
        return OG_SUCCESS;
    }

    switch (family1) {
        case AF_INET: {
            struct sockaddr_in *net4_c1 = (struct sockaddr_in *)&cidr1->addr;
            struct sockaddr_in *net4_c2 = (struct sockaddr_in *)&cidr2->addr;

            *result = (net4_c1->sin_addr.s_addr == net4_c2->sin_addr.s_addr);
            return OG_SUCCESS;
        }
        case AF_INET6: {
            struct sockaddr_in6 *net6_c1 = (struct sockaddr_in6 *)&cidr1->addr;
            struct sockaddr_in6 *net6_c2 = (struct sockaddr_in6 *)&cidr2->addr;

            for (int i = 0; i < 16; i++) {
                if (net6_c1->sin6_addr.s6_addr[i] != net6_c2->sin6_addr.s6_addr[i]) {
                    *result = OG_FALSE;
                    return OG_SUCCESS;
                }
            }
            *result = OG_TRUE;
            return OG_SUCCESS;
        }
        default:
            return OG_ERROR;
    }
}

// is ip in specified cidr list?
static inline status_t cm_ip_in_cidrs(const char *ip_str, list_t *l, bool32 *result)
{
    for (uint32 i = 0; i < l->count; i++) {
        cidr_t *cidr = (cidr_t *)cm_list_get(l, i);
        OG_RETURN_IFERR(cm_ip_in_cidr(ip_str, cidr, result));
        if (*result) {
            return OG_SUCCESS;
        }
    }

    *result = OG_FALSE;
    return OG_SUCCESS;
}

static inline bool32 cm_check_user_white_list(white_context_t *ogx, const char *ip_str, const char *user,
                                              bool32 *hostssl)
{
    list_t *uwl = &ogx->user_white_list;
    bool32 uwl_configed = uwl->count > 0;
    bool32 result = OG_FALSE;
    bool32 is_found = OG_FALSE;

    if (!uwl_configed) {
        return OG_TRUE;
    }
    for (uint32 i = 0; i < uwl->count; i++) {
        uwl_entry_t *uwl_entry = (uwl_entry_t *)cm_list_get(uwl, i);

        if (cm_ip_in_cidrs(ip_str, &uwl_entry->white_list, &result) != OG_SUCCESS) {
            return OG_FALSE;
        }

        // If there are duplicate users and ip, but the types are inconsistent,
        // it will take effect according to the hostssl mode with high security level
        if (result && (cm_str_equal_ins(uwl_entry->user, "*") || cm_str_equal_ins(uwl_entry->user, user))) {
            *hostssl = uwl_entry->hostssl;
            if (uwl_entry->hostssl) {
                return OG_TRUE;
            }
            is_found = OG_TRUE;
        }
    }
    return is_found;
}

static inline bool32 cm_check_ip_white_list(white_context_t *ogx, const char *ip_str)
{
    list_t *iwl = &ogx->ip_white_list;
    bool32 iwl_configed = ogx->iwl_enabled && (ogx->ip_white_list.count > 0);
    bool32 result = OG_FALSE;

    if (!iwl_configed) {
        return OG_TRUE;
    }

    if (cm_ip_in_cidrs(ip_str, iwl, &result) != OG_SUCCESS) {
        return OG_FALSE;
    }

    return result;
}

status_t cm_check_remote_ip(white_context_t *ogx, const char *ip_str, bool32 *check_res)
{
    bool32 result = OG_TRUE;
    *check_res = OG_TRUE;
    list_t *uwl = NULL;
    bool32 uwl_configed = OG_FALSE;

    if (ogx == NULL || !ogx->iwl_enabled || cm_is_local_ip(ip_str)) {
        return OG_SUCCESS;
    }

    if (ogx->ip_white_list.count > 0) {
        OG_RETURN_IFERR(cm_ip_in_cidrs(ip_str, &ogx->ip_white_list, &result));
        uwl = &ogx->user_white_list;
        uwl_configed = uwl->count > 0;
        if (result == OG_FALSE && !uwl_configed) {
            *check_res = OG_FALSE;
            return OG_SUCCESS;
        }
    }

    if (ogx->ip_black_list.count > 0) {
        OG_RETURN_IFERR(cm_ip_in_cidrs(ip_str, &ogx->ip_black_list, &result));
        if (result == OG_TRUE) {
            *check_res = OG_FALSE;
        }
    }

    return OG_SUCCESS;
}

static inline bool32 cm_check_black_list(white_context_t *ogx, const char *ip_str)
{
    bool32 result = OG_FALSE;

    if (!ogx->iwl_enabled || ogx->ip_black_list.count == 0) {
        return OG_TRUE;
    }

    if (cm_ip_in_cidrs(ip_str, &ogx->ip_black_list, &result) != OG_SUCCESS) {
        return OG_FALSE;
    }

    return !result;
}

static inline bool32 cm_check_white_list(white_context_t *ogx, const char *ip_str, const char *user, bool32 *hostssl)
{
    bool32 uwl_configed = ogx->user_white_list.count > 0;
    bool32 iwl_configed = ogx->iwl_enabled && (ogx->ip_white_list.count > 0);

    if (!uwl_configed) {
        if (cm_check_ip_white_list(ogx, ip_str)) {
            return OG_TRUE;
        }
        return OG_FALSE;
    }

    if (!iwl_configed) {
        if (cm_check_user_white_list(ogx, ip_str, user, hostssl)) {
            return OG_TRUE;
        }
        return OG_FALSE;
    }

    if (cm_check_user_white_list(ogx, ip_str, user, hostssl) || cm_check_ip_white_list(ogx, ip_str)) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

bool32 cm_check_ip(white_context_t *ogx, const char *ip_str, const char *user, bool32 *hostssl)
{
    // WE ALWAYS ALLOW CLSMGR/SYSDBA LOGIN
    if ((cm_is_local_ip(ip_str) && cm_str_equal_ins(user, "SYS")) || cm_str_equal_ins(user, "CLSMGR") ||
        cm_str_equal_ins(user, "SYSDBA")) {
        return OG_TRUE;
    }

    cm_spin_lock(&ogx->lock, NULL);

    if (cm_check_white_list(ogx, ip_str, user, hostssl) && cm_check_black_list(ogx, ip_str)) {
        cm_spin_unlock(&ogx->lock);
        return OG_TRUE;
    }
    cm_spin_unlock(&ogx->lock);

    return OG_FALSE;
}

static inline status_t cm_resolve_star_ipv4(char *ip_str, char *part[], int *cidrmask)
{
    char *strtok_last = NULL;
    bool32 meet_star = OG_FALSE;

    for (int i = 0; i < 4; i++) {
        part[i] = strtok_s(i == 0 ? ip_str : NULL, ".", &strtok_last);
        if (part[i] == NULL) {
            return OG_ERROR;
        }

        if (!meet_star) {
            int value;
            if (strcmp(part[i], "*") == 0) {
                meet_star = OG_TRUE;
                *cidrmask = i * 8;
                part[i] = "0";
            } else {
                if (cm_str2int(part[i], &value) != OG_SUCCESS || value < 0 || value > 255) {
                    return OG_ERROR;
                }
            }
        } else {
            if (strcmp(part[i], "*") == 0) {
                part[i] = "0";
            } else {
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

// 127.0.*.* --> 127.0.0.0/16
static inline status_t cm_extend_star_ipv4(const char *ip_str, char *ipv4_ex, bool32 *result)
{
    char *part[4];
    int cidrmask = 32;
    char tmp_ip[CM_MAX_IP_LEN];
    size_t ip_len;

    if (cm_get_ip_version(ip_str) != AF_INET || strchr(ip_str, '*') == NULL) {
        *result = OG_FALSE;
        return OG_SUCCESS;
    }

    ip_len = (uint32)strlen(ip_str);
    MEMS_RETURN_IFERR(strncpy_s(tmp_ip, CM_MAX_IP_LEN, ip_str, (size_t)ip_len));

    if (cm_resolve_star_ipv4(tmp_ip, part, &cidrmask) != OG_SUCCESS) {
        OG_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "invalid address \"%s\"", ip_str);
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(ipv4_ex, CM_MAX_IP_LEN, CM_MAX_IP_LEN - 1, "%s.%s.%s.%s/%d", part[0], part[1], part[2],
                                 part[3], cidrmask));

    *result = OG_TRUE;
    return OG_SUCCESS;
}

// !!Caution: cidr_str would be motified
status_t cm_str_to_cidr(char *cidr_str, cidr_t *cidr, uint32 cidr_str_len)
{
    sock_addr_t sock_addr;
    char ipv4_ex[CM_MAX_IP_LEN];
    bool32 result = OG_FALSE;

    OG_RETVALUE_IFTRUE((uint32)strlen(cidr_str) >= cidr_str_len, OG_ERROR);

    OG_RETURN_IFERR(cm_extend_star_ipv4(cidr_str, ipv4_ex, &result));
    cidr_str = result ? ipv4_ex : cidr_str;

    OG_RETURN_IFERR(cm_get_cidrmask(cidr_str, &cidr->mask));

    OG_RETURN_IFERR(cm_ip_to_sockaddr(cidr_str, &sock_addr));

    MEMS_RETURN_IFERR(memcpy_sp(&cidr->addr, (size_t)sock_addr.salen, &sock_addr.addr, (size_t)sock_addr.salen));

    return OG_SUCCESS;
}

bool32 cm_check_ip_valid(const char *ip)
{
    sock_addr_t sock_addr;
    int sa_family = cm_get_ip_version(ip);
    switch (sa_family) {
        case AF_INET:
            return OG_TRUE;
        
        case AF_INET6:
            return cm_ipport_to_sockaddr_ipv6(ip, 0, &sock_addr) == OG_SUCCESS ? OG_TRUE : OG_FALSE;

        default:
            return OG_FALSE;
    }

    return OG_FALSE;
}

// !!Caution: Invoker should cm_destroy_list(cidr_list) if OG_ERROR returned.
status_t cm_parse_cidrs(text_t *cidr_texts, list_t *cidr_list)
{
    text_t cidr_text;
    char cidr_str[CM_MAX_IP_LEN] = { 0 };
    cidr_t *cidr = NULL;

    OG_RETSUC_IFTRUE(cidr_texts == NULL || CM_IS_EMPTY(cidr_texts));

    if (CM_TEXT_BEGIN(cidr_texts) == '(' && CM_TEXT_END(cidr_texts) == ')') {
        CM_REMOVE_ENCLOSED_CHAR(cidr_texts);
    }

    while (cm_fetch_text(cidr_texts, ',', 0, &cidr_text)) {
        OG_CONTINUE_IFTRUE(cidr_text.len == 0);

        cm_trim_text(&cidr_text);
        OG_RETURN_IFERR(cm_text2str(&cidr_text, cidr_str, CM_MAX_IP_LEN));

        OG_RETURN_IFERR(cm_list_new(cidr_list, (pointer_t *)&cidr));

        OG_RETURN_IFERR(cm_str_to_cidr(cidr_str, cidr, CM_MAX_IP_LEN));
    }

    return OG_SUCCESS;
}

static inline bool32 cm_check_user_white_list_for_ssl(white_context_t *ogx, bool32 *hostssl)
{
    list_t *uwl = &ogx->user_white_list;
    bool32 uwl_configed = uwl->count > 0;

    if (!uwl_configed) {
        return OG_TRUE;
    }

    for (uint32 i = 0; i < uwl->count; i++) {
        uwl_entry_t *uwl_entry = (uwl_entry_t *)cm_list_get(uwl, i);
        if (uwl_entry->hostssl) {
            *hostssl = OG_TRUE;
        } else {
            *hostssl = OG_FALSE;
            return OG_TRUE;
        }
    }

    return OG_TRUE;
}

bool32 cm_check_user(white_context_t *ogx, const char *ip_str, const char *user, bool32 *hostssl)
{
    cm_spin_lock(&ogx->lock, NULL);

    cm_check_user_white_list_for_ssl(ogx, hostssl);
    if (*hostssl) {
        cm_spin_unlock(&ogx->lock);
        return OG_TRUE;
    }

    if (cm_check_user_white_list(ogx, ip_str, user, hostssl)) {
        cm_spin_unlock(&ogx->lock);
        return OG_TRUE;
    }
    cm_spin_unlock(&ogx->lock);

    return OG_FALSE;
}

status_t cm_domain_to_ip(const char *hostname, char *hostip)
{
    if (hostname == NULL || hostip == NULL) {
        OG_LOG_RUN_ERR("domain to ip failed, intput param invalid.");
        return OG_ERROR;
    }
    
    int status;
    struct addrinfo hints;
    struct addrinfo *res;
    char ipstr[INET6_ADDRSTRLEN];
    MEMS_RETURN_IFERR(memset_s(&hints, sizeof(struct addrinfo), 0, sizeof(struct addrinfo)));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status != 0) {
        OG_LOG_RUN_ERR("mes get ip failed, getaddrinfo %s", gai_strerror(status));
        return OG_ERROR;
    }

    status_t lookupstatus = OG_ERROR;

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        void *addr;
        const char *ipver;
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));

        errno_t ret = strncpy_s(hostip, CM_MAX_IP_LEN, ipstr, strlen(ipstr));
        MEMS_RETURN_IFERR(ret);
        lookupstatus = OG_SUCCESS;
        OG_LOG_RUN_INF("domain to ip, ipver %s, ip %s to %s", ipver, hostname, ipstr);
        break;
    }
    freeaddrinfo(res);
    if (lookupstatus != OG_SUCCESS) {
        OG_LOG_RUN_ERR("domain to ip, ip not found for %s", ipstr);
        return OG_ERROR;
    }
    return lookupstatus;
}
