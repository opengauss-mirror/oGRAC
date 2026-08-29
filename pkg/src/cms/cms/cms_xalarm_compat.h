/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
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
 * cms_xalarm_compat.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_xalarm_compat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_XALARM_COMPAT_H
#define CMS_XALARM_COMPAT_H

#ifdef ENABLE_XALARMD

#ifdef __cplusplus
extern "C" {
#endif

#include <xalarm/register_xalarm.h>
#include "securec.h"

/*
 * Legacy libxalarm: void xalarm_unregister_event(struct alarm_register *r);
 * New sysSentry:     void xalarm_unregister_event(struct alarm_register **r);
 */
static inline void CmsXalarmUnregisterEvent(struct alarm_register **register_holder)
{
    if (register_holder == NULL) {
        return;
    }
#ifndef CM_XALARM_LEGACY_REGISTER_ABI
    (void)xalarm_unregister_event(register_holder);
#else
    (void)xalarm_unregister_event(*register_holder);
#endif
}

static inline void CmsXalarmMsgToAlarmInfo(const struct alarm_msg *msg, struct alarm_info *out)
{
    if (msg == NULL || out == NULL) {
        return;
    }
    (void)memset_s(out, sizeof(*out), 0, sizeof(*out));
    out->usAlarmId = msg->usAlarmId;
    out->AlarmTime = msg->AlarmTime;
    (void)strncpy_s(out->pucParas, sizeof(out->pucParas), msg->pucParas, sizeof(out->pucParas) - 1);
    out->pucParas[sizeof(out->pucParas) - 1] = '\0';
}

#ifdef __cplusplus
}
#endif

#endif /* ENABLE_XALARMD */

#endif /* CMS_XALARM_COMPAT_H */
