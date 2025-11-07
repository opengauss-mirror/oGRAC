// Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
#ifndef __OGSQL_LOAD_H__
#define __OGSQL_LOAD_H__

#include "ogsql.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup OGSQL_CMD
* @brief The API of `ogsql` command interface
* @{ */
void ogsql_show_loader_opts(void);
status_t ogsql_load(text_t *cmd_text);

/** @} */  // end group OGSQL_CMD

#ifdef __cplusplus
}
#endif

#endif  // end __OGSQL_LOAD_H__