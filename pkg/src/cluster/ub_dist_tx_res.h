/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

 * rmrs is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *      http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef UB_DIST_TX_RES_H
#define UB_DIST_TX_RES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 定义日志级别常量
#ifndef LOG_LEVEL_DEBUG
#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_CRITICAL 4
#endif

/* Operation result: execution succeeded */
#define UB_RES_OK 0
/* Operation result: execution failed/error occurred */
#define UB_RES_ERROR -1

/**
 * @brief Initialize a distributed transaction resource object.
 * @param[out] handle : pointer to store the handle of the initialized resource object
 * @return Operation result status (UB_RES_OK for success, UB_RES_ERROR for failure)
 */
int ub_dist_tx_res_init(uint64_t *handle);

/**
 * @brief Set a specific value to the distributed transaction resource.
 * @param[in] handle : pointer to the handle of the target resource object
 * @param[in] value  : the value to be set to the distributed transaction resource
 * @return Operation result status (UB_RES_OK for success, UB_RES_ERROR for failure)
 */
int ub_dist_tx_res_set(uint64_t *handle, uint64_t value);

/**
 * @brief Get the current value of the distributed transaction resource.
 * @param[in]  handle   : pointer to the handle of the target resource object
 * @param[out] out_val  : pointer to store the retrieved value of the resource
 * @return Operation result status (UB_RES_OK for success, UB_RES_ERROR for failure)
 */
int ub_dist_tx_res_get(uint64_t *handle, uint64_t *out_val);

/**
 * @brief Atomically add a value to the distributed transaction resource and get the original value.
 * @param[in]  handle   : pointer to the handle of the target resource object
 * @param[in]  value    : the value to be atomically added to the resource
 * @param[out] out_val  : pointer to store the original value of the resource before the addition
 * @return Operation result status (UB_RES_OK for success, UB_RES_ERROR for failure)
 */
int ub_dist_tx_res_fetch_add(uint64_t *handle, uint64_t value, uint64_t *out_val);

#ifndef UB_ATOMIC_LOG_FUNC_TYPEDEF
#define UB_ATOMIC_LOG_FUNC_TYPEDEF
/*
* @brief log func
* @param level [in] : LogLevel
* @param file [in] : source file name
* @param func [in] : function name
* @param line [in] : line number
* @param message [in] : formatted message
*/
typedef int (*ub_atomic_log_func)(int level, const char *file, const char *func, uint32_t line, const char *message);

/*
* @brief register log function
* @param func [in] : user-defined log function pointer
*/
void ub_atomic_register_log_func(ub_atomic_log_func func);

/*
* @brief set log level threshold
* @param level [in] : log level threshold (LOG_LEVEL_DEBUG ~ LOG_LEVEL_CRITICAL)
* @return 0 on success, -1 on invalid level
*/
int ub_atomic_set_log_level(int level);
#endif
#ifdef __cplusplus
}
#endif

#endif /* UB_DIST_TX_RES_H */