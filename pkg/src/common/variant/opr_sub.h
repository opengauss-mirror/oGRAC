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
 * opr_sub.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_sub.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OPR_SUB_H__
#define __OPR_SUB_H__

#include "var_opr.h"

status_t opr_exec_sub(opr_operand_set_t *op_set);
status_t opr_type_infer_sub(og_type_t left, og_type_t right, og_type_t *result);

#endif