#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of oGRACDB databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
from ograc_install import oGRAC
from exception import NormalException

if __name__ == "__main__":
    Func = oGRAC()
    try:
        Func.ograc_start()
    except ValueError as err:
        exit(str(err))
    except Exception as err:
        exit(str(err))
    exit(0)