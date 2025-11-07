#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of oGRACDB databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
import sys
from ograc_install import oGRAC

if __name__ == "__main__":
    Func = oGRAC()
    Func.ograc_pre_install()
    sys.exit(0)
