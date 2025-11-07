# !/usr/bin/env python
# -*- coding: utf-8 -*-
from ograc_install import oGRAC

if __name__ == "__main__":
    Func = oGRAC()
    try:
        Func.post_check()
    except ValueError as err:
        exit(str(err))
    except Exception as err:
        exit(str(err))
    exit(0)