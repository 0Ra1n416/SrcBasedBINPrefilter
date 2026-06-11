#!/usr/bin/env python3
import idapro  # 必须放在首行[1](@ref)import ida_hexrays
import idautils
import idc
import sys
import os
import idaapi
import ida_auto
import ida_nalt



def get_extern_calls(input_bin, opened_db=False) -> list:
    """
    获取外部调用函数列表

    :param input_bin: 输入二进制文件路径
    :param opened_db: 如果为 True，则假定调用方已经打开了数据库，不重复 open/close
    :return extern_calls: 外部调用函数列表
    """


    if not opened_db:
        # 打开数据库并自动分析
        idapro.open_database(input_bin, True)
        ida_auto.auto_wait()

    imported_functions = []
    imported_seen = set()

    def _import_cb(_ea, name, _ord):
        if not name:
            return True
        if name in imported_seen:
            return True
        imported_seen.add(name)
        imported_functions.append(name)
        return True

    for entry_idx in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(entry_idx, _import_cb)


    if not opened_db:
        idapro.close_database()

    

    # 遍历imported_functions，如果函数名中存在@@，去掉该函数

    for func in imported_functions[:]:
        if '@@' in func:
            imported_functions.remove(func)

    # print(f"外部调用函数列表: {imported_functions}")
    return imported_functions