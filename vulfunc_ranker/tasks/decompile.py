#!/usr/bin/env python3
import idapro  # 必须放在首行[1](@ref)import ida_hexrays
import idautils
import idc
import sys
import os
import idaapi
import ida_auto


def decompile_function(func_ea) -> dict | str:
    """
    反编译单个函数并返回结果
    
    :param func_ea: 函数地址
    :return result: 反编译结果字典或错误信息字符串
    """
    try:
        dec = idaapi.decompile(func_ea)
        if dec is None:
            return f"[ERROR] 反编译失败: {hex(func_ea)}"
        return {
            "name": idc.get_func_name(func_ea),
            "address": hex(func_ea),
            "decompiled": str(dec).replace("\n", "\n    ")
        }
    except Exception as e:
        return f"[CRASH] {str(e)}"

def batch_decompile(input_file) -> tuple[list, bool]:
    """
    批量处理主函数
    
    :param input_file: 输入二进制文件路径
    :return results: 反编译结果列表
    :return has_real_name: 函数名是否可读
    """
    # 打开数据库并自动分析
    idapro.open_database(input_file, True)
    ida_auto.auto_wait()
    
    # 遍历所有函数
    results = []
    DEFAULT_PREFIXES = ["sub_", "nullsub_", "loc_", "sep_"]  # IDA反编译函数默认前缀集合
    default_name_count = 0
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        # print(f"Processing: {func_name} ({hex(func_ea)})...")
        # 统计默认名称函数数量
        if any(func_name.startswith(prefix) for prefix in DEFAULT_PREFIXES):
            default_name_count += 1
        
        # 反编译并保存结果,如果反编译失败则跳过
        result = decompile_function(func_ea)
        #如果反编译失败不加入结果
        if isinstance(result, dict):
            results.append(result)
    
    # 检查函数名恢复状态
    has_real_name = False
    if len(results) > 0:
        # 阈值说明：通常去符号文件的默认名称(sub_)比例 > 95%。
        # 设为 0.7 表示只要有超过 30% 的函数拥有具体名称，就认为加载了符号或PDB。
        if default_name_count / len(results) < 0.7:
            has_real_name = True
    
    # 关闭数据库
    idapro.close_database()
    return results, has_real_name

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <输入二进制> <输出目录>")
        sys.exit(1)
    
    input_bin = sys.argv[1]
    output_dir = sys.argv[2]
    

    results, has_real_name = batch_decompile(input_bin)
    print("反编译完成!")
    print(f"函数名恢复状态: {'已恢复' if has_real_name else '未恢复'}")