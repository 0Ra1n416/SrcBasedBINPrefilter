"""输入函数与输入解析函数的路径碰撞"""
import os
import sys
import vulfunc_ranker.tasks.input_funcs as inf
import vulfunc_ranker.tasks.recognize_input_parsing_funcs as inpf
import idapro
import idc
import idautils
import ida_auto

# inf_close_funcs = set()
# exist_path_collision_funcs = set()

def get_close_funcs(func) -> set:
    """
    通过调用IDA的API获取func的调用关系（主要是调用func的函数）
    
    :param func: 函数名
    :return close_funcs: 该函数的近邻函数集合
    """
    close_funcs = set()
    try:
        func_ea = idc.get_name_ea_simple(func)
        if func_ea == idc.BADADDR:
            return close_funcs
    except:
        return close_funcs

    for caller_ea in idautils.CodeRefsTo(func_ea, 0):
        caller_name = idc.get_func_name(caller_ea)
        close_funcs.add(caller_name)
        # print(f"Function {caller_name} calls {func}")
    return close_funcs

def get_inf_close_funcs(funcs) -> set:
    """
    获取输入函数的近邻函数集合
    
    :param funcs: 输入函数列表
    :return inf_close_funcs: 输入函数的近邻函数集合
    """
    inf_close_funcs = set()
    for func in funcs:
        inf_close_funcs.update(get_close_funcs(func))
        
    return inf_close_funcs

def get_inpf_close_funcs(inpf_funcs, inf_close_funcs) -> set:
    """
    获取有路径碰撞的输入解析函数集合
    
    :param inpf_funcs: 输入解析函数列表
    :param inf_close_funcs: 输入函数的近邻函数集合
    :return exist_path_collision_funcs: 有路径碰撞的输入解析函数集合
    """
    exist_path_collision_funcs = set()
    for func in inpf_funcs:
        # print(f"分析输入解析函数: {func} 的调用关系...")
        inpf_close_funcs = get_close_funcs(func)
        inpf_close_funcs.add(func)

        # 计算路径碰撞(inf_close_funcs与inpf_close_funcs的交集)
        path_collision = inf_close_funcs.intersection(inpf_close_funcs)
        if path_collision:
            exist_path_collision_funcs.add(func)
            
    return exist_path_collision_funcs
        
def path_collision_analysis(inf_funcs, inpf_funcs, input_bin) -> set:
    """
    分析输入函数与输入解析函数的路径碰撞情况
    
    :param inf_funcs: 输入函数列表
    :param inpf_funcs: 输入解析函数列表
    :param input_bin: 输入二进制文件路径
    :return exist_path_collision_funcs: 有路径碰撞的输入解析函数集合
    """
    idapro.open_database(input_bin, True)
    ida_auto.auto_wait()

    inf_close_funcs = get_inf_close_funcs(inf_funcs)
    # print(f"输入函数的近邻函数有: {inf_close_funcs}")
    exist_path_collision_funcs = get_inpf_close_funcs(inpf_funcs, inf_close_funcs)
    # print(f"存在路径碰撞的函数有: {exist_path_collision_funcs}")

    idapro.close_database()
    return exist_path_collision_funcs
