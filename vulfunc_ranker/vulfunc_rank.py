import sys
import os

# 将上级目录添加到sys.path，以便导入vulfunc_ranker模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入vulfunc_ranker模块中的各个子模块
import vulfunc_ranker.tasks.decompile
import vulfunc_ranker.tasks.ast_parse as ap
import vulfunc_ranker.tasks.parsing_logic as pl
import vulfunc_ranker.tasks.recognize_input_parsing_funcs
import vulfunc_ranker.tasks.path_collision as pc
import vulfunc_ranker.tasks.input_funcs as inf
import vulfunc_ranker.tasks.get_extern as ge

# 其他必要的导入
import json

# 配置路径和初始阈值
THRESHOLD = 6.0
NOW_PY_DIR = os.path.dirname(os.path.abspath(__file__))
ORIGINAL_CONFIG_PATH = os.path.join(NOW_PY_DIR, "caches_data", "config.json")
OUTPUT_BASE_DIR = os.path.join(NOW_PY_DIR, "temp")
# 强制将外部调用函数加入输入解析函数候选集
FORCE_ADD_EXTERN_CALLS = True

def vulfunc_rank(input_bin: str,
                 threshold_in: float=THRESHOLD,
                 original_config_path: str=ORIGINAL_CONFIG_PATH,
                 output_base_dir: str=OUTPUT_BASE_DIR,
                 force_add_extern_calls: bool=FORCE_ADD_EXTERN_CALLS,
                 ) -> int:
    """
    主程序入口，先反编译再检测
    
    :param input_bin: 输入二进制文件路径
    :param threshold_in: 输入解析函数识别的初始阈值，默认为THRESHOLD常量
    :param original_config_path: 原始配置文件路径
    :param output_base_dir: 输出文件基础目录，各个输出文件夹以输入二进制文件名命名，放在该目录下，即缓存文件夹
    :param force_add_extern_calls: 是否强制将外部调用函数加入输入解析函数候选集

    :return source_count: Source函数数量(除了预定义的Source函数以外)
    """

    # 确定 输出 目录路径
    output_base_dir = os.path.abspath(output_base_dir)
    
    # 确保目录存在
    os.makedirs(output_base_dir, exist_ok=True)
    
    # 确定 original_config_path 路径
    original_config_path = os.path.abspath(original_config_path)

    # 二进制文件不能直接放在输出下
    if os.path.dirname(input_bin) == output_base_dir:
        print(f"请勿将输入二进制文件放在输出目录中，以避免与输出文件发生路径冲突。")
        sys.exit(1)
    
    # 反编译输入二进制文件
    print(f"开始反编译: {input_bin}")
    decompiled_results, has_real_name = vulfunc_ranker.tasks.decompile.batch_decompile(input_bin)
    print("反编译完成!")

    # 新算法判断输入解析函数
    threshold = threshold_in
    if not has_real_name:
        threshold -= 1.5  # 如果函数名不可读，则降低阈值
    func_num = len(decompiled_results)
    top_k_init = 100
    if func_num * 0.02 < top_k_init:
        top_k_init = int(func_num * 0.02)
    results = vulfunc_ranker.tasks.recognize_input_parsing_funcs.batch_judge(decompiled_results, threshold=threshold, top_k=top_k_init)
   
    inpf_funcs = [res['name'] for res in results]
    inf_funcs = inf.get_input_funcs()
   
    # 路径碰撞分析
    print("开始路径碰撞分析...")
    path_collision_funcs = pc.path_collision_analysis(inf_funcs, inpf_funcs, input_bin)

    
    # NOTE：cheat，可以在这里直接修改最后出来的结果
    # -------------------------------------------------------
    # path_collision_funcs.add("fopen")
    # -------------------------------------------------------
    
    # 如有需要，强制将外部调用函数加入输入解析函数候选集
    extern_funcs = list()
    if force_add_extern_calls:
        extern_funcs = ge.get_extern_calls(input_bin)
    
    # Output:
    source_count = len(path_collision_funcs) + len(extern_funcs)
    
    return source_count

def source_func_count_by_algorithm(input_bin: str) -> int:
    """
    仅使用vulfunc_rank算法来判断输入解析函数数量，供bin_pre_filter.py调用
    
    :param input_bin: 输入二进制文件路径

    :return source_count: Source函数数量(除了预定义的Source函数以外)
    """
    return vulfunc_rank(input_bin)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("input_bin", help="输入二进制文件路径")
    parser.add_argument("--threshold", type=float, default=THRESHOLD, help="输入解析函数识别的初始阈值，默认为6.0")
    parser.add_argument("--original_config_path", type=str, default=ORIGINAL_CONFIG_PATH,
                        help="原始配置文件路径，默认为当前文件夹下的caches_data/config.json")
    parser.add_argument("--output_base_dir", type=str, default=OUTPUT_BASE_DIR,
                        help="输出文件基础目录，各个输出文件夹以输入二进制文件名命名，放在该目录下，默认为当前文件夹的上五级目录（根目录）")
    parser.add_argument("--not_force_add_extern_calls", action="store_true",
                        help="不要强制将外部调用函数加入输入解析函数候选集，默认为False，即默认会加入")

    args = parser.parse_args()

    source_count = vulfunc_rank(args.input_bin,
                 threshold_in=args.threshold,
                 original_config_path=args.original_config_path,
                 output_base_dir=args.output_base_dir,
                 force_add_extern_calls=not args.not_force_add_extern_calls) 
    
    print(f"Source函数数量: {source_count}")