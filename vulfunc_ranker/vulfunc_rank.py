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
                 ) -> list:
    """
    主程序入口，先反编译再检测
    
    :param input_bin: 输入二进制文件路径
    :param threshold_in: 输入解析函数识别的初始阈值，默认为THRESHOLD常量
    :param original_config_path: 原始配置文件路径
    :param output_base_dir: 输出文件基础目录，各个输出文件夹以输入二进制文件名命名，放在该目录下，即缓存文件夹
    :param force_add_extern_calls: 是否强制将外部调用函数加入输入解析函数候选集

    :return path_collision_funcs: 路径碰撞函数列表
    :return extern_funcs: 外部调用函数列表
    :return new_json_path: 更新后的配置文件路径
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

    # 反编译完成后，进行漏洞函数检测和排序
    #vulfunc_ranker.tasks.detect_input_parser_funcs_sort.execute(decompiled_results, OUTPUT_TXT, THRESHOLD)
    
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
   
    # 将结果写入文件,并在结尾加上input_bin文件名,input_bin还需要去掉文件格式
    output_name = os.path.splitext(os.path.basename(input_bin))[0]
    
    if not os.path.exists(os.path.join(output_base_dir, output_name, "origin")):
        os.makedirs(os.path.join(output_base_dir, output_name, "origin"))
    if not os.path.exists(os.path.join(output_base_dir, output_name, "origin", "config.json")):
        with open(original_config_path, "rb") as src, \
            open(os.path.join(output_base_dir, output_name, "origin", "config.json"), "wb") as dst:
            # 复制文件内容
            data = src.read()
            dst.write(data)
    output_path = os.path.join(output_base_dir, output_name, "origin", f"recognize_output_{output_name}.json")
    
    with open(output_path, "w") as f:
        # 每个dict的actions字段是set，转为list才能写入json文件
        for res in results:
            res['actions'] = list(res['actions'])
        json.dump(results, f, indent=4, ensure_ascii=False)

    # 读取原json文件
    json_path = os.path.join(output_base_dir, output_name, "origin", "config.json")
    # 读取json文件
    with open(json_path, "r") as f:
        config_data = json.load(f)
        # 在source字段的ret/0/1中都添加上path_collision_funcs,先判断是否存在该字段
        if 'sources' in config_data:
            if 'ret' in config_data['sources']:    
                config_data['sources']['ret'] += path_collision_funcs
                config_data['sources']['ret'] += extern_funcs
            if '0' in config_data['sources']:
                config_data['sources']['0'] += path_collision_funcs
                config_data['sources']['0'] += extern_funcs
            if '1' in config_data['sources']:
                config_data['sources']['1'] += path_collision_funcs
                config_data['sources']['1'] += extern_funcs
    
    new_json_path = os.path.join(output_base_dir, output_name, "origin", f"config_{output_name}.json")
    with open(new_json_path, "w") as f:
        # 写入json文件，保留原格式即可
        json.dump(config_data, f, indent=4)

    # Output:
    source_json_path = os.path.join(output_base_dir, output_name, f"source.json")

    source_funcs = set()
    with open(json_path, "r") as f:
        config_data = json.load(f)
        # 提取Source函数列表
        if 'sources' in config_data:
            if 'ret' in config_data['sources']:
                source_funcs.update(config_data['sources']['ret'])
            if '0' in config_data['sources']:
                source_funcs.update(config_data['sources']['0'])
            if '1' in config_data['sources']:
                source_funcs.update(config_data['sources']['1'])

    def make_json_template():
        return {
            "id": None,  # Need to be filled in later
            "function_name": "",  # Need to be filled in later
            "layer": 1,
            "sub_source_id": -1,
            "sub_source_function": None,
            "param_mapping": [
                {
                    "from_index": [-1],
                    "to_index": -1  # Need to be filled in later
                }
            ],
            "description": ""  # Need to be filled in later
        }
    
    source_func_list = []

    description_head = "第1层原始source。通用source函数。"
    description_tail = "无下层子source"

    id_counter = 1

    # Type A: 所有的通用Source函数（即原config.json中sources字段下的函数列表，包含ret/0/1等不同类型）
    param_json_path = os.path.join(original_config_path, "..", "config_params.json")
    with open(param_json_path, "r", encoding="utf-8") as f:
        param_data = json.load(f)
    for func in source_funcs:
        func_dict = make_json_template()
        func_dict["function_name"] = func
        func_dict["id"] = id_counter
        id_counter += 1
        
        # Extra Info
        description = ""
        if func in param_data and len(param_data[func]["index"]) > 0:
            param_mapping_list = []
            for idx in param_data[func]["index"]:
                param_mapping_list.append({
                    "from_index": [-1],
                    "to_index": idx
                })
            func_dict["param_mapping"] = param_mapping_list
            description += param_data[func]["description"]
            if not description.endswith("。"):
                description += "。"
        else:
            description += "暂无参数映射信息。"
        
        func_dict["description"] = description_head + description + description_tail
        source_func_list.append(func_dict)

    # Type B: 二进制中所有的外部调用函数（即通过IDA API获取到的extern调用函数列表）
    for func in extern_funcs:
        func_dict = make_json_template()
        func_dict["function_name"] = func
        func_dict["description"] = f"第1层原始source。外部调用函数。暂无参数映射信息。无下层子source。"
        func_dict["id"] = id_counter
        id_counter += 1
        source_func_list.append(func_dict)

    # Type C: 算法判断的输入解析函数（即通过新的算法判断出的输入解析函数列表，包含路径碰撞分析的结果）
    for func in path_collision_funcs:
        func_dict = make_json_template()
        func_dict["function_name"] = func
        func_dict["description"] = f"第1层原始source。算法判断的输入解析函数。暂无参数映射信息。无下层子source。"
        func_dict["id"] = id_counter
        id_counter += 1
        source_func_list.append(func_dict)

    # 将source函数列表写入source.json文件
    with open(source_json_path, "w", encoding="utf-8") as f:
        json.dump({
                    "target": output_name,
                    "sources": source_func_list
                  }, f, indent=4, ensure_ascii=False)

    # Report
    print("\n")
    print("Output Files:")
    print(f"Source JSON file for next steps: {source_json_path}")

    return path_collision_funcs, extern_funcs, new_json_path



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

    vulfunc_rank(args.input_bin,
                 threshold_in=args.threshold,
                 original_config_path=args.original_config_path,
                 output_base_dir=args.output_base_dir,
                 force_add_extern_calls=not args.not_force_add_extern_calls) 