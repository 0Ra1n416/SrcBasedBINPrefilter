import json
import os
import sys

NOW_PY_DIR = os.path.dirname(os.path.abspath(__file__))

def source_func_count() -> int:
    json_path = os.path.join(NOW_PY_DIR, "..", "caches_data", "config.json")
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
    
    return len(source_funcs)

if __name__ == "__main__":
    count = source_func_count()
    print(f"Source函数数量: {count}")
