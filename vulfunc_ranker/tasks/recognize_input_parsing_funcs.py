import os
import sys
# 从项目根目录导入
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import tasks.ast_parse as ap
import tasks.parsing_logic as pl

"""任务：识别输入解析函数"""

"""设计思路：

解析反编译后的函数代码，生成并遍历AST，寻找特定的模式和结构
特定模式和结构包括：
1.缓冲区操作
2.解析逻辑特征（协议解析/数据提取）
3.循环处理结构
4.验证和检查特征（边界检查/完整性检查）
5.数据结构构建特征
6.函数名模式匹配
7.强数据流特征
"""


def _parse_from_file(func: str) -> ap.AST:
    """
    解析单个函数，返回 AST 对象
    
    :param func: 函数文件路径
    :return: AST 对象
    """
    with open(func, "rb") as f:
        code = f.read()
    return ap.AST(code)


def _judge(func: str) -> None:
    """
    判断函数是否为输入解析函数的示例，并给出最终评分
    
    :param func: 函数文件路径
    """
    ast = _parse_from_file(func)
    parser = pl.InputParsingFuncRecognizer(ast)
    parser.parse()
    score = parser.score()
    actions = parser.actions()

    print("Final Score:")
    print(score)
    print("Actions Taken:")
    print(actions)
    
def parse(func: str) -> ap.AST:
    """
    解析单个函数，返回 AST 对象
    
    :param func: 函数代码字符串
    :return: AST 对象
    """
    #将func格式改为ap需要的格式 将str转成bytes
    code = func.encode("utf-8")
    return ap.AST(code)
    
def batch_judge(funcs, threshold: float=6.0, top_k: None|int=None) -> list[dict[str, str|float|set[str]]]:
    """
    批量判断多个函数是否为输入解析函数
    
    :param funcs: 函数列表，每个函数是一个包含"name", "address", "decompiled"字段的字典
    :param threshold: 评分阈值，默认值为6.0
    :param top_k: 筛选分数最高的前k个函数，默认值为None，表示仅使用阈值判断，为整型时则使用综合筛选
    :return results: 包含函数名称、地址、评分和动作的结果列表，返回筛选后函数列表
    """
    results = []
    for func in funcs:
        # print(f"Processing function: {func['name']} at address {func['address']}")
        ast = parse(func["decompiled"])
        parser = pl.InputParsingFuncRecognizer(ast)
        parser.parse()
        func_result = {
            "name": func["name"],
            "address": func["address"],
            "score": parser.score(),
            "actions": parser.actions()
        }
        results.append(func_result)
        # print(f"Function: {func['name']}, Score: {parser.score()}, Actions: {parser.actions()}")
    results.sort(key=lambda x: x["score"], reverse=True)
    
    filtered_results = []
    if top_k is not None:
        filtered_results = results[:top_k]
        filtered_results = [res for res in filtered_results if res["score"] > 0]
        threshold_reached_results = [res for res in filtered_results if res["score"] >= threshold]
        if len(threshold_reached_results) >= top_k * 0.3:
            filtered_results = threshold_reached_results
    else:
        filtered_results = [res for res in results if res["score"] >= threshold]
    
    for result in filtered_results:
        # print(f"Identified Input Parsing Function: {result['name']} with Score: {result['score']}")
        pass
    return filtered_results

if __name__ == "__main__":
    # 单函数测试代码
    _judge(r"C:\1111school\FuCai_Lib\FuncVulnRiskRanker\test_func\easy.c")