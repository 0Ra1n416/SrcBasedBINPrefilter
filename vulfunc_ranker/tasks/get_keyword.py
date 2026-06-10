import idapro
import ida_auto
import ida_idp
import ida_loader
import ida_pro
import ida_hexrays
import ida_lines
import ida_name
import idautils
import idaapi
import idc
import os

# 导入LLM相关
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))  # 将上级目录vulfunc_ranker添加到sys.path，以便导入create_input_LLM
from scripts.create_input_LLM import LLMStringAnalyzer, LLMClient

class IDAStringScorer:
    """
    IDA字符串分析评价器，提取字符串及其调用函数信息，并让LLM分析字符串的潜在风险，得到每个字符串的风险评分
    
    :param binary_path: 二进制文件路径
    :param threshold: 函数风险评分的阈值，默认为0.35，只有当函数风险评分大于等于该阈值时才会被认为是高风险函数
    """
    def __init__(self, binary_path: str, threshold: float = 0.35):
        self.binary_path = binary_path
        self.threshold = threshold
    
    @staticmethod
    def escape_visible(s: str) -> str:
        """
        将字符串中的不可见字符转为可见的转义序列，便于输出查看。例："line1\\nline2" -> "line1\\ \\nline2"

        :param s: 输入字符串
        :return: 转义后的字符串
        """
        try:
            if isinstance(s, bytes):
                s = s.decode('utf-8', errors='replace')
            return s.encode('unicode_escape').decode('ascii')
        except Exception:
            try:
                return repr(s)
            except Exception:
                return str(s)


    def _get_ida_string(self) -> dict[str, list[str]]:
        """
        提取IDA中的字符串作为关键字，并获得调用该字符串的函数名称
        
        :return: 字符串信息字典，格式为 {string_value: [calling_function_names]}
        """
        string_info = {}  # {string_value: [calling_function_names]}
        
        # idautils.Strings() doesn't accept (start, end) in this IDA Python
        # version — iterate all strings and load their contents.
        for s in idautils.Strings():
            try:
                s.load()
            except Exception:
                pass
            
            string_value = str(s)
            string_addr = s.ea  # 获取字符串的地址
            
            # 获取调用该字符串的函数名称
            calling_functions = set()
            
            # 查找所有引用该字符串地址的位置
            for ref_addr in idautils.XrefsTo(string_addr):
                # 获取该引用所在的函数
                func_addr = idaapi.get_func(ref_addr.frm)
                if func_addr:
                    func_name = idc.get_func_name(func_addr.start_ea)
                    if func_name:
                        calling_functions.add(func_name)
            
            # 存储字符串及其调用函数，如果没有调用函数则不存储
            if calling_functions:
                string_info[string_value] = list(calling_functions)
        
        return string_info

    def get_keyword(self, print_info: bool = True) -> dict[str, list[str]]:
        """
        加载二进制文件并提取关键字

        :return: 字符串信息字典，格式为 {string_value: [calling_function_names]}
        """
        # 加载二进制文件
        print(f"Loading binary: {self.binary_path}")
        
        # 打开数据库并自动分析
        idapro.open_database(self.binary_path, True)

        
        # 等待自动分析完成
        ida_auto.auto_wait()
        
        print("Extracting keywords...")

        string_info = self._get_ida_string()
        print(f"Extracted {len(string_info)} keywords.")
        
        # 打印字符串及其调用函数
        if print_info:
            for string_value, calling_functions in string_info.items():
                escaped = self.escape_visible(string_value)
                # print(f"String: '{escaped}' -> Called by: {calling_functions}")
        
        idapro.close_database()

        return string_info
    
    def _add_string_score(self, score: float, threshold: float=0.4, alpha: int=2) -> float:
        """
        添加字符串风险评分到函数风险评分中

        Score = Sigma(score_i^alpha) for i that score_i >= threshold / total nums of strings in the function
        :param threshold: 阈值，只有当字符串风险评分大于等于该阈值时才会被计入函数风险评分
        :param alpha: 非线性映射指数，默认为2（评分越高贡献越大）
        :return: 是否需要添加风险评分
        """
        if score >= threshold:
            return score ** alpha
        else:
            return 0.0
        
    def _store_string_scores(self, string_scores: dict[str, tuple[float, bool]],
                             output_path: str|None = None) -> None:
        """
        将字符串风险评分存储到缓存文件中，供后续分析使用（记忆化功能待完成，直接函数内修改即可）

        :param string_scores: 字符串风险评分字典，格式为 {string_value: (risk_score, in_cache)}
        :param output_path: 输出文件路径，如果为None则以默认路径输出（可视情况移除）
        """
        strings = {}
        for string, (score, in_cache) in string_scores.items():
            if not in_cache:
                strings[string] = score
        if not output_path:
            binary_name = Path(self.binary_path).name
            import os
            output_name = os.path.splitext(os.path.basename(binary_name))[0]
            test_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "caches_data", output_name, f"string_scores_{output_name}.json")
        else:
            test_path = output_path
        import json
        with open(test_path, "w", encoding="utf-8") as f:
            json.dump(strings, f, indent=4, ensure_ascii=False)

    def get_string_and_func_score(self,
                                  base_url: str,
                                  api_key: str,
                                  model: str | None = None,
                                  timeout: int = 300,
                                  thinking: bool = True
                                  ) -> tuple[dict[str, float], dict[str, float]]:
        """
        使用LLM分析字符串的潜在风险，并为每个字符串生成一个风险评分
        
        :param base_url: LLM API的基础URL
        :param api_key: LLM API的密钥
        :param model: LLM模型名称，默认为None使用LLMClient的默认模型(deepseek-ai/DeepSeek-V3)
        :param timeout: LLM API请求的超时时间，单位为秒，默认为300秒
        :param thinking: 是否在分析过程中显示思考提示，默认为False

        :return string_scores: 字符串风险评分字典，格式为 {string_value: risk_score}
        :return func_scores: 函数风险评分字典，格式为 {function_name: risk_score}
        """
        # 这里调用LLM进行分析，得到每个字符串的风险评分
        LLM_client = LLMClient(base_url, api_key, model=model, timeout=timeout, thinking=thinking)

        string_info = self.get_keyword(print_info=False)

        analyzer = LLMStringAnalyzer(client=LLM_client, string_info=string_info, batch_size=100)
        string_scores = analyzer.analyze_strings()

        func_scores = {}  # {function_name: risk_score}
        func_string_nums = {}  # {function_name: total nums_of_strings}
        
        print("Calculating function risk scores based on string scores...")
        
        for string, (score, in_cache) in string_scores.items():
            # 兼容模型返回可见转义 key（如 \n），避免 KeyError。
            functions = string_info.get(string)
            if functions is None:
                try:
                    unescaped = bytes(string, "utf-8").decode("unicode_escape")
                except Exception:
                    unescaped = string
                functions = string_info.get(unescaped)
            if not functions:
                print(f"Warning: unmatched string key from LLM: {self.escape_visible(string)}")
                continue

            for func in functions:
                if func not in func_scores:
                    func_scores[func] = 0
                    func_string_nums[func] = 0
                score_now = self._add_string_score(score)
                func_scores[func] += score_now
                if score_now > 0:
                    func_string_nums[func] += 1

        print("Adjusting function risk scores based on risky string ratio...")

        for func, num in func_string_nums.items():
            if num > 0:
                # 如果函数中有字符串，并且有字符串的风险评分超过阈值，计算平均分作为函数的风险评分
                func_scores[func] /= num

        # 风险评分0的函数不予考虑
        func_scores = {func: score for func, score in func_scores.items() if score > 0}
        
        print("Function risk scores calculated.")
        print("Filter functions by threshold...")

        func_scores = {func: score for func, score in func_scores.items() if score >= self.threshold}

        # TODO: 可以将字符串风险评分和函数风险评分写入缓存，供后续分析使用（记忆化功能待完成，直接函数内修改即可）
        # self._store_string_scores(string_scores)

        return string_scores, func_scores

if __name__ == "__main__":
    pass