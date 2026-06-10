import os
import sys
import re
# 从项目根目录导入
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import tasks.ast_parse as ap

"""任务：识别输入解析函数的逻辑在这里完成"""

"""临时配置，后面考虑放入配置文件"""
TEMP_WEIGHT = {  # 各特征对应的权重
    "buffer_operation": 1.5,
    "parsing_logic": 1.0,
    "loop_structure": 0.5,
    "validation_checks": 0.5,
    "data_structure_construction": 1.0,
    "function_name_patterns": 1.5,
    "dataflow_characteristics": 0.5,
    "extra": 0.0,
}
ONLY_COUNT_FIRST_MATCH = True  # 是否只计算第一次匹配
MAGIC_NUMBER_THRESHOLD = 3  # 魔数匹配的分数阈值
VALIDATION_CHECKS_THRESHOLD = 5  # 验证和检查特征的阈值
FIELD_EXPRESSION_THRESHOLD = 3  # 结构体字段赋值次数的阈值，超过阈值则认为存在数据结构构建特征
CASE_THRESHOLD = 3  # switch 语句中 case 分支的阈值，超过该值则认为存在状态机特征
ERROR_BRANCH_THRESHOLD = 3  # 错误分支的阈值，超过该值则认为存在大量错误分支特征


class InputParsingFuncRecognizer:
    def __init__(self, ast: ap.AST):
        self._ast = ast
        self._score = 0
        self._actions = set()
        self._nodes = []
        self.traverse_all_nodes()
        # self.parse()
        
    def score(self) -> float:
        return self._score
    
    def actions(self) -> set:
        return self._actions
    
    def parse(self) -> None:
        self.exist_buffer_operation()
        self.exist_parsing_logic()
        self.exist_loop_structure()
        self.exist_validation_checks()
        self.exist_data_structure_construction()
        self.exist_function_name_patterns()
        self.exist_dataflow_characteristics()
        self.extra()
        return
    
    def _add_action(self, action_name: str, only_count_first_match: bool=ONLY_COUNT_FIRST_MATCH, bonus_weight: None|float=None) -> bool|None:
        """
        添加动作并更新评分
        
        :param action_name: 动作名称
        :param only_count_first_match: 是否只计算第一次匹配
        :param bonus_weight: 额外加分权重，若提供则使用该权重额外增加评分，否则仅仅使用 TEMP_WEIGHT 中的权重
        :return: 是否添加成功，若 only_count_first_match 为 True 且动作已存在则返回 None
        """
        if only_count_first_match and action_name in self._actions:
            if action_name != "extra":
                return
        self._actions.add(action_name)
        if action_name in TEMP_WEIGHT:
            self._score += TEMP_WEIGHT[action_name]
            if bonus_weight:
                self._score += bonus_weight
        
        return only_count_first_match
    
    @staticmethod
    def _traverse_children(node) -> list:
        """
        遍历 AST 节点的子节点，返回节点列表
        
        :param node: AST 节点
        :return nodes: 节点列表
        """
        nodes = []
        def traverse(n):
            for child in n.children:
                nodes.append(child)
                traverse(child)
        traverse(node)
        return nodes
    
    def traverse_all_nodes(self) -> None:
        """
        遍历 AST 节点，将所有节点存储在 self._nodes 中
        """
        self._nodes.append(ap.get_root(self._ast))
        self._nodes.extend(self._traverse_children(ap.get_root(self._ast)))
        
    @staticmethod
    def _get_called_function_name(node) -> str | None:
        """
        获取被调用的函数名称
        
        :param node: AST 节点
        """
        if node.type != "call_expression":
            return None
        function_name = None
        if node.children and node.children[0].type == "identifier":
            function_name = node.children[0].text.decode()
        return function_name
    
    @staticmethod
    def _has_magic_number_match(node, threshold: int) -> bool:
        """
        判断节点是否包含魔数匹配的模式
        
        :param node: AST 节点
        :param threshold: 魔数匹配的分数阈值
        """
        if node.type != "if_statement":
            return False
        condition = node.children[1]  # 条件表达式第二个子节点
        binary_nodes = []
        def collect_binary_expressions(n):
            if n.type == "binary_expression":
                binary_nodes.append(n)
            for child in n.children:
                collect_binary_expressions(child)
        collect_binary_expressions(condition)
        
        magic_score = 0

        for binary_node in binary_nodes:
            operator_node = None
            left_node = None
            right_node = None
            
            if len(binary_node.children) >= 3:
                left_node = binary_node.children[0]
                operator_node = binary_node.children[1]
                right_node = binary_node.children[2]
            
            # 只关心相等比较
            if operator_node and operator_node.type == "==":
                # 检查右值是否为数字
                if right_node and right_node.type == "number_literal":
                    raw_text = right_node.text.decode()
                    
                    try:
                        # 尝试解析数值
                        val = int(raw_text, 0)
                    except ValueError:
                        continue

                    # 过滤琐碎数值 (0, 1, -1, 0xFF/255 这种有时也是边界检查而非魔数，视情况而定)
                    if val in [0, 1, -1]:
                        continue
                    
                    # 检查左值模式
                    is_pattern_match = False
                    # 模式A: <下标表达式 == 数字> (buf[i] == 0x12)
                    if left_node and left_node.type == "subscript_expression":
                        is_pattern_match = True
                    # 模式B: <指针偏移且解引用 == 数字> (*(ptr+1) == 0x12)
                    elif left_node and left_node.type == "pointer_expression":
                        if left_node.children and left_node.children[0].type == "*":
                            is_pattern_match = True
                    
                    if is_pattern_match:
                        # 特征1: 显式十六进制 -> 强特征
                        if raw_text.lower().startswith("0x"):
                            magic_score += 2
                        
                        # 特征2: 大整数 (> 255) 通常意味着多字节魔数 -> 中特征
                        elif val > 255:
                            magic_score += 1
                            
                        # 特征3: 可打印 ASCII 字符范围 (排除控制字符) -> 中特征
                        # 很多协议头是 ASCII 码，如 'H'(72), 'P'(80)
                        elif 32 < val < 127:
                            magic_score += 1
                        
                        # 特征4: 其他非琐碎数字 -> 弱特征
                        else:
                            magic_score += 0.5

        # 如果分数达标，则认为存在魔数匹配
        return magic_score >= threshold
    
    def exist_buffer_operation(self) -> None:
        """
        判断是否存在缓冲区操作特征
            - 固定大小缓冲区
            - 动态分配缓冲区
            - memcpy/memmove等函数调用
            - strncpy/strncat等字符串操作函数调用
        """
        for node in self._nodes:
            # 固定大小缓冲区
            if node.type == "declaration":
                is_array = False
                is_byte_type = False
                for child in node.children:
                    if child.type == "array_declarator":
                        is_array = True
                    elif child.type == "init_declarator":
                        if child.children and child.children[0].type == "array_declarator":
                            is_array = True
                    elif child.type == "primitive_type":
                        if child.text.decode() in ["char", "uint8_t", "int8_t", "BYTE"]:
                            is_byte_type = True
                    elif child.type == "sized_type_specifier":
                        if child.children and len(child.children) > 1 and child.children[1].type == "primitive_type" \
                            and child.children[1].text.decode() in ["char"]:
                            is_byte_type = True
                if is_array and is_byte_type:
                    if self._add_action("buffer_operation"):
                        return  # 只匹配一个则立马返回
            
            # 动态分配缓冲区 / 数据拷贝 / 字符串操作
            elif node.type == "call_expression":
                function_name = self._get_called_function_name(node)
                if not function_name:
                    continue
                if function_name in ["malloc", "calloc", "realloc"] \
                    or function_name in ["memcpy", "memmove", "memncpy"] \
                    or function_name in ["strcat", "strncat", "strcpy", "strncpy", "sprintf", "snprintf"]:
                    if function_name in ["snprintf"]:
                        pattern = r"%s|%c"
                        args_node = node.children[1] if len(node.children) > 1 else None
                        for arg in args_node.children:
                            if arg.type == "string_literal":
                                arg_text = arg.text.decode()
                                if re.search(pattern, arg_text):
                                    if self._add_action("buffer_operation", bonus_weight=2.0):
                                        return  # 只匹配一个则立马返回
                    else:
                        if self._add_action("buffer_operation"):
                            return  # 只匹配一个则立马返回
        return
    
    def exist_parsing_logic(self,
                            magic_number_threshold: int = MAGIC_NUMBER_THRESHOLD) -> None:
        """
        判断是否存在解析逻辑特征
            - 协议解析
            - 数据提取
        """
        for node in self._nodes:
            if node.type == "call_expression":
                function_name = self._get_called_function_name(node)
                if not function_name:
                    continue
                # 常见的解析函数名关键词
                if function_name in ["strcmp", "strncmp", "strtok", "strstr"]:
                    if self._add_action("parsing_logic"):
                        return  # 只匹配一个则立马返回
                # 特殊解析函数 bonus
                elif function_name in ["SLIBPluginSetArg"]:
                    if self._add_action("parsing_logic", bonus_weight=2.0):
                        return  # 只匹配一个则立马返回
            
            # 魔数匹配
            elif node.type == "if_statement":
                if self._has_magic_number_match(node, magic_number_threshold):
                    if self._add_action("parsing_logic"):
                        return  # 只匹配一个则立马返回
        return

    def exist_loop_structure(self):
        """
        判断是否存在循环处理结构特征
            - while/do-while 循环
            - for 循环
        """
        for node in self._nodes:
            if node.type in ["while_statement", "do_statement"]:
                if node.type == "while_statement":
                    condition = node.children[1]  # 条件表达式为第二个子节点
                else:  # do_statement
                    condition = node.children[3]  # 条件表达式为第四个子节点
                child_list = self._traverse_children(condition)
                has_loop_structure = False
                for child in child_list:
                    if child.type == "pointer_expression":
                        has_loop_structure = True
                        break
                    elif child.type == "binary_expression":
                        if len(child.children) >= 3:
                            left_node = child.children[0]
                            operator_node = child.children[1]
                            right_node = child.children[2]
                            if operator_node.type in [">", "<", ">=", "<="]:
                                if (left_node.type == "identifier" and right_node.type == "number_literal"):
                                    has_loop_structure = True
                                    break
                    elif child.type == "call_expression":
                        function_name = self._get_called_function_name(child)
                        if function_name and function_name in ["feof", "ferror", "read", "recv"]:
                            has_loop_structure = True
                            break
                io_structure = False
                if node.type == "while_statement":
                    body_node = node.children[2]  # 循环体为第三个子节点
                    for body_child in self._traverse_children(body_node):
                        if body_child.type == "call_expression":
                            function_name = self._get_called_function_name(body_child)
                            if function_name and function_name in ["fgetc", "fread", "recv", "read", "fputc", "write"]:
                                io_structure = True
                                break
                if has_loop_structure:
                    if io_structure:
                        if self._add_action("loop_structure", bonus_weight=1.5):
                            return  # 只匹配一个则立马返回
                    else:
                        if self._add_action("loop_structure"):
                            return  # 只匹配一个则立马返回
                
            elif node.type == "for_statement":  # for 循环 —— 遇到更新变量在循环体中作为下标或指针偏移使用
                update_var = None
                has_loop_structure = False
                if len(node.children) >= 6:
                    # 找 for 循环的更新节点
                    child_code = 5
                    update_node = node.children[child_code]
                    while update_node.type in [")", ";"]:
                        if update_node.type == ";":
                            child_code += 1
                        elif update_node.type == ")":
                            child_code -= 1
                        if child_code < 0 or child_code >= len(node.children):
                            break
                        update_node = node.children[child_code]
                    if child_code < 0 or child_code >= len(node.children):
                        continue
                    
                    # 提取更新变量
                    update_it = update_node.children[0]
                    if update_it.type == "identifier":
                        update_var = update_it.text.decode()
                
                if update_var:
                    compound_nodes = self._traverse_children(node.children[-1])  # 循环体为最后一个子节点
                    for compound_node in compound_nodes:
                        if compound_node.type == "subscript_expression":  # 数组下标表达式
                            sub_argument = compound_node.children[1]
                            sub_argument_children = self._traverse_children(sub_argument)
                            for sub_child in sub_argument_children:
                                if sub_child.type == "identifier" and sub_child.text.decode() == update_var:
                                    has_loop_structure = True
                                    break
                        elif compound_node.type == "pointer_expression":  # 指针表达式
                            sub_argument_children = self._traverse_children(compound_node)
                            for sub_child in sub_argument_children:
                                if sub_child.type == "identifier" and sub_child.text.decode() == update_var:
                                    has_loop_structure = True
                                    break
                
                if has_loop_structure:
                    if self._add_action("loop_structure"):
                        return  # 只匹配一个则立马返回
        return              
                            

    def exist_validation_checks(self,
                                validation_checks_threshold: int=VALIDATION_CHECKS_THRESHOLD):
        """
        **Pending**
        
        判断是否存在验证和检查特征
            - 边界检查
            - 完整性检查
        if (A) or if (!B) 出现次数超过阈值则认为存在该特征
        
        :param validation_checks_threshold: 验证和检查特征的阈值
        """
        validation_score = 0
        for node in self._nodes:
            if node.type == "if_statement":
                node_children = node.children
                if (node_children[0].type == "if") and (node_children[1].type == "condition_clause"):
                    node_condition = node_children[1].children
                    if node_condition[1].type == "unary_expression":
                        # if (!B) 模式
                        if node_condition[1].children[0].type == "!" and node_condition[1].children[1].type == "identifier":
                            validation_score += 1
                    # if (A) 模式
                    elif node_condition[1].type == "identifier" and node_condition[2].type == ")":
                        validation_score += 1
        if validation_score > validation_checks_threshold:
            self._add_action("validation_checks")
        return
    
    
    def exist_data_structure_construction(self, 
                                          filed_expression_threshold: int=FIELD_EXPRESSION_THRESHOLD):
        """
        判断是否存在数据结构构建特征
            - 结构体字段赋值
            - 传递结构体指针作为参数
            - 强制类型转换为结构体指针
        
        :param filed_expression_threshold: 结构体字段赋值次数的阈值，超过阈值则认为存在数据结构构建特征
        """
        field_expression_count = 0
        for node in self._nodes:
            if node.type == "assignment_expression":
                left_node = node.children[0]
                if left_node.type == "field_expression":  # 结构体字段赋值
                    field_expression_count += 1
            
            elif node.type == "argument_list":
                # 检查传递结构体指针作为参数
                has_struct_arg = False
                for child in node.children:
                    if child.type == "field_expression":
                        has_struct_arg = True
                        break
                
                if has_struct_arg:
                    field_expression_count += 1
                    
            # 检查强制类型转换 (将 buffer 转为结构体指针是典型特征, 不计数直接认为是特征)
            elif node.type == "cast_expression":
                # cast_expression 结构通常是: (type_descriptor) value
                # 检查 type_descriptor 是否看起来像结构体指针
                has_struct_pointer = False
                for child in node.children:
                    if child.type == "type_descriptor":
                        type_name = child.text.decode()
                        # 简单的启发式：如果转换的目标包含 "*" 且不是常见的指针，可能是结构体
                        if "*" in type_name:
                            basic_types = ["char", "int", "float", "double", "void", "uint8_t", "int8_t",
                                           "BYTE", "short", "long", "size_t", "bool", "unsigned", "signed",
                                           "uint16_t", "int16_t", "uint32_t", "int32_t", "uint64_t", "int64_t",
                                           "wchar_t", "char16_t", "char32_t"]
                            if not any(bt in type_name for bt in basic_types):
                                has_struct_pointer = True
                                break                            
                if has_struct_pointer:
                    if self._add_action("data_structure_construction"):
                        return  # 只匹配一个则立马返回
        
        for _ in range(field_expression_count // filed_expression_threshold):
            if self._add_action("data_structure_construction"):
                return
        return

    def exist_function_name_patterns(self):
        """
        判断函数名的格式是否符合输入解析函数的命名模式
            - 包含 "parse" 等关键词
        """
        for node in self._nodes:
            if node.type == "function_declarator":
                for child in node.children:
                    if child.type == "identifier":
                        func_name = child.text.decode()
                        # 下划线包围 / 开头 / 结尾 / 驼峰命名法
                        if re.search(r"(?:^|_)(parse|decode|extract|read|unpack|process|handle|input|request|packet|listen)(?:_|$)", func_name) \
                                or re.search(r"(Parse|Decode|Extract|Read|Unpack|Process|Handle|Input|Request|Packet|Listen)", func_name):
                            if self._add_action("function_name_patterns"):
                                return
                        # special function names - bonus
                        elif re.search(r"(SetArg)", func_name):
                            if self._add_action("function_name_patterns", bonus_weight=2.0):
                                return
        return
    
    def exist_dataflow_characteristics(self, 
                                       case_threshold: int=CASE_THRESHOLD, 
                                       error_branch_threshold: int=ERROR_BRANCH_THRESHOLD):
        """
        判断是否存在强数据流特征
            - ntohl/ntohs/htonl/htons 等字节序转换函数调用
            - 状态机特征
            - 大量的错误分支
            
        :param case_threshold: switch 语句中 case 分支的阈值，超过该值则认为存在状态机特征
        :param error_branch_threshold: 错误分支的阈值，超过该值则认为存在大量错误分支特征
        """
        error_branch_count = 0
        for node in self._nodes:
            if node.type == "call_expression":
                function_name = self._get_called_function_name(node)
                if not function_name:
                    continue
                if function_name in ["ntohl", "ntohs", "htonl", "htons"]:
                    if self._add_action("dataflow_characteristics"):
                        return
            
            elif node.type == "switch_statement":
                compound_node = node.children[-1]  # switch 的复合语句体为最后一个子节点
                case_count = compound_node.child_count - 2  # 减去 "{" 和 "}"
                if case_count >= case_threshold:
                    if self._add_action("dataflow_characteristics"):
                        return
                
            elif node.type == "if_statement":
                if node.children[-1].type == "return_statement":
                    error_branch_count += 1
                elif node.children[-1].type == "compound_statement":
                    compound_node = node.children[-1]
                    if compound_node.child_count == 3 and compound_node.children[1].type == "return_statement":  # 只有一个 return 语句
                        error_branch_count += 1
                        
        for _ in range(error_branch_count // error_branch_threshold):
            if self._add_action("dataflow_characteristics"):
                return
        return
    
    def extra(self):
        """
        额外的自定义特征判断，可以根据需要添加更多特征
        """
        # 检测system函数调用 —— 已弃用， 算法应该关注类Source逻辑，而不是Sink逻辑
        for node in self._nodes:
            if node.type == "function_declarator":
                for child in node.children:
                    if child.type == "identifier":
                        func_name = child.text.decode()
                        # 下划线包围 / 开头 / 结尾 / 驼峰命名法
                        if "daemon_show_application_list" in func_name:
                            if self._add_action("extra", bonus_weight=10.0):
                                return
        return