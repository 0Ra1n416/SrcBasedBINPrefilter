from tree_sitter import Language, Parser, Tree, Node
import tree_sitter_cpp


class AST:
    def __init__(self, code: bytes):
        self.tree: Tree = self.parse(code)

    def parse(self, code: bytes):
        # 兼容不同版本的 tree_sitter API：
        # - 新版: Language(tree_sitter_cpp.language())
        # - 旧版: 通过 tree_sitter_languages.get_language("cpp")
        try:
            cpp_language = Language(tree_sitter_cpp.language())
        except TypeError:
            from tree_sitter_languages import get_language

            cpp_language = get_language("cpp")

        parser = Parser()
        if hasattr(parser, "set_language"):
            parser.set_language(cpp_language)
        else:
            # 新版 bindings 可能改为 language 属性赋值
            parser.language = cpp_language

        if isinstance(code, str):
            code = code.encode("utf-8", errors="ignore")

        try:
            return parser.parse(code)
        except Exception as e:
            print(f"Failed to parse ast with exception: {e}")
            return
        

def get_root(ast: AST) -> Node:
    return ast.tree.root_node

def get_children(node) -> list:
    return [child for child in node.children]

def get_nodes_list(ast: AST) -> list:
    """获取 AST 中的所有节点，返回节点列表"""
    if ast is None or getattr(ast, 'tree', None) is None:
        return []
    nodes = []

    def traverse(node):
        if node.children:
            for child in node.children:
                traverse(child)
        nodes.append(node)

    traverse(ast.tree.root_node)
    return nodes

