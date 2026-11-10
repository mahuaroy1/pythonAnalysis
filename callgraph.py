import ast

from graphviz import Digraph


class CallGraphBuilder(ast.NodeVisitor):
    """Build a call graph for functions in a Python syntax tree."""

    def __init__(self):
        self.call_graph = {}
        self.current_function = None
        self.scope_stack = []

    def visit_FunctionDef(self, node):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_function(node)

    def _visit_function(self, node):
        previous_function = self.current_function
        qualified_name = ".".join([*self.scope_stack, node.name])
        self.scope_stack.append(node.name)
        self.current_function = qualified_name
        self.call_graph.setdefault(qualified_name, set())
        self.generic_visit(node)
        self.scope_stack.pop()
        self.current_function = previous_function

    def visit_ClassDef(self, node):
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_Call(self, node):
        if self.current_function:
            if isinstance(node.func, ast.Name):
                self.call_graph[self.current_function].add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                self.call_graph[self.current_function].add(node.func.attr)
        self.generic_visit(node)


class MultiFileCallGraphBuilder:
    """Build and optionally render per-file call graphs."""

    def __init__(self):
        self.global_call_graph = {}

    def build_call_graph(self, python_files_ast):
        self.global_call_graph = {}
        for file_name, ast_tree in python_files_ast.items():
            builder = CallGraphBuilder()
            builder.visit(ast_tree)
            if builder.call_graph:
                self.global_call_graph[file_name] = builder.call_graph

    def visualize_global_call_graph(self, output_filename="multi_file_call_graph"):
        dot = Digraph(comment="Multi-File Call Graph")
        for file_name, call_graph in self.global_call_graph.items():
            dot.node(file_name, file_name, shape="box", style="filled", color="lightblue")
            for function, calls in call_graph.items():
                function_node = f"{file_name}:{function}"
                dot.node(function_node, function, shape="ellipse", style="filled", color="yellow")
                dot.edge(file_name, function_node, label="defined in")
                for call in calls:
                    call_node = f"{file_name}:{function}:{call}"
                    dot.node(call_node, call, shape="ellipse", style="filled", color="green")
                    dot.edge(function_node, call_node, label="calls")

        dot.render(output_filename, format="png", cleanup=True)
        print(f"Global call graph visualization saved to {output_filename}.png")
