import ast
from graphviz import Digraph

class CallGraphBuilder(ast.NodeVisitor):
    """
    Builds a call graph by traversing the AST of Python source code.
    """
    def __init__(self):
        # key - function, value - set of functions it calls
        self.call_graph = {}  # Adjacency list representing function calls
        self.current_function = None

    def visit_FunctionDef(self, node):
        """
        Visits a function definition, setting it as the current function
        and tracking its calls.
        """
        self.current_function = node.name
        if self.current_function not in self.call_graph:
            self.call_graph[self.current_function] = set()
        self.generic_visit(node)
        self.current_function = None  # Reset after processing the function

    def visit_Call(self, node):
        """
        Visits a function call and adds it to the graph if it occurs
        within a function.
        """
        if self.current_function:
            # Handle direct function calls (e.g., foo())
            if isinstance(node.func, ast.Name):
                self.call_graph[self.current_function].add(node.func.id)
            # Handle method calls or attribute calls (e.g., obj.method())
            # Todo fully qualified name
            elif isinstance(node.func, ast.Attribute):
                self.call_graph[self.current_function].add(node.func.attr)
        self.generic_visit(node)


class MultiFileCallGraphBuilder:
    def __init__(self):
        self.global_call_graph = {}  # Unified call graph across all files

    def build_call_graph(self, python_files_ast):
        for file_name, ast_tree in python_files_ast.items():
            builder = CallGraphBuilder()
            builder.visit(ast_tree)

            # Merge the call graph of the current file into the global call graph
            for function, calls in builder.call_graph.items():
                if file_name not in self.global_call_graph:
                    self.global_call_graph[file_name] = {}
                self.global_call_graph[file_name][function] = calls

    def visualize_global_call_graph(self, output_filename="multi_file_call_graph"):
        dot = Digraph(comment="Multi-File Call Graph")
        for file_name, call_graph in self.global_call_graph.items():
            # Create nodes for the file and its functions
            dot.node(file_name, file_name, shape="box", style="filled", color="lightblue")
            for function, calls in call_graph.items():
                dot.node(function, function, shape="ellipse", style="filled", color="yellow")
                dot.edge(file_name, function, label="defined in")
                for call in calls:
                    dot.node(call, call, shape="ellipse", style="filled", color="green")
                    dot.edge(function, call, label="calls")

        dot.render(output_filename, format="png", cleanup=True)
        print(f"Global call graph visualization saved to {output_filename}.png")
