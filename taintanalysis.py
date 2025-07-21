import os
import zipfile
from io import TextIOWrapper
import ast


def get_name(node, name):
    # Resolve the base object (value) of the attribute
    if isinstance(node, ast.Name):
        name.append(node.id)
        return name
    # Handle chained attributes recursively (e.g., obj.attr.subattr)
    elif isinstance(node, ast.Attribute):
        name.append(node.attr)
        return get_name(node.value, name)


class TaintAnalyzer(ast.NodeVisitor):
    """
    Performs static taint analysis on Python source code.
    Identifies flows of untrusted data (tainted sources) to sensitive operations (sinks).
    """

    def __init__(self):
        # Track variables that are tainted (untrusted)
        self.tainted_vars = set()
        self.tainted_collections = {}  # Track tainted elements in lists/dicts
        self.tainted_functions = {}  # Track functions that propagate taint

        # List of issues found (tainted data flowing to sensitive sinks)
        self.issues = []

        # Define sources of tainted data (e.g., user input functions)
        self.taint_sources = {"input", "os.environ.get"}
        # Define sensitive sinks (e.g., functions or operations that must not accept tainted data)
        self.sensitive_sinks = {"eval", "exec", "os.system", "subprocess.run"}

    def visit_Call(self, node):
        """
        Visits function calls to detect sources, sinks, and propagation.
        """
        name = get_name(node.func, [])
        callname = ".".join(name[::-1])
        # Detect taint sources
        if callname in self.taint_sources:
            if isinstance(node.parent, ast.Assign):
                for target in node.parent.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
                        print(f"Taint Source: {target.id} is tainted by {callname}")

        # Detect taint reaching sensitive sinks
        if callname in self.sensitive_sinks:
            for arg in node.args:
                if self._is_tainted(arg):
                    self.issues.append(
                        f"Tainted data passed to sensitive function '{callname}' at line {node.lineno}"
                    )

        # Detect tainted function return values
        if callname in self.tainted_functions:
            if isinstance(node.parent, ast.Assign):
                for target in node.parent.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
                        print(f"Propagation: {target.id} is tainted by function '{callname}'")

        self.generic_visit(node)

    def visit_Assign(self, node):
        """
        Visits assignments to propagate taint, including list and dictionaries
        """
        # Propagate taint between variables
        if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
                    print(f"Propagation: {target.id} is tainted by {node.value.id}")

        # Track tainted lists or dictionaries
        if isinstance(node.value, (ast.List, ast.Dict)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_collections[target.id] = self._extract_tainted_elements(node.value)

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        """
        Tracks functions that propagate taint from arguments to return values.
        """
        # Check if the function returns tainted data
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                if self._is_tainted(child.value):
                    self.tainted_functions[node.name] = True
                    print(f"Function '{node.name}' propagates taint through its return value")

        self.generic_visit(node)

    def visit_Return(self, node):
        """
        Checks whether a return statement propagates taint.
        """
        if self._is_tainted(node.value):
            print(f"Return statement at line {node.lineno} propagates taint")

        self.generic_visit(node)

    def _is_tainted(self, node):
        """
        Helper function to check if a variable, list element, or dictionary key/value is tainted.
        """
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.Subscript):  # Handles list/dictionary elements
            collection_name = node.value.id if isinstance(node.value, ast.Name) else None
            if collection_name in self.tainted_collections:
                return True
        if isinstance(node, ast.Call):  # Function call
            name = get_name(node.func, [])
            callname = ".".join(name[::-1])
            return callname in self.tainted_functions
        if isinstance(node, ast.BinOp):  # Binary operation
            return self._is_tainted(node.left) or self._is_tainted(node.right)

        return False

    def _extract_tainted_elements(self, node):
        """
        Extracts tainted elements from lists or dictionaries during assignment.
        """
        tainted_elements = set()
        if isinstance(node, ast.List):
            for elt in node.elts:
                if isinstance(elt, ast.Name) and elt.id in self.tainted_vars:
                    tainted_elements.add(elt.id)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(value, ast.Name) and value.id in self.tainted_vars:
                    tainted_elements.add(key.s if isinstance(key, ast.Str) else key.id)
        return tainted_elements

    def analyze(self, tree):
        """
        Perform taint analysis on the given source code.
        """
        # Parse the source code into an AST
        #tree = ast.parse(source_code)

        # Attach parent nodes to facilitate analysis
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child.parent = node

        # Visit all nodes in the AST
        self.visit(tree)

        return self.issues


class MultiFileTaintAnalyzer:
    """
    Performs taint analysis across multiple Python files.
    """
    def __init__(self):
        self.tainted_vars = set()  # Global set of tainted variables
        self.sensitive_sinks = {"eval", "exec", "os.system", "subprocess.run", "os.eval"}
        self.taint_sources = {"input", "os.environ.get", "sys.argv"}
        self.issues = []  # List of identified issues
        self.filewise_taint = {}  # File-specific taints and analysis

    def analyze_file(self, file_name, tree):
        """
        Analyze a single file's AST for taint sources and sinks.
        """
        local_taint_analyzer = TaintAnalyzer()
        local_issues = local_taint_analyzer.analyze(tree)
        self.tainted_vars.update(local_taint_analyzer.tainted_vars)  # Propagate tainted vars globally
        self.issues.extend(local_issues)  # Collect issues
        self.filewise_taint[file_name] = local_taint_analyzer.tainted_vars

    def analyze_files(self, python_files_ast):
        """
        Perform taint analysis across multiple ASTs.
        """
        for file_name, tree in python_files_ast.items():
            self.analyze_file(file_name, tree)

    def get_report(self):
        """
        Generate a consolidated report of taint analysis findings.
        """
        report = "\nGlobal Tainted Variables:\n" + ", ".join(self.tainted_vars) + "\n\n"
        report += "Issues:\n"
        for issue in self.issues:
            report += issue + "\n"
        return report


