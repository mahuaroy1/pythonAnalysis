import ast


def get_name(node, name=None):
    """Return dotted name components for a name or attribute expression."""
    if name is None:
        name = []
    if isinstance(node, ast.Name):
        name.append(node.id)
    elif isinstance(node, ast.Attribute):
        get_name(node.value, name)
        name.append(node.attr)
    return name


def _call_name(node):
    return ".".join(get_name(node))


class TaintAnalyzer(ast.NodeVisitor):
    """Find selected flows from untrusted sources to sensitive operations."""

    def __init__(self):
        self.tainted_vars = set()
        self.tainted_collections = {}
        self.tainted_functions = {}
        self.tainted_function_args = {}
        self.issues = []
        self.taint_sources = {"input", "os.environ.get", "sys.argv"}
        self.sensitive_sinks = {"eval", "exec", "os.system", "subprocess.run"}

    def analyze(self, tree):
        self._summarize_functions(tree)
        self.visit(tree)
        return self.issues

    def _summarize_functions(self, tree):
        functions = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for _ in range(len(functions) + 1):
            changed = False
            for function in functions:
                parameters = (
                    function.args.posonlyargs
                    + function.args.args
                    + function.args.kwonlyargs
                )
                parameter_indexes = {
                    parameter.arg: index
                    for index, parameter in enumerate(parameters)
                }
                tainted_indexes = set(
                    self.tainted_function_args.get(function.name, set())
                )
                returns_taint = function.name in self.tainted_functions
                for child in ast.walk(function):
                    if isinstance(child, ast.Return) and child.value is not None:
                        is_tainted, returned_indexes = self._summarize_expression(
                            child.value, parameter_indexes
                        )
                        returns_taint = returns_taint or is_tainted
                        tainted_indexes.update(returned_indexes)

                if returns_taint and function.name not in self.tainted_functions:
                    self.tainted_functions[function.name] = True
                    changed = True
                if tainted_indexes != self.tainted_function_args.get(function.name, set()):
                    self.tainted_function_args[function.name] = tainted_indexes
                    changed = True
            if not changed:
                break

    def _summarize_expression(self, node, parameter_indexes):
        if isinstance(node, ast.Name) and node.id in parameter_indexes:
            return False, {parameter_indexes[node.id]}
        if isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            if call_name in self.taint_sources or call_name in self.tainted_functions:
                is_tainted = True
            else:
                is_tainted = False
            tainted_indexes = set()
            summary_indexes = self.tainted_function_args.get(call_name, set())
            for index, argument in enumerate(node.args):
                argument_tainted, argument_indexes = self._summarize_expression(
                    argument, parameter_indexes
                )
                tainted_indexes.update(argument_indexes)
                if index in summary_indexes:
                    is_tainted = is_tainted or argument_tainted or bool(argument_indexes)
                else:
                    is_tainted = is_tainted or argument_tainted
            for keyword in node.keywords:
                argument_tainted, argument_indexes = self._summarize_expression(
                    keyword.value, parameter_indexes
                )
                is_tainted = is_tainted or argument_tainted
                tainted_indexes.update(argument_indexes)
            return is_tainted, tainted_indexes
        is_tainted = False
        tainted_indexes = set()
        for child in ast.iter_child_nodes(node):
            child_tainted, child_indexes = self._summarize_expression(
                child, parameter_indexes
            )
            is_tainted = is_tainted or child_tainted
            tainted_indexes.update(child_indexes)
        return is_tainted, tainted_indexes

    def visit_Call(self, node):
        call_name = _call_name(node.func)
        if call_name in self.sensitive_sinks:
            arguments = list(node.args) + [keyword.value for keyword in node.keywords]
            if any(self._is_tainted(argument) for argument in arguments):
                self.issues.append(
                    f"Tainted data passed to sensitive function "
                    f"'{call_name}' at line {node.lineno}"
                )
        self.generic_visit(node)

    def visit_Assign(self, node):
        is_tainted = self._is_tainted(node.value)
        for target in node.targets:
            self._assign_taint(target, is_tainted, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._assign_taint(node.target, self._is_tainted(node.value), node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        is_tainted = self._is_tainted(node.target) or self._is_tainted(node.value)
        self._assign_taint(node.target, is_tainted, None)
        self.generic_visit(node)

    def _assign_taint(self, target, is_tainted, value):
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_vars.add(target.id)
            else:
                self.tainted_vars.discard(target.id)
            if isinstance(value, (ast.List, ast.Tuple, ast.Dict)):
                self.tainted_collections[target.id] = self._tainted_collection_keys(value)
            else:
                self.tainted_collections.pop(target.id, None)

    def _tainted_collection_keys(self, node):
        tainted_keys = set()
        if isinstance(node, (ast.List, ast.Tuple)):
            for index, element in enumerate(node.elts):
                if self._is_tainted(element):
                    tainted_keys.add(index)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if self._is_tainted(value):
                    try:
                        tainted_keys.add(ast.literal_eval(key))
                    except (ValueError, TypeError):
                        tainted_keys.add(None)
        return tainted_keys

    def _is_tainted(self, node):
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.Attribute):
            if _call_name(node) in self.taint_sources:
                return True
            return any(self._is_tainted(child) for child in ast.iter_child_nodes(node))
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            tainted_keys = self.tainted_collections.get(node.value.id, set())
            if not tainted_keys:
                return False
            try:
                key = ast.literal_eval(node.slice)
            except (ValueError, TypeError):
                return None in tainted_keys or bool(tainted_keys)
            return key in tainted_keys or None in tainted_keys
        if isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            if call_name in self.taint_sources or call_name in self.tainted_functions:
                return True
            tainted_indexes = self.tainted_function_args.get(call_name, set())
            for index, argument in enumerate(node.args):
                if index in tainted_indexes and self._is_tainted(argument):
                    return True
            for keyword in node.keywords:
                if keyword.arg in tainted_indexes and self._is_tainted(keyword.value):
                    return True
        return any(self._is_tainted(child) for child in ast.iter_child_nodes(node))


class MultiFileTaintAnalyzer:
    """Collect per-file taint results and a consolidated report."""

    def __init__(self):
        self.tainted_vars = set()
        self.taint_sources = {"input", "os.environ.get", "sys.argv"}
        self.sensitive_sinks = {"eval", "exec", "os.system", "subprocess.run"}
        self.issues = []
        self.filewise_taint = {}

    def analyze_file(self, file_name, tree):
        local_analyzer = TaintAnalyzer()
        self.issues.extend(local_analyzer.analyze(tree))
        self.tainted_vars.update(local_analyzer.tainted_vars)
        self.filewise_taint[file_name] = local_analyzer.tainted_vars

    def analyze_files(self, python_files_ast):
        for file_name, tree in python_files_ast.items():
            self.analyze_file(file_name, tree)

    def get_report(self):
        report = "\nGlobal Tainted Variables:\n"
        report += ", ".join(sorted(self.tainted_vars)) + "\n\nIssues:\n"
        for issue in self.issues:
            report += issue + "\n"
        return report
