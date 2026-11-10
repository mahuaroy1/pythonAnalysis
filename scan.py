import ast
import argparse
import zipfile
import sys
from graphviz import Digraph
from cfgbuilder import MultiModuleCFGBuilder, GlobalRegistry
from callgraph import MultiFileCallGraphBuilder
from taintanalysis import MultiFileTaintAnalyzer

def parse_all_python_files(zip_file_path):
    """
    Parse Python files in a ZIP archive without extracting its contents.

    Args:
        zip_file_path (str): Path to the ZIP archive.

    Returns:
        dict: A dictionary where keys are file paths in the zip, and values are their ASTs.
    """
    python_files_ast = {}
    with zipfile.ZipFile(zip_file_path) as zip_file:
        for file_name in zip_file.namelist():
            if not file_name.endswith(".py"):
                continue
            try:
                source = zip_file.read(file_name)
                python_files_ast[file_name] = ast.parse(source, filename=file_name)
            except (SyntaxError, UnicodeDecodeError) as error:
                print(f"Error parsing {file_name}: {error}", file=sys.stderr)

    return python_files_ast

def visualize_call_graph(call_graph, output_filename="call_graph"):
    """
    Visualizes a call graph using graphviz.
    """
    dot = Digraph(comment="Call Graph")
    for function, calls in call_graph.items():
        dot.node(function, function)
        for call in calls:
            dot.node(call, call)
            dot.edge(function, call)
    dot.render(output_filename, format="png", cleanup=True)
    print(f"Call graph saved to {output_filename}.png")

def visualize_global_registry(global_registry):
    # Create a directed graph
    dot = Digraph(comment="Inter-Module Visualization")

    # Add module nodes and their symbols
    for module_name, symbols in global_registry.registry.items():
        dot.node(module_name, module_name, shape="box", style="filled", color="lightblue")

        for symbol, details in symbols.items():
            symbol_label = f"{symbol} ({details['type']})"
            dot.node(symbol, symbol_label, shape="ellipse", style="filled", color="yellow")
            dot.edge(module_name, symbol)

            # Handle connections for imported symbols
            if "imported_from" in details:
                imported_module = details["imported_from"]
                dot.edge(imported_module, symbol, label="imported")

            # Handle lambda free variables
            if details["type"] == "lambda" and "free_vars" in details:
                for free_var in details["free_vars"]:
                    dot.edge(free_var, symbol, label="used in lambda", color="red")

    # Render and visualize the graph
    dot.render("inter_module_visualization", format="png", cleanup=True)
    print("Inter-Module Visualization generated: inter_module_visualization.png")

class MultiFileAnalyzer:
    def __init__(self, global_registry):
        self.global_registry = global_registry

    def analyze_files(self, python_files_ast):
        for file_name, ast_tree in python_files_ast.items():
            print(f"Analyzing {file_name}...")
            cfg_builder = MultiModuleCFGBuilder(self.global_registry)
            cfg_builder.visit(ast_tree)
            cfg_builder.dataflow_analysis()

    def visualize_analysis(self):
        visualize_global_registry(self.global_registry)

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Analyze Python files contained in a ZIP archive."
    )
    parser.add_argument("filename", help="ZIP archive containing Python source files")
    args = parser.parse_args(argv)

    global_registry = GlobalRegistry()
    try:
        parsed_files = parse_all_python_files(args.filename)
    except (OSError, zipfile.BadZipFile) as error:
        parser.error(f"cannot read ZIP archive {args.filename!r}: {error}")
    if not parsed_files:
        parser.error(f"no parseable Python files found in {args.filename!r}")

    # Perform multi-file analysis
    analyzer = MultiFileAnalyzer(global_registry)
    analyzer.analyze_files(parsed_files)

    multi_file_builder = MultiFileCallGraphBuilder()
    multi_file_builder.build_call_graph(parsed_files)
    print("Call graph")
    for file, callnodes in multi_file_builder.global_call_graph.items():
        print(file, {function: sorted(calls) for function, calls in callnodes.items()})

    # Perform multi-file taint analysis
    multi_file_analyzer = MultiFileTaintAnalyzer()
    multi_file_analyzer.analyze_files(parsed_files)

    # Print the taint analysis report
    print(multi_file_analyzer.get_report())

    print("\nGlobal Registry:")
    for module, symbols in global_registry.registry.items():
        print(module, symbols)

if __name__ == "__main__":
    main()
