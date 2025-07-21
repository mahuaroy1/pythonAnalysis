import ast
import argparse
import graphviz
#import networkx
from graphviz import Digraph
import zipfile
import os
from io import TextIOWrapper
from cfgbuilder import CFGBuilder, MultiModuleCFGBuilder, GlobalRegistry
from callgraph import MultiFileCallGraphBuilder
from taintanalysis import (MultiFileTaintAnalyzer)

def parse_all_python_files(zip_file_path):
    """
    Reads a zip file and parses all Python files (*.py) within it, including directories.

    Args:
        zip_file_path (str): The path to the zip file.

    Returns:
        dict: A dictionary where keys are file paths in the zip, and values are their ASTs.
    """
    # Dictionary to store the parsed AST for each Python file
    python_files_ast = {}

    # Open the zip file
    with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
        # List all files in the archive
        for file_name in zip_file.namelist():
            # Check if the file is a Python file
            if file_name.endswith('.py'):
                # Read the content of the Python file
                with zip_file.open(file_name) as file:
                    try:
                        # Parse the Python file content into an AST
                        file_content = TextIOWrapper(file, encoding='utf-8').read()
                        python_ast = ast.parse(file_content, filename=file_name)
                        # Store the parsed AST in the dictionary
                        python_files_ast[file_name] = python_ast
                    except Exception as e:
                        print(f"Error parsing {file_name}: {e}")

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

            '''
            # Print the CFG
            for node_name, node in cfg_builder.nodes.items():
                print(node)
            # print(ast.dump(ast_tree, indent=2))  # Pretty print the AST
            # Print the Context Registry
            print("\nContext Registry:")
            for var, details in cfg_builder.scope_manager.context_registry.items():
                print(var, details)
                '''

    def visualize_analysis(self):
        visualize_global_registry(self.global_registry)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Build a Control Flow Graph (CFG) for a Python program.")
    parser.add_argument("filename", help="The Python source file to analyze")
    args = parser.parse_args()

    # Initialize the global registry and process both modules
    global_registry = GlobalRegistry()
    # Parse Python files from the zip archive
    parsed_files = parse_all_python_files(args.filename)

    # Perform multi-file analysis
    analyzer = MultiFileAnalyzer(global_registry)
    analyzer.analyze_files(parsed_files)

    # Visualize the inter-module relationships and contexts
    #analyzer.visualize_analysis()

    # Build and visualize multi-file call graph
    multi_file_builder = MultiFileCallGraphBuilder()
    multi_file_builder.build_call_graph(parsed_files)
    print("call graph")
    for file, callnodes in multi_file_builder.global_call_graph.items():
        print(file,callnodes)
    #multi_file_builder.visualize_global_call_graph(output_filename="multi_file_call_graph")

    # Perform multi-file taint analysis
    multi_file_analyzer = MultiFileTaintAnalyzer()
    multi_file_analyzer.analyze_files(parsed_files)

    # Print the taint analysis report
    print(multi_file_analyzer.get_report())

    # Print the global registry
    print("\nGlobal Registry:")
    for module, symbols in global_registry.registry.items():
        print(module, symbols)

if __name__ == "__main__":
    main()
