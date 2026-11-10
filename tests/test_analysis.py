import ast
import tempfile
import unittest
import zipfile
from pathlib import Path

from callgraph import CallGraphBuilder
from cfgbuilder import CFGBuilder
from scan import parse_all_python_files
from taintanalysis import TaintAnalyzer


class TaintAnalyzerTests(unittest.TestCase):
    def analyze(self, source):
        analyzer = TaintAnalyzer()
        issues = analyzer.analyze(ast.parse(source))
        return analyzer, issues

    def test_detects_source_to_sink_through_assignment_and_expression(self):
        _, issues = self.analyze(
            "raw = input()\n"
            "alias = 'prefix-' + raw\n"
            "eval(alias)\n"
        )

        self.assertEqual(len(issues), 1)
        self.assertIn("'eval'", issues[0])

    def test_tracks_tainted_and_untainted_collection_elements(self):
        _, issues = self.analyze(
            "items = [input(), 'safe']\n"
            "eval(items[0])\n"
            "eval(items[1])\n"
        )

        self.assertEqual(len(issues), 1)

    def test_tracks_a_function_returning_a_source(self):
        _, issues = self.analyze(
            "def get_command():\n"
            "    return input()\n"
            "command = get_command()\n"
            "os.system(command)\n"
        )

        self.assertEqual(len(issues), 1)
        self.assertIn("'os.system'", issues[0])

    def test_tracks_taint_through_a_function_parameter(self):
        _, issues = self.analyze(
            "def identity(value):\n"
            "    return value\n"
            "command = identity(input())\n"
            "eval(command)\n"
        )

        self.assertEqual(len(issues), 1)

    def test_checks_keyword_arguments_at_sinks(self):
        _, issues = self.analyze(
            "command = input()\n"
            "subprocess.run(args=command)\n"
        )

        self.assertEqual(len(issues), 1)


class CallGraphTests(unittest.TestCase):
    def test_tracks_nested_class_and_async_functions_without_losing_scope(self):
        tree = ast.parse(
            "class Worker:\n"
            "    def run(self):\n"
            "        def helper():\n"
            "            leaf()\n"
            "        helper()\n"
            "        after()\n"
            "async def serve():\n"
            "    await start()\n"
        )
        builder = CallGraphBuilder()
        builder.visit(tree)

        self.assertEqual(builder.call_graph["Worker.run"], {"helper", "after"})
        self.assertEqual(builder.call_graph["Worker.run.helper"], {"leaf"})
        self.assertEqual(builder.call_graph["serve"], {"start"})


class CFGBuilderTests(unittest.TestCase):
    def test_if_branches_join_instead_of_running_sequentially(self):
        builder = CFGBuilder()
        builder.visit(ast.parse("if flag:\n    left = 1\nelse:\n    right = 2\n"))

        condition = builder.nodes["if_condition_0"]
        then_node = builder.nodes["if_then_1"]
        else_node = builder.nodes["if_else_3"]
        join_node = builder.nodes["if_join_5"]

        self.assertEqual(condition.successors, [then_node, else_node])
        self.assertIn(join_node, builder.nodes["assign_2"].successors)
        self.assertIn(join_node, builder.nodes["assign_4"].successors)

    def test_loop_has_back_edge_and_exit_path(self):
        builder = CFGBuilder()
        builder.visit(ast.parse("while ready:\n    step()\n"))

        condition = builder.nodes["while_condition_0"]
        body = builder.nodes["while_body_1"]
        exit_node = builder.nodes["while_exit_4"]

        self.assertIn(body, condition.successors)
        self.assertIn(exit_node, condition.successors)
        self.assertIn(condition, builder.nodes["expr_2"].successors)


class ArchiveParsingTests(unittest.TestCase):
    def test_parses_python_files_from_zip_without_extracting(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("package/module.py", "value = 1\n")
                archive.writestr("README.txt", "not Python")

            parsed = parse_all_python_files(archive_path)

        self.assertEqual(set(parsed), {"package/module.py"})
        self.assertEqual(parsed["package/module.py"].body[0].targets[0].id, "value")


if __name__ == "__main__":
    unittest.main()
