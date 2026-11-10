# pythonAnalysis

`pythonAnalysis` is an experimental, AST-based static analysis tool for Python
projects. It builds control-flow and call-graph information and reports selected
taint flows across the Python files in an archive.

## Requirements

- Python 3
- The Python `graphviz` package

Install the Python dependency with:

```powershell
python -m pip install graphviz
```

The Graphviz system executable is only needed if you enable the visualization
functions in `scan.py`; the default scan does not render graphs.

## Run a scan

From the repository root, pass a ZIP archive containing Python files:

```powershell
python scan.py tests\tainttest.zip
```

The scanner parses `.py` files in the archive as UTF-8. Findings and analysis
details, including the call graph and taint report, are printed to the terminal.
Files that cannot be parsed are reported and skipped.

## Limitations

This is a demo/prototype, not a complete security scanner. Its AST-based checks
cover only selected patterns, so results may be incomplete. Review
the analyzed code and findings independently.
