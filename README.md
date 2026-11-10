# pythonAnalysis

`pythonAnalysis` is a small, experimental static-analysis prototype. It reads
Python source files from a ZIP archive, builds control-flow/dataflow structures,
and prints a syntactic call graph and selected taint-flow findings.

## Requirements

- Python 3 (the test suite was run with Python 3.13)
- The Python dependency listed in [`requirements.txt`](requirements.txt)

Install the dependency with:

```powershell
python -m pip install -r requirements.txt
```

The Graphviz system executable is only required when using the optional graph
visualization functions; the default scan prints text output.

## Run a scan

From the repository root, pass a ZIP archive containing `.py` files:

```powershell
python scan.py tests\tainttest.zip
```

The scanner reads Python files directly from the archive (it does not extract
them). Parse errors are reported and skipped. The call graph and taint findings
are printed to the terminal.

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

## Scope and limitations

This project is experimental, not a complete Python analyzer or
security scanner. Its analyses are syntax-based and only cover selected cases:

- Taint sources include `input()`, `os.environ.get()`, and `sys.argv`.
- Sensitive sinks include `eval()`, `exec()`, `os.system()`, and
  `subprocess.run()`.
- The call graph records syntactic calls; it does not resolve dynamic dispatch,
  imports, or runtime behavior.
- CFG and dataflow results are approximate and do not model every Python
  construct or execution path.

As a result, findings can be missed or incorrectly reported. Do not use the
results as a substitute for code review or a dedicated security analysis tool.
