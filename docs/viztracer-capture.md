# Default Python function capture

`mop capture -- python job.py` now uses VizTracer 1.1.1 by default for explicitly launched Python script files. The same capture command works through `hmop` and `bmop`. Existing live process monitoring does not attach to arbitrary processes or read their memory.

```bash
mop capture -- python job.py
mop capture --no-viztracer -- python job.py
mop capture --viztracer-max-functions 512 -- python job.py
```

The model endpoint must already be available. The capture pipeline does not start a model, restart Tetragon, or install any system service. A failed model request yields unknown advice and a nonzero capture command status when the workload itself succeeded. A workload failure retains its exit status.

Scope: the selected script file and its Python functions, including tested standard ThreadPoolExecutor dispatch. Function parameters, assignments in declared functions, and return representations become `source=viztracer` guard events. Stdout/stderr observation continues as before. Internal events are imported and submitted after the workload exits, not streamed at each assignment. They use the existing provider, categories, batching, audit and prompt logs.

Supported launch form: a Python interpreter followed by a `.py` script, optionally preceded by `-u`, `-B`, `-O` or `-OO`. Non-Python commands and `python -c`/`python -m` retain output capture only, counted as skipped internal capture. The selected interpreter is preserved, including its virtual environment. It must contain the pinned VizTracer dependency; missing dependencies produce a clear preflight error before the workload starts, with `--no-viztracer` as the explicit alternative. Child-process instrumentation is disabled.

The default function review budget is 256 (configurable 1..4096). Extra observations remain in the private report but are not classified, and the omitted count plus a visible error counter are recorded. A 20,000-entry tracer buffer and 32 MiB import budget bound the report path. Overflow is reported as incomplete capture. Reports live in private mode-0700 directories under `.runtime/function-captures`; they can contain original application values before best-effort redaction. They are not automatically uploaded or deleted. Detailed tracing can invoke object representations and adds overhead; it is not an OS sandbox or a complete dataflow proof.

Configuration keys: `viztracer: true`, `viztracer_max_functions: 256`. Defaults apply to MOP capture, not system-wide profiling. `--no-viztracer` takes precedence over the configuration file.

Validation covers real Python 3.10 capture, thread-pool calls, arguments/assignments/returns, original stdout without VizTracer progress noise, opt-out, target exit code, top-level-only scripts and explicit budget gaps. Provider tests use a fixture; previous Open-Jev-2B runs validate the imported event schema separately.
